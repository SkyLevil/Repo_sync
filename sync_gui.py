import signal
import sys
import traceback
from datetime import datetime
from pathlib import Path

from crash_logger import init_app_logging, init_crash_logging


def _emergency_bootstrap_log(message: str) -> None:
    try:
        log_dir = Path.home() / ".repo_sync_gui"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / "bootstrap_crash.log"
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(f"{datetime.now().isoformat()} {message}\n")
    except Exception:
        return


def main() -> None:
    _emergency_bootstrap_log("[BOOT] main() entered")
    write_marker, log_path = init_crash_logging()
    write_marker(f"Application startup. Crash log: {log_path}")
    _emergency_bootstrap_log(f"[BOOT] crash logger initialized: {log_path}")

    # Initialise the rotating application log (writes to ~/.repo_sync_gui/app.log).
    app_logger = init_app_logging()
    app_logger.info("Application startup — PID %d", __import__("os").getpid())

    try:
        write_marker("[BOOT] Importing PySide6 QApplication...")
        from PySide6.QtWidgets import QApplication
        from PySide6.QtCore import QSettings, QtMsgType, qInstallMessageHandler

        write_marker("[BOOT] Importing MainWindow...")
        from main_window import MainWindow

        def _qt_message_handler(msg_type, context, message):  # noqa: ANN001
            level_map = {
                QtMsgType.QtDebugMsg: "QT_DEBUG",
                QtMsgType.QtInfoMsg: "QT_INFO",
                QtMsgType.QtWarningMsg: "QT_WARN",
                QtMsgType.QtCriticalMsg: "QT_CRITICAL",
                QtMsgType.QtFatalMsg: "QT_FATAL",
            }
            level = level_map.get(msg_type, "QT")
            location = ""
            if context and getattr(context, "file", None):
                location = f" ({context.file}:{getattr(context, 'line', '?')})"
            write_marker(f"[{level}] {message}{location}")
            # Also mirror Qt messages into the app log
            app_logger.debug("[%s] %s%s", level, message, location)

        try:
            qInstallMessageHandler(_qt_message_handler)
            write_marker("[BOOT] Qt message handler installed.")
        except Exception as qt_handler_exc:  # noqa: BLE001
            write_marker(f"[BOOT-WARN] Failed to install Qt message handler: {qt_handler_exc}")

        write_marker("[BOOT] Creating QApplication...")
        app = QApplication([])

        # --- Graceful shutdown on SIGINT / SIGTERM ---
        def _signal_handler(signum, _frame):
            sig_name = signal.Signals(signum).name
            app_logger.info("Received %s — initiating graceful shutdown", sig_name)
            write_marker(f"Received {sig_name} — shutting down gracefully")
            app.quit()

        signal.signal(signal.SIGINT, _signal_handler)
        signal.signal(signal.SIGTERM, _signal_handler)

        # Allow Python signal handlers to fire while the Qt event loop runs.
        # A short-interval timer gives the interpreter a chance to process them.
        from PySide6.QtCore import QTimer
        _signal_timer = QTimer()
        _signal_timer.start(500)
        _signal_timer.timeout.connect(lambda: None)

        app.aboutToQuit.connect(lambda: write_marker("Application shutdown requested."))
        app.aboutToQuit.connect(lambda: app_logger.info("Application shutdown requested"))

        write_marker("[BOOT] Creating MainWindow...")
        try:
            window = MainWindow()
        except Exception as first_window_exc:  # noqa: BLE001
            write_marker(
                "[BOOT-WARN] MainWindow init failed. "
                f"Attempting one-time settings reset and retry.\n{first_window_exc}\n{traceback.format_exc()}"
            )
            app_logger.error("MainWindow init failed — resetting settings and retrying:\n%s", traceback.format_exc())
            _emergency_bootstrap_log(
                "[BOOT-WARN] MainWindow init failed; resetting QSettings and retrying once."
            )
            settings = QSettings("RepoSync", "FolderSyncGui")
            settings.clear()
            settings.sync()

            window = MainWindow()
            write_marker("[BOOT] MainWindow recovered after settings reset.")
            app_logger.info("MainWindow recovered after settings reset")

        write_marker("[BOOT] Showing MainWindow...")
        window.show()
        write_marker("Main window shown.")
        app_logger.info("Main window shown — entering event loop")
        _emergency_bootstrap_log("[BOOT] Entering QApplication event loop")
        app.exec()
        app_logger.info("Event loop exited normally")
    except Exception as exc:  # noqa: BLE001
        _emergency_bootstrap_log(f"[BOOT-CRASH] {exc}\n{traceback.format_exc()}")
        write_marker(f"Fatal startup/runtime exception: {exc}\n{traceback.format_exc()}")
        app_logger.critical("Fatal exception:\n%s", traceback.format_exc())
        raise


if __name__ == "__main__":
    main()
