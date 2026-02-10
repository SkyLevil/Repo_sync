import traceback

from PySide6.QtWidgets import QApplication

from crash_logger import init_crash_logging
from main_window import MainWindow


def main() -> None:
    write_marker, log_path = init_crash_logging()
    write_marker(f"Application startup. Crash log: {log_path}")

    app = QApplication([])
    app.aboutToQuit.connect(lambda: write_marker("Application shutdown requested."))

    try:
        window = MainWindow()
        window.show()
        write_marker("Main window shown.")
        app.exec()
    except Exception as exc:  # noqa: BLE001
        write_marker(f"Fatal startup/runtime exception: {exc}\n{traceback.format_exc()}")
        raise


if __name__ == "__main__":
    main()
