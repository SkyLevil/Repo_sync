from __future__ import annotations

import faulthandler
import logging
import logging.handlers
import sys
import threading
import traceback
from datetime import datetime
from pathlib import Path
from typing import Callable

_FAULT_STREAM = None
_APP_LOGGER: logging.Logger | None = None


def init_crash_logging(app_name: str = "repo_sync_gui") -> tuple[Callable[[str], None], Path]:
    """Bootstrap crash logging: fault handler, exception hooks, persistent crash log."""
    log_dir = Path.home() / f".{app_name}"
    log_dir.mkdir(parents=True, exist_ok=True)
    crash_log_path = log_dir / "crash.log"

    logger = logging.getLogger(f"{app_name}.crash")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    # Ensure a file handler for this exact crash log path always exists.
    target_path = str(crash_log_path.resolve())
    has_target_handler = False
    for handler in logger.handlers:
        if isinstance(handler, logging.FileHandler) and getattr(handler, "baseFilename", "") == target_path:
            has_target_handler = True
            break

    if not has_target_handler:
        handler = logging.FileHandler(crash_log_path, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        logger.addHandler(handler)

    def write(message: str) -> None:
        logger.info(message)
        for h in logger.handlers:
            h.flush()

    def _write_exception(header: str, exc_type, exc_value, exc_tb) -> None:
        formatted = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
        write(f"{header}\n{formatted}")

    def handle_exception(exc_type, exc_value, exc_tb) -> None:
        _write_exception("[CRASH] Unhandled exception", exc_type, exc_value, exc_tb)
        # Also forward to app logger if available
        app = get_app_logger()
        if app:
            app.critical("Unhandled exception\n%s", "".join(traceback.format_exception(exc_type, exc_value, exc_tb)))

    def handle_thread_exception(args: threading.ExceptHookArgs) -> None:
        thread_name = args.thread.name if args.thread else "unknown"
        _write_exception(
            f"[CRASH] Unhandled thread exception in {thread_name}",
            args.exc_type,
            args.exc_value,
            args.exc_traceback,
        )
        app = get_app_logger()
        if app:
            app.critical(
                "Unhandled thread exception in %s\n%s",
                thread_name,
                "".join(traceback.format_exception(args.exc_type, args.exc_value, args.exc_traceback)),
            )

    def log_marker(text: str) -> None:
        write(f"[MARKER] {text}")

    sys.excepthook = handle_exception
    threading.excepthook = handle_thread_exception

    global _FAULT_STREAM
    fault_stream = crash_log_path.open("a", encoding="utf-8")
    fault_stream.write(f"\n===== Session started: {datetime.now().isoformat()} =====\n")
    fault_stream.flush()
    faulthandler.enable(file=fault_stream, all_threads=True)
    _FAULT_STREAM = fault_stream

    return log_marker, crash_log_path


def init_app_logging(app_name: str = "repo_sync_gui") -> logging.Logger:
    """Set up the rotating application log that captures everything automatically.

    Returns a standard ``logging.Logger`` that all modules should use.  The log
    is written to ``~/.repo_sync_gui/app.log`` with automatic rotation (5 MB
    per file, 3 backups kept).
    """
    global _APP_LOGGER
    if _APP_LOGGER is not None:
        return _APP_LOGGER

    log_dir = Path.home() / f".{app_name}"
    log_dir.mkdir(parents=True, exist_ok=True)
    app_log_path = log_dir / "app.log"

    logger = logging.getLogger(app_name)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    # Rotating file handler — 5 MB per file, keep 3 backups.
    target_path = str(app_log_path.resolve())
    already_attached = any(
        isinstance(h, logging.handlers.RotatingFileHandler) and getattr(h, "baseFilename", "") == target_path
        for h in logger.handlers
    )
    if not already_attached:
        rotating = logging.handlers.RotatingFileHandler(
            app_log_path,
            maxBytes=5 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8",
        )
        rotating.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] [%(name)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
        )
        logger.addHandler(rotating)

    _APP_LOGGER = logger
    logger.info("===== Application log session started =====")
    return logger


def get_app_logger() -> logging.Logger | None:
    """Return the app logger if already initialised, else ``None``."""
    return _APP_LOGGER
