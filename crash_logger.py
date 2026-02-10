from __future__ import annotations

import faulthandler
import logging
import sys
import threading
import traceback
from datetime import datetime
from pathlib import Path
from typing import Callable

_FAULT_STREAM = None


def init_crash_logging(app_name: str = "repo_sync_gui") -> tuple[Callable[[str], None], Path]:
    log_dir = Path.home() / f".{app_name}"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / "crash.log"

    logger = logging.getLogger(app_name)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    # Ensure a file handler for this exact log path always exists.
    target_path = str(log_path.resolve())
    has_target_handler = False
    for handler in logger.handlers:
        if isinstance(handler, logging.FileHandler) and getattr(handler, "baseFilename", "") == target_path:
            has_target_handler = True
            break

    if not has_target_handler:
        handler = logging.FileHandler(log_path, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        logger.addHandler(handler)

    def write(message: str) -> None:
        logger.info(message)
        for handler in logger.handlers:
            handler.flush()

    def _write_exception(header: str, exc_type, exc_value, exc_tb) -> None:
        formatted = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
        write(f"{header}\n{formatted}")

    def handle_exception(exc_type, exc_value, exc_tb) -> None:
        _write_exception("[CRASH] Unhandled exception", exc_type, exc_value, exc_tb)

    def handle_thread_exception(args: threading.ExceptHookArgs) -> None:
        _write_exception(
            f"[CRASH] Unhandled thread exception in {args.thread.name}",
            args.exc_type,
            args.exc_value,
            args.exc_traceback,
        )

    def log_marker(text: str) -> None:
        write(f"[MARKER] {text}")

    sys.excepthook = handle_exception
    threading.excepthook = handle_thread_exception

    global _FAULT_STREAM
    fault_stream = log_path.open("a", encoding="utf-8")
    fault_stream.write(f"\n===== Session started: {datetime.now().isoformat()} =====\n")
    fault_stream.flush()
    faulthandler.enable(file=fault_stream, all_threads=True)
    _FAULT_STREAM = fault_stream

    return log_marker, log_path
