"""Shared logging utilities for Vajra."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from vajra.common.paths import PROJECT_ROOT

LOGS_DIR = PROJECT_ROOT / "logs"


def setup_logging(
    name: str,
    log_file: Optional[str | Path] = None,
    level: int = logging.INFO,
    format_str: Optional[str] = None,
) -> logging.Logger:
    """Ensure the logs directory exists and configure standard logging handlers.

    Creates the target logs directory before opening the FileHandler so that
    modules can safely initialize logging at import time on fresh clones.

    Args:
        name: Name of the logger to retrieve.
        log_file: Name or path of the log file (e.g. 'soar_engine.log' or 'logs/soar_engine.log').
            Defaults to f"{name}.log" if not specified.
        level: Logging level (default: logging.INFO).
        format_str: Log message format string.

    Returns:
        logging.Logger: The configured logger instance.
    """
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    Path("logs").mkdir(parents=True, exist_ok=True)

    if log_file is None:
        target_path = LOGS_DIR / f"{name}.log"
    else:
        p = Path(log_file)
        if p.is_absolute():
            target_path = p
        elif p.parts and p.parts[0] == "logs":
            target_path = PROJECT_ROOT / p
        else:
            target_path = LOGS_DIR / p

    target_path.parent.mkdir(parents=True, exist_ok=True)

    fmt = format_str or "%(asctime)s [%(levelname)s] %(message)s"

    file_handler = logging.FileHandler(str(target_path))
    file_handler.setFormatter(logging.Formatter(fmt))

    logger = logging.getLogger(name)
    logger.setLevel(level)
    if not any(isinstance(h, logging.FileHandler) and getattr(h, "baseFilename", None) == str(target_path) for h in logger.handlers):
        logger.addHandler(file_handler)

    logging.basicConfig(
        level=level,
        format=fmt,
        handlers=[
            logging.StreamHandler(),
            file_handler,
        ],
        force=True,
    )

    return logger
