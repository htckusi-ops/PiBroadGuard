import logging
import os
from logging.handlers import RotatingFileHandler


def setup_logging(log_level: str, log_path: str) -> None:
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    fmt = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    datefmt = "%Y-%m-%dT%H:%M:%S"
    formatter = logging.Formatter(fmt=fmt, datefmt=datefmt)

    file_handler = RotatingFileHandler(
        log_path,
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)

    level = getattr(logging, log_level.upper(), logging.INFO)

    # Attach file handler to root logger so ALL loggers write to the file.
    # basicConfig() is a no-op when the root logger already has handlers
    # (uvicorn configures it before our code runs), so we add explicitly.
    root = logging.getLogger()
    root.setLevel(level)

    # Avoid duplicate handlers on reload (dev mode)
    if not any(isinstance(h, RotatingFileHandler) and h.baseFilename == file_handler.baseFilename
               for h in root.handlers):
        root.addHandler(file_handler)
