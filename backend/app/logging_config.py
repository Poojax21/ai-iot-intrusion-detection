"""
Structured logging configuration for Pahredaar-IoT.
Supports both human-readable development output and structured JSON formatting.
"""

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any, Dict


class JSONFormatter(logging.Formatter):
    """Formats log records as single-line JSON objects with ISO 8601 timestamps."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: Dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "line": record.lineno,
        }
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        if hasattr(record, "extra") and isinstance(record.extra, dict):
            log_entry.update(record.extra)
        return json.dumps(log_entry)


def setup_logging(level: str = "INFO", json_format: bool = False) -> logging.Logger:
    """Configures the root and application logger."""
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logger = logging.getLogger("iot_ids")
    logger.setLevel(numeric_level)

    # Avoid duplicate handlers on re-initialization
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(numeric_level)
        if json_format:
            handler.setFormatter(JSONFormatter())
        else:
            formatter = logging.Formatter(
                fmt="%(asctime)s [%(levelname)s] [%(name)s:%(module)s:%(lineno)d] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
            handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger


logger = setup_logging()
