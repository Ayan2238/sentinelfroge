"""
Structured Logger
~~~~~~~~~~~~~~~~~
Provides a rich, coloured, structured logger for SentinelForge.
All output goes through this module so the verbosity, format, and
destination can be changed in one place.
"""

from __future__ import annotations

import logging
import sys
from datetime import datetime, timezone
from enum import IntEnum
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Custom severity levels
# ---------------------------------------------------------------------------

SUCCESS_LEVEL = 25      # between INFO and WARNING
logging.addLevelName(SUCCESS_LEVEL, "SUCCESS")

FINDING_LEVEL = 35      # between WARNING and ERROR
logging.addLevelName(FINDING_LEVEL, "FINDING")


# ---------------------------------------------------------------------------
# ANSI colour helpers (gracefully disabled when stdout is not a TTY)
# ---------------------------------------------------------------------------

_RESET = "\033[0m"
_BOLD = "\033[1m"

_COLOURS: dict[str, str] = {
    "DEBUG":   "\033[36m",   # cyan
    "INFO":    "\033[34m",   # blue
    "SUCCESS": "\033[32m",   # green
    "WARNING": "\033[33m",   # yellow
    "FINDING": "\033[35m",   # magenta
    "ERROR":   "\033[31m",   # red
    "CRITICAL":"\033[41m",   # red background
}


def _colourise(level_name: str, text: str) -> str:
    if not sys.stdout.isatty():
        return text
    colour = _COLOURS.get(level_name, "")
    return f"{colour}{text}{_RESET}"


# ---------------------------------------------------------------------------
# Formatter
# ---------------------------------------------------------------------------


class SentinelFormatter(logging.Formatter):
    """
    Compact coloured formatter:

        [HH:MM:SS] [MODULE   ] [LEVEL  ] message
    """

    _WIDTH = 10   # fixed-width column for level name

    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        module = record.name.split(".")[-1][:12].ljust(12)
        level = record.levelname.ljust(self._WIDTH)
        msg = record.getMessage()

        if record.exc_info:
            msg += "\n" + self.formatException(record.exc_info)

        coloured_level = _colourise(record.levelname, level)
        return f"[{ts}] [{module}] [{coloured_level}] {msg}"


# ---------------------------------------------------------------------------
# Public Logger class
# ---------------------------------------------------------------------------


class SentinelLogger:
    """
    Thin wrapper around :class:`logging.Logger` that adds:

    * ``success(msg)`` – green SUCCESS level
    * ``finding(msg, **evidence)`` – coloured FINDING level
    * Session-scoped file handler

    Parameters
    ----------
    name:
        Logger name (usually ``__name__`` of the caller module).
    level:
        Minimum log level string (``"DEBUG"``, ``"INFO"``, etc.).
    log_dir:
        When set, a rotating file handler is added under this directory.
    session_id:
        When provided, logs go to ``<log_dir>/<session_id>.log``.
    """

    def __init__(
        self,
        name: str = "sentinelforge",
        level: str = "INFO",
        log_dir: str | Path | None = None,
        session_id: str | None = None,
    ) -> None:
        self._logger = logging.getLogger(name)
        self._logger.setLevel(getattr(logging, level.upper(), logging.INFO))
        self._logger.propagate = False

        if not self._logger.handlers:
            self._add_console_handler()

        if log_dir:
            self._add_file_handler(Path(log_dir), session_id)

    # ------------------------------------------------------------------
    # Standard levels
    # ------------------------------------------------------------------

    def debug(self, msg: str, **ctx: Any) -> None:
        self._logger.debug(self._fmt(msg, ctx))

    def info(self, msg: str, **ctx: Any) -> None:
        self._logger.info(self._fmt(msg, ctx))

    def warning(self, msg: str, **ctx: Any) -> None:
        self._logger.warning(self._fmt(msg, ctx))

    def error(self, msg: str, exc_info: bool = False, **ctx: Any) -> None:
        self._logger.error(self._fmt(msg, ctx), exc_info=exc_info)

    def critical(self, msg: str, **ctx: Any) -> None:
        self._logger.critical(self._fmt(msg, ctx))

    # ------------------------------------------------------------------
    # Custom levels
    # ------------------------------------------------------------------

    def success(self, msg: str, **ctx: Any) -> None:
        self._logger.log(SUCCESS_LEVEL, self._fmt(msg, ctx))

    def finding(self, msg: str, severity: str = "info", **ctx: Any) -> None:
        """Log a security finding."""
        prefix = _colourise("FINDING", f"[{severity.upper()}]")
        self._logger.log(FINDING_LEVEL, f"{prefix} {self._fmt(msg, ctx)}")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _fmt(msg: str, ctx: dict[str, Any]) -> str:
        if not ctx:
            return msg
        kv = " ".join(f"{k}={v!r}" for k, v in ctx.items())
        return f"{msg}  {kv}"

    def _add_console_handler(self) -> None:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(SentinelFormatter())
        self._logger.addHandler(handler)

    def _add_file_handler(
        self, log_dir: Path, session_id: str | None
    ) -> None:
        from logging.handlers import RotatingFileHandler

        log_dir.mkdir(parents=True, exist_ok=True)
        filename = f"{session_id}.log" if session_id else "sentinelforge.log"
        path = log_dir / filename
        handler = RotatingFileHandler(
            path, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
        )
        # File handler: plain (no ANSI colour codes)
        handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s %(name)-20s %(levelname)-10s %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S",
            )
        )
        self._logger.addHandler(handler)

    def set_level(self, level: str) -> None:
        self._logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    def child(self, name: str) -> "SentinelLogger":
        """Return a child logger inheriting this logger's handlers."""
        child = SentinelLogger.__new__(SentinelLogger)
        child._logger = self._logger.getChild(name)
        return child


# ---------------------------------------------------------------------------
# Module-level convenience instance
# ---------------------------------------------------------------------------

_root_logger: SentinelLogger | None = None


def get_logger(name: str = "sentinelforge") -> SentinelLogger:
    """Return (or create) the root logger."""
    global _root_logger
    if _root_logger is None:
        _root_logger = SentinelLogger(name)
    return _root_logger


def configure_logging(
    level: str = "INFO",
    log_dir: str | Path | None = None,
    session_id: str | None = None,
) -> SentinelLogger:
    """Configure the root logger. Call once at startup."""
    global _root_logger
    _root_logger = SentinelLogger(
        name="sentinelforge",
        level=level,
        log_dir=log_dir,
        session_id=session_id,
    )
    return _root_logger
