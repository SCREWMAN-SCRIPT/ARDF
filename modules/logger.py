"""
modules/logger.py
──────────────────
Structured logging for ARDF.
Every log record is written as:
  - Rich formatted text  → console  (human-readable, coloured)
  - Plain text           → session log file
  - JSON                 → session.jsonl
"""

import logging
import os
import json
import traceback
from datetime import datetime, timezone
from pathlib  import Path
from typing   import Any, Dict, Optional

from rich.console import Console
from rich.logging import RichHandler


JSONL_SUFFIX  = ".jsonl"
LOG_SUFFIX    = ".log"
_INITIALIZED  = False
_SESSION_ID: Optional[str] = None

FINDING_LEVEL = 35
logging.addLevelName(FINDING_LEVEL, "FINDING")


class _JSONLHandler(logging.Handler):
    def __init__(self, filepath: Path):
        super().__init__()
        filepath.parent.mkdir(parents=True, exist_ok=True)
        self._path = filepath
        self._fh   = open(filepath, "a", encoding="utf-8")

    def emit(self, record: logging.LogRecord):
        try:
            entry: Dict[str, Any] = {
                "ts":     datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
                "level":  record.levelname,
                "logger": record.name,
                "msg":    record.getMessage(),
            }
            for key in getattr(record, "_extra_keys", []):
                entry[key] = getattr(record, key, None)
            if record.exc_info:
                entry["exc"] = traceback.format_exception(*record.exc_info)
            self._fh.write(json.dumps(entry, default=str) + "\n")
            self._fh.flush()
        except Exception:
            self.handleError(record)

    def close(self):
        self._fh.close()
        super().close()


def _make_file_handler(filepath: Path) -> logging.FileHandler:
    filepath.parent.mkdir(parents=True, exist_ok=True)
    fh = logging.FileHandler(filepath, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        fmt     = "%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s",
        datefmt = "%Y-%m-%d %H:%M:%S",
    ))
    return fh


class ARDFLogger:
    _SUCCESS_LEVEL = 25
    logging.addLevelName(_SUCCESS_LEVEL, "SUCCESS")

    def __init__(self, name: str):
        self._log     = logging.getLogger(f"ardf.{name}")
        self._console = Console(stderr=False)

    def _emit(self, level: int, msg: str, **kwargs):
        if not self._log.isEnabledFor(level):
            return
        record = self._log.makeRecord(
            name     = self._log.name,
            level    = level,
            fn       = "",
            lno      = 0,
            msg      = msg,
            args     = (),
            exc_info = None,
        )
        record._extra_keys = list(kwargs.keys())
        for k, v in kwargs.items():
            setattr(record, k, v)
        self._log.handle(record)

    def debug(self, msg: str, **kwargs):    self._emit(logging.DEBUG,    msg, **kwargs)
    def info(self, msg: str, **kwargs):     self._emit(logging.INFO,     msg, **kwargs)
    def warning(self, msg: str, **kwargs):  self._emit(logging.WARNING,  msg, **kwargs)
    def error(self, msg: str, **kwargs):    self._emit(logging.ERROR,    msg, **kwargs)
    def critical(self, msg: str, **kwargs): self._emit(logging.CRITICAL, msg, **kwargs)

    def exception(self, msg: str, **kwargs):
        record = self._log.makeRecord(
            name=self._log.name, level=logging.ERROR,
            fn="", lno=0, msg=msg, args=(), exc_info=True,
        )
        record._extra_keys = list(kwargs.keys())
        for k, v in kwargs.items():
            setattr(record, k, v)
        self._log.handle(record)

    def success(self, msg: str, **kwargs):
        self._emit(self._SUCCESS_LEVEL, f"✔  {msg}", **kwargs)

    def finding(
        self,
        msg:      str,
        severity: str = "info",
        host:     str = "",
        port:     Optional[int]  = None,
        cve:      Optional[str]  = None,
        **kwargs,
    ):
        prefix = {
            "critical": "🔴 CRITICAL",
            "high":     "🟠 HIGH    ",
            "medium":   "🟡 MEDIUM  ",
            "low":      "🔵 LOW     ",
            "info":     "⚪ INFO    ",
        }.get(severity.lower(), "⚪ INFO    ")
        full_msg = f"{prefix} | {msg}"
        if host: full_msg += f" | host={host}"
        if port: full_msg += f":{port}"
        if cve:  full_msg += f" | {cve}"
        self._emit(FINDING_LEVEL, full_msg,
                   severity=severity, host=host, port=port, cve=cve, **kwargs)

    def banner(self, title: str, style: str = "bold cyan"):
        from rich.rule import Rule
        self._console.print(Rule(title, style=style))

    def cmd(self, command: str):
        self._emit(logging.INFO, f"[CMD] {command}", type="cmd")

    def cmd_out(self, output: str, truncate: int = 800):
        preview = output[:truncate] + ("…" if len(output) > truncate else "")
        self._emit(logging.DEBUG, f"[OUT] {preview}", type="cmd_out")

    def cmd_err(self, stderr: str, truncate: int = 400):
        if stderr.strip():
            preview = stderr[:truncate] + ("…" if len(stderr) > truncate else "")
            self._emit(logging.WARNING, f"[ERR] {preview}", type="cmd_err")


def setup_logging(
    log_dir:    str  = "logs",
    session_id: str  = "default",
    log_level:  int  = logging.DEBUG,
    quiet:      bool = False,
) -> Dict[str, Path]:
    global _INITIALIZED, _SESSION_ID

    if _INITIALIZED:
        return {}

    _SESSION_ID = session_id
    log_path    = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)

    log_file   = log_path / f"{session_id}{LOG_SUFFIX}"
    jsonl_file = log_path / f"{session_id}{JSONL_SUFFIX}"

    root = logging.getLogger("ardf")
    root.setLevel(logging.DEBUG)
    root.propagate = False

    if not quiet:
        ch = RichHandler(
            rich_tracebacks = True,
            show_time       = True,
            show_path       = False,
            markup          = True,
            log_time_format = "[%H:%M:%S]",
        )
        ch.setLevel(log_level)
        ch.setFormatter(logging.Formatter("%(message)s"))
        root.addHandler(ch)

    root.addHandler(_make_file_handler(log_file))
    root.addHandler(_JSONLHandler(jsonl_file))

    for noisy in ("urllib3", "requests", "httpx", "charset_normalizer"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    _INITIALIZED = True
    logging.getLogger("ardf.setup").info(
        f"Logging initialised | session={session_id} | "
        f"log={log_file} | jsonl={jsonl_file}"
    )
    return {"log_file": log_file, "jsonl_file": jsonl_file}


def reset_logging():
    global _INITIALIZED
    root = logging.getLogger("ardf")
    root.handlers.clear()
    _INITIALIZED = False


_loggers: Dict[str, ARDFLogger] = {}

def get_logger(name: str = "core") -> ARDFLogger:
    if not _INITIALIZED:
        setup_logging()
    if name not in _loggers:
        _loggers[name] = ARDFLogger(name)
    return _loggers[name]
