"""
modules/session.py
───────────────────
Session & Workspace Management for ARDF.
Every scan run lives in a named session folder.
Sessions are resumable and carry full state.
"""

import os
import json
import time
import uuid
import shutil
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field, asdict
from enum import Enum


# ---------------------------------------------------------------------------
# Enums & Constants
# ---------------------------------------------------------------------------

class SessionStatus(str, Enum):
    CREATED   = "created"
    RUNNING   = "running"
    PAUSED    = "paused"
    COMPLETED = "completed"
    FAILED    = "failed"

class Mode(str, Enum):
    RED  = "red"
    BLUE = "blue"
    FULL = "full"

class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"

SESSIONS_ROOT = Path(__file__).parent.parent / "output" / "sessions"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    id:          str              = field(default_factory=lambda: uuid.uuid4().hex[:8])
    source:      str              = ""
    title:       str              = ""
    description: str              = ""
    severity:    SeverityLevel    = SeverityLevel.INFO
    host:        str              = ""
    port:        Optional[int]    = None
    cve:         Optional[str]    = None
    evidence:    str              = ""
    remediation: str              = ""
    tags:        List[str]        = field(default_factory=list)
    timestamp:   str              = field(default_factory=lambda: datetime.utcnow().isoformat())
    raw:         Dict[str, Any]   = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d

    @staticmethod
    def from_dict(d: dict) -> "Finding":
        d["severity"] = SeverityLevel(d.get("severity", "info"))
        return Finding(**d)


@dataclass
class SessionMeta:
    session_id:   str
    name:         str
    target:       str
    mode:         Mode
    status:       SessionStatus
    created_at:   str
    updated_at:   str
    completed_at: Optional[str]        = None
    tags:         List[str]            = field(default_factory=list)
    modules_done: List[str]            = field(default_factory=list)
    findings_count: int                = 0
    risk_score:   float                = 0.0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["mode"]   = self.mode.value
        d["status"] = self.status.value
        return d

    @staticmethod
    def from_dict(d: dict) -> "SessionMeta":
        d["mode"]   = Mode(d["mode"])
        d["status"] = SessionStatus(d["status"])
        return SessionMeta(**d)


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------

class Session:
    _SEVERITY_WEIGHT: Dict[str, float] = {
        "critical": 10.0,
        "high":      7.0,
        "medium":    4.0,
        "low":       1.5,
        "info":      0.0,
    }

    def __init__(self, meta: SessionMeta):
        self.meta = meta
        self.root = SESSIONS_ROOT / meta.session_id
        self._ensure_dirs()

    def _ensure_dirs(self):
        for sub in ("recon", "exploit", "defense", "intel", "report", "logs"):
            (self.root / sub).mkdir(parents=True, exist_ok=True)

    def dir(self, module: str) -> Path:
        p = self.root / module
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def log_file(self) -> Path:
        return self.root / "logs" / f"session_{self.meta.session_id}.log"

    @property
    def findings_file(self) -> Path:
        return self.root / "findings.jsonl"

    @property
    def meta_file(self) -> Path:
        return self.root / "meta.json"

    def save(self):
        self.meta.updated_at = datetime.utcnow().isoformat()
        with open(self.meta_file, "w") as f:
            json.dump(self.meta.to_dict(), f, indent=2)

    def add_finding(self, finding: Finding):
        with open(self.findings_file, "a") as f:
            f.write(json.dumps(finding.to_dict()) + "\n")
        self.meta.findings_count += 1
        self.meta.risk_score = round(
            self.meta.risk_score + self._SEVERITY_WEIGHT.get(finding.severity.value, 0), 2
        )
        self.save()

    def add_findings(self, findings: List[Finding]):
        for f in findings:
            self.add_finding(f)

    def get_findings(
        self,
        severity: Optional[SeverityLevel] = None,
        source:   Optional[str] = None,
    ) -> List[Finding]:
        if not self.findings_file.exists():
            return []
        results = []
        with open(self.findings_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    finding = Finding.from_dict(json.loads(line))
                    if severity and finding.severity != severity:
                        continue
                    if source and finding.source != source:
                        continue
                    results.append(finding)
                except Exception:
                    continue
        return results

    def findings_summary(self) -> Dict[str, int]:
        counts = {s.value: 0 for s in SeverityLevel}
        for f in self.get_findings():
            counts[f.severity.value] += 1
        return counts

    def mark_module_done(self, module: str):
        if module not in self.meta.modules_done:
            self.meta.modules_done.append(module)
        self.save()

    def is_module_done(self, module: str) -> bool:
        return module in self.meta.modules_done

    def set_status(self, status: SessionStatus):
        self.meta.status = status
        if status == SessionStatus.COMPLETED:
            self.meta.completed_at = datetime.utcnow().isoformat()
        self.save()

    def export_findings_json(self) -> Path:
        out = self.root / "report" / "findings.json"
        with open(out, "w") as f:
            json.dump([x.to_dict() for x in self.get_findings()], f, indent=2)
        return out

    def archive(self) -> Path:
        archive_path = SESSIONS_ROOT / f"{self.meta.session_id}.zip"
        shutil.make_archive(str(archive_path.with_suffix("")), "zip", str(self.root))
        return archive_path

    def __repr__(self) -> str:
        return (
            f"<Session id={self.meta.session_id} target={self.meta.target} "
            f"mode={self.meta.mode.value} status={self.meta.status.value} "
            f"findings={self.meta.findings_count} risk={self.meta.risk_score}>"
        )


# ---------------------------------------------------------------------------
# SessionManager
# ---------------------------------------------------------------------------

class SessionManager:
    def __init__(self, sessions_root: Path = SESSIONS_ROOT):
        self.root = sessions_root
        self.root.mkdir(parents=True, exist_ok=True)

    def create(
        self,
        target: str,
        mode:   Mode = Mode.FULL,
        name:   Optional[str] = None,
        tags:   Optional[List[str]] = None,
    ) -> Session:
        session_id = datetime.utcnow().strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:6]
        now  = datetime.utcnow().isoformat()
        meta = SessionMeta(
            session_id   = session_id,
            name         = name or f"{target}_{session_id}",
            target       = target,
            mode         = mode,
            status       = SessionStatus.CREATED,
            created_at   = now,
            updated_at   = now,
            tags         = tags or [],
        )
        session = Session(meta)
        session.save()
        return session

    def load(self, session_id: str) -> Session:
        meta_file = self.root / session_id / "meta.json"
        if not meta_file.exists():
            raise FileNotFoundError(f"Session not found: {session_id}")
        with open(meta_file) as f:
            meta = SessionMeta.from_dict(json.load(f))
        return Session(meta)

    def load_latest(self, target: Optional[str] = None) -> Optional[Session]:
        sessions = self.list_sessions()
        if target:
            sessions = [s for s in sessions if s["target"] == target]
        if not sessions:
            return None
        latest = max(sessions, key=lambda s: s["updated_at"])
        return self.load(latest["session_id"])

    def list_sessions(self) -> List[Dict[str, Any]]:
        results = []
        for path in self.root.iterdir():
            if not path.is_dir():
                continue
            meta_file = path / "meta.json"
            if not meta_file.exists():
                continue
            try:
                with open(meta_file) as f:
                    results.append(json.load(f))
            except Exception:
                continue
        return sorted(results, key=lambda s: s.get("updated_at", ""), reverse=True)

    def search(self, query: str) -> List[Dict[str, Any]]:
        q = query.lower()
        return [
            s for s in self.list_sessions()
            if q in s.get("target", "").lower()
            or q in s.get("name", "").lower()
            or any(q in t.lower() for t in s.get("tags", []))
        ]

    def delete(self, session_id: str):
        path = self.root / session_id
        if path.exists():
            shutil.rmtree(path)

    def cleanup_old(self, keep_last: int = 20):
        sessions    = self.list_sessions()
        to_delete   = sessions[keep_last:]
        for s in to_delete:
            self.delete(s["session_id"])

    def print_sessions(self):
        try:
            from rich.table import Table
            from rich.console import Console
            console = Console()
            table   = Table(title="ARDF Sessions", show_lines=True)
            table.add_column("ID",       style="cyan",    no_wrap=True)
            table.add_column("Target",   style="green")
            table.add_column("Mode",     style="magenta")
            table.add_column("Status",   style="yellow")
            table.add_column("Findings", justify="right")
            table.add_column("Risk",     justify="right", style="red")
            table.add_column("Updated",  style="dim")
            for s in self.list_sessions():
                status_color = {
                    "completed": "green", "running": "yellow",
                    "failed":    "red",   "paused":  "blue",
                    "created":   "white",
                }.get(s.get("status", ""), "white")
                table.add_row(
                    s.get("session_id", ""),
                    s.get("target", ""),
                    s.get("mode", ""),
                    f"[{status_color}]{s.get('status','')}[/{status_color}]",
                    str(s.get("findings_count", 0)),
                    str(s.get("risk_score", 0.0)),
                    s.get("updated_at", "")[:19],
                )
            console.print(table)
        except ImportError:
            for s in self.list_sessions():
                print(
                    f"{s['session_id']} | {s['target']} | "
                    f"{s['status']} | findings={s['findings_count']}"
                )


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------

_manager: Optional[SessionManager] = None

def get_manager() -> SessionManager:
    global _manager
    if _manager is None:
        _manager = SessionManager()
    return _manager

def new_session(
    target: str,
    mode:   Mode = Mode.FULL,
    name:   str  = None,
    tags:   List[str] = None,
) -> Session:
    return get_manager().create(target=target, mode=mode, name=name, tags=tags)

def resume_session(session_id: str) -> Session:
    return get_manager().load(session_id)
