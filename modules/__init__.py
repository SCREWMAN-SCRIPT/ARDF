"""
ARDF Modules Layer
──────────────────
Core execution primitives. Each module wraps Kali toolchain
components with structured output, session persistence,
and finding creation.

Existing modules (unchanged from your codebase)
────────────────────────────────────────────────
  recon     Passive → normal → depth reconnaissance
  exploit   Web, network, password, post-exploitation
  intel     CVE, Shodan, AbuseIPDB, VirusTotal, IOC, AI enrichment
  session   Session lifecycle, findings JSONL store, risk scoring
  logger    Rich console + plain text + JSONL structured logging
  report    Self-contained HTML report generation

New modules (added by ARDF)
────────────────────────────
  defense/  Sigma writer, hardening generator, remediation builder
  purple/   Parallel red+blue runner, coverage mapper
  comms/    C2 stub, exfil simulation
"""

from modules.logger  import get_logger, setup_logging, ARDFLogger
from modules.session import (
    Session,
    SessionManager,
    SessionMeta,
    SessionStatus,
    Finding,
    SeverityLevel,
    Mode,
    get_manager,
    new_session,
    resume_session,
)

__all__ = [
    # Logger
    "get_logger",
    "setup_logging",
    "ARDFLogger",
    # Session
    "Session",
    "SessionManager",
    "SessionMeta",
    "SessionStatus",
    "Finding",
    "SeverityLevel",
    "Mode",
    "get_manager",
    "new_session",
    "resume_session",
]
