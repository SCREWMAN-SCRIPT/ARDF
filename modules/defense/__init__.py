"""
ARDF Defense Layer
──────────────────
Blue team modules — detection, hardening, and remediation.

Components
──────────
  monitor     Network and host activity monitoring
  hardening   Auto-hardening script and config generator
  sigma_writer   Sigma detection rule generator from findings
  remediation Remediation script builder
"""

from modules.defense.sigma_writer  import SigmaWriter
from modules.defense.hardening     import HardeningEngine
from modules.defense.remediation   import RemediationBuilder
from modules.defense.monitor       import SecurityMonitor

__all__ = [
    "SigmaWriter",
    "HardeningEngine",
    "RemediationBuilder",
    "SecurityMonitor",
]
