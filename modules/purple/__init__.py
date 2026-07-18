"""
ARDF Purple Team Layer
───────────────────────
Simultaneous red and blue execution with detection coverage mapping.

Components
──────────
  purple_runner    Parallel red + blue phase execution engine
  coverage_mapper  Attack vs detection coverage analysis + MITRE mapping
"""

from modules.purple.purple_runner   import PurpleRunner
from modules.purple.coverage_mapper import CoverageMapper

__all__ = [
    "PurpleRunner",
    "CoverageMapper",
]
