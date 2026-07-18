"""
ARDF AI Layer
─────────────
Local-first AI orchestration using Ollama.
All inference runs on-device. No data leaves the machine.

Components
──────────
  local_model   Ollama interface — model management, inference, streaming
  planner       Objective → ordered task graph generator
  analyst       Finding interpreter — correlation, chain building, risk scoring
  tactician     Failure handler — alternate tactic selector, WAF bypass, retry logic

Models
──────
  Primary   : qwen2.5:0.5b   (fast, tactical decisions)
  Secondary : qwen2.5:7b     (deeper analysis, if hardware supports)
  Fallback  : tinyllama:1.1b (minimal hardware, always available)
"""

from ai.local_model import LocalModel, ModelManager, get_model
from ai.planner     import MissionPlanner
from ai.analyst     import FindingAnalyst
from ai.tactician   import Tactician

__all__ = [
    "LocalModel",
    "ModelManager",
    "get_model",
    "MissionPlanner",
    "FindingAnalyst",
    "Tactician",
]
