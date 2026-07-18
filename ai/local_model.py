"""
ai/local_model.py
─────────────────
Ollama interface for ARDF.
Handles model selection, availability checks, inference,
streaming, retries, and context window management.

All inference is local. No API keys. No outbound AI calls.
"""

import json
import time
import subprocess
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional

from modules.logger import get_logger, ARDFLogger


# ─────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────

OLLAMA_BASE        = "http://127.0.0.1:11434"
OLLAMA_GENERATE    = f"{OLLAMA_BASE}/api/generate"
OLLAMA_CHAT        = f"{OLLAMA_BASE}/api/chat"
OLLAMA_TAGS        = f"{OLLAMA_BASE}/api/tags"
OLLAMA_SHOW        = f"{OLLAMA_BASE}/api/show"

DEFAULT_TIMEOUT    = 120
STREAM_TIMEOUT     = 300

MODEL_PRIORITY = [
    "qwen2.5:0.5b",
    "qwen2.5:7b",
    "qwen2.5:14b",
    "tinyllama:1.1b",
]

MODEL_ROLES = {
    "tactical":  ["qwen2.5:0.5b", "tinyllama:1.1b"],
    "analysis":  ["qwen2.5:7b",   "qwen2.5:0.5b", "tinyllama:1.1b"],
    "planning":  ["qwen2.5:7b",   "qwen2.5:0.5b", "tinyllama:1.1b"],
    "fast":      ["qwen2.5:0.5b", "tinyllama:1.1b"],
}

PROMPTS_DIR = Path(__file__).parent / "prompts"


# ─────────────────────────────────────────────────────────────
# Prompt loader
# ─────────────────────────────────────────────────────────────

def load_prompt(name: str) -> str:
    """Load a prompt template from ai/prompts/."""
    path = PROMPTS_DIR / f"{name}.txt"
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    return ""


# ─────────────────────────────────────────────────────────────
# ModelManager — availability & selection
# ─────────────────────────────────────────────────────────────

class ModelManager:
    """
    Discovers and manages locally available Ollama models.
    Selects best model for a given role based on availability.
    """

    def __init__(self, logger: Optional[ARDFLogger] = None):
        self.logger    = logger or get_logger("ai.model_manager")
        self._cache:   Optional[List[str]] = None
        self._checked: bool = False

    # ── Ollama daemon check ───────────────────────────────────

    def ollama_running(self) -> bool:
        try:
            req = urllib.request.Request(f"{OLLAMA_BASE}/api/tags")
            with urllib.request.urlopen(req, timeout=3):
                return True
        except Exception:
            return False

    def start_ollama(self) -> bool:
        """Attempt to start the Ollama daemon if not running."""
        if self.ollama_running():
            return True
        self.logger.info("Ollama not running — attempting to start...")
        try:
            subprocess.Popen(
                ["ollama", "serve"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            for _ in range(10):
                time.sleep(1)
                if self.ollama_running():
                    self.logger.success("Ollama started")
                    return True
        except FileNotFoundError:
            self.logger.error("Ollama binary not found. Install from https://ollama.ai")
        return False

    # ── Model discovery ───────────────────────────────────────

    def list_models(self, force_refresh: bool = False) -> List[str]:
        """Return list of locally installed model names."""
        if self._cache is not None and not force_refresh:
            return self._cache
        try:
            req = urllib.request.Request(OLLAMA_TAGS)
            with urllib.request.urlopen(req, timeout=5) as resp:
                data   = json.loads(resp.read())
                models = [m["name"] for m in data.get("models", [])]
                self._cache = models
                return models
        except Exception as e:
            self.logger.warning(f"Could not list Ollama models: {e}")
            return []

    def is_available(self, model_name: str) -> bool:
        return model_name in self.list_models()

    def pull_model(self, model_name: str) -> bool:
        """Pull a model from Ollama registry (requires internet on first pull)."""
        self.logger.info(f"Pulling model {model_name}...")
        try:
            result = subprocess.run(
                ["ollama", "pull", model_name],
                capture_output=False,
                timeout=600,
            )
            success = result.returncode == 0
            if success:
                self._cache = None
                self.logger.success(f"Model {model_name} ready")
            return success
        except Exception as e:
            self.logger.error(f"Pull failed: {e}")
            return False

    # ── Model selection ───────────────────────────────────────

    def best_model(self, role: str = "tactical") -> Optional[str]:
        """
        Return best available model for a given role.
        Falls back down the priority list until one is found.
        """
        candidates = MODEL_ROLES.get(role, MODEL_PRIORITY)
        available  = self.list_models()
        for candidate in candidates:
            for installed in available:
                if installed.startswith(candidate.split(":")[0]):
                    return installed
        # Last resort — return anything
        if available:
            self.logger.warning(f"No ideal model for role '{role}', using {available[0]}")
            return available[0]
        return None

    def model_info(self, model_name: str) -> Dict[str, Any]:
        """Get model metadata from Ollama."""
        try:
            payload = json.dumps({"name": model_name}).encode()
            req     = urllib.request.Request(
                OLLAMA_SHOW,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read())
        except Exception:
            return {}


# ─────────────────────────────────────────────────────────────
# LocalModel — inference interface
# ─────────────────────────────────────────────────────────────

class LocalModel:
    """
    Primary inference interface.

    Supports:
      - generate()      Single-turn completion
      - chat()          Multi-turn conversation
      - stream()        Streaming token-by-token generation
      - json_generate() Structured JSON output
    """

    def __init__(
        self,
        model:   Optional[str] = None,
        role:    str = "tactical",
        timeout: int = DEFAULT_TIMEOUT,
        logger:  Optional[ARDFLogger] = None,
    ):
        self.manager = ModelManager()
        self.logger  = logger or get_logger("ai.local_model")
        self.timeout = timeout
        self.role    = role
        self.model   = model or self._resolve_model(role)
        self._history: List[Dict] = []

    # ── Model resolution ──────────────────────────────────────

    def _resolve_model(self, role: str) -> str:
        if not self.manager.start_ollama():
            raise RuntimeError("Ollama is not available. Cannot run AI inference.")
        model = self.manager.best_model(role)
        if not model:
            raise RuntimeError(
                "No Ollama models installed. "
                "Run: ollama pull qwen2.5:0.5b"
            )
        self.logger.info(f"AI model selected: {model} (role={role})")
        return model

    # ── Low-level HTTP POST ───────────────────────────────────

    def _post(self, url: str, payload: Dict, timeout: int) -> Dict:
        data = json.dumps(payload).encode()
        req  = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read())
        except urllib.error.URLError as e:
            raise ConnectionError(f"Ollama request failed: {e}")

    def _post_stream(self, url: str, payload: Dict) -> Generator[str, None, None]:
        payload["stream"] = True
        data = json.dumps(payload).encode()
        req  = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=STREAM_TIMEOUT) as resp:
                for raw_line in resp:
                    line = raw_line.decode("utf-8").strip()
                    if not line:
                        continue
                    try:
                        chunk = json.loads(line)
                        token = chunk.get("response") or chunk.get("message", {}).get("content", "")
                        if token:
                            yield token
                        if chunk.get("done"):
                            break
                    except json.JSONDecodeError:
                        continue
        except urllib.error.URLError as e:
            raise ConnectionError(f"Ollama stream failed: {e}")

    # ── Public API ────────────────────────────────────────────

    def generate(
        self,
        prompt:      str,
        system:      str = "",
        temperature: float = 0.2,
        max_tokens:  int = 1024,
        retries:     int = 2,
    ) -> str:
        """
        Single-turn text completion.
        Returns the model response as a string.
        """
        payload: Dict[str, Any] = {
            "model":  self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }
        if system:
            payload["system"] = system

        for attempt in range(retries + 1):
            try:
                resp = self._post(OLLAMA_GENERATE, payload, self.timeout)
                return resp.get("response", "").strip()
            except Exception as e:
                if attempt < retries:
                    self.logger.warning(f"Inference attempt {attempt+1} failed: {e}. Retrying...")
                    time.sleep(2)
                else:
                    self.logger.error(f"All inference attempts failed: {e}")
                    return ""
        return ""

    def chat(
        self,
        message:     str,
        system:      str = "",
        temperature: float = 0.2,
        max_tokens:  int = 1024,
        reset:       bool = False,
    ) -> str:
        """
        Multi-turn conversation.
        Maintains history across calls unless reset=True.
        """
        if reset:
            self._history = []

        if system and not self._history:
            self._history.append({"role": "system", "content": system})

        self._history.append({"role": "user", "content": message})

        payload: Dict[str, Any] = {
            "model":    self.model,
            "messages": self._history,
            "stream":   False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }

        try:
            resp    = self._post(OLLAMA_CHAT, payload, self.timeout)
            content = resp.get("message", {}).get("content", "").strip()
            self._history.append({"role": "assistant", "content": content})
            return content
        except Exception as e:
            self.logger.error(f"Chat inference failed: {e}")
            return ""

    def stream(
        self,
        prompt:      str,
        system:      str = "",
        temperature: float = 0.3,
    ) -> Generator[str, None, None]:
        """
        Streaming token generator.
        Yields tokens as they arrive from Ollama.
        """
        payload: Dict[str, Any] = {
            "model":  self.model,
            "prompt": prompt,
            "options": {"temperature": temperature},
        }
        if system:
            payload["system"] = system
        yield from self._post_stream(OLLAMA_GENERATE, payload)

    def json_generate(
        self,
        prompt:      str,
        system:      str = "",
        temperature: float = 0.1,
        max_tokens:  int = 2048,
        retries:     int = 3,
    ) -> Optional[Dict]:
        """
        Generate structured JSON output.
        Strips markdown fences and retries on parse failure.
        """
        json_system = (
            (system + "\n\n" if system else "") +
            "You must respond with valid JSON only. "
            "No markdown, no explanation, no code fences. "
            "Raw JSON object only."
        )
        for attempt in range(retries):
            raw = self.generate(
                prompt      = prompt,
                system      = json_system,
                temperature = temperature,
                max_tokens  = max_tokens,
            )
            cleaned = raw.strip()
            # Strip markdown fences
            if cleaned.startswith("```"):
                lines   = cleaned.splitlines()
                cleaned = "\n".join(
                    l for l in lines
                    if not l.strip().startswith("```")
                )
            try:
                return json.loads(cleaned)
            except json.JSONDecodeError:
                # Try extracting first {...} block
                start = cleaned.find("{")
                end   = cleaned.rfind("}") + 1
                if start >= 0 and end > start:
                    try:
                        return json.loads(cleaned[start:end])
                    except json.JSONDecodeError:
                        pass
                self.logger.warning(
                    f"JSON parse failed (attempt {attempt+1}/{retries}). "
                    f"Raw: {raw[:120]}..."
                )
                time.sleep(1)
        return None

    # ── Utilities ─────────────────────────────────────────────

    def reset_history(self):
        self._history = []

    def switch_model(self, model: str):
        if self.manager.is_available(model):
            self.model = model
            self.logger.info(f"Switched to model: {model}")
        else:
            self.logger.warning(f"Model {model} not available locally")

    def __repr__(self) -> str:
        return f"<LocalModel model={self.model} role={self.role}>"


# ─────────────────────────────────────────────────────────────
# Module-level singleton
# ─────────────────────────────────────────────────────────────

_instances: Dict[str, LocalModel] = {}

def get_model(role: str = "tactical", logger: Optional[ARDFLogger] = None) -> LocalModel:
    """Return (and cache) a LocalModel instance for the given role."""
    if role not in _instances:
        _instances[role] = LocalModel(role=role, logger=logger)
    return _instances[role]
