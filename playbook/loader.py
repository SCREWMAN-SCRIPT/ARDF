"""
playbook/loader.py
───────────────────
PlaybookLoader — loads and parses YAML playbook files.

Resolves playbook paths, validates structure, and
returns a normalised playbook dict ready for the executor.
"""

import yaml
from pathlib import Path
from typing  import Dict, List, Optional

from modules.logger import get_logger, ARDFLogger


# ─────────────────────────────────────────────────────────────
# Default playbook search paths
# ─────────────────────────────────────────────────────────────

PLAYBOOK_SEARCH_PATHS = [
    Path("config/playbooks"),
    Path("/opt/ardf/config/playbooks"),
    Path.home() / ".ardf" / "playbooks",
]

BUILT_IN_PLAYBOOKS = {
    "full":    "full_pentest.yaml",
    "passive": "passive_osint.yaml",
    "web":     "web_audit.yaml",
    "purple":  "purple_team.yaml",
}


class PlaybookLoader:
    """
    Loads YAML playbook files from disk.

    Usage
    ─────
        loader   = PlaybookLoader()
        playbook = loader.load("full_pentest.yaml")
        playbook = loader.load_by_name("full")
    """

    def __init__(self, logger: Optional[ARDFLogger] = None):
        self.logger = logger or get_logger("playbook.loader")

    def load(self, path_or_name: str) -> Dict:
        """
        Load a playbook by file path or built-in name.

        Args:
            path_or_name : file path (absolute or relative) or
                           built-in name (full / passive / web / purple)
        """
        # Check built-in alias
        if path_or_name in BUILT_IN_PLAYBOOKS:
            return self.load_by_name(path_or_name)

        # Try as direct path
        path = Path(path_or_name)
        if path.exists():
            return self._load_file(path)

        # Search in known directories
        for search_dir in PLAYBOOK_SEARCH_PATHS:
            candidate = search_dir / path_or_name
            if candidate.exists():
                return self._load_file(candidate)
            # Try with .yaml extension
            candidate_yaml = search_dir / f"{path_or_name}.yaml"
            if candidate_yaml.exists():
                return self._load_file(candidate_yaml)

        raise FileNotFoundError(
            f"Playbook not found: {path_or_name}\n"
            f"Search paths: {[str(p) for p in PLAYBOOK_SEARCH_PATHS]}\n"
            f"Built-in names: {list(BUILT_IN_PLAYBOOKS.keys())}"
        )

    def load_by_name(self, name: str) -> Dict:
        """Load a built-in playbook by short name."""
        filename = BUILT_IN_PLAYBOOKS.get(name)
        if not filename:
            raise ValueError(
                f"Unknown built-in playbook: {name}. "
                f"Available: {list(BUILT_IN_PLAYBOOKS.keys())}"
            )
        for search_dir in PLAYBOOK_SEARCH_PATHS:
            path = search_dir / filename
            if path.exists():
                return self._load_file(path)
        raise FileNotFoundError(
            f"Built-in playbook file not found: {filename}\n"
            f"Expected in one of: {[str(p) for p in PLAYBOOK_SEARCH_PATHS]}"
        )

    def list_available(self) -> List[Dict]:
        """List all available playbooks across all search paths."""
        found = []
        seen  = set()
        for search_dir in PLAYBOOK_SEARCH_PATHS:
            if not search_dir.exists():
                continue
            for yaml_file in sorted(search_dir.glob("*.yaml")):
                if yaml_file.name in seen:
                    continue
                seen.add(yaml_file.name)
                try:
                    pb = self._load_file(yaml_file)
                    found.append({
                        "name":        pb.get("name", yaml_file.stem),
                        "description": pb.get("description", ""),
                        "mode":        pb.get("mode", "red"),
                        "phases":      len(pb.get("phases", [])),
                        "path":        str(yaml_file),
                    })
                except Exception as e:
                    self.logger.debug(f"Could not read {yaml_file}: {e}")
        return found

    def _load_file(self, path: Path) -> Dict:
        """Read and parse a YAML playbook file."""
        self.logger.info(f"Loading playbook: {path}")
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = yaml.safe_load(f)
            if not isinstance(content, dict):
                raise ValueError(f"Playbook must be a YAML dict: {path}")
            content["_path"] = str(path)
            self.logger.success(
                f"Playbook loaded: {content.get('name','?')} "
                f"({len(content.get('phases',[]))} phases)"
            )
            return content
        except yaml.YAMLError as e:
            raise ValueError(f"YAML parse error in {path}: {e}")
