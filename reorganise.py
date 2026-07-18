#!/usr/bin/env python3
"""
reorganise.py
──────────────
Moves all ARDF files from the current flat structure
into the planned project directory layout.

Run from the directory containing all your flat files:
    python reorganise.py

Or with a custom source and destination:
    python reorganise.py --src /path/to/flat --dst /path/to/ardf
"""

import argparse
import shutil
import sys
from pathlib import Path


# ─────────────────────────────────────────────────────────────
# File → destination mapping
# ─────────────────────────────────────────────────────────────

FILE_MAP = {

    # ── Root ─────────────────────────────────────────────────
    "ardf.py":          ".",
    "requirements.txt": ".",
    "README.md":        ".",

    # ── Config ───────────────────────────────────────────────
    "ardf.yaml":          "config",
    "wordlists.yaml":     "config",
    "full_pentest.yaml":  "config/playbooks",
    "passive_osint.yaml": "config/playbooks",
    "web_audit.yaml":     "config/playbooks",
    "purple_team.yaml":   "config/playbooks",

    # ── AI ───────────────────────────────────────────────────
    "local_model.py":  "ai",
    "planner.py":      "ai",
    "analyst.py":      "ai",
    "tactician.py":    "ai",

    # AI prompts
    "plan_mission.txt":     "ai/prompts",
    "analyse_output.txt":   "ai/prompts",
    "select_tactic.txt":    "ai/prompts",
    "generate_commands.txt":"ai/prompts",
    "purple_detect.txt":    "ai/prompts",

    # ── Core ─────────────────────────────────────────────────
    "orchestrator.py":       "core",
    "mission.py":            "core",
    "task_graph.py":         "core",
    "response_classifier.py":"core",
    "confirmation_gate.py":  "core",

    # ── Modules ──────────────────────────────────────────────
    "report.py":     "modules",
    # recon.py, exploit.py, intel.py, session.py, logger.py
    # — drop these in manually from your existing codebase

    # Defense submodule
    "sigma_writer.py": "modules/defense",
    "hardening.py":    "modules/defense",
    "remediation.py":  "modules/defense",
    "monitor.py":      "modules/defense",

    # Purple submodule
    "purple_runner.py":  "modules/purple",
    "coverage_mapper.py":"modules/purple",

    # ── Interface ─────────────────────────────────────────────
    "banner.py":   "interface",
    "chat.py":     "interface",
    "progress.py": "interface",

    # ── Playbook ─────────────────────────────────────────────
    "loader.py":    "playbook",
    "validator.py": "playbook",
    "executor.py":  "playbook",

    # ── Graph ────────────────────────────────────────────────
    "finding_graph.py":   "graph",
    "attack_path.py":     "graph",
    "kill_chain_mapper.py":"graph",

    # ── Daemon ───────────────────────────────────────────────
    "monitor_daemon.py": "daemon",
    "scheduler.py":      "daemon",
    "alerter.py":        "daemon",

    # ── Tests ────────────────────────────────────────────────
    "test_orchestrator.py":   "tests",
    "test_modules.py":        "tests",
    "test_decision_engine.py":"tests",
}

# ── __init__.py files needed per package ─────────────────────
INIT_PACKAGES = [
    "ai",
    "ai/prompts",
    "core",
    "modules",
    "modules/defense",
    "modules/purple",
    "modules/comms",
    "interface",
    "playbook",
    "graph",
    "daemon",
    "tests",
    "config",
    "config/playbooks",
    "output/sessions",
    "output/reports",
    "logs",
]

# Packages that get __init__.py (not data dirs)
PYTHON_PACKAGES = {
    "ai", "core", "modules", "modules/defense",
    "modules/purple", "modules/comms",
    "interface", "playbook", "graph", "daemon", "tests",
}

# ── Missing files that need to be created ────────────────────
# These are files the project needs that were not yet generated.
# Content is minimal — stubs that wire things together.
MISSING_FILES = {

    "modules/comms/__init__.py": '''\
"""
ARDF Comms Layer
─────────────────
Stub module for C2 simulation — not implemented in v1.
Reserved for future purple team comms simulation.
"""
''',

    "output/.gitkeep":        "",
    "output/sessions/.gitkeep":"",
    "output/reports/.gitkeep": "",
    "logs/.gitkeep":           "",

    ".gitignore": """\
# ARDF .gitignore
output/
logs/
__pycache__/
*.pyc
*.pyo
.env
*.egg-info/
.pytest_cache/
""",
}


# ─────────────────────────────────────────────────────────────
# Reorganiser
# ─────────────────────────────────────────────────────────────

def reorganise(src: Path, dst: Path, dry_run: bool = False):
    """
    Move files from src (flat) into dst (structured).

    Args:
        src     : directory containing flat files
        dst     : destination project root
        dry_run : if True, only print what would happen
    """
    print(f"\n{'DRY RUN — ' if dry_run else ''}ARDF Reorganiser")
    print(f"Source : {src}")
    print(f"Dest   : {dst}")
    print("─" * 60)

    moved   = []
    skipped = []
    missing = []

    # ── Create directory structure ────────────────────────────
    print("\n[1/4] Creating directory structure...")
    for pkg in INIT_PACKAGES:
        pkg_path = dst / pkg
        if not dry_run:
            pkg_path.mkdir(parents=True, exist_ok=True)
        print(f"  mkdir {pkg_path.relative_to(dst)}")

    # ── Move files ────────────────────────────────────────────
    print("\n[2/4] Moving files...")
    for filename, dest_rel in FILE_MAP.items():
        src_file  = src / filename
        dest_dir  = dst / dest_rel
        dest_file = dest_dir / filename

        if not src_file.exists():
            missing.append(filename)
            print(f"  ✘ MISSING  {filename}")
            continue

        if dest_file.exists():
            skipped.append(filename)
            print(f"  ⊘ EXISTS   {dest_rel}/{filename}")
            continue

        if not dry_run:
            dest_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src_file, dest_file)

        moved.append(filename)
        print(f"  ✔ MOVED    {filename} → {dest_rel}/")

    # ── Write __init__.py files ───────────────────────────────
    print("\n[3/4] Writing __init__.py files...")
    for pkg in PYTHON_PACKAGES:
        init_path = dst / pkg / "__init__.py"
        if init_path.exists():
            print(f"  ⊘ EXISTS   {pkg}/__init__.py")
            continue
        if not dry_run:
            init_path.parent.mkdir(parents=True, exist_ok=True)
            # Use existing __init__ content if already in FILE_MAP
            init_path.write_text(
                f'"""\nARDF — {pkg.replace("/",".")} package\n"""\n',
                encoding="utf-8",
            )
        print(f"  ✔ CREATED  {pkg}/__init__.py")

    # ── Write missing stub files ──────────────────────────────
    print("\n[4/4] Creating missing stub files...")
    for rel_path, content in MISSING_FILES.items():
        file_path = dst / rel_path
        if file_path.exists():
            print(f"  ⊘ EXISTS   {rel_path}")
            continue
        if not dry_run:
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(content, encoding="utf-8")
        print(f"  ✔ CREATED  {rel_path}")

    # ── Summary ───────────────────────────────────────────────
    print("\n" + "─" * 60)
    print(f"SUMMARY")
    print(f"  Moved   : {len(moved)}")
    print(f"  Skipped : {len(skipped)}  (already in place)")
    print(f"  Missing : {len(missing)}  (source file not found)")

    if missing:
        print(f"\nMISSING FILES — copy these manually into the project:")
        for f in missing:
            dest = FILE_MAP.get(f, "?")
            print(f"  {f}  →  {dest}/")
        print()
        print("  Your existing module files go here:")
        print("  recon.py    → modules/recon.py")
        print("  exploit.py  → modules/exploit.py")
        print("  intel.py    → modules/intel.py")
        print("  session.py  → modules/session.py")
        print("  logger.py   → modules/logger.py")
        print("  defense.py  → (already split into modules/defense/)")

    if not dry_run:
        print(f"\n✔ Project structure built at: {dst}")
        print(f"  Run:  cd {dst} && python ardf.py --help")
    else:
        print(f"\n  Re-run without --dry-run to apply changes.")


# ─────────────────────────────────────────────────────────────
# Flat __init__.py handler
# ─────────────────────────────────────────────────────────────

def handle_flat_init(src: Path, dst: Path, dry_run: bool):
    """
    The flat directory has one __init__.py — figure out
    which package it belongs to and place it correctly.
    We copy it to all Python packages as a safe fallback.
    """
    flat_init = src / "__init__.py"
    if not flat_init.exists():
        return

    print("\n  Handling flat __init__.py...")
    # Copy to ai package as it was likely the ai/__init__.py
    # All others will be generated fresh
    target = dst / "ai" / "__init__.py"
    if not target.exists() and not dry_run:
        shutil.copy2(flat_init, target)
        print(f"  ✔ Placed __init__.py → ai/__init__.py")


# ─────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Reorganise ARDF flat files into project structure",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Reorganise in place (src = current dir, dst = ./ardf/)
  python reorganise.py

  # Preview without making changes
  python reorganise.py --dry-run

  # Custom source and destination
  python reorganise.py --src ~/Downloads/ardf_flat --dst ~/projects/ardf

  # Reorganise flat dir into a new subdir inside it
  python reorganise.py --src . --dst ./ardf_project
        """,
    )
    parser.add_argument(
        "--src",
        type    = Path,
        default = Path("."),
        help    = "Source directory with flat files (default: current directory)",
    )
    parser.add_argument(
        "--dst",
        type    = Path,
        default = Path("./ardf_project"),
        help    = "Destination project root (default: ./ardf_project)",
    )
    parser.add_argument(
        "--dry-run",
        action  = "store_true",
        help    = "Preview changes without moving anything",
    )
    parser.add_argument(
        "--in-place",
        action  = "store_true",
        help    = "Build structure inside the source directory (src == dst)",
    )

    args = parser.parse_args()

    src = args.src.resolve()
    dst = src if args.in_place else args.dst.resolve()

    if not src.exists():
        print(f"ERROR: Source directory does not exist: {src}")
        sys.exit(1)

    if dst == src and not args.in_place:
        print("WARNING: Source and destination are the same.")
        print("         Use --in-place to confirm this is intended.")
        sys.exit(1)

    reorganise(src=src, dst=dst, dry_run=args.dry_run)
    handle_flat_init(src=src, dst=dst, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
