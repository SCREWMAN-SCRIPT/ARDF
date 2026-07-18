"""
modules/purple/purple_runner.py
────────────────────────────────
PurpleRunner — coordinates red team assessment actions with
simultaneous blue team detection monitoring.

Every offensive action requires explicit human confirmation.
Blue team monitors run in parallel and generate detection
artifacts for each observed technique.

Design
──────
  1. Human confirms each phase before execution
  2. Red action runs (scoped, authorised tools only)
  3. Blue monitors capture what was observable
  4. Sigma rules generated for each technique
  5. Coverage gap reported
"""

import json
import time
from datetime import datetime
from pathlib  import Path
from typing   import Any, Callable, Dict, List, Optional

from modules.session         import Session, Finding, SeverityLevel
from modules.logger          import get_logger, ARDFLogger
from modules.defense.monitor import SecurityMonitor
from modules.defense.sigma_writer import SigmaWriter


# ─────────────────────────────────────────────────────────────
# Phase result schema
# ─────────────────────────────────────────────────────────────

class PhaseResult:
    def __init__(
        self,
        phase_id:       str,
        phase_name:     str,
        red_findings:   List[Finding],
        blue_findings:  List[Finding],
        sigma_rules:    List[Dict],
        coverage_pct:   float,
        duration_secs:  float,
    ):
        self.phase_id      = phase_id
        self.phase_name    = phase_name
        self.red_findings  = red_findings
        self.blue_findings = blue_findings
        self.sigma_rules   = sigma_rules
        self.coverage_pct  = coverage_pct
        self.duration_secs = duration_secs
        self.timestamp     = datetime.utcnow().isoformat()

    def to_dict(self) -> Dict:
        return {
            "phase_id":      self.phase_id,
            "phase_name":    self.phase_name,
            "timestamp":     self.timestamp,
            "duration_secs": self.duration_secs,
            "red": {
                "findings_count": len(self.red_findings),
                "findings": [f.to_dict() for f in self.red_findings],
            },
            "blue": {
                "findings_count":  len(self.blue_findings),
                "sigma_rules":     len(self.sigma_rules),
                "coverage_pct":    self.coverage_pct,
                "findings": [f.to_dict() for f in self.blue_findings],
            },
            "sigma_rules": self.sigma_rules,
        }


# ─────────────────────────────────────────────────────────────
# PurpleRunner
# ─────────────────────────────────────────────────────────────

class PurpleRunner:
    """
    Coordinates red team and blue team actions in a single
    purple team exercise.

    Every offensive phase requires explicit human confirmation.
    Blue team monitors run alongside and capture detection
    artifacts for each technique.
    """

    def __init__(
        self,
        session:  Session,
        logger:   Optional[ARDFLogger] = None,
        auto_confirm: bool = False,
    ):
        self.session      = session
        self.logger       = logger or get_logger("purple.runner")
        self.auto_confirm = auto_confirm
        self.monitor      = SecurityMonitor(session, logger=self.logger)
        self.sigma_writer = SigmaWriter(session, logger=self.logger)
        self.out_dir      = session.dir("report") / "purple"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self._phase_results: List[PhaseResult] = []

    # ── Public API ────────────────────────────────────────────

    def run_purple_phase(
        self,
        phase_id:     str,
        phase_name:   str,
        red_action:   Callable[[], Any],
        blue_action:  Optional[Callable[[], Any]] = None,
        confirm_msg:  str = "",
        mitre_ids:    Optional[List[str]] = None,
    ) -> PhaseResult:
        """
        Run one purple team phase with human confirmation gate.

        Args:
            phase_id    : unique phase identifier
            phase_name  : human-readable phase name
            red_action  : callable that performs the red team action
            blue_action : callable that performs blue team monitoring
            confirm_msg : message shown at confirmation gate
            mitre_ids   : MITRE ATT&CK technique IDs for this phase

        Returns:
            PhaseResult with red and blue findings + sigma rules
        """
        self.logger.banner(
            f"PURPLE PHASE: {phase_name}",
            style="bold magenta",
        )

        # ── Human confirmation gate ───────────────────────────
        if not self._confirm(phase_name, confirm_msg):
            self.logger.info(f"Phase {phase_name} skipped by operator")
            return self._empty_result(phase_id, phase_name)

        start_time    = time.time()
        before_count  = self.session.meta.findings_count

        # ── Baseline before red action ────────────────────────
        self.monitor.set_baseline()
        self.logger.info(f"Blue team baseline captured for {phase_name}")

        # ── Execute red action ────────────────────────────────
        self.logger.info(f"[RED] Executing: {phase_name}")
        try:
            red_action()
        except Exception as e:
            self.logger.error(f"Red action failed: {e}")

        # ── Capture blue team observations ────────────────────
        self.logger.info(f"[BLUE] Capturing detection data for: {phase_name}")

        blue_findings_before = len(self.session.get_findings(source="defense.monitor"))

        if blue_action:
            try:
                blue_action()
            except Exception as e:
                self.logger.error(f"Blue action failed: {e}")
        else:
            # Run default monitors if no specific blue action
            self._run_default_monitors()

        # ── Collect delta findings ────────────────────────────
        all_findings      = self.session.get_findings()
        new_findings      = all_findings[before_count:]
        red_findings      = [f for f in new_findings if "defense" not in f.source]
        blue_new_findings = self.session.get_findings(source="defense.monitor")
        blue_delta        = blue_new_findings[blue_findings_before:]

        # ── Generate Sigma rules for observed techniques ──────
        sigma_rules = self._generate_sigma_for_phase(
            red_findings, mitre_ids or []
        )

        # ── Calculate detection coverage ──────────────────────
        coverage_pct = self._calculate_coverage(
            red_findings, blue_delta, sigma_rules
        )

        duration = time.time() - start_time
        result   = PhaseResult(
            phase_id      = phase_id,
            phase_name    = phase_name,
            red_findings  = red_findings,
            blue_findings = blue_delta,
            sigma_rules   = sigma_rules,
            coverage_pct  = coverage_pct,
            duration_secs = round(duration, 2),
        )

        self._phase_results.append(result)
        self._save_phase_result(result)

        self.logger.success(
            f"Phase {phase_name} complete | "
            f"red={len(red_findings)} blue={len(blue_delta)} "
            f"sigma={len(sigma_rules)} coverage={coverage_pct:.0f}%"
        )
        return result

    def run_full_purple(
        self,
        phases: List[Dict],
    ) -> Dict[str, Any]:
        """
        Run a complete purple team exercise from a phase list.
        Each phase dict must contain: id, name, red_fn, blue_fn,
        confirm_msg, mitre_ids.

        Returns full exercise summary.
        """
        self.logger.banner("PURPLE TEAM EXERCISE", style="bold magenta")
        self.logger.info(f"Target: {self.session.meta.target}")
        self.logger.info(f"Phases: {len(phases)}")

        exercise_start = time.time()

        for phase_def in phases:
            self.run_purple_phase(
                phase_id    = phase_def.get("id", "unknown"),
                phase_name  = phase_def.get("name", "Unknown Phase"),
                red_action  = phase_def.get("red_fn", lambda: None),
                blue_action = phase_def.get("blue_fn"),
                confirm_msg = phase_def.get("confirm_msg", ""),
                mitre_ids   = phase_def.get("mitre_ids", []),
            )

        exercise_duration = time.time() - exercise_start
        summary           = self._build_exercise_summary(exercise_duration)

        # Save sigma rules bundle
        all_sigma = []
        for result in self._phase_results:
            all_sigma.extend(result.sigma_rules)
        if all_sigma:
            self.sigma_writer.save_rules(all_sigma, self.out_dir / "sigma_rules")

        # Save exercise report
        summary_path = self.out_dir / "purple_exercise_summary.json"
        summary_path.write_text(
            json.dumps(summary, indent=2, default=str),
            encoding="utf-8",
        )

        self.logger.success(
            f"Purple exercise complete | "
            f"phases={len(self._phase_results)} | "
            f"duration={exercise_duration:.0f}s"
        )
        return summary

    # ── Internal ──────────────────────────────────────────────

    def _confirm(self, phase_name: str, confirm_msg: str) -> bool:
        """Human confirmation gate. Never bypassed in production."""
        if self.auto_confirm:
            self.logger.warning(
                f"AUTO-CONFIRM enabled — skipping gate for: {phase_name}"
            )
            return True

        msg = confirm_msg or (
            f"Ready to execute purple phase: {phase_name}\n"
            f"This will run assessment tools against: {self.session.meta.target}\n"
        )

        print(f"\n{'='*60}")
        print(f"  PURPLE TEAM CONFIRMATION REQUIRED")
        print(f"{'='*60}")
        print(f"  Phase  : {phase_name}")
        print(f"  Target : {self.session.meta.target}")
        print(f"  {msg}")
        print(f"{'='*60}")
        choice = input("  Proceed? [yes/no]: ").strip().lower()
        print(f"{'='*60}\n")

        if choice in ("yes", "y"):
            return True
        self.logger.info(f"Phase '{phase_name}' declined by operator")
        return False

    def _run_default_monitors(self):
        """Run default blue team monitors when no specific monitor provided."""
        try:
            self.monitor.monitor_connections()
            self.monitor.monitor_failed_logins()
            self.monitor.monitor_logs()
        except Exception as e:
            self.logger.debug(f"Default monitor error: {e}")

    def _generate_sigma_for_phase(
        self,
        findings:  List[Finding],
        mitre_ids: List[str],
    ) -> List[Dict]:
        """Generate Sigma rules for all findings in a phase."""
        rules = []
        seen  = set()

        for finding in findings:
            rule = self.sigma_writer.generate_for_finding(finding)
            if rule and rule["template_key"] not in seen:
                rules.append(rule)
                seen.add(rule["template_key"])

        # Generate rules for MITRE techniques
        for tid in mitre_ids:
            technique = tid.replace("T", "").lower()
            rule = self.sigma_writer.generate_for_technique(
                technique,
                context={"finding_title": f"MITRE {tid}", "host": self.session.meta.target},
            )
            if rule and rule.get("template_key", "") not in seen:
                if rule:
                    rules.append(rule)

        return rules

    def _calculate_coverage(
        self,
        red_findings:  List[Finding],
        blue_findings: List[Finding],
        sigma_rules:   List[Dict],
    ) -> float:
        """
        Calculate detection coverage percentage for this phase.

        Coverage = (detected techniques / total techniques attempted) * 100
        A Sigma rule counts as partial detection coverage even without
        a direct blue finding.
        """
        if not red_findings:
            return 0.0

        total      = len(red_findings)
        detected   = len(blue_findings)
        rule_bonus = min(len(sigma_rules), total) * 0.3

        raw = (detected + rule_bonus) / total * 100
        return min(round(raw, 1), 100.0)

    def _empty_result(self, phase_id: str, phase_name: str) -> PhaseResult:
        return PhaseResult(
            phase_id      = phase_id,
            phase_name    = phase_name,
            red_findings  = [],
            blue_findings = [],
            sigma_rules   = [],
            coverage_pct  = 0.0,
            duration_secs = 0.0,
        )

    def _save_phase_result(self, result: PhaseResult):
        path = self.out_dir / f"phase_{result.phase_id}.json"
        path.write_text(
            json.dumps(result.to_dict(), indent=2, default=str),
            encoding="utf-8",
        )

    def _build_exercise_summary(self, duration: float) -> Dict:
        total_red    = sum(len(r.red_findings)  for r in self._phase_results)
        total_blue   = sum(len(r.blue_findings) for r in self._phase_results)
        total_sigma  = sum(len(r.sigma_rules)   for r in self._phase_results)
        avg_coverage = (
            sum(r.coverage_pct for r in self._phase_results) /
            max(len(self._phase_results), 1)
        )

        return {
            "exercise_summary": {
                "target":           self.session.meta.target,
                "session_id":       self.session.meta.session_id,
                "phases_run":       len(self._phase_results),
                "total_duration_s": round(duration, 2),
                "generated_at":     datetime.utcnow().isoformat(),
            },
            "red_team": {
                "total_findings":  total_red,
                "critical":        sum(
                    sum(1 for f in r.red_findings if f.severity == SeverityLevel.CRITICAL)
                    for r in self._phase_results
                ),
                "high": sum(
                    sum(1 for f in r.red_findings if f.severity == SeverityLevel.HIGH)
                    for r in self._phase_results
                ),
            },
            "blue_team": {
                "total_detections":  total_blue,
                "sigma_rules_generated": total_sigma,
                "average_coverage_pct":  round(avg_coverage, 1),
            },
            "phases": [r.to_dict() for r in self._phase_results],
        }
