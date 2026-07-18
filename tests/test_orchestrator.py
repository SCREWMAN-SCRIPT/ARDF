"""
tests/test_orchestrator.py
───────────────────────────
Unit tests for the ARDF orchestration layer.

Tests cover:
  - TaskGraph dependency resolution
  - ConfirmationGate decision recording
  - ResponseClassifier output classification
  - Mission lifecycle state machine
  - MissionPlanner rule-based planning
"""

import pytest
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.task_graph          import TaskGraph, Task, TaskStatus
from core.mission             import Mission, MissionStatus
from core.response_classifier import ResponseClassifier
from core.confirmation_gate   import ConfirmationGate, GateDecision


# ─────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────

def _make_session(tmp_path):
    """Create a minimal test session."""
    from modules.session import SessionMeta, Session, SessionStatus, Mode
    from datetime import datetime
    now  = datetime.utcnow().isoformat()
    meta = SessionMeta(
        session_id   = "test_session_001",
        name         = "test_session",
        target       = "test.example.com",
        mode         = Mode.RED,
        status       = SessionStatus.CREATED,
        created_at   = now,
        updated_at   = now,
    )
    # Override sessions root to tmp_path
    import modules.session as session_module
    original_root = session_module.SESSIONS_ROOT
    session_module.SESSIONS_ROOT = tmp_path / "sessions"
    s = Session(meta)
    s.save()
    yield s
    session_module.SESSIONS_ROOT = original_root


def _make_plan(tasks_list):
    """Build a minimal plan dict from a tasks list."""
    return {
        "mission_id": "test_mission_001",
        "objective":  "test objective",
        "mode":       "red",
        "tasks":      tasks_list,
    }


# ─────────────────────────────────────────────────────────────
# TaskGraph tests
# ─────────────────────────────────────────────────────────────

class TestTaskGraph:

    def test_builds_from_plan(self):
        plan = _make_plan([
            {"id": "t1", "name": "Task 1", "module": "modules.recon",
             "function": "run_recon", "priority": 1, "depends_on": []},
            {"id": "t2", "name": "Task 2", "module": "modules.intel",
             "function": "run_intel", "priority": 2, "depends_on": ["t1"]},
        ])
        graph = TaskGraph(plan)
        assert len(graph) == 2
        assert "t1" in graph.tasks
        assert "t2" in graph.tasks

    def test_topological_order_respects_deps(self):
        plan = _make_plan([
            {"id": "t2", "name": "Task 2", "module": "m", "function": "f",
             "priority": 2, "depends_on": ["t1"]},
            {"id": "t1", "name": "Task 1", "module": "m", "function": "f",
             "priority": 1, "depends_on": []},
        ])
        graph  = TaskGraph(plan)
        order  = graph.topological_order()
        ids    = [t.id for t in order]
        assert ids.index("t1") < ids.index("t2")

    def test_marks_ready_when_no_deps(self):
        plan = _make_plan([
            {"id": "t1", "name": "Task 1", "module": "m", "function": "f",
             "priority": 1, "depends_on": []},
        ])
        graph = TaskGraph(plan)
        assert len(graph.ready_tasks) == 1
        assert graph.ready_tasks[0].id == "t1"

    def test_dep_not_ready_until_parent_done(self):
        plan = _make_plan([
            {"id": "t1", "name": "T1", "module": "m", "function": "f",
             "priority": 1, "depends_on": []},
            {"id": "t2", "name": "T2", "module": "m", "function": "f",
             "priority": 2, "depends_on": ["t1"]},
        ])
        graph = TaskGraph(plan)
        assert graph.tasks["t2"].status == TaskStatus.PENDING

        # Complete t1
        graph.tasks["t1"].mark_completed()
        graph._update_ready_status()
        assert graph.tasks["t2"].status == TaskStatus.READY

    def test_detects_circular_dependency(self):
        plan = _make_plan([
            {"id": "t1", "name": "T1", "module": "m", "function": "f",
             "priority": 1, "depends_on": ["t2"]},
            {"id": "t2", "name": "T2", "module": "m", "function": "f",
             "priority": 2, "depends_on": ["t1"]},
        ])
        with pytest.raises(ValueError, match="circular"):
            TaskGraph(plan)

    def test_all_done_when_all_complete(self):
        plan = _make_plan([
            {"id": "t1", "name": "T1", "module": "m", "function": "f",
             "priority": 1, "depends_on": []},
        ])
        graph = TaskGraph(plan)
        assert not graph.all_done
        graph.tasks["t1"].mark_completed()
        assert graph.all_done

    def test_summary_counts(self):
        plan = _make_plan([
            {"id": "t1", "name": "T1", "module": "m", "function": "f",
             "priority": 1, "depends_on": []},
            {"id": "t2", "name": "T2", "module": "m", "function": "f",
             "priority": 2, "depends_on": []},
        ])
        graph = TaskGraph(plan)
        graph.tasks["t1"].mark_completed()
        graph.tasks["t2"].mark_failed("error")
        s = graph.summary()
        assert s["completed"] == 1
        assert s["failed"]    == 1

    def test_unknown_dep_is_removed_gracefully(self):
        plan = _make_plan([
            {"id": "t1", "name": "T1", "module": "m", "function": "f",
             "priority": 1, "depends_on": ["nonexistent"]},
        ])
        # Should not raise — unknown dep is stripped with a warning
        graph = TaskGraph(plan)
        assert len(graph.tasks) == 1


# ─────────────────────────────────────────────────────────────
# Task tests
# ─────────────────────────────────────────────────────────────

class TestTask:

    def _task(self, **kwargs):
        defaults = {
            "id": "t1", "name": "Test", "module": "m",
            "function": "f", "priority": 1, "depends_on": [],
        }
        defaults.update(kwargs)
        return Task(defaults)

    def test_initial_status_pending(self):
        t = self._task()
        assert t.status == TaskStatus.PENDING

    def test_mark_running_sets_start_time(self):
        import time
        t = self._task()
        t.mark_running()
        assert t.start_time is not None
        assert t.status == TaskStatus.RUNNING

    def test_mark_completed(self):
        t = self._task()
        t.mark_running()
        t.mark_completed({"result": "ok"})
        assert t.status    == TaskStatus.COMPLETED
        assert t.succeeded is True
        assert t.is_done   is True

    def test_mark_failed(self):
        t = self._task()
        t.mark_running()
        t.mark_failed("timeout")
        assert t.status    == TaskStatus.FAILED
        assert t.succeeded is False
        assert t.error     == "timeout"

    def test_mark_skipped(self):
        t = self._task()
        t.mark_skipped("gate declined")
        assert t.status == TaskStatus.SKIPPED
        assert t.is_done is True

    def test_can_retry(self):
        t = self._task(max_retries=2)
        assert t.can_retry is True
        t.retries = 2
        assert t.can_retry is False

    def test_duration_increases_over_time(self):
        import time
        t = self._task()
        t.mark_running()
        time.sleep(0.05)
        assert t.duration > 0

    def test_to_dict_has_required_keys(self):
        t = self._task()
        d = t.to_dict()
        for key in ("id", "name", "module", "function", "status", "priority"):
            assert key in d


# ─────────────────────────────────────────────────────────────
# ResponseClassifier tests
# ─────────────────────────────────────────────────────────────

class TestResponseClassifier:

    def setup_method(self):
        self.clf = ResponseClassifier()

    def test_detects_waf_cloudflare(self):
        result = self.clf.classify(
            stdout="", stderr="Error 403: cloudflare blocked"
        )
        assert result["waf_detected"] is True
        assert result["waf_type"]     == "cloudflare"

    def test_detects_modsecurity(self):
        result = self.clf.classify(stderr="mod_security rule 12345 triggered")
        assert result["waf_detected"] is True
        assert result["waf_type"]     == "modsecurity"

    def test_detects_rate_limit(self):
        result = self.clf.classify(stdout="429 Too Many Requests")
        assert result["rate_limited"]  is True
        assert result["failure_type"]  == "rate_limited"

    def test_detects_timeout(self):
        result = self.clf.classify(stderr="Connection timed out")
        assert result["timed_out"]    is True
        assert result["failure_type"] == "timeout"

    def test_detects_auth_required(self):
        result = self.clf.classify(stdout="401 Unauthorized")
        assert result["auth_required"] is True

    def test_detects_binary_missing(self):
        result = self.clf.classify(
            stdout="", stderr="command not found",
            return_code=127
        )
        assert result["binary_missing"] is True
        assert result["failure_type"]   == "binary_missing"

    def test_detects_findings(self):
        result = self.clf.classify(
            stdout="[+] vulnerable to SQLi — injectable parameter found"
        )
        assert result["has_findings"] is True
        assert result["success"]      is True

    def test_no_results(self):
        result = self.clf.classify(stdout="", stderr="", return_code=0)
        assert result["no_results"]   is True
        assert result["has_findings"] is False

    def test_http_200_success(self):
        result = self.clf.classify_http(200)
        assert result["success"]    is True
        assert result["status_class"] == "success"

    def test_http_429_rate_limited(self):
        result = self.clf.classify_http(429)
        assert result["rate_limited"] is True

    def test_http_403_forbidden(self):
        result = self.clf.classify_http(403)
        assert result["auth_required"] is True

    def test_summarise_waf(self):
        result = self.clf.classify(stderr="cloudflare blocked request")
        summary = self.clf.summarise(result)
        assert "WAF" in summary

    def test_summarise_success(self):
        result = self.clf.classify(stdout="[+] found open port 80")
        summary = self.clf.summarise(result)
        assert "Findings" in summary or "successfully" in summary

    def test_no_false_waf_on_clean_output(self):
        result = self.clf.classify(
            stdout="subfinder found 15 subdomains",
            return_code=0,
        )
        assert result["waf_detected"] is False


# ─────────────────────────────────────────────────────────────
# ConfirmationGate tests
# ─────────────────────────────────────────────────────────────

class TestConfirmationGate:

    def test_auto_approve_returns_approved(self):
        gate     = ConfirmationGate(auto_approve=True)
        decision = gate.request("t1", "Test Task", "example.com")
        assert decision == GateDecision.APPROVED

    def test_non_interactive_returns_declined(self):
        gate     = ConfirmationGate(non_interactive=True, auto_approve=False)
        decision = gate.request("t1", "Test Task", "example.com")
        assert decision == GateDecision.DECLINED

    def test_audit_log_records_decision(self):
        gate = ConfirmationGate(auto_approve=True)
        gate.request("t1", "Task One", "example.com", tier=2)
        gate.request("t2", "Task Two", "example.com", tier=3)
        log = gate.get_audit_log()
        assert len(log) == 2
        assert log[0]["task_id"]  == "t1"
        assert log[0]["decision"] == GateDecision.APPROVED
        assert log[1]["tier"]     == 3

    def test_audit_log_saves_to_file(self, tmp_path):
        audit_path = tmp_path / "gate_audit.json"
        gate       = ConfirmationGate(
            auto_approve = True,
            audit_path   = audit_path,
        )
        gate.request("t1", "Test", "example.com")
        gate.save_audit_log()
        assert audit_path.exists()
        import json
        data = json.loads(audit_path.read_text())
        assert len(data) == 1

    def test_declined_is_recorded(self):
        gate = ConfirmationGate(non_interactive=True, auto_approve=False)
        gate.request("t1", "Task", "example.com")
        log = gate.get_audit_log()
        assert log[0]["decision"] == GateDecision.DECLINED


# ─────────────────────────────────────────────────────────────
# Mission lifecycle tests
# ─────────────────────────────────────────────────────────────

class TestMission:

    def _make_mock_session(self):
        """Minimal mock session for mission tests."""
        class MockMeta:
            session_id   = "mock_001"
            target       = "test.example.com"
            modules_done = []
            findings_count = 0
            risk_score   = 0.0
            mode         = type("Mode", (), {"value": "red"})()

        class MockSession:
            meta = MockMeta()
            def set_status(self, s): pass
            def get_findings(self): return []
            def dir(self, d): return Path("/tmp")

        return MockSession()

    def test_initial_status_created(self):
        s = self._make_mock_session()
        m = Mission(session=s, objective="test", mode="red")
        assert m.status == MissionStatus.CREATED

    def test_set_plan_marks_planned(self):
        s    = self._make_mock_session()
        m    = Mission(session=s, objective="test", mode="red")
        plan = {"tasks": [{"id": "t1"}]}
        m.set_plan(plan)
        assert m.status == MissionStatus.PLANNED

    def test_start_marks_running(self):
        s = self._make_mock_session()
        m = Mission(session=s, objective="test", mode="red")
        m.set_plan({"tasks": []})
        m.start()
        assert m.status     == MissionStatus.RUNNING
        assert m.start_time is not None

    def test_complete_sets_end_time(self):
        s = self._make_mock_session()
        m = Mission(session=s, objective="test", mode="red")
        m.set_plan({"tasks": []})
        m.start()
        m.complete()
        assert m.status   == MissionStatus.COMPLETED
        assert m.end_time is not None

    def test_abort_sets_aborted(self):
        s = self._make_mock_session()
        m = Mission(session=s, objective="test", mode="red")
        m.set_plan({"tasks": []})
        m.start()
        m.abort("test reason")
        assert m.status        == MissionStatus.ABORTED
        assert m.should_abort  is True

    def test_pause_and_resume(self):
        s = self._make_mock_session()
        m = Mission(session=s, objective="test", mode="red")
        m.set_plan({"tasks": []})
        m.start()
        m.pause()
        assert m.should_pause is True
        m.resume()
        assert m.should_pause is False
        assert m.status       == MissionStatus.RUNNING

    def test_task_tracking(self):
        s = self._make_mock_session()
        m = Mission(session=s, objective="test", mode="red")
        m.set_plan({"tasks": [{"id": "t1"}, {"id": "t2"}]})
        m.mark_task_complete("t1")
        m.mark_task_failed("t2", "timeout")
        assert "t1" in m.completed_tasks
        assert "t2" in m.failed_tasks

    def test_duration_str_format(self):
        s = self._make_mock_session()
        m = Mission(session=s, objective="test", mode="red")
        m.set_plan({"tasks": []})
        m.start()
        d = m.duration_str()
        assert isinstance(d, str)
        assert len(d) > 0

    def test_to_dict_has_required_keys(self):
        s = self._make_mock_session()
        m = Mission(session=s, objective="test", mode="red")
        m.set_plan({"tasks": []})
        d = m.to_dict()
        for key in ("mission_id","objective","mode","status","target"):
            assert key in d


# ─────────────────────────────────────────────────────────────
# MissionPlanner tests (rule-based)
# ─────────────────────────────────────────────────────────────

class TestMissionPlannerRuleBased:

    def _make_session_and_planner(self, tmp_path):
        from modules.session import SessionMeta, Session, SessionStatus, Mode
        from ai.planner import MissionPlanner
        from datetime import datetime

        now  = datetime.utcnow().isoformat()
        meta = SessionMeta(
            session_id = "plan_test_001",
            name       = "plan_test",
            target     = "example.com",
            mode       = Mode.RED,
            status     = SessionStatus.CREATED,
            created_at = now,
            updated_at = now,
        )
        import modules.session as sm
        sm.SESSIONS_ROOT = tmp_path / "sessions"
        s = Session(meta)
        s.save()

        planner = MissionPlanner(session=s)
        return s, planner

    def test_passive_objective_excludes_exploit(self, tmp_path):
        _, planner = self._make_session_and_planner(tmp_path)
        plan = planner.plan("run a passive recon", mode="osint", use_ai=False)
        task_ids = [t["id"] for t in plan["tasks"]]
        for tid in task_ids:
            assert "exploit" not in tid

    def test_plan_always_has_report(self, tmp_path):
        _, planner = self._make_session_and_planner(tmp_path)
        plan = planner.plan("enumerate subdomains", mode="osint", use_ai=False)
        task_ids = [t["id"] for t in plan["tasks"]]
        assert "report_generate" in task_ids

    def test_plan_injects_target(self, tmp_path):
        _, planner = self._make_session_and_planner(tmp_path)
        plan = planner.plan("passive recon", mode="osint", use_ai=False)
        for task in plan["tasks"]:
            assert task["args"].get("target") == "example.com"

    def test_mode_detected_from_objective(self, tmp_path):
        _, planner = self._make_session_and_planner(tmp_path)
        mode = planner._detect_mode("run a purple team exercise")
        assert mode == "purple"

    def test_plan_has_mission_id(self, tmp_path):
        _, planner = self._make_session_and_planner(tmp_path)
        plan = planner.plan("scan example.com", use_ai=False)
        assert "mission_id" in plan
        assert len(plan["mission_id"]) > 0

    def test_playbook_plan_converts_phases(self, tmp_path):
        _, planner = self._make_session_and_planner(tmp_path)
        phases = [
            {
                "id": "phase_01", "name": "Passive Recon",
                "module": "modules.recon", "function": "run_recon",
                "depth": "passive", "depends_on": [],
                "confirmation": False, "timeout_minutes": 60,
                "tags": ["recon"],
            },
        ]
        plan = planner.plan_from_playbook(phases=phases, mode="red")
        assert len(plan["tasks"]) == 1
        assert plan["tasks"][0]["id"] == "phase_01"


# ─────────────────────────────────────────────────────────────
# Run tests
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
