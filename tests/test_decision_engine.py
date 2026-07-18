"""
tests/test_decision_engine.py
──────────────────────────────
Integration tests for the ARDF decision and graph layers.

Tests cover:
  - AttackPathBuilder path detection
  - KillChainMapper stage assignment
  - PlaybookLoader and Validator
  - Scheduler passive job enforcement
  - Alerter finding creation
"""

import json
import pytest
import sys
from datetime import datetime
from pathlib  import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


# ─────────────────────────────────────────────────────────────
# Shared session factory
# ─────────────────────────────────────────────────────────────

def _make_session(tmp_path, session_id="decision_test"):
    from modules.session import (
        SessionMeta, Session, SessionStatus,
        Mode, Finding, SeverityLevel,
    )
    import modules.session as sm
    sm.SESSIONS_ROOT = tmp_path / "sessions"
    now  = datetime.utcnow().isoformat()
    meta = SessionMeta(
        session_id = session_id,
        name       = session_id,
        target     = "example.com",
        mode       = Mode.RED,
        status     = SessionStatus.CREATED,
        created_at = now,
        updated_at = now,
    )
    s = Session(meta)
    s.save()
    return s, Finding, SeverityLevel


# ─────────────────────────────────────────────────────────────
# AttackPathBuilder tests
# ─────────────────────────────────────────────────────────────

class TestAttackPathBuilder:

    def test_detects_web_to_shell_path(self, tmp_path):
        from graph.attack_path import AttackPathBuilder
        s, Finding, SeverityLevel = _make_session(tmp_path, "path_test_1")

        s.add_finding(Finding(
            source="recon.passive", title="Subdomain found",
            severity=SeverityLevel.INFO, host="app.example.com",
            tags=["subdomain","passive"],
        ))
        s.add_finding(Finding(
            source="exploit.web", title="SQL Injection confirmed",
            severity=SeverityLevel.CRITICAL, host="app.example.com",
            tags=["sqli","confirmed"],
        ))
        s.add_finding(Finding(
            source="exploit.web", title="Remote Code Execution",
            severity=SeverityLevel.CRITICAL, host="app.example.com",
            tags=["rce","shell","confirmed"],
        ))

        builder = AttackPathBuilder(s)
        paths   = builder.build_all()
        names   = [p.name for p in paths]
        assert any("Web Application" in n or "Reconnaissance" in n for n in names)

    def test_path_has_required_fields(self, tmp_path):
        from graph.attack_path import AttackPathBuilder
        s, Finding, SeverityLevel = _make_session(tmp_path, "path_test_2")

        s.add_finding(Finding(
            source="recon.passive", title="Subdomain",
            severity=SeverityLevel.INFO, host="x.example.com",
            tags=["subdomain"],
        ))
        s.add_finding(Finding(
            source="recon.normal", title="Port scan",
            severity=SeverityLevel.INFO, host="x.example.com",
            tags=["port","nmap"],
        ))

        builder = AttackPathBuilder(s)
        paths   = builder.build_all()
        if paths:
            d = paths[0].to_dict()
            for key in ("name","severity","score","steps","mitre","findings"):
                assert key in d

    def test_empty_session_returns_no_paths(self, tmp_path):
        from graph.attack_path import AttackPathBuilder
        s, _, _ = _make_session(tmp_path, "path_empty")
        paths   = AttackPathBuilder(s).build_all()
        assert paths == []

    def test_paths_sorted_by_score(self, tmp_path):
        from graph.attack_path import AttackPathBuilder
        s, Finding, SeverityLevel = _make_session(tmp_path, "path_score")

        for i in range(3):
            s.add_finding(Finding(
                source="recon.passive", title=f"Sub {i}",
                severity=SeverityLevel.INFO, host="example.com",
                tags=["subdomain","passive"],
            ))
            s.add_finding(Finding(
                source="recon.normal", title=f"Port {i}",
                severity=SeverityLevel.INFO, host="example.com",
                tags=["port","nmap"],
            ))

        builder = AttackPathBuilder(s)
        paths   = builder.build_all()
        for i in range(len(paths)-1):
            assert paths[i].score >= paths[i+1].score

    def test_saves_to_json(self, tmp_path):
        from graph.attack_path import AttackPathBuilder
        s, Finding, SeverityLevel = _make_session(tmp_path, "path_save")
        s.add_finding(Finding(
            source="recon.passive", title="Subdomain",
            severity=SeverityLevel.INFO, host="x.com",
            tags=["subdomain"],
        ))
        s.add_finding(Finding(
            source="recon.normal", title="Port",
            severity=SeverityLevel.INFO, host="x.com",
            tags=["port"],
        ))

        builder = AttackPathBuilder(s)
        paths   = builder.build_all()
        out     = builder.save(paths, s.dir("report"))
        assert out.exists()
        data = json.loads(out.read_text())
        assert "paths" in data


# ─────────────────────────────────────────────────────────────
# KillChainMapper tests
# ─────────────────────────────────────────────────────────────

class TestKillChainMapper:

    def test_maps_recon_to_reconnaissance(self, tmp_path):
        from graph.kill_chain_mapper import KillChainMapper
        s, Finding, SeverityLevel = _make_session(tmp_path, "kc_test_1")
        s.add_finding(Finding(
            source="recon.passive", title="Subdomain found",
            severity=SeverityLevel.INFO, host="example.com",
            tags=["subdomain","passive"],
        ))
        mapper = KillChainMapper(s)
        result = mapper.map()
        assert len(result["stages"]["Reconnaissance"]) >= 1

    def test_maps_exploit_to_initial_access(self, tmp_path):
        from graph.kill_chain_mapper import KillChainMapper
        s, Finding, SeverityLevel = _make_session(tmp_path, "kc_test_2")
        s.add_finding(Finding(
            source="exploit.web", title="SQLi",
            severity=SeverityLevel.CRITICAL, host="example.com",
            tags=["sqli"],
        ))
        mapper = KillChainMapper(s)
        result = mapper.map()
        assert (
            len(result["stages"]["Initial Access"]) >= 1 or
            len(result["stages"]["Execution"]) >= 1
        )

    def test_coverage_pct_between_0_and_100(self, tmp_path):
        from graph.kill_chain_mapper import KillChainMapper
        s, Finding, SeverityLevel = _make_session(tmp_path, "kc_test_3")
        s.add_finding(Finding(
            source="recon.passive", title="Finding",
            severity=SeverityLevel.INFO, host="x.com",
            tags=["passive"],
        ))
        mapper = KillChainMapper(s)
        result = mapper.map()
        assert 0.0 <= result["coverage_pct"] <= 100.0

    def test_saves_kill_chain_json(self, tmp_path):
        from graph.kill_chain_mapper import KillChainMapper
        s, Finding, SeverityLevel = _make_session(tmp_path, "kc_save")
        s.add_finding(Finding(
            source="recon.passive", title="Sub",
            severity=SeverityLevel.INFO, host="x.com",
            tags=["subdomain"],
        ))
        mapper = KillChainMapper(s)
        mapper.map()
        out = s.dir("report") / "kill_chain.json"
        assert out.exists()

    def test_result_has_all_stages(self, tmp_path):
        from graph.kill_chain_mapper import KillChainMapper, KILL_CHAIN_STAGES
        s, _, _ = _make_session(tmp_path, "kc_stages")
        mapper  = KillChainMapper(s)
        result  = mapper.map()
        for stage in KILL_CHAIN_STAGES:
            assert stage in result["stages"]


# ─────────────────────────────────────────────────────────────
# PlaybookValidator tests
# ─────────────────────────────────────────────────────────────

class TestPlaybookValidator:

    def _valid_playbook(self):
        return {
            "name":    "test_playbook",
            "version": "1.0",
            "mode":    "red",
            "phases": [
                {
                    "id":       "phase_01",
                    "name":     "Passive Recon",
                    "module":   "modules.recon",
                    "function": "run_recon",
                    "depends_on": [],
                    "timeout_minutes": 60,
                    "on_failure": "continue",
                    "confirmation": False,
                }
            ],
        }

    def test_valid_playbook_passes(self):
        from playbook.validator import PlaybookValidator
        v = PlaybookValidator()
        valid, errors, warnings = v.validate(self._valid_playbook())
        assert valid   is True
        assert errors  == []

    def test_missing_required_field_fails(self):
        from playbook.validator import PlaybookValidator
        pb = self._valid_playbook()
        del pb["mode"]
        v = PlaybookValidator()
        valid, errors, _ = v.validate(pb)
        assert valid  is False
        assert any("mode" in e for e in errors)

    def test_invalid_mode_fails(self):
        from playbook.validator import PlaybookValidator
        pb = self._valid_playbook()
        pb["mode"] = "attack"
        v = PlaybookValidator()
        valid, errors, _ = v.validate(pb)
        assert valid is False
        assert any("mode" in e.lower() for e in errors)

    def test_empty_phases_fails(self):
        from playbook.validator import PlaybookValidator
        pb = self._valid_playbook()
        pb["phases"] = []
        v = PlaybookValidator()
        valid, errors, _ = v.validate(pb)
        assert valid is False

    def test_duplicate_phase_id_fails(self):
        from playbook.validator import PlaybookValidator
        pb = self._valid_playbook()
        pb["phases"].append({
            "id": "phase_01", "name": "Duplicate",
            "module": "modules.recon", "function": "run_recon",
        })
        v = PlaybookValidator()
        valid, errors, _ = v.validate(pb)
        assert valid is False
        assert any("Duplicate" in e or "duplicate" in e.lower() for e in errors)

    def test_unknown_dep_fails(self):
        from playbook.validator import PlaybookValidator
        pb = self._valid_playbook()
        pb["phases"][0]["depends_on"] = ["nonexistent_phase"]
        v = PlaybookValidator()
        valid, errors, _ = v.validate(pb)
        assert valid is False

    def test_long_timeout_warns(self):
        from playbook.validator import PlaybookValidator
        pb = self._valid_playbook()
        pb["phases"][0]["timeout_minutes"] = 600
        v = PlaybookValidator()
        valid, errors, warnings = v.validate(pb)
        assert valid is True
        assert any("timeout" in w.lower() for w in warnings)

    def test_non_standard_module_warns(self):
        from playbook.validator import PlaybookValidator
        pb = self._valid_playbook()
        pb["phases"][0]["module"] = "custom.my_module"
        v = PlaybookValidator()
        valid, errors, warnings = v.validate(pb)
        assert valid is True
        assert any("non-standard" in w.lower() for w in warnings)


# ─────────────────────────────────────────────────────────────
# Scheduler tests
# ─────────────────────────────────────────────────────────────

class TestScheduler:

    def test_rejects_non_passive_job_type(self):
        from daemon.scheduler import Scheduler
        sched = Scheduler()
        with pytest.raises(ValueError, match="not allowed"):
            sched.add_job(
                job_id       = "exploit_job",
                target       = "example.com",
                job_type     = "exploit_web",
                interval_hrs = 1.0,
                fn           = lambda: None,
            )

    def test_accepts_passive_job_type(self):
        from daemon.scheduler import Scheduler
        sched = Scheduler()
        job   = sched.add_job(
            job_id       = "recon_job",
            target       = "example.com",
            job_type     = "passive_recon",
            interval_hrs = 24.0,
            fn           = lambda: None,
        )
        assert job.job_id == "recon_job"

    def test_job_is_due_on_first_add(self):
        from daemon.scheduler import Scheduler
        sched = Scheduler()
        job   = sched.add_job(
            job_id="due_job", target="x.com",
            job_type="monitor", interval_hrs=1.0,
            fn=lambda: None,
        )
        assert job.is_due is True

    def test_job_not_due_after_recent_run(self):
        import time
        from daemon.scheduler import Scheduler
        sched = Scheduler()
        job   = sched.add_job(
            job_id="not_due_job", target="x.com",
            job_type="monitor", interval_hrs=24.0,
            fn=lambda: None,
        )
        job.last_run = time.time()
        assert job.is_due is False

    def test_disable_job(self):
        from daemon.scheduler import Scheduler
        sched = Scheduler()
        sched.add_job(
            job_id="disable_test", target="x.com",
            job_type="intel", interval_hrs=1.0,
            fn=lambda: None,
        )
        sched.disable_job("disable_test")
        assert sched._jobs["disable_test"].enabled is False
        assert sched._jobs["disable_test"].is_due  is False

    def test_remove_job(self):
        from daemon.scheduler import Scheduler
        sched = Scheduler()
        sched.add_job(
            job_id="remove_test", target="x.com",
            job_type="report", interval_hrs=1.0,
            fn=lambda: None,
        )
        sched.remove_job("remove_test")
        assert "remove_test" not in sched._jobs

    def test_list_jobs(self):
        from daemon.scheduler import Scheduler
        sched = Scheduler()
        sched.add_job(
            job_id="list_test", target="x.com",
            job_type="passive_recon", interval_hrs=6.0,
            fn=lambda: None,
        )
        jobs = sched.list_jobs()
        assert any(j["job_id"] == "list_test" for j in jobs)


# ─────────────────────────────────────────────────────────────
# Alerter tests
# ─────────────────────────────────────────────────────────────

class TestAlerter:

    def test_send_creates_session_finding(self, tmp_path):
        from daemon.alerter import Alerter
        s, _, SeverityLevel = _make_session(tmp_path, "alerter_test_1")
        alerter = Alerter(session=s)
        alerter.send(
            title     = "New open port detected: 6379",
            anomalies = [{
                "type":    "new_port",
                "port":    6379,
                "severity":"high",
                "reason":  "Port 6379 (Redis) opened since baseline",
            }],
            cycle=1,
        )
        findings = s.get_findings()
        assert any("6379" in f.title or "Alert" in f.title for f in findings)

    def test_send_increments_alert_count(self, tmp_path):
        from daemon.alerter import Alerter
        s, _, _ = _make_session(tmp_path, "alerter_test_2")
        alerter = Alerter(session=s)
        assert alerter.alert_count == 0
        alerter.send(
            title="Test alert",
            anomalies=[{"type":"test","severity":"low","reason":"test"}],
        )
        assert alerter.alert_count == 1

    def test_alert_written_to_jsonl(self, tmp_path):
        from daemon.alerter import Alerter
        s, _, _    = _make_session(tmp_path, "alerter_test_3")
        alert_path = tmp_path / "alerts.jsonl"
        alerter    = Alerter(session=s, alert_path=alert_path)
        alerter.send(
            title="File test alert",
            anomalies=[{"type":"file_test","severity":"medium","reason":"test"}],
        )
        assert alert_path.exists()
        lines = alert_path.read_text().splitlines()
        assert len(lines) >= 1
        data  = json.loads(lines[0])
        assert "title"    in data
        assert "severity" in data

    def test_callback_invoked_on_alert(self, tmp_path):
        from daemon.alerter import Alerter
        s, _, _ = _make_session(tmp_path, "alerter_cb")
        received = []
        alerter  = Alerter(session=s, on_alert=lambda a: received.append(a))
        alerter.send(
            title="Callback test",
            anomalies=[{"type":"cb","severity":"low","reason":"test"}],
        )
        assert len(received) == 1
        assert received[0]["title"] == "Callback test"

    def test_get_all_returns_sent_alerts(self, tmp_path):
        from daemon.alerter import Alerter
        s, _, _ = _make_session(tmp_path, "alerter_get")
        alerter = Alerter(session=s)
        for i in range(3):
            alerter.send(
                title=f"Alert {i}",
                anomalies=[{"type":"t","severity":"low","reason":"r"}],
            )
        all_alerts = alerter.get_all()
        assert len(all_alerts) == 3

    def test_severity_mapping_to_finding(self, tmp_path):
        from daemon.alerter import Alerter
        from modules.session import SeverityLevel
        s, _, _ = _make_session(tmp_path, "alerter_sev")
        alerter = Alerter(session=s)
        alerter.send(
            title="Critical alert",
            anomalies=[{"type":"critical_test","severity":"critical","reason":"r"}],
        )
        findings = s.get_findings(source="daemon.monitor")
        assert any(f.severity == SeverityLevel.CRITICAL for f in findings)


# ─────────────────────────────────────────────────────────────
# Run
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
