"""
tests/test_modules.py
──────────────────────
Unit tests for ARDF modules:
  - Session management and findings
  - Logger structured output
  - FindingGraph relationship building
  - SigmaWriter rule generation
  - RemediationBuilder plan generation
  - CoverageMapper technique mapping
"""

import json
import pytest
import sys
from datetime import datetime
from pathlib  import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


# ─────────────────────────────────────────────────────────────
# Session tests
# ─────────────────────────────────────────────────────────────

class TestSession:

    def _make_session(self, tmp_path):
        from modules.session import (
            SessionMeta, Session, SessionStatus,
            Mode, Finding, SeverityLevel,
        )
        import modules.session as sm
        sm.SESSIONS_ROOT = tmp_path / "sessions"

        now  = datetime.utcnow().isoformat()
        meta = SessionMeta(
            session_id = "sess_test_001",
            name       = "test",
            target     = "example.com",
            mode       = Mode.RED,
            status     = SessionStatus.CREATED,
            created_at = now,
            updated_at = now,
        )
        s = Session(meta)
        s.save()
        return s, Finding, SeverityLevel

    def test_session_creates_directories(self, tmp_path):
        s, _, _ = self._make_session(tmp_path)
        for sub in ("recon", "exploit", "defense", "intel", "report", "logs"):
            assert (s.root / sub).exists()

    def test_add_finding_increments_count(self, tmp_path):
        s, Finding, SeverityLevel = self._make_session(tmp_path)
        assert s.meta.findings_count == 0
        s.add_finding(Finding(
            source   = "recon.passive",
            title    = "Subdomain found",
            severity = SeverityLevel.INFO,
            host     = "sub.example.com",
        ))
        assert s.meta.findings_count == 1

    def test_get_findings_returns_all(self, tmp_path):
        s, Finding, SeverityLevel = self._make_session(tmp_path)
        for i in range(5):
            s.add_finding(Finding(
                source   = "recon.passive",
                title    = f"Finding {i}",
                severity = SeverityLevel.LOW,
                host     = "example.com",
            ))
        findings = s.get_findings()
        assert len(findings) == 5

    def test_get_findings_filtered_by_severity(self, tmp_path):
        s, Finding, SeverityLevel = self._make_session(tmp_path)
        s.add_finding(Finding(
            source="recon", title="High finding",
            severity=SeverityLevel.HIGH, host="x.com",
        ))
        s.add_finding(Finding(
            source="recon", title="Low finding",
            severity=SeverityLevel.LOW, host="x.com",
        ))
        high = s.get_findings(severity=SeverityLevel.HIGH)
        assert len(high) == 1
        assert high[0].title == "High finding"

    def test_risk_score_accumulates(self, tmp_path):
        s, Finding, SeverityLevel = self._make_session(tmp_path)
        s.add_finding(Finding(
            source="recon", title="Critical",
            severity=SeverityLevel.CRITICAL, host="x.com",
        ))
        assert s.meta.risk_score == 10.0

    def test_findings_summary_counts(self, tmp_path):
        s, Finding, SeverityLevel = self._make_session(tmp_path)
        s.add_finding(Finding(
            source="recon", title="C1",
            severity=SeverityLevel.CRITICAL, host="x.com",
        ))
        s.add_finding(Finding(
            source="recon", title="H1",
            severity=SeverityLevel.HIGH, host="x.com",
        ))
        summary = s.findings_summary()
        assert summary["critical"] == 1
        assert summary["high"]     == 1
        assert summary["medium"]   == 0

    def test_mark_module_done(self, tmp_path):
        s, _, _ = self._make_session(tmp_path)
        s.mark_module_done("recon.passive")
        assert "recon.passive" in s.meta.modules_done
        # Idempotent
        s.mark_module_done("recon.passive")
        assert s.meta.modules_done.count("recon.passive") == 1

    def test_findings_persist_to_disk(self, tmp_path):
        s, Finding, SeverityLevel = self._make_session(tmp_path)
        s.add_finding(Finding(
            source="recon", title="Persisted finding",
            severity=SeverityLevel.MEDIUM, host="x.com",
        ))
        # Reload
        from modules.session import Session, SessionMeta
        with open(s.meta_file) as f:
            meta = SessionMeta.from_dict(json.load(f))
        s2       = Session(meta)
        findings = s2.get_findings()
        assert len(findings) == 1
        assert findings[0].title == "Persisted finding"

    def test_export_findings_json(self, tmp_path):
        s, Finding, SeverityLevel = self._make_session(tmp_path)
        s.add_finding(Finding(
            source="recon", title="Export test",
            severity=SeverityLevel.LOW, host="x.com",
        ))
        path = s.export_findings_json()
        assert path.exists()
        data = json.loads(path.read_text())
        assert len(data) == 1


# ─────────────────────────────────────────────────────────────
# Logger tests
# ─────────────────────────────────────────────────────────────

class TestLogger:

    def test_get_logger_returns_ardf_logger(self):
        from modules.logger import get_logger, ARDFLogger, reset_logging
        reset_logging()
        log = get_logger("test_module")
        assert isinstance(log, ARDFLogger)

    def test_get_logger_cached(self):
        from modules.logger import get_logger, reset_logging
        reset_logging()
        a = get_logger("cached_test")
        b = get_logger("cached_test")
        assert a is b

    def test_setup_logging_returns_paths(self, tmp_path):
        from modules.logger import setup_logging, reset_logging
        reset_logging()
        result = setup_logging(
            log_dir    = str(tmp_path / "logs"),
            session_id = "test_123",
            quiet      = True,
        )
        assert "log_file"   in result
        assert "jsonl_file" in result
        assert result["log_file"].exists()

    def test_jsonl_file_created(self, tmp_path):
        from modules.logger import setup_logging, reset_logging
        reset_logging()
        result = setup_logging(
            log_dir    = str(tmp_path / "logs"),
            session_id = "jsonl_test",
            quiet      = True,
        )
        assert result["jsonl_file"].suffix == ".jsonl"

    def test_finding_log_level(self, tmp_path):
        from modules.logger import setup_logging, get_logger, reset_logging
        reset_logging()
        setup_logging(
            log_dir    = str(tmp_path / "logs"),
            session_id = "finding_test",
            quiet      = True,
        )
        log = get_logger("finding_test")
        # Should not raise
        log.finding(
            "SQLi detected",
            severity = "critical",
            host     = "example.com",
            port     = 80,
            cve      = "CVE-2021-1234",
        )

    def test_success_log_level(self, tmp_path):
        from modules.logger import setup_logging, get_logger, reset_logging
        reset_logging()
        setup_logging(
            log_dir    = str(tmp_path / "logs"),
            session_id = "success_test",
            quiet      = True,
        )
        log = get_logger("success_test")
        log.success("Task completed successfully")

    def test_reset_logging_allows_reinit(self, tmp_path):
        from modules.logger import setup_logging, reset_logging
        reset_logging()
        r1 = setup_logging(
            log_dir="str(tmp_path/'logs1')", session_id="r1", quiet=True
        )
        reset_logging()
        r2 = setup_logging(
            log_dir="str(tmp_path/'logs2')", session_id="r2", quiet=True
        )
        assert r1 != r2


# ─────────────────────────────────────────────────────────────
# FindingGraph tests
# ─────────────────────────────────────────────────────────────

class TestFindingGraph:

    def _make_session_with_findings(self, tmp_path):
        from modules.session import (
            SessionMeta, Session, SessionStatus,
            Mode, Finding, SeverityLevel,
        )
        import modules.session as sm
        sm.SESSIONS_ROOT = tmp_path / "sessions"
        now  = datetime.utcnow().isoformat()
        meta = SessionMeta(
            session_id = "graph_test_001",
            name       = "graph_test",
            target     = "example.com",
            mode       = Mode.RED,
            status     = SessionStatus.CREATED,
            created_at = now,
            updated_at = now,
        )
        s = Session(meta)
        s.save()

        # Add related findings
        s.add_finding(Finding(
            source="recon.passive", title="Subdomain A",
            severity=SeverityLevel.INFO, host="a.example.com",
            tags=["subdomain", "passive"],
        ))
        s.add_finding(Finding(
            source="recon.normal", title="Port 80 open",
            severity=SeverityLevel.INFO, host="a.example.com",
            tags=["port", "nmap"],
        ))
        s.add_finding(Finding(
            source="exploit.web", title="SQLi confirmed",
            severity=SeverityLevel.CRITICAL, host="a.example.com",
            tags=["sqli", "confirmed"], cve="CVE-2021-1234",
        ))
        s.add_finding(Finding(
            source="exploit.web", title="XSS found",
            severity=SeverityLevel.HIGH, host="b.example.com",
            tags=["xss"],
        ))
        return s

    def test_graph_builds_nodes(self, tmp_path):
        from graph.finding_graph import FindingGraph
        s = self._make_session_with_findings(tmp_path)
        g = FindingGraph(s).build()
        assert len(g.nodes) == 4

    def test_same_host_edges_created(self, tmp_path):
        from graph.finding_graph import FindingGraph, RelType
        s = self._make_session_with_findings(tmp_path)
        g = FindingGraph(s).build()
        same_host_edges = [
            e for e in g.edges if e.rel_type == RelType.SAME_HOST
        ]
        assert len(same_host_edges) > 0

    def test_top_nodes_sorted_by_score(self, tmp_path):
        from graph.finding_graph import FindingGraph
        s   = self._make_session_with_findings(tmp_path)
        g   = FindingGraph(s).build()
        top = g.top_nodes(3)
        assert top[0].score >= top[-1].score

    def test_clusters_groups_related_findings(self, tmp_path):
        from graph.finding_graph import FindingGraph
        s        = self._make_session_with_findings(tmp_path)
        g        = FindingGraph(s).build()
        clusters = g.get_clusters()
        assert len(clusters) >= 1

    def test_empty_session_builds_empty_graph(self, tmp_path):
        from graph.finding_graph import FindingGraph
        from modules.session import SessionMeta, Session, SessionStatus, Mode
        import modules.session as sm
        sm.SESSIONS_ROOT = tmp_path / "sessions2"
        now  = datetime.utcnow().isoformat()
        meta = SessionMeta(
            session_id="empty_graph", name="empty",
            target="x.com", mode=Mode.RED,
            status=SessionStatus.CREATED,
            created_at=now, updated_at=now,
        )
        s = Session(meta)
        s.save()
        g = FindingGraph(s).build()
        assert len(g.nodes) == 0
        assert len(g.edges) == 0

    def test_to_dict_structure(self, tmp_path):
        from graph.finding_graph import FindingGraph
        s = self._make_session_with_findings(tmp_path)
        g = FindingGraph(s).build()
        d = g.to_dict()
        assert "nodes"    in d
        assert "edges"    in d
        assert "clusters" in d
        assert "stats"    in d


# ─────────────────────────────────────────────────────────────
# SigmaWriter tests
# ─────────────────────────────────────────────────────────────

class TestSigmaWriter:

    def _make_session(self, tmp_path):
        from modules.session import (
            SessionMeta, Session, SessionStatus,
            Mode, Finding, SeverityLevel,
        )
        import modules.session as sm
        sm.SESSIONS_ROOT = tmp_path / "sessions"
        now  = datetime.utcnow().isoformat()
        meta = SessionMeta(
            session_id="sigma_test", name="sigma",
            target="example.com", mode=Mode.RED,
            status=SessionStatus.CREATED,
            created_at=now, updated_at=now,
        )
        s = Session(meta)
        s.save()
        s.add_finding(Finding(
            source="exploit.web", title="SQLi confirmed",
            severity=SeverityLevel.CRITICAL, host="example.com",
            tags=["sqli", "confirmed"],
        ))
        s.add_finding(Finding(
            source="recon.normal", title="Port 22 open",
            severity=SeverityLevel.INFO, host="example.com",
            tags=["port", "ssh"],
        ))
        return s, Finding, SeverityLevel

    def test_generates_rules_from_findings(self, tmp_path):
        from modules.defense.sigma_writer import SigmaWriter
        s, _, _ = self._make_session(tmp_path)
        writer  = SigmaWriter(s)
        rules   = writer.generate_all()
        assert len(rules) >= 1

    def test_rule_has_required_fields(self, tmp_path):
        from modules.defense.sigma_writer import SigmaWriter
        s, _, _ = self._make_session(tmp_path)
        writer  = SigmaWriter(s)
        rules   = writer.generate_all()
        for rule in rules:
            assert "id"         in rule
            assert "title"      in rule
            assert "sigma_rule" in rule
            assert "level"      in rule

    def test_sigma_yaml_contains_title(self, tmp_path):
        from modules.defense.sigma_writer import SigmaWriter
        s, _, _ = self._make_session(tmp_path)
        writer  = SigmaWriter(s)
        rules   = writer.generate_all()
        for rule in rules:
            assert "title:" in rule["sigma_rule"]
            assert "detection:" in rule["sigma_rule"]
            assert "logsource:" in rule["sigma_rule"]

    def test_saves_rules_to_disk(self, tmp_path):
        from modules.defense.sigma_writer import SigmaWriter
        s, _, _   = self._make_session(tmp_path)
        writer    = SigmaWriter(s)
        rules     = writer.generate_all()
        out_dir   = tmp_path / "sigma_out"
        saved     = writer.save_rules(rules, out_dir)
        assert len(saved) >= 1
        for path in saved:
            assert path.exists()
            assert path.suffix == ".yml"

    def test_deduplicates_same_template(self, tmp_path):
        from modules.session import Finding, SeverityLevel
        from modules.defense.sigma_writer import SigmaWriter
        s, Finding, SeverityLevel = self._make_session(tmp_path)
        # Add second sqli finding — should not create duplicate rule
        s.add_finding(Finding(
            source="exploit.web", title="Second SQLi",
            severity=SeverityLevel.HIGH, host="example.com",
            tags=["sqli"],
        ))
        writer = SigmaWriter(s)
        rules  = writer.generate_all()
        sqli_rules = [r for r in rules if "sqli" in r.get("template_key","")]
        assert len(sqli_rules) == 1


# ─────────────────────────────────────────────────────────────
# RemediationBuilder tests
# ─────────────────────────────────────────────────────────────

class TestRemediationBuilder:

    def _make_session(self, tmp_path):
        from modules.session import (
            SessionMeta, Session, SessionStatus,
            Mode, Finding, SeverityLevel,
        )
        import modules.session as sm
        sm.SESSIONS_ROOT = tmp_path / "sessions"
        now  = datetime.utcnow().isoformat()
        meta = SessionMeta(
            session_id="rem_test", name="rem",
            target="example.com", mode=Mode.RED,
            status=SessionStatus.CREATED,
            created_at=now, updated_at=now,
        )
        s = Session(meta)
        s.save()
        s.add_finding(Finding(
            source="exploit.web", title="SQL Injection",
            severity=SeverityLevel.CRITICAL, host="example.com",
            tags=["sqli"], cve="CVE-2021-0001",
        ))
        s.add_finding(Finding(
            source="exploit.web", title="XSS found",
            severity=SeverityLevel.HIGH, host="example.com",
            tags=["xss"],
        ))
        return s

    def test_builds_remediation_plan(self, tmp_path):
        from modules.defense.remediation import RemediationBuilder
        s    = self._make_session(tmp_path)
        rb   = RemediationBuilder(s)
        plan = rb.build()
        assert "items"      in plan
        assert len(plan["items"]) >= 1

    def test_items_sorted_by_severity(self, tmp_path):
        from modules.defense.remediation import RemediationBuilder
        s    = self._make_session(tmp_path)
        rb   = RemediationBuilder(s)
        plan = rb.build()
        items = plan["items"]
        order = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
        for i in range(len(items)-1):
            assert (order.get(items[i]["severity"],9) <=
                    order.get(items[i+1]["severity"],9))

    def test_each_item_has_steps(self, tmp_path):
        from modules.defense.remediation import RemediationBuilder
        s    = self._make_session(tmp_path)
        rb   = RemediationBuilder(s)
        plan = rb.build()
        for item in plan["items"]:
            assert "steps"  in item
            assert len(item["steps"]) >= 1
            assert "effort" in item
            assert "owner"  in item

    def test_saves_markdown_and_json(self, tmp_path):
        from modules.defense.remediation import RemediationBuilder
        s  = self._make_session(tmp_path)
        rb = RemediationBuilder(s)
        rb.build()
        out = s.dir("report") / "remediation"
        assert (out / "remediation_plan.json").exists()
        assert (out / "remediation_plan.md").exists()

    def test_cve_included_in_item(self, tmp_path):
        from modules.defense.remediation import RemediationBuilder
        s    = self._make_session(tmp_path)
        rb   = RemediationBuilder(s)
        plan = rb.build()
        cves = [item["cve"] for item in plan["items"] if item.get("cve")]
        assert "CVE-2021-0001" in cves


# ─────────────────────────────────────────────────────────────
# CoverageMapper tests
# ─────────────────────────────────────────────────────────────

class TestCoverageMapper:

    def _make_session(self, tmp_path):
        from modules.session import (
            SessionMeta, Session, SessionStatus,
            Mode, Finding, SeverityLevel,
        )
        import modules.session as sm
        sm.SESSIONS_ROOT = tmp_path / "sessions"
        now  = datetime.utcnow().isoformat()
        meta = SessionMeta(
            session_id="cov_test", name="cov",
            target="example.com", mode=Mode.PURPLE,
            status=SessionStatus.CREATED,
            created_at=now, updated_at=now,
        )
        s = Session(meta)
        s.save()
        s.add_finding(Finding(
            source="exploit.web", title="SQLi confirmed",
            severity=SeverityLevel.CRITICAL, host="example.com",
            tags=["sqli"],
        ))
        s.add_finding(Finding(
            source="defense.monitor.web_attack_monitor",
            title="[Monitor] SQLi detected in web logs",
            severity=SeverityLevel.HIGH, host="example.com",
            tags=["monitor", "sqli"],
        ))
        return s

    def test_map_returns_coverage_pct(self, tmp_path):
        from modules.purple.coverage_mapper import CoverageMapper
        s      = self._make_session(tmp_path)
        mapper = CoverageMapper(s)
        result = mapper.map_coverage()
        assert "coverage_pct"    in result
        assert "observed_count"  in result
        assert "detected_count"  in result
        assert isinstance(result["coverage_pct"], float)

    def test_observed_techniques_found(self, tmp_path):
        from modules.purple.coverage_mapper import CoverageMapper
        s      = self._make_session(tmp_path)
        mapper = CoverageMapper(s)
        result = mapper.map_coverage()
        assert result["observed_count"] >= 1

    def test_heatmap_has_all_techniques(self, tmp_path):
        from modules.purple.coverage_mapper import CoverageMapper, MITRE_TECHNIQUES
        s       = self._make_session(tmp_path)
        mapper  = CoverageMapper(s)
        result  = mapper.map_coverage()
        heatmap = result["heatmap"]
        assert len(heatmap) == len(MITRE_TECHNIQUES)

    def test_gap_analysis_lists_undetected(self, tmp_path):
        from modules.purple.coverage_mapper import CoverageMapper
        s      = self._make_session(tmp_path)
        mapper = CoverageMapper(s)
        result = mapper.map_coverage()
        assert isinstance(result["gap_analysis"], list)

    def test_recommendations_sorted_by_priority(self, tmp_path):
        from modules.purple.coverage_mapper import CoverageMapper
        s      = self._make_session(tmp_path)
        mapper = CoverageMapper(s)
        result = mapper.map_coverage()
        recs   = result["recommendations"]
        order  = {"critical":0,"high":1,"medium":2,"low":3}
        for i in range(len(recs)-1):
            assert (order.get(recs[i]["priority"],9) <=
                    order.get(recs[i+1]["priority"],9))

    def test_saves_coverage_map_json(self, tmp_path):
        from modules.purple.coverage_mapper import CoverageMapper
        s      = self._make_session(tmp_path)
        mapper = CoverageMapper(s)
        mapper.map_coverage()
        out = s.dir("report") / "purple" / "coverage_map.json"
        assert out.exists()


# ─────────────────────────────────────────────────────────────
# Run
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
