"""
modules/recon/dev.py
────────────────────
Developer tools and debugging reconnaissance.

Provides:
  - Development Interfaces (admin consoles, debug endpoints)
  - Development Artifacts (source maps, .git, backup files)
  - Logging & Monitoring (verbose logging, debug mode)
  - Third-Party Tools (Jenkins, Jira, Grafana, Prometheus)
  - API Documentation Tools (Swagger UI, GraphiQL)
"""

import re
import json
from typing import Any, Dict, List, Optional, Set
from pathlib import Path

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel
from modules.stealth import get_stealth_engine, ScanMode


class DevRecon:
    """
    Developer tools and debugging reconnaissance.
    """

    # Development tool paths
    DEV_PATHS = {
        "swagger_ui": ["/swagger-ui", "/swagger-ui.html", "/api-docs", "/v2/api-docs", "/v3/api-docs", "/openapi"],
        "graphiql": ["/graphiql", "/graphql/playground", "/graphql/graphiql"],
        "admin_console": ["/admin", "/adminer", "/phpmyadmin", "/mysql", "/pgadmin", "/mongodb"],
        "debug": ["/debug", "/_debug", "/dev", "/test", "/_test", "/staging"],
        "health": ["/health", "/status", "/ping", "/ready", "/live", "/metrics"],
        "actuator": ["/actuator", "/actuator/health", "/actuator/metrics", "/actuator/env", "/actuator/info"],
        "jenkins": ["/jenkins", "/jenkins/login", "/jenkins/job"],
        "jira": ["/jira", "/jira/login", "/jira/dashboard"],
        "confluence": ["/confluence", "/wiki", "/wiki/spaces"],
        "grafana": ["/grafana", "/grafana/login", "/grafana/dashboards"],
        "prometheus": ["/prometheus", "/metrics", "/targets"],
        "kibana": ["/kibana", "/kibana/app"],
        "elastic": ["/elastic", "/elasticsearch", "/_cat"],
        "rabbitmq": ["/rabbitmq", "/rabbitmq/management", "/#/queues"],
        "redis": ["/redis", "/redis/status", "/redis/keys"],
        "memcached": ["/memcached", "/memcached/status"],
        "sentry": ["/sentry", "/sentry/login", "/sentry/errors"],
        "newrelic": ["/newrelic", "/newrelic/login"],
        "datadog": ["/datadog", "/datadog/login"],
        "splunk": ["/splunk", "/splunk/app"],
        "elk": ["/elk", "/elasticsearch", "/kibana", "/logstash"],
    }

    # Artifact patterns
    ARTIFACT_PATTERNS = {
        "source_map": [r"\.js\.map", r"\.css\.map", r"sourceMappingURL="],
        "git": [r"\.git/config", r"\.git/HEAD", r"\.git/index", r"\.git/refs"],
        "svn": [r"\.svn/entries", r"\.svn/wc.db"],
        "backup": [r"\.bak", r"\.old", r"\.backup", r"\.copy", r"\.tmp", r"\.swp", r"\.save", r"\.orig"],
        "sql": [r"\.sql", r"\.dump", r"\.db", r"\.sqlite"],
        "archive": [r"\.zip", r"\.tar\.gz", r"\.tgz", r"\.rar", r"\.7z"],
        "config": [r"\.env", r"\.config", r"web\.config", r"php\.ini", r"\.htaccess"],
        "log": [r"\.log", r"\.log\.[0-9]+", r"access\.log", r"error\.log"],
        "cache": [r"\.cache", r"\.cache\.[a-z]+", r"\.min\.", r"\.min\.js"],
    }

    def __init__(self, session: Session, logger: Optional[ARDFLogger] = None):
        self.session = session
        self.logger = logger or get_logger("recon.dev")
        self.out_dir = session.dir("recon") / "dev"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.stealth = get_stealth_engine(self.logger)

    def discover_dev_interfaces(self, target: str) -> List[Dict[str, str]]:
        """
        Discover development interfaces.
        """
        self.logger.info(f"Dev interface discovery: {target}")

        results = []
        urls = [
            f"https://{target}",
            f"http://{target}",
        ]

        for base_url in urls:
            for tool, paths in self.DEV_PATHS.items():
                for path in paths[:3]:  # Limit per tool
                    try:
                        test_url = base_url.rstrip("/") + path
                        status, headers, content = self.stealth.get(test_url, timeout=5)

                        if status in [200, 302, 401, 403]:
                            results.append({
                                "url": test_url,
                                "status": status,
                                "tool": tool
                            })
                            self.logger.finding(f"Dev interface: {tool} -> {test_url}", severity="info", host=target)
                            self.session.add_finding(Finding(
                                source="recon.dev",
                                title=f"Development interface: {tool}",
                                severity=SeverityLevel.MEDIUM if tool in ["admin_console", "debug", "actuator"] else SeverityLevel.LOW,
                                host=target,
                                tags=["dev", tool],
                                evidence=test_url,
                                remediation=f"Restrict access to {tool} in production environments.",
                            ))

                        self.stealth.sleep(0.3)

                    except Exception:
                        pass

        return results

    def discover_artifacts(self, target: str) -> List[Dict[str, str]]:
        """
        Discover development artifacts.
        """
        self.logger.info(f"Artifact discovery: {target}")

        results = []
        urls = [
            f"https://{target}",
            f"http://{target}",
        ]

        # Common artifact paths
        artifact_paths = [
            "/.git/config", "/.git/HEAD", "/.git/index",
            "/.svn/entries", "/.svn/wc.db",
            "/.env", "/.env.local", "/.env.production", "/.env.development",
            "/web.config", "/php.ini", "/.htaccess",
            "/config.php", "/config.ini", "/settings.json",
            "/backup.sql", "/db.sql", "/dump.sql",
            "/sitemap.xml", "/robots.txt",
            "/.well-known/security.txt",
        ]

        for base_url in urls:
            for path in artifact_paths:
                try:
                    test_url = base_url.rstrip("/") + path
                    status, headers, content = self.stealth.get(test_url, timeout=5)

                    if status == 200 and content and len(content) > 20:
                        artifact_type = "unknown"
                        for atype, patterns in self.ARTIFACT_PATTERNS.items():
                            for pattern in patterns:
                                if re.search(pattern, path, re.I):
                                    artifact_type = atype
                                    break
                            if artifact_type != "unknown":
                                break

                        results.append({
                            "url": test_url,
                            "path": path,
                            "type": artifact_type,
                            "size": len(content)
                        })

                        severity = SeverityLevel.HIGH if artifact_type in ["git", "config", "sql"] else SeverityLevel.MEDIUM
                        self.logger.finding(f"Artifact found: {path} ({artifact_type})", severity=severity.value, host=target)
                        self.session.add_finding(Finding(
                            source="recon.dev",
                            title=f"Development artifact: {path}",
                            severity=severity,
                            host=target,
                            tags=["artifact", artifact_type],
                            evidence=test_url,
                            remediation=f"Remove {path} from production. Use environment variables for configuration.",
                        ))

                    self.stealth.sleep(0.3)

                except Exception:
                    pass

        return results

    def detect_logging(self, target: str) -> List[Dict[str, str]]:
        """
        Detect logging and monitoring systems.
        """
        self.logger.info(f"Logging detection: {target}")

        results = []

        # Check for logging endpoints
        log_paths = [
            "/logs", "/log", "/debug", "/trace",
            "/_log", "/_debug", "/_trace",
            "/var/log", "/var/logs",
            "/api/logs", "/api/debug",
        ]

        for base_url in [f"https://{target}", f"http://{target}"]:
            for path in log_paths:
                try:
                    test_url = base_url.rstrip("/") + path
                    status, headers, content = self.stealth.get(test_url, timeout=5)

                    if status in [200, 401, 403]:
                        # Check for logging indicators
                        content_lower = content.lower()
                        log_indicators = ["log", "debug", "trace", "error", "warning", "info", "verbose"]

                        if any(ind in content_lower for ind in log_indicators):
                            results.append({
                                "url": test_url,
                                "status": status,
                                "type": "log_endpoint"
                            })
                            self.logger.finding(f"Logging endpoint: {test_url}", severity="critical", host=target)
                            self.session.add_finding(Finding(
                                source="recon.dev",
                                title=f"Logging endpoint: {path}",
                                severity=SeverityLevel.HIGH,
                                host=target,
                                tags=["logging", "debug", "exposure"],
                                evidence=test_url,
                                remediation="Secure logging endpoints. Disable verbose logging in production.",
                            ))

                    self.stealth.sleep(0.3)

                except Exception:
                    pass

        return results

    def detect_third_party_tools(self, target: str) -> List[Dict[str, str]]:
        """
        Detect third-party development tools.
        """
        self.logger.info(f"Third-party tool detection: {target}")

        results = []

        # Check for specific tool paths
        tool_paths = {
            "jenkins": ["/jenkins", "/jenkins/login", "/jenkins/job"],
            "jira": ["/jira", "/jira/login", "/jira/dashboard"],
            "confluence": ["/confluence", "/wiki", "/wiki/spaces"],
            "grafana": ["/grafana", "/grafana/login", "/grafana/dashboards"],
            "prometheus": ["/prometheus", "/metrics", "/targets"],
            "kibana": ["/kibana", "/kibana/app"],
            "elasticsearch": ["/elasticsearch", "/_cat", "/_cluster"],
            "rabbitmq": ["/rabbitmq", "/rabbitmq/management"],
            "sentry": ["/sentry", "/sentry/login", "/sentry/errors"],
            "datadog": ["/datadog", "/datadog/login"],
            "splunk": ["/splunk", "/splunk/app"],
        }

        for base_url in [f"https://{target}", f"http://{target}"]:
            for tool, paths in tool_paths.items():
                for path in paths[:2]:
                    try:
                        test_url = base_url.rstrip("/") + path
                        status, headers, content = self.stealth.get(test_url, timeout=5)

                        if status in [200, 302, 401, 403]:
                            results.append({
                                "url": test_url,
                                "status": status,
                                "tool": tool
                            })
                            self.logger.finding(f"Third-party tool: {tool} -> {test_url}", severity="info", host=target)
                            self.session.add_finding(Finding(
                                source="recon.dev",
                                title=f"Third-party tool: {tool}",
                                severity=SeverityLevel.MEDIUM,
                                host=target,
                                tags=["dev", "third-party", tool],
                                evidence=test_url,
                                remediation=f"Restrict access to {tool} in production.",
                            ))

                        self.stealth.sleep(0.3)

                    except Exception:
                        pass

        return results

    def run(self, target: str) -> Dict[str, Any]:
        """
        Run full development reconnaissance.
        """
        self.logger.banner(f"DEV RECON: {target}", style="bold blue")

        self.stealth.config.scan_mode = ScanMode.LOW

        results = {
            "target": target,
            "dev_interfaces": [],
            "artifacts": [],
            "logging": [],
            "third_party_tools": []
        }

        # Discover dev interfaces
        results["dev_interfaces"] = self.discover_dev_interfaces(target)

        # Discover artifacts
        results["artifacts"] = self.discover_artifacts(target)

        # Detect logging
        results["logging"] = self.detect_logging(target)

        # Detect third-party tools
        results["third_party_tools"] = self.detect_third_party_tools(target)

        # Save results
        report_path = self.out_dir / f"dev_{_safe(target)}.json"
        report_path.write_text(json.dumps(results, indent=2, default=str))

        self.logger.success(f"Dev recon: {len(results['dev_interfaces'])} interfaces, {len(results['artifacts'])} artifacts")
        return results


def _safe(s: str) -> str:
    return re.sub(r"[^\w.-]", "_", s)[:50]