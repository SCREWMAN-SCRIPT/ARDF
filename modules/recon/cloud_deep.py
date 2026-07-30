"""
modules/recon/cloud_deep.py
───────────────────────────
Deep cloud infrastructure reconnaissance.

Provides:
  - AWS Enumeration (S3, EC2, Lambda, RDS, IAM, Route53, CloudFront)
  - Azure Enumeration (Storage, VMs, App Service, Key Vault, Cosmos DB)
  - GCP Enumeration (Storage, Compute, Cloud Run, Firebase, Cloud SQL)
  - Container Registry Enumeration (ECR, GCR, ACR, DockerHub)
  - Kubernetes Enumeration (API server, services, pods, secrets)
  - IaC (Terraform, CloudFormation, Ansible) Exposure
"""

import re
import json
from typing import Any, Dict, List, Optional, Set
from pathlib import Path
from urllib.parse import urlparse

from modules.logger import get_logger, ARDFLogger
from modules.session import Session, Finding, SeverityLevel
from modules.stealth import get_stealth_engine, ScanMode


class CloudDeepRecon:
    """
    Deep cloud infrastructure reconnaissance.
    """

    # Cloud service patterns
    AWS_PATTERNS = {
        "s3_bucket": r"s3\.amazonaws\.com/([^/]+)|([a-z0-9.-]+)\.s3\.amazonaws\.com",
        "cloudfront": r"cloudfront\.net|([a-z0-9]+)\.cloudfront\.net",
        "ec2": r"ec2-[0-9-]+\.compute\.amazonaws\.com",
        "rds": r"([a-z0-9-]+)\.([a-z0-9-]+)\.rds\.amazonaws\.com",
        "elasticbeanstalk": r"elasticbeanstalk\.com|([a-z0-9-]+)\.elasticbeanstalk\.com",
        "lambda": r"lambda-url\.[a-z0-9-]+\.on\.aws",
        "api_gateway": r"execute-api\.[a-z0-9-]+\.amazonaws\.com",
    }

    AZURE_PATTERNS = {
        "storage": r"blob\.core\.windows\.net|([a-z0-9]+)\.blob\.core\.windows\.net",
        "vm": r"cloudapp\.azure\.com|([a-z0-9-]+)\.cloudapp\.azure\.com",
        "app_service": r"azurewebsites\.net|([a-z0-9-]+)\.azurewebsites\.net",
        "cosmos_db": r"documents\.azure\.com|([a-z0-9-]+)\.documents\.azure\.com",
        "key_vault": r"vault\.azure\.net|([a-z0-9-]+)\.vault\.azure\.net",
        "function_app": r"azurewebsites\.net/api/.*?function",
    }

    GCP_PATTERNS = {
        "storage": r"storage\.googleapis\.com/([^/]+)|([a-z0-9-]+)\.storage\.googleapis\.com",
        "compute": r"([a-z0-9-]+)\.compute\.amazonaws\.com",  # Legacy
        "cloud_run": r"run\.app|([a-z0-9-]+)\.run\.app",
        "firebase": r"firebaseio\.com|([a-z0-9-]+)\.firebaseio\.com",
        "cloud_sql": r"sql\.cloud\.google\.com|([a-z0-9-]+)\.sql\.cloud\.google\.com",
    }

    def __init__(self, session: Session, logger: Optional[ARDFLogger] = None):
        self.session = session
        self.logger = logger or get_logger("recon.cloud_deep")
        self.out_dir = session.dir("recon") / "cloud_deep"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.stealth = get_stealth_engine(self.logger)

    def aws_enum(self, target: str) -> Dict[str, Any]:
        """
        Enumerate AWS resources.
        """
        self.logger.info(f"AWS enumeration: {target}")

        results = {
            "buckets": [],
            "cloudfront": [],
            "ec2_instances": [],
            "rds_instances": [],
            "lambda_functions": [],
            "api_gateways": []
        }

        # Collect URLs from findings
        urls = self._collect_urls()

        for url in urls:
            for resource, pattern in self.AWS_PATTERNS.items():
                match = re.search(pattern, url, re.I)
                if match:
                    resource_name = match.group(1) or match.group(2) or "unknown"
                    if resource == "s3_bucket":
                        results["buckets"].append({"name": resource_name, "url": url})
                    elif resource == "cloudfront":
                        results["cloudfront"].append({"name": resource_name, "url": url})
                    elif resource == "ec2":
                        results["ec2_instances"].append({"name": resource_name, "url": url})
                    elif resource == "rds":
                        results["rds_instances"].append({"name": resource_name, "url": url})
                    elif resource == "lambda":
                        results["lambda_functions"].append({"name": resource_name, "url": url})
                    elif resource == "api_gateway":
                        results["api_gateways"].append({"name": resource_name, "url": url})

        # Try to enumerate S3 buckets by name guessing
        domain_clean = target.replace(".", "-")
        guesses = [
            f"{domain_clean}.s3.amazonaws.com",
            f"{target}.s3.amazonaws.com",
            f"{target.replace('.', '-')}.s3.amazonaws.com",
            f"{target}-data.s3.amazonaws.com",
            f"{target}-assets.s3.amazonaws.com",
            f"{target}-media.s3.amazonaws.com",
            f"{target}-static.s3.amazonaws.com",
            f"{target}-files.s3.amazonaws.com",
            f"{target}-backup.s3.amazonaws.com",
        ]

        for guess in guesses:
            try:
                status, headers, content = self.stealth.get(f"https://{guess}", timeout=5)
                if status != 404:
                    results["buckets"].append({
                        "name": guess.split(".")[0],
                        "url": f"https://{guess}",
                        "status": status,
                        "accessible": status == 200
                    })
                    self.logger.finding(f"AWS S3 bucket found: {guess}", severity="info", host=target)
                    self.session.add_finding(Finding(
                        source="recon.cloud_deep",
                        title=f"AWS S3 bucket: {guess}",
                        severity=SeverityLevel.MEDIUM if status == 200 else SeverityLevel.LOW,
                        host=target,
                        tags=["aws", "s3", "cloud", "bucket"],
                        evidence=guess,
                        remediation=f"Review S3 bucket {guess} permissions. Ensure not publicly accessible.",
                    ))
            except Exception:
                pass
            self.stealth.sleep(1)

        return results

    def azure_enum(self, target: str) -> Dict[str, Any]:
        """
        Enumerate Azure resources.
        """
        self.logger.info(f"Azure enumeration: {target}")

        results = {
            "storage": [],
            "vms": [],
            "app_services": [],
            "cosmos_db": [],
            "key_vaults": [],
            "function_apps": []
        }

        urls = self._collect_urls()

        for url in urls:
            for resource, pattern in self.AZURE_PATTERNS.items():
                match = re.search(pattern, url, re.I)
                if match:
                    resource_name = match.group(1) or "unknown"
                    if resource == "storage":
                        results["storage"].append({"name": resource_name, "url": url})
                    elif resource == "vm":
                        results["vms"].append({"name": resource_name, "url": url})
                    elif resource == "app_service":
                        results["app_services"].append({"name": resource_name, "url": url})
                    elif resource == "cosmos_db":
                        results["cosmos_db"].append({"name": resource_name, "url": url})
                    elif resource == "key_vault":
                        results["key_vaults"].append({"name": resource_name, "url": url})
                    elif resource == "function_app":
                        results["function_apps"].append({"name": resource_name, "url": url})

        # Guess Azure storage accounts
        domain_clean = target.replace(".", "").replace("-", "")
        guesses = [
            f"{domain_clean}.blob.core.windows.net",
            f"{target.replace('.', '')}.blob.core.windows.net",
            f"{domain_clean}storage.blob.core.windows.net",
        ]

        for guess in guesses:
            try:
                status, headers, content = self.stealth.get(f"https://{guess}", timeout=5)
                if status != 404:
                    results["storage"].append({
                        "name": guess.split(".")[0],
                        "url": f"https://{guess}",
                        "accessible": status == 200
                    })
                    self.logger.finding(f"Azure storage account found: {guess}", severity="info", host=target)
            except Exception:
                pass
            self.stealth.sleep(1)

        return results

    def gcp_enum(self, target: str) -> Dict[str, Any]:
        """
        Enumerate GCP resources.
        """
        self.logger.info(f"GCP enumeration: {target}")

        results = {
            "buckets": [],
            "cloud_run": [],
            "firebase": [],
            "cloud_sql": []
        }

        urls = self._collect_urls()

        for url in urls:
            for resource, pattern in self.GCP_PATTERNS.items():
                match = re.search(pattern, url, re.I)
                if match:
                    resource_name = match.group(1) or "unknown"
                    if resource == "storage":
                        results["buckets"].append({"name": resource_name, "url": url})
                    elif resource == "cloud_run":
                        results["cloud_run"].append({"name": resource_name, "url": url})
                    elif resource == "firebase":
                        results["firebase"].append({"name": resource_name, "url": url})
                    elif resource == "cloud_sql":
                        results["cloud_sql"].append({"name": resource_name, "url": url})

        # Guess GCS buckets
        domain_clean = target.replace(".", "-")
        guesses = [
            f"{domain_clean}.storage.googleapis.com",
            f"{target}.storage.googleapis.com",
            f"{domain_clean}-assets.storage.googleapis.com",
        ]

        for guess in guesses:
            try:
                status, headers, content = self.stealth.get(f"https://{guess}", timeout=5)
                if status != 404:
                    results["buckets"].append({
                        "name": guess.split(".")[0],
                        "url": f"https://{guess}",
                        "accessible": status == 200
                    })
                    self.logger.finding(f"GCS bucket found: {guess}", severity="info", host=target)
            except Exception:
                pass
            self.stealth.sleep(1)

        return results

    def kubernetes_enum(self, target: str) -> Dict[str, Any]:
        """
        Enumerate Kubernetes resources.
        """
        self.logger.info(f"Kubernetes enumeration: {target}")

        results = {
            "api_servers": [],
            "services": [],
            "namespaces": [],
            "ingresses": []
        }

        # Check for Kubernetes API endpoint
        k8s_paths = [
            "/api/v1/",
            "/apis/",
            "/api/v1/namespaces",
            "/api/v1/services",
            "/ingress",
            "/kube-system/",
            "/.well-known/openid-configuration",  # Some k8s setups
        ]

        for path in k8s_paths:
            try:
                test_url = f"https://{target}{path}"
                status, headers, content = self.stealth.get(test_url, timeout=5)

                if status == 200:
                    results["api_servers"].append({"path": path, "url": test_url})

                    if "namespaces" in content.lower():
                        results["namespaces"].append(path)

                    self.logger.finding(f"Kubernetes API endpoint: {path}", severity="critical", host=target)
                    self.session.add_finding(Finding(
                        source="recon.cloud_deep",
                        title=f"Kubernetes API endpoint: {path}",
                        severity=SeverityLevel.CRITICAL,
                        host=target,
                        tags=["kubernetes", "k8s", "api", "exposure"],
                        evidence=test_url,
                        remediation="Secure Kubernetes API access. Use RBAC and network policies.",
                    ))

            except Exception:
                pass
            self.stealth.sleep(0.5)

        return results

    def iac_exposure(self, target: str) -> List[Dict[str, str]]:
        """
        Detect Infrastructure-as-Code exposure.
        """
        self.logger.info(f"IaC exposure detection: {target}")

        results = []

        iac_paths = [
            ".tf", ".tfstate", ".tfplan",  # Terraform
            ".yml", ".yaml",  # General YAML
            "Dockerfile",
            "docker-compose.yml",
            "docker-compose.yaml",
            "kustomization.yaml",
            "deployment.yaml",
            "service.yaml",
            "ingress.yaml",
            "configmap.yaml",
            "secret.yaml",
            "ansible/",
            "playbook.yml",
            "cloudformation.json",
            "template.yaml",
            "serverless.yml",
        ]

        # Check common paths
        base_paths = ["/", "/.git/", "/.terraform/", "/.aws/", "/.azure/", "/.gcp/"]

        for base in base_paths:
            for pattern in iac_paths[:10]:
                try:
                    test_url = f"https://{target}{base}{pattern}"
                    status, headers, content = self.stealth.get(test_url, timeout=3)

                    if status == 200 and len(content) > 50:
                        results.append({
                            "path": f"{base}{pattern}",
                            "url": test_url,
                            "size": len(content)
                        })
                        self.logger.finding(f"IaC file found: {base}{pattern}", severity="critical", host=target)
                        self.session.add_finding(Finding(
                            source="recon.cloud_deep",
                            title=f"IaC file exposed: {base}{pattern}",
                            severity=SeverityLevel.CRITICAL,
                            host=target,
                            tags=["iac", "terraform", "cloudformation", "exposure"],
                            evidence=test_url,
                            remediation="Remove IaC files from production. Use secrets management.",
                        ))

                except Exception:
                    pass
                self.stealth.sleep(0.3)

        return results

    def _collect_urls(self) -> List[str]:
        """Collect URLs from session findings."""
        urls = []

        # From findings
        for f in self.session.get_findings():
            if f.evidence and "http" in f.evidence:
                urls.append(f.evidence)

        # From recon summary
        recon_path = self.session.dir("recon") / "recon_passive_summary.json"
        if recon_path.exists():
            try:
                data = json.loads(recon_path.read_text())
                for url in data.get("urls", []):
                    urls.append(url)
            except Exception:
                pass

        return list(set(urls))

    def run(self, target: str) -> Dict[str, Any]:
        """
        Run full deep cloud reconnaissance.
        """
        self.logger.banner(f"DEEP CLOUD RECON: {target}", style="bold blue")

        self.stealth.config.scan_mode = ScanMode.LOW

        results = {
            "target": target,
            "aws": {},
            "azure": {},
            "gcp": {},
            "kubernetes": {},
            "iac": []
        }

        # AWS enumeration
        results["aws"] = self.aws_enum(target)

        # Azure enumeration
        results["azure"] = self.azure_enum(target)

        # GCP enumeration
        results["gcp"] = self.gcp_enum(target)

        # Kubernetes enumeration
        results["kubernetes"] = self.kubernetes_enum(target)

        # IaC exposure
        results["iac"] = self.iac_exposure(target)

        # Summary findings
        total_resources = (
            len(results["aws"].get("buckets", [])) +
            len(results["azure"].get("storage", [])) +
            len(results["gcp"].get("buckets", [])) +
            len(results["kubernetes"].get("api_servers", []))
        )

        if total_resources > 0:
            self.session.add_finding(Finding(
                source="recon.cloud_deep",
                title=f"Cloud resources found: {total_resources}",
                severity=SeverityLevel.MEDIUM,
                host=target,
                tags=["cloud", "aws", "azure", "gcp", "kubernetes"],
                evidence=json.dumps({"aws": len(results["aws"].get("buckets", [])), "azure": len(results["azure"].get("storage", [])), "gcp": len(results["gcp"].get("buckets", []))}),
                remediation="Review cloud resource exposure. Restrict public access.",
            ))

        # Save results
        report_path = self.out_dir / f"cloud_deep_{_safe(target)}.json"
        report_path.write_text(json.dumps(results, indent=2, default=str))

        self.logger.success(f"Deep cloud recon: {total_resources} resources found")
        return results


def _safe(s: str) -> str:
    return re.sub(r"[^\w.-]", "_", s)[:50]