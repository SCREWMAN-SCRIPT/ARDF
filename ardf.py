#!/usr/bin/env python3
"""
ardf.py
───────
ARDF — Autonomous Red/Blue Defense Framework

Main CLI entry point for the ARDF framework.

Usage:
    python ardf.py --target example.com --depth normal
    python ardf.py --target example.com --playbook full
    python ardf.py --target example.com --mode red --sqli
    python ardf.py --target example.com --mode red --bruteforce
    python ardf.py --target example.com --chat
    python ardf.py --session <id> --report
"""

import os
import sys
import json
import time
import argparse
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.absolute()
sys.path.insert(0, str(PROJECT_ROOT))

# ─────────────────────────────────────────────────────────────
# Import ARDF modules
# ─────────────────────────────────────────────────────────────

from modules.logger import init_logger, get_logger
from modules.session import Session, SessionMode, SessionStatus
from modules.recon import run_recon
from modules.exploit import run_exploit
from modules.intel import run_intel
from modules.bypass import run_bypass
from modules.workflow import run_workflow
from modules.redteam import run_redteam
from modules.report import generate_report
from modules.stealth import get_stealth_engine, ScanMode

# NEW: Import validation modules
from modules.validate.sqli import SQLiValidator
from modules.validate.nosqli import NoSQLiValidator
from modules.validate.ldap import LDAPValidator
from modules.validate.cmdi import CMDIValidator
from modules.validate.code import CodeValidator
from modules.validate.xxe import XXEValidator
from modules.validate.xpath import XPathValidator
from modules.validate.path_traversal import PathTraversalValidator
from modules.validate.auth import AuthValidator
from modules.validate.session import SessionValidator
from modules.validate.jwt import JWTValidator
from modules.validate.oauth import OAuthValidator
from modules.validate.mfa import MFAValidator
from modules.validate.classifier import VulnerabilityClassifier

# NEW: Import tool wrappers
from modules.tools.sqlmap_wrapper import SQLMapWrapper
from modules.tools.hydra_wrapper import HydraWrapper
from modules.tools.nmap_wrapper import NmapWrapper

# NEW: Import recon submodules
from modules.recon.domain import DomainRecon
from modules.recon.subdomain import SubdomainRecon
from modules.recon.web import WebRecon
from modules.recon.cdn import CDNRecon
from modules.recon.cloud import CloudRecon
from modules.recon.social import SocialRecon
from modules.recon.cache import CacheRecon
from modules.recon.vuln_intel import VulnIntelRecon
from modules.recon.network import NetworkRecon
from modules.recon.web_deep import WebDeepRecon
from modules.recon.database import DatabaseRecon
from modules.recon.service import ServiceRecon
from modules.recon.cloud_deep import CloudDeepRecon
from modules.recon.vpn import VPNRecon
from modules.recon.auth import AuthRecon
from modules.recon.dev import DevRecon
from modules.recon.lateral import LateralRecon

# NEW: Import core enhancements
from core.orchestrator import run_orchestrator
from core.mission import run_mission
from core.task_graph import build_and_execute_graph
from core.response_classifier import classify_response


# ─────────────────────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────────────────────

def print_banner() -> None:
    """Print the ARDF banner."""
    banner = r"""
    ___    ____  ____  ______
   /   |  / __ \/ __ \/ ____/
  / /| | / /_/ / / / / /_
 / ___ |/ _, _/ /_/ / __/
/_/  |_/_/ |_/_____/_/

"""
    print("\033[36m" + banner + "\033[0m")
    print("\033[1mARDF — Autonomous Red/Blue Defense Framework\033[0m")
    print("v1.0.0 — NightHawk\n")


# ─────────────────────────────────────────────────────────────
# CLI Parser
# ─────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="ARDF — Autonomous Red/Blue Defense Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Target options
    target_group = parser.add_argument_group("Target")
    target_group.add_argument(
        "-t", "--target",
        help="Target domain or IP address"
    )
    target_group.add_argument(
        "-f", "--target-file",
        help="File containing list of targets"
    )
    target_group.add_argument(
        "-s", "--session",
        help="Session ID to resume or process"
    )

    # Mode options
    mode_group = parser.add_argument_group("Mode")
    mode_group.add_argument(
        "--mode", "-m",
        choices=["red", "blue", "purple", "full", "osint"],
        default="full",
        help="Execution mode (default: full)"
    )
    mode_group.add_argument(
        "--depth",
        choices=["passive", "normal", "depth"],
        default="normal",
        help="Reconnaissance depth (default: normal)"
    )
    mode_group.add_argument(
        "--playbook",
        help="Run a specific playbook"
    )

    # NEW: Validation options
    validate_group = parser.add_argument_group("Validation")
    validate_group.add_argument(
        "--sqli",
        action="store_true",
        help="Run SQL injection validation"
    )
    validate_group.add_argument(
        "--nosqli",
        action="store_true",
        help="Run NoSQL injection validation"
    )
    validate_group.add_argument(
        "--ldap",
        action="store_true",
        help="Run LDAP injection validation"
    )
    validate_group.add_argument(
        "--cmdi",
        action="store_true",
        help="Run OS command injection validation"
    )
    validate_group.add_argument(
        "--code",
        action="store_true",
        help="Run code injection validation"
    )
    validate_group.add_argument(
        "--xxe",
        action="store_true",
        help="Run XXE validation"
    )
    validate_group.add_argument(
        "--xpath",
        action="store_true",
        help="Run XPath injection validation"
    )
    validate_group.add_argument(
        "--path-traversal",
        action="store_true",
        help="Run path traversal validation"
    )
    validate_group.add_argument(
        "--bruteforce",
        action="store_true",
        help="Run brute-force authentication validation"
    )
    validate_group.add_argument(
        "--session-test",
        action="store_true",
        help="Run session management validation"
    )
    validate_group.add_argument(
        "--jwt",
        action="store_true",
        help="Run JWT validation"
    )
    validate_group.add_argument(
        "--oauth",
        action="store_true",
        help="Run OAuth/SAML validation"
    )
    validate_group.add_argument(
        "--mfa",
        action="store_true",
        help="Run MFA bypass validation"
    )
    validate_group.add_argument(
        "--validate-all",
        action="store_true",
        help="Run all validation modules"
    )

    # NEW: Tool options
    tool_group = parser.add_argument_group("Tools")
    tool_group.add_argument(
        "--sqlmap",
        action="store_true",
        help="Run SQLMap scan"
    )
    tool_group.add_argument(
        "--hydra",
        action="store_true",
        help="Run Hydra brute-force"
    )
    tool_group.add_argument(
        "--nmap",
        action="store_true",
        help="Run Nmap scan"
    )
    tool_group.add_argument(
        "--tool",
        choices=["sqlmap", "hydra", "nmap"],
        help="Run specific tool"
    )

    # NEW: Recon options
    recon_group = parser.add_argument_group("Recon")
    recon_group.add_argument(
        "--domain",
        action="store_true",
        help="Run domain intelligence"
    )
    recon_group.add_argument(
        "--subdomain",
        action="store_true",
        help="Run subdomain enumeration"
    )
    recon_group.add_argument(
        "--web",
        action="store_true",
        help="Run web intelligence"
    )
    recon_group.add_argument(
        "--cdn",
        action="store_true",
        help="Run CDN detection"
    )
    recon_group.add_argument(
        "--cloud",
        action="store_true",
        help="Run cloud intelligence"
    )
    recon_group.add_argument(
        "--social",
        action="store_true",
        help="Run social intelligence"
    )
    recon_group.add_argument(
        "--cache",
        action="store_true",
        help="Run cache intelligence"
    )
    recon_group.add_argument(
        "--vuln-intel",
        action="store_true",
        help="Run vulnerability intelligence"
    )
    recon_group.add_argument(
        "--network-scan",
        action="store_true",
        help="Run network scan"
    )
    recon_group.add_argument(
        "--web-deep",
        action="store_true",
        help="Run deep web recon"
    )
    recon_group.add_argument(
        "--database",
        action="store_true",
        help="Run database recon"
    )
    recon_group.add_argument(
        "--service",
        action="store_true",
        help="Run service enumeration"
    )
    recon_group.add_argument(
        "--cloud-deep",
        action="store_true",
        help="Run deep cloud recon"
    )
    recon_group.add_argument(
        "--vpn",
        action="store_true",
        help="Run VPN detection"
    )
    recon_group.add_argument(
        "--auth",
        action="store_true",
        help="Run authentication recon"
    )
    recon_group.add_argument(
        "--dev",
        action="store_true",
        help="Run developer recon"
    )
    recon_group.add_argument(
        "--lateral",
        action="store_true",
        help="Run lateral movement recon"
    )

    # NEW: Stealth options
    stealth_group = parser.add_argument_group("Stealth")
    stealth_group.add_argument(
        "--stealth",
        choices=["passive", "low", "medium", "high"],
        default="low",
        help="Stealth level (default: low)"
    )
    stealth_group.add_argument(
        "--rate-limit",
        type=float,
        default=2.0,
        help="Requests per second (default: 2.0)"
    )
    stealth_group.add_argument(
        "--proxy",
        help="Proxy address (e.g., socks5://127.0.0.1:9050)"
    )

    # Workflow options
    workflow_group = parser.add_argument_group("Workflow")
    workflow_group.add_argument(
        "--workflow",
        action="store_true",
        help="Run adaptive workflow"
    )
    workflow_group.add_argument(
        "--resume",
        action="store_true",
        help="Resume existing workflow"
    )

    # Output options
    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "--report",
        action="store_true",
        help="Generate report"
    )
    output_group.add_argument(
        "--open",
        action="store_true",
        help="Open report in browser"
    )
    output_group.add_argument(
        "--verbose", "-v",
        action="count",
        default=0,
        help="Increase verbosity"
    )

    # Interface options
    interface_group = parser.add_argument_group("Interface")
    interface_group.add_argument(
        "--chat",
        action="store_true",
        help="Start interactive chat interface"
    )
    interface_group.add_argument(
        "--progress",
        action="store_true",
        help="Show live progress"
    )

    # Miscellaneous
    parser.add_argument(
        "--list-playbooks",
        action="store_true",
        help="List available playbooks"
    )
    parser.add_argument(
        "--list-tools",
        action="store_true",
        help="List available tools"
    )
    parser.add_argument(
        "--version",
        action="version",
        version="ARDF v1.0.0 — NightHawk"
    )

    return parser.parse_args()


# ─────────────────────────────────────────────────────────────
# Main execution
# ─────────────────────────────────────────────────────────────

def main() -> None:
    """Main entry point."""
    args = parse_args()

    # Print banner
    if not args.chat:
        print_banner()

    # Set up logging
    log_level = max(0, 3 - args.verbose)
    logger = init_logger(log_level=log_level)

    # ── Handle list commands ──────────────────────────────────

    if args.list_playbooks:
        from core.mission import MissionLoader
        loader = MissionLoader(logger)
        playbooks = loader.list_playbooks()
        print("\n\033[1mAvailable playbooks:\033[0m")
        for p in playbooks:
            print(f"  - {p}")
        return

    if args.list_tools:
        print("\n\033[1mAvailable tools:\033[0m")
        tools = [
            ("sqlmap", "SQL injection automation"),
            ("hydra", "Brute-force password cracking"),
            ("nmap", "Network discovery and scanning"),
        ]
        for tool, desc in tools:
            try:
                result = subprocess.run(["which", tool], capture_output=True, text=True, timeout=2)
                status = "\033[32m✅ installed\033[0m" if result.returncode == 0 else "\033[31m❌ not found\033[0m"
            except Exception:
                status = "\033[31m❌ not found\033[0m"
            print(f"  {tool}: {desc} - {status}")
        return

    # ── Validate required arguments ──────────────────────────

    if not args.session and not args.target and not args.target_file and not args.chat:
        logger.error("Either --target, --target-file, --session, or --chat is required")
        sys.exit(1)

    # ── Chat mode ─────────────────────────────────────────────

    if args.chat:
        if args.session:
            session = Session.load(args.session)
            if not session:
                logger.error(f"Session {args.session} not found")
                sys.exit(1)
        else:
            session = Session(args.target or "localhost", SessionMode(args.mode))
        from interface.chat import run_chat
        run_chat(session, logger)
        return

    # ── Set stealth configuration ────────────────────────────

    stealth = get_stealth_engine(logger)
    stealth.config.scan_mode = ScanMode(args.stealth)
    if args.rate_limit:
        stealth.config.rate_limit = args.rate_limit
    if args.proxy:
        stealth.config.proxy_enabled = True
        stealth.config.proxy_address = args.proxy

    # ── Load or create session ───────────────────────────────

    session = None
    if args.session:
        session = Session.load(args.session)
        if not session:
            logger.error(f"Session {args.session} not found")
            sys.exit(1)
    else:
        # Create new session
        target = args.target
        if args.target_file:
            with open(args.target_file, "r") as f:
                targets = [l.strip() for l in f if l.strip()]
            if targets:
                target = targets[0]
            else:
                logger.error("No targets found in target file")
                sys.exit(1)

        session = Session(target, SessionMode(args.mode))

    logger.success(f"Session: {session.meta.session_id}")

    # ── Progress mode ─────────────────────────────────────────

    if args.progress:
        from interface.progress import show_progress
        show_progress(session, logger, live=True)
        return

    # ── Run workflow ──────────────────────────────────────────

    if args.workflow or args.playbook:
        if args.playbook:
            from core.mission import run_mission
            result = run_mission(session, args.playbook, logger)
        else:
            result = run_orchestrator(session, logger, {"depth": args.depth}, resume=args.resume)

        if args.report:
            generate_report(session, logger, open_browser=args.open)
        return

    # ── Run specific recon modules ───────────────────────────

    recon_ran = False

    if any([
        args.domain, args.subdomain, args.web, args.cdn,
        args.cloud, args.social, args.cache, args.vuln_intel,
        args.network_scan, args.web_deep, args.database,
        args.service, args.cloud_deep, args.vpn,
        args.auth, args.dev, args.lateral
    ]):
        recon_ran = True

        if args.domain:
            recon = DomainRecon(session, logger)
            recon.run(session.meta.target)

        if args.subdomain:
            recon = SubdomainRecon(session, logger)
            recon.run(session.meta.target)

        if args.web:
            recon = WebRecon(session, logger)
            recon.run(session.meta.target)

        if args.cdn:
            recon = CDNRecon(session, logger)
            recon.run(session.meta.target)

        if args.cloud:
            recon = CloudRecon(session, logger)
            recon.run(session.meta.target)

        if args.social:
            recon = SocialRecon(session, logger)
            recon.run(session.meta.target)

        if args.cache:
            recon = CacheRecon(session, logger)
            recon.run(session.meta.target)

        if args.vuln_intel:
            recon = VulnIntelRecon(session, logger)
            recon.run(session.meta.target)

        if args.network_scan:
            recon = NetworkRecon(session, logger)
            recon.run(session.meta.target)

        if args.web_deep:
            recon = WebDeepRecon(session, logger)
            recon.run(session.meta.target)

        if args.database:
            recon = DatabaseRecon(session, logger)
            recon.run(session.meta.target)

        if args.service:
            recon = ServiceRecon(session, logger)
            recon.run(session.meta.target)

        if args.cloud_deep:
            recon = CloudDeepRecon(session, logger)
            recon.run(session.meta.target)

        if args.vpn:
            recon = VPNRecon(session, logger)
            recon.run(session.meta.target)

        if args.auth:
            recon = AuthRecon(session, logger)
            recon.run(session.meta.target)

        if args.dev:
            recon = DevRecon(session, logger)
            recon.run(session.meta.target)

        if args.lateral:
            recon = LateralRecon(session, logger)
            recon.run(session.meta.target)

    # ── Run specific validation modules ──────────────────────

    validate_ran = False

    if any([
        args.sqli, args.nosqli, args.ldap, args.cmdi,
        args.code, args.xxe, args.xpath, args.path_traversal,
        args.bruteforce, args.session_test, args.jwt,
        args.oauth, args.mfa, args.validate_all
    ]):
        validate_ran = True

        if args.validate_all or args.sqli:
            validator = SQLiValidator(session, logger)
            validator.run(session.meta.target)

        if args.validate_all or args.nosqli:
            validator = NoSQLiValidator(session, logger)
            validator.run(session.meta.target)

        if args.validate_all or args.ldap:
            validator = LDAPValidator(session, logger)
            validator.run(session.meta.target)

        if args.validate_all or args.cmdi:
            validator = CMDIValidator(session, logger)
            validator.run(session.meta.target)

        if args.validate_all or args.code:
            validator = CodeValidator(session, logger)
            validator.run(session.meta.target)

        if args.validate_all or args.xxe:
            validator = XXEValidator(session, logger)
            validator.run(session.meta.target)

        if args.validate_all or args.xpath:
            validator = XPathValidator(session, logger)
            validator.run(session.meta.target)

        if args.validate_all or args.path_traversal:
            validator = PathTraversalValidator(session, logger)
            validator.run(session.meta.target)

        if args.validate_all or args.bruteforce:
            validator = AuthValidator(session, logger)
            validator.run(session.meta.target)

        if args.validate_all or args.session_test:
            validator = SessionValidator(session, logger)
            validator.run(session.meta.target)

        if args.validate_all or args.jwt:
            validator = JWTValidator(session, logger)
            validator.run(session.meta.target)

        if args.validate_all or args.oauth:
            validator = OAuthValidator(session, logger)
            validator.run(session.meta.target)

        if args.validate_all or args.mfa:
            validator = MFAValidator(session, logger)
            validator.run(session.meta.target)

    # ── Run specific tools ────────────────────────────────────

    tool_ran = False

    if any([args.sqlmap, args.hydra, args.nmap, args.tool]):
        tool_ran = True
        target = session.meta.target

        if args.sqlmap or args.tool == "sqlmap":
            wrapper = SQLMapWrapper(session, logger)
            wrapper.run(target)

        if args.hydra or args.tool == "hydra":
            wrapper = HydraWrapper(session, logger)
            wrapper.run(target)

        if args.nmap or args.tool == "nmap":
            wrapper = NmapWrapper(session, logger)
            wrapper.run(target, depth=args.stealth)

    # ── Run full reconnaissance ──────────────────────────────

    if not any([recon_ran, validate_ran, tool_ran, args.workflow, args.playbook]):
        # Run standard recon
        depth = args.depth
        logger.info(f"Running {depth} reconnaissance on {session.meta.target}")

        run_recon(session.meta.target, depth, session, logger)

        # Run intelligence if not passive
        if depth != "passive":
            run_intel(session, logger)

            # Run bypass if Cloudflare detected
            recon_path = session.dir("recon") / f"recon_{depth}_summary.json"
            if recon_path.exists():
                try:
                    data = json.loads(recon_path.read_text())
                    if data.get("cloudflare", {}).get("detected", False):
                        logger.info("Cloudflare detected, running bypass...")
                        run_bypass(session.meta.target, session, logger)
                except Exception:
                    pass

            # Run exploit analysis
            run_exploit(session, logger, mode="full")

    # ── Generate report ──────────────────────────────────────

    if args.report:
        generate_report(session, logger, open_browser=args.open)

    logger.success(f"Session complete: {session.meta.session_id}")
    logger.info(f"Findings: {session.meta.findings_count}")
    logger.info(f"Risk Score: {session.meta.risk_score:.0f}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\033[33mInterrupted by user\033[0m")
        sys.exit(0)
    except Exception as e:
        print(f"\033[31mError: {e}\033[0m")
        import traceback
        traceback.print_exc()
        sys.exit(1)