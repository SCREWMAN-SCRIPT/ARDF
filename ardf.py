"""
ardf.py
────────
ARDF — Autonomous Red/Blue Defense Framework
Main entry point and CLI.

Usage
─────
  python ardf.py --target example.com --mode red
  python ardf.py --target example.com --playbook full
  python ardf.py --target example.com --objective "passive recon only"
  python ardf.py --chat
  python ardf.py --sessions
  python ardf.py --report --session 20240601_abc123
"""

import sys
import argparse
from pathlib import Path
from typing  import Optional

# ── Ensure project root is on path ───────────────────────────
sys.path.insert(0, str(Path(__file__).parent))


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog        = "ardf",
        description = "ARDF — Autonomous Red/Blue Defense Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ardf.py --target example.com --mode red
  python ardf.py --target example.com --playbook full
  python ardf.py --target example.com --playbook passive
  python ardf.py --target example.com --objective "enumerate subdomains passively"
  python ardf.py --chat
  python ardf.py --sessions
  python ardf.py --report --session 20240601_abc123
  python ardf.py --monitor --session 20240601_abc123
        """,
    )

    # ── Target / session ──────────────────────────────────────
    p.add_argument("--target",    "-t", help="Target hostname or IP address")
    p.add_argument("--session",   "-s", help="Resume existing session by ID")
    p.add_argument("--name",            help="Session name label")

    # ── Execution mode ────────────────────────────────────────
    p.add_argument(
        "--mode", "-m",
        choices=["red", "blue", "purple", "full", "osint"],
        default="full",
        help="Operation mode (default: full)",
    )

    # ── Objective / playbook ──────────────────────────────────
    p.add_argument(
        "--objective", "-o",
        help="Natural language mission objective",
    )
    p.add_argument(
        "--playbook", "-p",
        help="Playbook name or path (full / passive / web / purple)",
    )

    # ── Recon depth ───────────────────────────────────────────
    p.add_argument(
        "--depth", "-d",
        choices=["passive", "normal", "depth"],
        default="passive",
        help="Recon depth (default: passive)",
    )

    # ── Interface modes ───────────────────────────────────────
    p.add_argument("--chat",      action="store_true", help="Start interactive chat interface")
    p.add_argument("--sessions",  action="store_true", help="List all sessions and exit")
    p.add_argument("--report",    action="store_true", help="Generate report for a session")
    p.add_argument("--monitor",   action="store_true", help="Run blue team monitors on session")
    p.add_argument("--intel",     action="store_true", help="Run intel enrichment on session")
    p.add_argument("--harden",    action="store_true", help="Generate hardening report")
    p.add_argument("--sigma",     action="store_true", help="Generate Sigma rules from findings")
    p.add_argument("--coverage",  action="store_true", help="Generate MITRE coverage map")

    # ── Execution options ─────────────────────────────────────
    p.add_argument(
        "--auto-approve",
        action="store_true",
        help="Auto-approve all confirmation gates (authorised automated testing only)",
    )
    p.add_argument(
        "--non-interactive",
        action="store_true",
        help="Non-interactive mode — decline all gates not pre-approved",
    )
    p.add_argument(
        "--open-browser",
        action="store_true",
        help="Open report in browser after generation",
    )
    p.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress console output",
    )

    return p.parse_args()


def main():
    args = _parse_args()

    # ── Bootstrap logging ─────────────────────────────────────
    from modules.logger import setup_logging, get_logger
    setup_logging(
        log_dir    = "logs",
        session_id = args.session or "ardf_startup",
        quiet      = args.quiet,
    )
    logger = get_logger("main")

    # ── Banner ────────────────────────────────────────────────
    from interface.banner import print_banner
    if not args.quiet:
        print_banner(mode=args.mode)

    # ── Session listing ───────────────────────────────────────
    if args.sessions:
        from modules.session import get_manager
        get_manager().print_sessions()
        return

    # ── Session acquisition ───────────────────────────────────
    session = None

    if args.session:
        # Resume existing session
        from modules.session import resume_session
        try:
            session = resume_session(args.session)
            logger.success(f"Resumed session: {session.meta.session_id}")
        except FileNotFoundError:
            logger.error(f"Session not found: {args.session}")
            sys.exit(1)

    elif args.target:
        # Create new session
        from modules.session import new_session, Mode
        try:
            mode    = Mode(args.mode if args.mode != "osint" else "red")
        except ValueError:
            mode    = Mode.FULL
        session = new_session(
            target = args.target,
            mode   = mode,
            name   = args.name,
        )
        # Re-initialise logging with session ID
        from modules.logger import reset_logging
        reset_logging()
        setup_logging(
            log_dir    = str(session.dir("logs")),
            session_id = session.meta.session_id,
            quiet      = args.quiet,
        )
        logger = get_logger("main")
        logger.success(f"Session created: {session.meta.session_id}")

    # ── Chat interface ────────────────────────────────────────
    if args.chat:
        from interface.chat import ChatInterface
        from core.orchestrator import Orchestrator
        from ai.planner        import MissionPlanner

        def on_objective(objective: str, sess):
            orch    = Orchestrator(
                session         = sess,
                logger          = logger,
                auto_approve    = args.auto_approve,
                non_interactive = args.non_interactive,
            )
            planner = MissionPlanner(session=sess, logger=logger)
            plan    = planner.plan(objective)
            from core.mission import Mission
            mission = Mission(session=sess, objective=objective, mode=args.mode)
            mission.set_plan(plan)
            summary = orch.run(mission)
            from interface.banner import print_summary
            print_summary(summary)

        chat = ChatInterface(
            session      = session,
            logger       = logger,
            on_objective = on_objective,
        )
        chat.run()
        return

    # ── Require session for remaining commands ─────────────────
    if session is None:
        print(
            "ERROR: Specify --target or --session, or use --chat.\n"
            "       Run with --help for usage."
        )
        sys.exit(1)

    # ── Single-module commands ────────────────────────────────

    if args.report:
        from modules.report import generate_report
        path = generate_report(
            session      = session,
            logger       = logger,
            open_browser = args.open_browser,
        )
        print(f"Report: {path}")
        return

    if args.intel:
        from modules.intel import run_intel
        run_intel(session=session, logger=logger)
        return

    if args.monitor:
        from modules.defense.monitor import SecurityMonitor
        mon = SecurityMonitor(session=session, logger=logger)
        mon.run_all()
        return

    if args.harden:
        from modules.defense.hardening import HardeningEngine
        eng = HardeningEngine(session=session, logger=logger)
        report = eng.generate_hardening_report()
        print(f"Hardening scripts: {session.dir('report') / 'hardening'}")
        return

    if args.sigma:
        from modules.defense.sigma_writer import SigmaWriter
        writer = SigmaWriter(session=session, logger=logger)
        rules  = writer.generate_all()
        paths  = writer.save_rules(rules)
        print(f"Sigma rules: {len(paths)} files saved")
        return

    if args.coverage:
        from modules.purple.coverage_mapper import CoverageMapper
        mapper = CoverageMapper(session=session, logger=logger)
        result = mapper.map_coverage()
        print(
            f"Coverage: {result['coverage_pct']}% "
            f"({result['observed_count']} techniques observed, "
            f"{result['gap_count']} gaps)"
        )
        return

    # ── Playbook execution ────────────────────────────────────
    if args.playbook:
        from playbook.executor import PlaybookExecutor
        from core.orchestrator import Orchestrator
        from core.mission      import Mission
        from interface.progress import ProgressDisplay

        executor = PlaybookExecutor(session=session, logger=logger)
        plan     = executor.load_and_build(args.playbook)

        if not plan:
            logger.error(f"Failed to load playbook: {args.playbook}")
            sys.exit(1)

        orch    = Orchestrator(
            session         = session,
            logger          = logger,
            auto_approve    = args.auto_approve,
            non_interactive = args.non_interactive,
        )
        progress = ProgressDisplay()
        orch.set_progress_callback(progress.on_event)

        mission = Mission(
            session   = session,
            objective = plan.get("objective", f"{args.playbook} playbook"),
            mode      = plan.get("playbook_mode", args.mode),
            logger    = logger,
        )
        mission.set_plan(plan)
        progress.print_task_header(len(plan.get("tasks", [])), session.meta.target)

        summary = orch.run(mission)

        # Auto-generate report after playbook completes
        from modules.report import generate_report
        report_path = generate_report(
            session      = session,
            logger       = logger,
            open_browser = args.open_browser,
            purple_mode  = plan.get("playbook_mode") == "purple",
        )

        from interface.banner import print_summary
        print_summary(summary)
        print(f"\nReport: {report_path}")
        return

    # ── Objective-driven mission ──────────────────────────────
    if args.objective:
        from ai.planner        import MissionPlanner
        from core.orchestrator import Orchestrator
        from core.mission      import Mission
        from interface.progress import ProgressDisplay

        planner = MissionPlanner(session=session, logger=logger)
        plan    = planner.plan(args.objective, mode=args.mode)

        orch     = Orchestrator(
            session         = session,
            logger          = logger,
            auto_approve    = args.auto_approve,
            non_interactive = args.non_interactive,
        )
        progress = ProgressDisplay()
        orch.set_progress_callback(progress.on_event)

        mission = Mission(
            session   = session,
            objective = args.objective,
            mode      = args.mode,
            logger    = logger,
        )
        mission.set_plan(plan)
        progress.print_task_header(len(plan.get("tasks", [])), session.meta.target)

        summary = orch.run(mission)

        from modules.report import generate_report
        report_path = generate_report(session=session, logger=logger)

        from interface.banner import print_summary
        print_summary(summary)
        print(f"\nReport: {report_path}")
        return

    # ── Default — passive recon only ──────────────────────────
    logger.info(f"No objective specified — running passive recon on {session.meta.target}")
    from modules.recon  import run_recon
    from modules.report import generate_report

    run_recon(
        target  = session.meta.target,
        depth   = args.depth,
        session = session,
        logger  = logger,
    )
    path = generate_report(
        session      = session,
        logger       = logger,
        open_browser = args.open_browser,
    )
    print(f"\nReport: {path}")


if __name__ == "__main__":
    main()
