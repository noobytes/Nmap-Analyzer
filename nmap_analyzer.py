import argparse
import logging
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pentest_assistant.pipeline import AnalysisConfig, analyze_scan
from pentest_assistant.providers import (
    DEFAULT_MODELS,
    create_stage_providers,
    get_missing_stage_models,
    get_model_for_stage,
    resolve_models,
)
from pentest_assistant.reporting import build_text_report, generate_html_report
from update_cve_db import UpdateConfig as CVEUpdateConfig
from update_cve_db import update_cve_database

AI_PROVIDERS = ["ollama"]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Nmap Analyzer — turn nmap XML into actionable pentest reports with AI attack plans, CVE matching, risk scoring, and enumeration playbooks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "reports are saved to reports/<project>_<timestamp>/ by default\n\n"
            "examples:\n"
            "  %(prog)s scan.xml -C acme                              Analyze with project name\n"
            "  %(prog)s scan.xml                                      Analyze (playbooks only)\n"
            "  %(prog)s scan.xml --ai -C acme                         Playbooks + AI (Ollama)\n"
            "  %(prog)s scan.xml --ai --profile external -C acme      External pentest profile\n"
            "  %(prog)s scan.xml --ai --profile internal -C acme      Internal pentest profile\n"
            "  %(prog)s fast.xml full.xml -C acme --ai                Merge multiple scan files\n"
            "  %(prog)s --cve-db-update                               Build/update CVE database\n\n"
            "AI provider env vars:\n"
            "  ollama    OLLAMA_HOST (default: http://127.0.0.1:11434)"
        ),
    )
    parser.add_argument("scan", nargs="*", help="One or more Nmap XML files to analyze (multiple files are merged by IP)")
    parser.add_argument("-C", "--project", default=None, help="Project name (used as report subfolder name)")

    # --- AI options ---
    ai_group = parser.add_argument_group("AI options")
    ai_group.add_argument(
        "--ai", nargs="?", const="ollama", default=None,
        choices=AI_PROVIDERS, metavar="PROVIDER",
        help="Enable AI suggestions using local Ollama (default: ollama)",
    )
    ai_group.add_argument(
        "--preset",
        choices=["quick", "deep"],
        default="",
        help="Select a stage-routing model preset. No preset keeps current default behavior unchanged.",
    )
    ai_group.add_argument(
        "--profile", choices=["external", "internal"], default=None,
        help=(
            "Engagement profile for AI attack plan analysis. "
            "'external' — internet-facing targets, initial access focus. "
            "'internal' — inside the network, lateral movement and AD focus. "
            "Requires --ai."
        ),
    )
    ai_group.add_argument(
        "--model", "--ai-model",
        dest="ai_model",
        default="",
        help="Override the primary AI model name. --ai-model is kept as a compatibility alias.",
    )
    ai_group.add_argument(
        "--review-model",
        default="",
        help="Override the review model used for result-review stages.",
    )
    ai_group.add_argument("--ai-key", default=None, help="API key for AI provider (or use env vars)")
    ai_group.add_argument("--ai-timeout", type=float, default=10.0, help="Ollama connection timeout in seconds (default: 10). Generation itself has no timeout — the model runs until done.")
    ai_group.add_argument("--max-ai-commands", type=int, default=8, help="Max AI commands per service (default: 8)")

    # --- CVE database update ---
    cve_group = parser.add_argument_group("CVE database update")
    cve_group.add_argument("--cve-db-update", action="store_true", help="Build/update local CVE database from NVD API")
    cve_group.add_argument("--cve-rebuild", action="store_true", help="Drop and rebuild CVE tables before importing")
    cve_group.add_argument("--cve-update-mode", choices=("auto", "full", "incremental"), default="auto", help="Update mode: auto (default), full, or incremental")
    cve_group.add_argument("--cve-force-download", action="store_true", help="Incremental: ignore last-update timestamp and re-fetch the full window")
    cve_group.add_argument("--nvd-api-key", default="", help="NVD API key for ~10x faster downloads. Free at nvd.nist.gov/developers/request-an-api-key. Can also set NVD_API_KEY env var.")
    cve_group.add_argument("--min-cvss", type=float, default=0.0, help="Only store CVEs with CVSS >= this value (default: 0.0 = all)")
    cve_group.add_argument("--cve-start-year", type=int, default=2018, help=argparse.SUPPRESS)
    cve_group.add_argument("--cve-end-year", type=int, default=datetime.now(UTC).year, help=argparse.SUPPRESS)
    # Legacy flags — accepted but unused
    cve_group.add_argument("--cve-offline", action="store_true", help=argparse.SUPPRESS)
    cve_group.add_argument("--cve-feed-dir", default="data/nvd_feeds", help=argparse.SUPPRESS)

    # --- Execution options ---
    exec_group = parser.add_argument_group("execution")
    exec_group.add_argument(
        "--execute", action="store_true",
        help="Execute safe enumeration commands against scan targets (requires confirmation)",
    )
    exec_group.add_argument(
        "--exec-timeout", type=float, default=60.0,
        help="Timeout per command in seconds (default: 60)",
    )
    exec_group.add_argument(
        "--max-exec-commands", type=int, default=30,
        help="Max commands to execute automatically (default: 30)",
    )
    exec_group.add_argument(
        "--workflow", choices=["iterative", "legacy"], default=None,
        help=(
            "Execution workflow. Defaults to iterative when both --ai and --execute are enabled; "
            "otherwise defaults to legacy."
        ),
    )
    exec_group.add_argument(
        "--iterative-batch-size", type=int, default=1,
        help="Max approved validation commands per iterative loop (default: 1, max: 3)",
    )
    exec_group.add_argument(
        "--host-batch-size", type=int, default=5,
        help="Max concurrent hosts per SSH batch (default: 5). Limits tmux windows opened per iteration.",
    )
    exec_group.add_argument(
        "--min-action-value", type=float, default=0.0,
        help="Skip candidates scored below this expected_value (0-10, default: 0 = disabled).",
    )
    exec_group.add_argument(
        "--max-noise-streak", type=int, default=6,
        help="Stop loop early after N consecutive noise/inconclusive results "
             "(default: 6; auto-set to 10 for --profile internal, 4 for --profile external).",
    )
    exec_group.add_argument(
        "--no-confirm", action="store_true",
        help="Skip confirmation prompt before executing commands",
    )
    exec_group.add_argument(
        "--case-state", default="",
        help="Path to save or resume iterative workflow state (default: report_dir/case_state.json)",
    )
    exec_group.add_argument(
        "--remote-host", default="", metavar="USER@HOST",
        help="Execute commands on a remote host via SSH (e.g. kali@192.168.1.100)",
    )
    exec_group.add_argument(
        "--remote-key", default="", metavar="PATH",
        help="Path to SSH private key for remote host (default: uses SSH agent / default key)",
    )
    exec_group.add_argument(
        "--remote-port", type=int, default=22,
        help="SSH port for remote host (default: 22)",
    )

    # --- Output options ---
    output_group = parser.add_argument_group("output options")
    output_group.add_argument("--playbooks", default="data/enumeration_playbooks.json", help="Path to playbooks JSON file (default: data/enumeration_playbooks.json)")
    output_group.add_argument("--wordlist", default="", metavar="PATH", help="Wordlist for web content fuzzing tools (ffuf, feroxbuster, etc.). Defaults to common.txt")
    output_group.add_argument("--db", default="data/cve_database.db", help=argparse.SUPPRESS)
    output_group.add_argument(
        "--regenerate-report", metavar="REPORT_DIR",
        help="Regenerate report.html from an existing report folder without re-running any scans or AI calls (e.g. --regenerate-report reports/myproject_20260428_221239)",
    )
    output_group.add_argument(
        "--screenshot", action="store_true",
        help="Capture web screenshots with gowitness after analysis. Requires gowitness on the scanning host (remote when --remote-host is set, otherwise local).",
    )

    # --- Logging / debug ---
    log_group = parser.add_argument_group("logging")
    log_group.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"], help="Logging verbosity (default: INFO)")
    log_group.add_argument("--debug", action="store_true", help="Shortcut for --log-level DEBUG")
    return parser


def _print_execution_plan(plan: Any, remote_host: str = "") -> None:
    """Print the execution plan to terminal for user review."""
    print("\n" + "=" * 60)
    print("EXECUTION PLAN")
    print("=" * 60)
    mode = f"remote ({remote_host})" if remote_host else "local"
    print(f"Execution mode: {mode}")

    if plan.commands:
        print(f"\nCommands to execute ({len(plan.commands)}):\n")
        for i, cmd in enumerate(plan.commands, 1):
            print(f"  [{i:02d}] [{cmd.tool}] {cmd.command}")
    else:
        print("\n  No executable commands found.")

    if plan.manual_suggestions:
        print(f"\nManual suggestions — run these yourself ({len(plan.manual_suggestions)}):\n")
        for cmd in plan.manual_suggestions:
            print(f"  $ {cmd}")
    print()


def _confirm_execution() -> bool:
    """Ask user to confirm before executing commands."""
    try:
        answer = input("Proceed with execution? [y/N]: ").strip().lower()
        return answer in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        print("\nAborted.")
        return False


def _preflight_scan(scan_paths: list[str], playbook_path: str, cve_db_path: str) -> tuple[list[str], list[str]]:
    """Check file prerequisites. Returns (errors, warnings)."""
    errors: list[str] = []
    warnings: list[str] = []

    for scan_path in scan_paths:
        if not Path(scan_path).exists():
            errors.append(f"Nmap XML not found: {scan_path}")
    if not Path(playbook_path).exists():
        errors.append(f"Playbook file not found: {playbook_path}")
    if not Path(cve_db_path).exists():
        warnings.append(
            f"CVE database not found at {cve_db_path}. Vulnerability hints will be unavailable."
        )
    return errors, warnings


def _preflight_ai(
    provider_name: str,
    resolved_models: dict[str, Any],
    strict_routing: bool,
    api_key: str | None,
) -> tuple[bool, list[str], list[str]]:
    """Validate AI provider availability. Returns (ok, warnings, errors)."""
    warnings: list[str] = []
    errors: list[str] = []

    if provider_name == "ollama":
        try:
            missing_models = get_missing_stage_models(provider_name, resolved_models)
            if missing_models:
                if strict_routing:
                    for stage, model in missing_models:
                        errors.append(
                            f"Missing Ollama model '{model}' for stage '{stage}'. "
                            f"Pull it with: ollama pull {model}"
                        )
                    return False, warnings, errors

                resolved_model = get_model_for_stage("network_overview", resolved_models) or DEFAULT_MODELS["ollama"]
                warnings.append(f"Ollama model '{resolved_model}' not found locally. AI disabled.")
                return False, warnings, errors
        except Exception as exc:
            message = f"Ollama unavailable ({exc})."
            if strict_routing:
                errors.append(message)
                return False, warnings, errors
            warnings.append(message + " AI disabled.")
            return False, warnings, errors

    return True, warnings, errors


_NOISE_STREAK_BY_PROFILE: dict[str, int] = {
    "internal": 10,
    "external": 4,
}
_NOISE_STREAK_DEFAULT = 6  # used when no profile is selected


def _resolve_noise_streak(args: "argparse.Namespace") -> int:
    """Return the effective max_noise_streak for this run.

    Priority order:
    1. Explicit --max-noise-streak on the CLI (user override always wins)
    2. Profile-based default (internal=10, external=4)
    3. Global default (6)
    """
    # argparse sets the value to the default when the flag is absent.
    # We detect an explicit user override by comparing against the argparse default.
    user_set = args.max_noise_streak != _NOISE_STREAK_DEFAULT
    if user_set:
        return args.max_noise_streak

    profile = (args.profile or "").lower().strip()
    return _NOISE_STREAK_BY_PROFILE.get(profile, _NOISE_STREAK_DEFAULT)


def _regenerate_report(report_dir: Path) -> int:
    """Rebuild report.html from an existing report folder — no scans, no AI calls."""
    import json as _json
    import re as _re

    from pentest_assistant.models import (
        AnalysisResult, CommandResult, CommandSuggestion, Host, Service,
        ServiceFinding,
    )
    from pentest_assistant.state import CaseState

    if not report_dir.is_dir():
        print(f"Error: report directory not found: {report_dir}", file=sys.stderr)
        return 1

    cs_path = report_dir / "case_state.json"
    if not cs_path.exists():
        print(f"Error: case_state.json not found in {report_dir}", file=sys.stderr)
        return 1

    print(f"Regenerating report from: {report_dir}")

    # ── Load case state ────────────────────────────────────────────────────
    case_state = CaseState.from_dict(_json.loads(cs_path.read_text(encoding="utf-8")))

    # ── Reconstruct Hosts ──────────────────────────────────────────────────
    hosts: list[Any] = []
    role_groups: dict[str, list[str]] = {}
    for h in case_state.hosts_summary.get("hosts", []):
        ip, role = h.get("ip", ""), h.get("role", "Unknown")
        svcs = [Service(port=0, protocol="tcp", name=s) for s in h.get("services", [])]
        hosts.append(Host(ip=ip, role=role, hostname=h.get("hostname", ""), services=svcs))
        role_groups.setdefault(role, []).append(ip)

    # ── Reconstruct ServiceFindings ────────────────────────────────────────
    findings: list[Any] = []
    for sid, ss in case_state.service_states.items():
        parts = sid.split("|")
        proto   = parts[0] if len(parts) > 0 else "tcp"
        port_s  = parts[1] if len(parts) > 1 else "0"
        name    = parts[2] if len(parts) > 2 else sid
        port    = int(port_s) if port_s.isdigit() else 0
        svc = Service(port=port, protocol=proto, name=name)
        findings.append(ServiceFinding(
            service=svc, ips=list(ss.affected_hosts),
            cves=[], playbook_commands=[], ai_commands=[],
            playbook_confidence=0.0, ai_confidence=0.0,
            command_suggestions=[
                CommandSuggestion(
                    command=v.command_template,
                    source=v.source or "state",
                    confidence=v.confidence,
                )
                for v in ss.recommended_validations if v.command_template
            ],
            risk_score=0.0,
        ))

    # ── Load execution results from enumeration files ──────────────────────
    _CMD  = _re.compile(r"^Command\s*:\s*(.+)$", _re.MULTILINE)
    _IP   = _re.compile(r"^Target\s*:\s*(.+)$",  _re.MULTILINE)
    _SVC  = _re.compile(r"^Service\s*:\s*(.+)$", _re.MULTILINE)
    _DUR  = _re.compile(r"^Duration\s*:\s*([\d.]+)", _re.MULTILINE)
    _STAT = _re.compile(r"^Status\s*:\s*(.+)$",  _re.MULTILINE)
    _OUT  = _re.compile(r"=== OUTPUT ===\s*\n(.*?)(?:=== STDERR ===|\Z)", _re.DOTALL)
    _ERR  = _re.compile(r"=== STDERR ===\s*\n(.*?)$", _re.DOTALL)

    def _g(m: Any, n: int = 1) -> str:
        return m.group(n).strip() if m else ""

    execution_results: list[Any] = []
    enum_dir = report_dir / "enumeration"
    if enum_dir.is_dir():
        for f in sorted(enum_dir.glob("**/*.txt"), key=lambda x: x.name):
            try:
                raw = f.read_text(encoding="utf-8", errors="replace")
                cmd = _g(_CMD.search(raw))
                if not cmd:
                    continue
                stat = _g(_STAT.search(raw))
                timed_out = "timed out" in stat.lower()
                rc_m = _re.search(r"exit\s+(-?\d+)", stat)
                rc = int(rc_m.group(1)) if rc_m else (1 if timed_out else 0)
                execution_results.append(CommandResult(
                    command=cmd,
                    service_label=_g(_SVC.search(raw)),
                    target_ip=_g(_IP.search(raw)),
                    tool=cmd.split()[0] if cmd else "",
                    stdout=_g(_OUT.search(raw)),
                    stderr=_g(_ERR.search(raw)),
                    return_code=rc,
                    duration=float(_g(_DUR.search(raw)) or "0"),
                    timed_out=timed_out,
                ))
            except Exception as exc:
                logging.getLogger(__name__).debug("Skip %s: %s", f.name, exc)

    print(f"  Loaded {len(execution_results)} execution results from enumeration/")

    def _read(p: Path) -> str:
        return p.read_text(encoding="utf-8").strip() if p.exists() else ""

    result = AnalysisResult(
        hosts=hosts,
        role_groups=role_groups,
        findings=findings,
        ai_enabled=True,
        workflow="iterative",
        execution_results=execution_results,
        live_findings=_read(report_dir / "live_findings.txt"),
        ai_analysis=_read(report_dir / "ai_report.txt"),
        case_state=case_state,
        manual_suggestions=[],
    )

    out_path = report_dir / "report.html"
    generate_html_report(result, out_path, scan_path="")
    print(f"  report.html regenerated → {out_path}")
    print(f"  {len(hosts)} hosts | {len(findings)} service groups | {len(execution_results)} commands")
    return 0


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    if not args.scan and not args.cve_db_update and not args.regenerate_report:
        parser.error("scan is required unless --cve-db-update or --regenerate-report is used")

    log_level = "DEBUG" if args.debug else args.log_level

    # Always write a full DEBUG log to logs/run_<timestamp>.log
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    run_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"run_{run_timestamp}.log"

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    # File handler — always DEBUG, full format with timestamps
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)-8s %(name)s: %(message)s",
                          datefmt="%Y-%m-%d %H:%M:%S")
    )
    root_logger.addHandler(file_handler)

    # Console handler — respects --log-level, minimal format
    console_handler = logging.StreamHandler()
    console_handler.setLevel(getattr(logging, log_level))
    console_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    root_logger.addHandler(console_handler)

    logging.getLogger(__name__).info("Log file: %s", log_file)

    if args.cve_db_update:
        db_path = Path(args.db)
        resolved_mode = args.cve_update_mode
        if resolved_mode == "auto":
            resolved_mode = "full" if not db_path.exists() else "incremental"

        update_config = CVEUpdateConfig(
            db_path=db_path,
            download_dir=Path(args.cve_feed_dir),
            mode=resolved_mode,
            start_year=args.cve_start_year,
            end_year=args.cve_end_year,
            force_download=args.cve_force_download,
            offline=args.cve_offline,
            rebuild=args.cve_rebuild,
            batch_size=5000,
            explicit_feeds=[],
            api_key=args.nvd_api_key,
            min_cvss=args.min_cvss,
        )
        try:
            update_cve_database(update_config)
        except Exception as exc:
            print(f"Error: CVE update failed: {exc}", file=sys.stderr)
            return 1
        if not args.scan:
            return 0

    # --regenerate-report: rebuild report.html from an existing report folder
    if args.regenerate_report:
        return _regenerate_report(Path(args.regenerate_report))

    # Preflight checks
    preflight_errors, preflight_warnings = _preflight_scan(
        scan_paths=args.scan,
        playbook_path=args.playbooks,
        cve_db_path=args.db,
    )

    if args.profile and not args.ai:
        parser.error("--profile requires --ai (e.g. --ai --profile external)")

    ai_provider = args.ai  # None if not set, "ollama" if set
    resolved_models = resolve_models(cli_args=args)
    if ai_provider:
        strict_routing = bool(args.preset or args.ai_model or args.review_model)
        ai_ok, ai_warnings, ai_errors = _preflight_ai(
            ai_provider,
            resolved_models,
            strict_routing=strict_routing,
            api_key=args.ai_key,
        )
        preflight_warnings.extend(ai_warnings)
        if ai_errors:
            for error in ai_errors:
                print(f"Error: {error}", file=sys.stderr)
            return 1
        if not ai_ok:
            ai_provider = None

    for warning in preflight_warnings:
        print(f"Warning: {warning}", file=sys.stderr)
    if preflight_errors:
        for error in preflight_errors:
            print(f"Error: {error}", file=sys.stderr)
        return 1

    if ai_provider:
        overview_model = get_model_for_stage("network_overview", resolved_models) or DEFAULT_MODELS.get(ai_provider, "")
        profile_model = get_model_for_stage("profile_analysis", resolved_models) or overview_model
        command_model = get_model_for_stage("command_generation", resolved_models) or overview_model
        iterative_model = get_model_for_stage("iterative_ranking", resolved_models) or overview_model
        result_review_model = get_model_for_stage("result_review", resolved_models)
        profile_note = f", profile: {args.profile}" if args.profile else ""
        if args.preset or args.ai_model or args.review_model:
            print(
                "AI enabled: "
                f"{ai_provider} (network_overview: {overview_model}, "
                f"profile_analysis: {profile_model}, "
                f"command_generation: {command_model}, "
                f"iterative_ranking: {iterative_model}, "
                f"result_review: {result_review_model or iterative_model}{profile_note})",
                file=sys.stderr,
            )
        else:
            print(f"AI enabled: {ai_provider} (model: {overview_model}{profile_note})", file=sys.stderr)

    if args.execute and not ai_provider:
        print("Warning: --execute works best with --ai for live findings synthesis.", file=sys.stderr)

    resolved_workflow = args.workflow
    if resolved_workflow is None:
        resolved_workflow = "iterative" if (args.execute and ai_provider) else "legacy"

    timestamp = run_timestamp
    if args.project:
        safe_name = re.sub(r"[^A-Za-z0-9_-]", "_", args.project).strip("_")
        folder_name = f"{safe_name}_{timestamp}"
    else:
        folder_name = timestamp
    report_dir = Path("reports") / folder_name
    report_dir.mkdir(parents=True, exist_ok=True)
    case_state_path = Path(args.case_state) if args.case_state else (report_dir / "case_state.json")

    config = AnalysisConfig(
        cve_db_path=args.db,
        playbook_path=args.playbooks,
        ai_provider=ai_provider,
        ai_model=args.ai_model,
        review_model=args.review_model,
        preset=args.preset,
        ai_key=args.ai_key or "",
        ai_timeout_seconds=max(1.0, args.ai_timeout),
        max_ai_commands=max(0, args.max_ai_commands),
        profile=args.profile,
        execute=args.execute,
        max_exec_commands=max(1, args.max_exec_commands),
        workflow=resolved_workflow,
        iterative_batch_size=max(1, min(args.iterative_batch_size, 3)),
        host_batch_size=max(1, args.host_batch_size),
        min_action_value=max(0.0, args.min_action_value),
        max_noise_streak=max(0, _resolve_noise_streak(args)),
        case_state_path=str(case_state_path),
        resolved_models=resolved_models,
        wordlist=args.wordlist,
    )

    try:
        result = analyze_scan(args.scan if len(args.scan) > 1 else args.scan[0], config)
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 1

    text_report = build_text_report(result)
    print(text_report)

    # --- Execution phase ---
    if args.execute and result.execution_plan:
        plan = result.execution_plan
        _print_execution_plan(plan, remote_host=args.remote_host)

        should_run = bool(plan.commands) and (args.no_confirm or _confirm_execution())
        if should_run:
            from pentest_assistant.executor import (
                ExecutionEngine, SSHConfig, SSHMaster,
                check_tools_available, check_sudo_passwordless,
            )
            from pentest_assistant.ai import ScanAnalyzer
            from pentest_assistant.analysis_loop import run_iterative_analysis_loop

            ssh_config = None
            ssh_master_for_preflight: Any = None
            if args.remote_host:
                ssh_config = SSHConfig(
                    host=args.remote_host,
                    port=args.remote_port,
                    key_path=args.remote_key,
                )
                print(f"\nConnecting to {args.remote_host}...")

            # --- Pre-flight: tool availability + sudo check ---
            print("\nRunning pre-flight checks...")
            if result.workflow == "iterative":
                tools_needed = {
                    action.approved_tool
                    for action in result.recommended_validations
                    if action.action_type == "safe_enumeration" and action.approved_tool
                }
            else:
                tools_needed = {cmd.tool for cmd in plan.commands}

            try:
                master_ctx = SSHMaster(ssh_config) if ssh_config else None
                if master_ctx:
                    master_ctx.connect()

                tool_status = check_tools_available(tools_needed, master_ctx)
                sudo_ok = check_sudo_passwordless(master_ctx)

                missing = [t for t, ok in tool_status.items() if not ok]
                if missing:
                    print(f"\n  WARNING — Tools not found on target system:")
                    for t in sorted(missing):
                        print(f"    ✗  {t}")
                    print("  Commands using these tools will fail. Install them or skip.\n")

                # Check if any planned command uses sudo
                uses_sudo = any("sudo" in cmd.command for cmd in plan.commands)
                if uses_sudo and not sudo_ok:
                    print(
                        "  WARNING — Some commands use sudo but sudo requires a password.\n"
                        "  Those commands will fail. To fix:\n"
                        "    echo 'kali ALL=(ALL) NOPASSWD: ALL' | sudo tee /etc/sudoers.d/nmap-analyzer\n"
                        "  Or remove sudo from the relevant commands.\n"
                    )
                elif uses_sudo and sudo_ok:
                    print("  Sudo: passwordless ✓")

                if not missing and (not uses_sudo or sudo_ok):
                    print("  All checks passed ✓")

                if master_ctx:
                    master_ctx.disconnect()

            except Exception as exc:
                print(f"  Pre-flight check failed: {exc}")

            engine = ExecutionEngine(timeout=args.exec_timeout, ssh_config=ssh_config)
            if result.workflow == "iterative" and result.case_state is not None:
                print(
                    f"\nRunning iterative approved-validation workflow "
                    f"(batch size: {config.iterative_batch_size}, max commands: {config.max_exec_commands})...\n"
                )
                stage_providers = {}
                if ai_provider:
                    try:
                        stage_providers = create_stage_providers(
                            ai_provider,
                            resolved_models=resolved_models,
                            stages=["iterative_ranking", "result_review"],
                            api_key=args.ai_key or None,
                            timeout=args.ai_timeout,
                        )
                    except Exception as exc:
                        logging.getLogger(__name__).warning("Iterative AI provider setup failed: %s", exc)
                result = run_iterative_analysis_loop(
                    result=result,
                    case_state=result.case_state,
                    ranking_provider=stage_providers.get("iterative_ranking"),
                    review_provider=stage_providers.get("result_review"),
                    max_exec_commands=config.max_exec_commands,
                    batch_size=config.iterative_batch_size,
                    output_dir=report_dir,
                    execution_runner=engine.run,
                    case_state_path=case_state_path,
                    host_batch_size=config.host_batch_size,
                    min_action_value=config.min_action_value,
                    max_noise_streak=config.max_noise_streak,
                )
                total_cmds = len(result.execution_results)
                successes = sum(1 for r in result.execution_results if r.success)
                ssl_errors = sum(1 for r in result.execution_results if r.return_code == 60)
                failed = total_cmds - successes - ssl_errors
                print(f"Iterative execution complete: {successes}/{total_cmds} succeeded", end="")
                if ssl_errors:
                    print(f", {ssl_errors} SSL cert error (exit 60 — commands now use -k)", end="")
                print(f", {failed} failed/timed out." if failed else ".")

                # Final AI synthesis — runs once after all iterations are done.
                # Produces Confirmed Findings / Key Intelligence / Next Steps / Final Verdict.
                if ai_provider and result.execution_results:
                    print(
                        f"\nRunning final AI synthesis across {total_cmds} execution results...\n"
                        f"  This may take a few minutes depending on the model..."
                    )
                    try:
                        synth_stage_providers = create_stage_providers(
                            ai_provider,
                            resolved_models=resolved_models,
                            stages=["result_review"],
                            api_key=args.ai_key or None,
                            timeout=args.ai_timeout,
                        )
                        synth_provider = synth_stage_providers.get("result_review")
                        if synth_provider is None:
                            raise RuntimeError("No routed model available for synthesis")
                        analyzer = ScanAnalyzer(synth_provider, profile=args.profile)
                        iterative_enum_dir = report_dir / "enumeration"
                        synthesis = analyzer.synthesize_execution_results(
                            result.execution_results,
                            enum_dir=iterative_enum_dir,
                            profile=args.profile,
                        )
                        if synthesis:
                            # Prepend the case-state summary so the HTML shows both
                            result.live_findings = synthesis + "\n\n---\n\n" + (result.live_findings or "")
                            print("  Final synthesis complete.")
                        else:
                            print("  Warning: AI synthesis returned empty — case state summary shown instead.")
                    except Exception as exc:
                        logging.getLogger(__name__).warning("Final synthesis failed: %s", exc)
            else:
                print(f"\nExecuting {len(plan.commands)} commands...\n")
                enum_dir = report_dir / "enumeration"
                result.execution_results = engine.run(plan.commands, enum_dir)
                result.manual_suggestions = plan.manual_suggestions

                total_cmds = len(result.execution_results)
                successes = sum(1 for r in result.execution_results if r.success)
                failed = total_cmds - successes
                print(f"\nExecution complete: {successes}/{total_cmds} succeeded", end="")
                print(f", {failed} failed/timed out." if failed else ".")

                # AI synthesis — always runs after execution if AI is enabled,
                # regardless of how many commands succeeded. Partial results are
                # still valuable and Ollama explicitly notes what failed.
                if ai_provider and result.execution_results:
                    print(
                        f"\nSynthesizing {total_cmds} enumeration results with Ollama...\n"
                        f"  Reading full output from: {enum_dir}/\n"
                        f"  This may take a few minutes depending on the model..."
                    )
                    try:
                        stage_providers = create_stage_providers(
                            ai_provider,
                            resolved_models=resolved_models,
                            stages=["result_review"],
                            api_key=args.ai_key or None,
                            timeout=args.ai_timeout,
                        )
                        synth_provider = stage_providers.get("result_review")
                        if synth_provider is None:
                            raise RuntimeError("No routed model available for result_review stage")
                        analyzer = ScanAnalyzer(synth_provider, profile=args.profile)
                        result.live_findings = analyzer.synthesize_execution_results(
                            result.execution_results,
                            enum_dir=enum_dir,
                            profile=args.profile,
                        )
                        if result.live_findings:
                            print("  Synthesis complete.")
                        else:
                            print("  Warning: Ollama returned an empty synthesis.")
                    except Exception as exc:
                        logging.getLogger(__name__).warning("Synthesis failed: %s", exc)
        else:
            result.manual_suggestions = plan.manual_suggestions
            if plan.commands and not should_run:
                print("Execution skipped.")

    # --- Screenshot capture (gowitness) ---
    if args.screenshot and args.scan:
        from pentest_assistant.screenshot import GoWitnessRunner
        from pentest_assistant.executor import SSHConfig as _SSHConfig

        _ssh_cfg = None
        if args.remote_host:
            _ssh_cfg = _SSHConfig(
                host=args.remote_host,
                port=args.remote_port,
                key_path=args.remote_key,
            )

        print("\nCapturing web screenshots with gowitness...")
        gw_runner = GoWitnessRunner(
            report_dir=report_dir,
            nmap_xml=args.scan[0],
            ssh_config=_ssh_cfg,
        )
        gw_result = gw_runner.run()
        if gw_result.error:
            print(f"  gowitness warning: {gw_result.error}", file=sys.stderr)
        else:
            result.screenshot_result = gw_result
            svc_count = len(gw_result.services)
            print(f"  {svc_count} web service(s) captured")
            if gw_result.html_path:
                print(f"  screenshots/ → {gw_result.html_path}")

    # --- Save reports ---
    report_dir.mkdir(parents=True, exist_ok=True)
    text_report = build_text_report(result)
    text_path = report_dir / "findings.txt"
    text_path.write_text(text_report + "\n", encoding="utf-8")

    generate_html_report(result, report_dir / "report.html", args.scan[0] if args.scan else "")

    print(f"\nReports saved to: {report_dir}/")
    print(f"  findings.txt")
    print(f"  report.html")

    if result.ai_analysis:
        ai_path = report_dir / "ai_report.txt"
        ai_path.write_text(result.ai_analysis + "\n", encoding="utf-8")
        print(f"  ai_report.txt")

    if result.execution_results:
        print(f"  enumeration/   ({len(result.execution_results)} command outputs)")

    if result.live_findings:
        lf_path = report_dir / "live_findings.txt"
        lf_path.write_text(result.live_findings + "\n", encoding="utf-8")
        print(f"  live_findings.txt")

    if result.case_state is not None and case_state_path.exists():
        print(f"  case_state.json")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
