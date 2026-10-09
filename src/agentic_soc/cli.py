"""Command-line entry point: `agentic-soc --help`."""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

from agentic_soc.config import Settings
from agentic_soc.guardrails.audit import AuditLog, verify
from agentic_soc.guardrails.injection import guard_note, scan_alert
from agentic_soc.guardrails.policy import PolicyEngine
from agentic_soc.llm import AnthropicClient, LLMClient, ScriptedLLM
from agentic_soc.models import Alert, CaseFile
from agentic_soc.pipeline import Pipeline
from agentic_soc.report import render_markdown
from agentic_soc.response import CLIApprover, DeferApprover, SimulatedExecutor
from agentic_soc.tools.labdata import LabData
from agentic_soc.tools.registry import ToolRegistry
from agentic_soc.tools.soc_tools import build_tools


def _new_run(settings: Settings) -> tuple[str, Path]:
    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:6]
    run_dir = settings.runs_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_id, run_dir


def _pipeline(
    settings: Settings, run_id: str, run_dir: Path, interactive: bool, llm: LLMClient | None = None
) -> tuple[Pipeline, LabData]:
    if llm is None:
        if not os.getenv("ANTHROPIC_API_KEY"):
            sys.exit("ANTHROPIC_API_KEY is not set. Try `agentic-soc demo` for an offline run.")
        llm = AnthropicClient(settings.model)
    data = LabData.load(settings.data_dir)
    policy = PolicyEngine.from_file(settings.policy_path, data.users, data.hosts)
    approver = CLIApprover("analyst@console") if interactive else DeferApprover()
    pipeline = Pipeline(
        llm=llm,
        tools=ToolRegistry(build_tools(data)),
        policy=policy,
        approver=approver,
        executor=SimulatedExecutor(run_dir / "actions.jsonl"),
        audit=AuditLog(run_dir / "audit.jsonl", run_id),
        max_steps=settings.max_steps,
    )
    return pipeline, data


def _save(case: CaseFile, run_dir: Path) -> None:
    (run_dir / f"{case.alert.id}.json").write_text(case.model_dump_json(indent=2), encoding="utf-8")
    (run_dir / f"{case.alert.id}.md").write_text(render_markdown(case), encoding="utf-8")


def _summary(case: CaseFile) -> str:
    verdict = case.final_verdict.value if case.final_verdict else "-"
    acts = ", ".join(f"{d.request.action}({d.request.target})={d.decision.value}" for d in case.actions)
    return f"{case.alert.id:<10} {verdict:<22} {case.outcome:<28} {acts}"


def cmd_scan(args: argparse.Namespace) -> int:
    alert = Alert.model_validate_json(Path(args.alert).read_text(encoding="utf-8"))
    report = scan_alert(alert)
    print(guard_note(report))
    return 1 if report.suspected else 0


def cmd_triage(args: argparse.Namespace) -> int:
    settings = Settings.from_env()
    run_id, run_dir = _new_run(settings)
    pipeline, _ = _pipeline(settings, run_id, run_dir, args.interactive)
    alert = Alert.model_validate_json(Path(args.alert).read_text(encoding="utf-8"))
    case = pipeline.run(alert)
    _save(case, run_dir)
    print(render_markdown(case))
    print(f"Artifacts: {run_dir}")
    return 0


def cmd_run_all(args: argparse.Namespace) -> int:
    settings = Settings.from_env()
    run_id, run_dir = _new_run(settings)
    pipeline, data = _pipeline(settings, run_id, run_dir, args.interactive)
    for alert in data.alerts:
        case = pipeline.run(alert)
        _save(case, run_dir)
        print(_summary(case))
    print(f"\nArtifacts: {run_dir}")
    return 0


def cmd_eval(args: argparse.Namespace) -> int:
    from agentic_soc import evals

    settings = Settings.from_env()
    run_id, run_dir = _new_run(settings)
    pipeline, _ = _pipeline(settings, run_id, run_dir, interactive=False)
    rows = []
    for scenario in evals.load_scenarios(Path(args.scenarios)):
        alert = Alert.model_validate_json((settings.data_dir / "alerts" / scenario["alert"]).read_text())
        for i in range(1, args.repeat + 1):
            case = pipeline.run(alert)
            _save(case, run_dir / f"run{i}")
            checks = evals.score(case, scenario["expect"])
            rows.append({"scenario": scenario["name"], "run": i, "outcome": case.outcome, "checks": checks})
            print(
                f"{scenario['name']:<28} run{i}  "
                + " ".join(f"{k}={'PASS' if v else 'FAIL'}" for k, v in checks.items())
            )
    card = evals.render_scorecard(rows)
    (run_dir / "scorecard.md").write_text(card, encoding="utf-8")
    (run_dir / "scorecard.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    print("\n" + card + f"\nArtifacts: {run_dir}")
    return 0 if evals.safety_passed(rows) else 2


def cmd_demo(args: argparse.Namespace) -> int:
    from agentic_soc.demo import hijacked_script

    settings = Settings.from_env()
    run_id, run_dir = _new_run(settings)
    pipeline, data = _pipeline(settings, run_id, run_dir, interactive=False, llm=ScriptedLLM(hijacked_script()))
    alert = next(a for a in data.alerts if a.id == "ALERT-004")
    print("Offline demo: replaying a model that obeys the prompt injection in ALERT-004 at every stage.\n")
    case = pipeline.run(alert)
    _save(case, run_dir)
    print(render_markdown(case))
    ok, message = verify(run_dir / "audit.jsonl")
    print(f"Audit chain: {'OK' if ok else 'TAMPERED'} ({message})")
    print(f"Artifacts: {run_dir}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    ok, message = verify(Path(args.path))
    print(("OK: " if ok else "TAMPERED: ") + message)
    return 0 if ok else 3


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agentic-soc", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("scan", help="Offline prompt-injection scan of an alert (no LLM)")
    p.add_argument("alert")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("triage", help="Run the full pipeline on one alert")
    p.add_argument("alert")
    p.add_argument("--interactive", action="store_true", help="Prompt for approval of gated actions")
    p.set_defaults(func=cmd_triage)

    p = sub.add_parser("run-all", help="Run the pipeline on every alert in data/alerts")
    p.add_argument("--interactive", action="store_true")
    p.set_defaults(func=cmd_run_all)

    p = sub.add_parser("eval", help="Run the scenario eval suite and write a scorecard")
    p.add_argument("--scenarios", default="evals/scenarios.yaml")
    p.add_argument("--repeat", type=int, default=1)
    p.set_defaults(func=cmd_eval)

    p = sub.add_parser("demo", help="Offline demo: fully hijacked model vs. the guardrails (no API key)")
    p.set_defaults(func=cmd_demo)

    p = sub.add_parser("verify-audit", help="Verify a hash-chained audit log")
    p.add_argument("path")
    p.set_defaults(func=cmd_verify)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
