"""Approvers and executors for proposed response actions."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from agentic_soc.models import ActionRequest, InvestigationReport


class Approver(Protocol):
    def decide(self, request: ActionRequest, report: InvestigationReport) -> tuple[bool | None, str]:
        """Return (True, why) to approve, (False, why) to deny, (None, why) to defer."""
        ...


class DeferApprover:
    """Non-interactive default: nothing that needs a human is ever executed."""

    def decide(self, request: ActionRequest, report: InvestigationReport) -> tuple[bool | None, str]:
        return None, "queued for human approval (non-interactive run)"


class CLIApprover:
    def __init__(self, approver_name: str) -> None:
        self.approver_name = approver_name

    def decide(self, request: ActionRequest, report: InvestigationReport) -> tuple[bool | None, str]:
        print("\n" + "=" * 72)
        print(
            f"APPROVAL REQUIRED  [{report.alert_id}]  verdict={report.verdict.value} confidence={report.confidence:.2f}"
        )
        print(f"  action : {request.action}")
        print(f"  target : {request.target}")
        print(f"  why    : {request.justification}")
        answer = input("Approve? [y/N] ").strip().lower()
        if answer == "y":
            return True, f"approved by {self.approver_name}"
        return False, f"denied by {self.approver_name}"


class Executor(Protocol):
    def execute(self, request: ActionRequest, alert_id: str) -> None: ...


class SimulatedExecutor:
    """Writes actions to a JSONL file instead of calling real APIs.

    Swap for real adapters (Cloudflare lists/rules, Entra ID Graph, AWS IAM, EDR) behind
    the same interface. The policy engine stays in front of whichever executor is used.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)

    def execute(self, request: ActionRequest, alert_id: str) -> None:
        record = {
            "ts": datetime.now(UTC).isoformat(),
            "alert_id": alert_id,
            "simulated": True,
            **request.model_dump(),
        }
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
