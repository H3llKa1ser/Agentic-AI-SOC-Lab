from __future__ import annotations

from pathlib import Path

import pytest

from agentic_soc.guardrails.audit import AuditLog
from agentic_soc.guardrails.policy import PolicyEngine
from agentic_soc.models import Alert, InvestigationReport, Severity, Verdict
from agentic_soc.tools.labdata import LabData
from agentic_soc.tools.registry import ToolRegistry
from agentic_soc.tools.soc_tools import build_tools

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def data() -> LabData:
    return LabData.load(ROOT / "data")


@pytest.fixture
def policy(data: LabData) -> PolicyEngine:
    return PolicyEngine.from_file(ROOT / "config" / "policy.yaml", data.users, data.hosts)


@pytest.fixture
def registry(data: LabData) -> ToolRegistry:
    return ToolRegistry(build_tools(data))


@pytest.fixture
def audit(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl", run_id="test-run")


def alert(alert_id: str, data: LabData) -> Alert:
    return next(a for a in data.alerts if a.id == alert_id)


@pytest.fixture
def tp_report() -> InvestigationReport:
    return InvestigationReport(
        alert_id="ALERT-X",
        verdict=Verdict.TRUE_POSITIVE,
        severity=Severity.HIGH,
        confidence=0.9,
        summary="Confirmed malicious activity for testing.",
        timeline=["t0 - thing happened"],
        attack_techniques=["T1190"],
        affected_entities={},
        evidence=["web: 14 blocked SQLi requests"],
    )
