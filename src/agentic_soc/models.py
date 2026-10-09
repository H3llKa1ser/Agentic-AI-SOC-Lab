"""Typed contracts passed between pipeline stages.

Agents never hand each other free text. Every stage ends by calling a submit tool whose
input is validated into one of these models, so malformed or out-of-range output is
rejected before it can influence the next stage.
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator

ATTACK_ID = re.compile(r"^T\d{4}(\.\d{3})?$")


class Severity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Verdict(StrEnum):
    TRUE_POSITIVE = "true_positive"
    BENIGN_TRUE_POSITIVE = "benign_true_positive"
    FALSE_POSITIVE = "false_positive"
    NEEDS_HUMAN = "needs_human"


class Alert(BaseModel):
    id: str
    title: str
    source: str
    severity: Severity
    created_at: datetime
    description: str = ""
    entities: dict[str, list[str]] = Field(default_factory=dict)
    raw: dict[str, Any] = Field(default_factory=dict)


class InjectionHit(BaseModel):
    path: str
    rule: str
    excerpt: str


class GuardReport(BaseModel):
    suspected: bool
    hits: list[InjectionHit] = Field(default_factory=list)


class TriageResult(BaseModel):
    alert_id: str
    verdict: Verdict
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str = Field(min_length=10, max_length=2000)
    escalate: bool
    injection_suspected: bool = False
    overrides: list[str] = Field(default_factory=list)


class InvestigationReport(BaseModel):
    alert_id: str
    verdict: Verdict
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str = Field(min_length=10, max_length=4000)
    timeline: list[str] = Field(min_length=1)
    attack_techniques: list[str] = Field(default_factory=list)
    affected_entities: dict[str, list[str]] = Field(default_factory=dict)
    evidence: list[str] = Field(min_length=1)
    recommended_next_steps: list[str] = Field(default_factory=list)

    @field_validator("attack_techniques")
    @classmethod
    def _valid_attack_ids(cls, value: list[str]) -> list[str]:
        bad = [t for t in value if not ATTACK_ID.match(t)]
        if bad:
            raise ValueError(f"invalid ATT&CK technique IDs {bad}; use the form T1234 or T1234.001")
        return sorted(set(value))


class ActionRequest(BaseModel):
    action: str
    target: str = Field(min_length=1, max_length=200)
    justification: str = Field(min_length=10, max_length=1000)


class ResponsePlan(BaseModel):
    rationale: str = Field(min_length=10)
    actions: list[ActionRequest] = Field(default_factory=list)


class Decision(StrEnum):
    AUTO_EXECUTED = "auto_executed"
    APPROVED_EXECUTED = "approved_executed"
    PENDING_APPROVAL = "pending_approval"
    DENIED = "denied"
    BLOCKED_BY_POLICY = "blocked_by_policy"


EXECUTED = {Decision.AUTO_EXECUTED, Decision.APPROVED_EXECUTED}


class ActionDecision(BaseModel):
    request: ActionRequest
    decision: Decision
    reason: str

    @property
    def executed(self) -> bool:
        return self.decision in EXECUTED


class CaseFile(BaseModel):
    run_id: str
    alert: Alert
    guard: GuardReport
    triage: TriageResult | None = None
    investigation: InvestigationReport | None = None
    response_rationale: str | None = None
    actions: list[ActionDecision] = Field(default_factory=list)
    outcome: str = "open"
    error: str | None = None

    @property
    def final_verdict(self) -> Verdict | None:
        if self.investigation:
            return self.investigation.verdict
        return self.triage.verdict if self.triage else None
