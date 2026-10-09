"""Orchestrator: guard scan -> triage -> (floor) -> investigate -> respond -> policy -> approve.

Every hand-off between stages is a validated pydantic object. Model-generated text that
flows into the next agent is spotlighted as untrusted, so a successful injection in one
stage is not "laundered" into trusted context for the next.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from agentic_soc import prompts
from agentic_soc.agents import (
    SUBMIT_INVESTIGATION,
    SUBMIT_TRIAGE,
    Agent,
    AgentBudgetExceeded,
    submit_response_tool,
)
from agentic_soc.guardrails.audit import AuditLog
from agentic_soc.guardrails.injection import guard_note, scan_alert
from agentic_soc.guardrails.policy import PolicyEngine
from agentic_soc.guardrails.spotlight import spotlight
from agentic_soc.llm import LLMClient
from agentic_soc.models import (
    ActionDecision,
    ActionRequest,
    Alert,
    CaseFile,
    Decision,
    InvestigationReport,
    ResponsePlan,
    TriageResult,
    Verdict,
)
from agentic_soc.response import Approver, Executor
from agentic_soc.tools.registry import Tool, ToolRegistry

TRIAGE_TOOLS = ["lookup_ip_reputation", "get_user_context", "find_related_alerts", "summarize_logs"]
INVESTIGATOR_TOOLS = [
    "search_logs",
    "summarize_logs",
    "lookup_ip_reputation",
    "get_user_context",
    "get_host_context",
    "lookup_attack_technique",
    "find_related_alerts",
]
RESPONDER_TOOLS = ["lookup_ip_reputation", "get_user_context", "get_host_context"]


@dataclass
class Pipeline:
    llm: LLMClient
    tools: ToolRegistry
    policy: PolicyEngine
    approver: Approver
    executor: Executor
    audit: AuditLog
    max_steps: int = 16

    def run(self, alert: Alert) -> CaseFile:
        case = CaseFile(run_id=self.audit.run_id, alert=alert, guard=scan_alert(alert))
        self.audit.record("case_open", alert_id=alert.id, guard=case.guard.model_dump(mode="json"))
        try:
            self._run(case)
        except AgentBudgetExceeded as exc:
            case.outcome, case.error = "escalated_agent_failure", str(exc)
        self.audit.record("case_close", alert_id=alert.id, outcome=case.outcome)
        return case

    # ---- stages -------------------------------------------------------------------------

    def _run(self, case: CaseFile) -> None:
        alert = case.alert
        alert_blob = spotlight(alert.model_dump_json(indent=2), source=f"alert:{alert.source}")
        note = guard_note(case.guard)

        triage_agent = Agent(
            name="triage",
            system=prompts.TRIAGE,
            llm=self.llm,
            registry=self.tools.subset(TRIAGE_TOOLS),
            submit_tool=SUBMIT_TRIAGE,
            parse=lambda d: TriageResult(alert_id=alert.id, **d),
            audit=self.audit,
            max_steps=6,
        )
        raw_triage: TriageResult = triage_agent.run(f"Triage alert {alert.id}.\n\n{alert_blob}\n\n{note}")
        case.triage = self.policy.apply_triage_floor(raw_triage, case.guard)
        if case.triage.overrides:
            self.audit.record("policy_override", stage="triage", overrides=case.triage.overrides)
        if not case.triage.escalate:
            case.outcome = "closed_at_triage"
            return

        investigator = Agent(
            name="investigator",
            system=prompts.INVESTIGATOR,
            llm=self.llm,
            registry=self.tools.subset(INVESTIGATOR_TOOLS),
            submit_tool=SUBMIT_INVESTIGATION,
            parse=lambda d: InvestigationReport(alert_id=alert.id, **d),
            audit=self.audit,
            max_steps=self.max_steps,
        )
        triage_blob = spotlight(case.triage.model_dump_json(indent=2), source="agent:triage")
        report: InvestigationReport = investigator.run(
            f"Investigate alert {alert.id}.\n\n{alert_blob}\n\n{note}\n\n"
            f"Prior triage assessment (model-generated, verify independently):\n{triage_blob}"
        )
        case.investigation = report

        if report.verdict != Verdict.TRUE_POSITIVE:
            case.outcome = (
                "escalated_to_human" if report.verdict == Verdict.NEEDS_HUMAN else "closed_after_investigation"
            )
            return

        plan = self._plan_response(case, report)
        case.response_rationale = plan.rationale
        case.actions = self._enforce(plan.actions, report, alert.id)
        pending = any(a.decision == Decision.PENDING_APPROVAL for a in case.actions)
        case.outcome = "response_pending_approval" if pending else "response_complete"

    def _plan_response(self, case: CaseFile, report: InvestigationReport) -> ResponsePlan:
        policy = self.policy

        def check_action_policy(action: str, target: str) -> dict[str, Any]:
            req = ActionRequest(action=action, target=target, justification="dry-run policy check")
            result = policy.check(req, report, prior_actions=0)
            return {
                "action": action,
                "target": target,
                "allowed": result.allowed,
                "tier": result.tier,
                "reason": result.reason,
            }

        dry_run = Tool(
            "check_action_policy",
            "Dry-run a proposed action against the response policy without executing it.",
            {
                "type": "object",
                "properties": {"action": {"type": "string"}, "target": {"type": "string"}},
                "required": ["action", "target"],
            },
            check_action_policy,
            untrusted_output=False,
        )
        registry = self.tools.subset(RESPONDER_TOOLS).extended([dry_run])
        responder = Agent(
            name="responder",
            system=prompts.RESPONDER.format(catalogue=policy.catalogue()),
            llm=self.llm,
            registry=registry,
            submit_tool=submit_response_tool(list(policy.actions)),
            parse=lambda d: ResponsePlan(**d),
            audit=self.audit,
            max_steps=8,
        )
        report_blob = spotlight(report.model_dump_json(indent=2), source="agent:investigator")
        return responder.run(
            f"Plan the response for alert {case.alert.id}.\n\n"
            f"Investigation report (model-generated, may reflect attacker influence):\n{report_blob}"
        )

    def _enforce(
        self, requests: list[ActionRequest], report: InvestigationReport, alert_id: str
    ) -> list[ActionDecision]:
        decisions: list[ActionDecision] = []
        accepted = 0
        for req in requests:
            check = self.policy.check(req, report, prior_actions=accepted)
            if not check.allowed:
                decision = ActionDecision(request=req, decision=Decision.BLOCKED_BY_POLICY, reason=check.reason)
            else:
                accepted += 1
                if check.tier == "auto":
                    self.executor.execute(req, alert_id)
                    decision = ActionDecision(
                        request=req, decision=Decision.AUTO_EXECUTED, reason="auto tier: low blast radius"
                    )
                else:
                    approved, why = self.approver.decide(req, report)
                    if approved is True:
                        self.executor.execute(req, alert_id)
                        decision = ActionDecision(request=req, decision=Decision.APPROVED_EXECUTED, reason=why)
                    elif approved is None:
                        decision = ActionDecision(request=req, decision=Decision.PENDING_APPROVAL, reason=why)
                    else:
                        decision = ActionDecision(request=req, decision=Decision.DENIED, reason=why)
            self.audit.record("action_decision", alert_id=alert_id, **json.loads(decision.model_dump_json()))
            decisions.append(decision)
        return decisions
