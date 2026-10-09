"""Generic tool-using agent loop plus the three SOC agents' submit contracts."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

from agentic_soc.guardrails.audit import AuditLog
from agentic_soc.llm import LLMClient
from agentic_soc.models import Severity, Verdict
from agentic_soc.tools.registry import ToolRegistry

T = TypeVar("T", bound=BaseModel)

VERDICTS = [v.value for v in Verdict]
SEVERITIES = [s.value for s in Severity]
STRINGS = {"type": "array", "items": {"type": "string"}}


class AgentBudgetExceeded(RuntimeError):
    pass


SUBMIT_TRIAGE = {
    "name": "submit_triage",
    "description": "Submit the triage decision. Ends the triage stage.",
    "input_schema": {
        "type": "object",
        "properties": {
            "verdict": {"type": "string", "enum": VERDICTS},
            "severity": {"type": "string", "enum": SEVERITIES},
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
            "summary": {"type": "string", "description": "2-4 sentences, evidence-based"},
            "escalate": {"type": "boolean"},
            "injection_suspected": {"type": "boolean"},
        },
        "required": ["verdict", "severity", "confidence", "summary", "escalate", "injection_suspected"],
    },
}

SUBMIT_INVESTIGATION = {
    "name": "submit_investigation",
    "description": "Submit the investigation report. Ends the investigation stage.",
    "input_schema": {
        "type": "object",
        "properties": {
            "verdict": {"type": "string", "enum": VERDICTS},
            "severity": {"type": "string", "enum": SEVERITIES},
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
            "summary": {"type": "string"},
            "timeline": {**STRINGS, "description": "'<ISO timestamp> - <what happened>' lines, earliest first"},
            "attack_techniques": {**STRINGS, "description": "ATT&CK IDs, e.g. T1110.004"},
            "affected_entities": {
                "type": "object",
                "description": 'e.g. {"user": [...], "ip": [...], "access_key": [...]}',
                "additionalProperties": STRINGS,
            },
            "evidence": STRINGS,
            "recommended_next_steps": STRINGS,
        },
        "required": [
            "verdict",
            "severity",
            "confidence",
            "summary",
            "timeline",
            "attack_techniques",
            "affected_entities",
            "evidence",
        ],
    },
}


def submit_response_tool(action_names: list[str]) -> dict[str, Any]:
    return {
        "name": "submit_response_plan",
        "description": "Submit proposed response actions. Ends the response stage.",
        "input_schema": {
            "type": "object",
            "properties": {
                "rationale": {"type": "string"},
                "actions": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "action": {"type": "string", "enum": action_names},
                            "target": {"type": "string"},
                            "justification": {"type": "string"},
                        },
                        "required": ["action", "target", "justification"],
                    },
                },
            },
            "required": ["rationale", "actions"],
        },
    }


@dataclass
class Agent:
    name: str
    system: str
    llm: LLMClient
    registry: ToolRegistry
    submit_tool: dict[str, Any]
    parse: Callable[[dict[str, Any]], BaseModel]
    audit: AuditLog
    max_steps: int = 12

    def run(self, prompt: str) -> Any:
        tools = self.registry.schemas() + [self.submit_tool]
        submit = self.submit_tool["name"]
        messages: list[dict[str, Any]] = [{"role": "user", "content": prompt}]
        self.audit.record("agent_start", agent=self.name, tools=[t["name"] for t in tools])

        for step in range(1, self.max_steps + 1):
            resp = self.llm.complete(system=self.system, messages=messages, tools=tools)
            content = resp.content or [{"type": "text", "text": "(empty response)"}]
            messages.append({"role": "assistant", "content": content})
            if resp.text:
                self.audit.record("agent_text", agent=self.name, step=step, text=resp.text[:2000])

            calls = resp.tool_calls
            if not calls:
                self.audit.record("agent_nudge", agent=self.name, step=step)
                messages.append({"role": "user", "content": f"Finish by calling `{submit}`. Free text is discarded."})
                continue

            results: list[dict[str, Any]] = []
            for call in calls:
                self.audit.record("tool_call", agent=self.name, step=step, tool=call.name, input=call.input)
                if call.name == submit:
                    try:
                        parsed = self.parse(call.input)
                    except ValidationError as exc:
                        msg = f"Submission rejected by schema validation. Fix and resubmit:\n{exc}"
                        self.audit.record("submit_rejected", agent=self.name, step=step, error=str(exc)[:2000])
                        results.append(_tool_result(call.id, msg[:4000], True))
                        continue
                    self.audit.record("agent_submit", agent=self.name, step=step, output=parsed.model_dump(mode="json"))
                    return parsed
                output, is_error = self.registry.execute(call.name, call.input)
                self.audit.record(
                    "tool_result",
                    agent=self.name,
                    step=step,
                    tool=call.name,
                    is_error=is_error,
                    chars=len(output),
                )
                results.append(_tool_result(call.id, output, is_error))
            messages.append({"role": "user", "content": results})

        self.audit.record("agent_budget_exceeded", agent=self.name, max_steps=self.max_steps)
        raise AgentBudgetExceeded(f"{self.name} did not submit within {self.max_steps} steps")


def _tool_result(tool_use_id: str, content: str, is_error: bool) -> dict[str, Any]:
    block: dict[str, Any] = {"type": "tool_result", "tool_use_id": tool_use_id, "content": content}
    if is_error:
        block["is_error"] = True
    return block
