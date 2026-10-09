"""Deterministic policy engine: the real security boundary of the pipeline.

Prompt-level defences reduce how often a model is manipulated. This module ensures that
being manipulated does not matter much: a fully hijacked responder can only *propose*
actions, and every proposal is checked here against an allow-list, target validation,
protected assets, confidence floors and per-incident limits before any human sees it.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from agentic_soc.models import (
    ActionRequest,
    GuardReport,
    InvestigationReport,
    TriageResult,
    Verdict,
)

ACCESS_KEY = re.compile(r"^(AKIA|ASIA)[A-Z0-9]{16}$")
INDICATOR = re.compile(r"^[\w.:/@\-]{3,200}$")


@dataclass
class PolicyCheck:
    allowed: bool
    tier: str | None
    reason: str


@dataclass
class PolicyEngine:
    config: dict[str, Any]
    users: dict[str, dict[str, Any]] = field(default_factory=dict)
    hosts: dict[str, dict[str, Any]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        protected = self.config.get("protected", {})
        self._cidrs = [ipaddress.ip_network(c) for c in protected.get("ip_cidrs", [])]
        self._users = {u.lower() for u in protected.get("users", [])} | {
            name.lower() for name, rec in self.users.items() if rec.get("break_glass") or rec.get("protected")
        }
        self._hosts = {h.lower() for h in protected.get("hosts", [])} | {
            name.lower() for name, rec in self.hosts.items() if rec.get("protected")
        }
        self._known_users = {u.lower() for u in self.users}
        self._known_hosts = {h.lower() for h in self.hosts}

    @classmethod
    def from_file(cls, path: Path, users: dict[str, dict[str, Any]], hosts: dict[str, dict[str, Any]]) -> PolicyEngine:
        return cls(yaml.safe_load(path.read_text(encoding="utf-8")), users, hosts)

    @property
    def actions(self) -> dict[str, dict[str, Any]]:
        return self.config.get("actions", {})

    def catalogue(self) -> str:
        lines = [
            f"- {name}: tier={spec['tier']}, target={spec['target_type']}, containment={spec['containment']}"
            for name, spec in self.actions.items()
        ]
        return "\n".join(lines)

    # ---- triage floor -------------------------------------------------------------------

    def apply_triage_floor(self, triage: TriageResult, guard: GuardReport) -> TriageResult:
        cfg = self.config.get("triage", {})
        result = triage.model_copy(deep=True)
        overrides: list[str] = []

        if guard.suspected and cfg.get("injection_forces_escalation", True):
            result.injection_suspected = True
            if result.verdict in (Verdict.FALSE_POSITIVE, Verdict.BENIGN_TRUE_POSITIVE):
                overrides.append(
                    f"benign verdict '{result.verdict.value}' on an alert containing injection "
                    "markers replaced with needs_human"
                )
                result.verdict = Verdict.NEEDS_HUMAN
            if not result.escalate:
                overrides.append("injection markers detected: escalation forced")
                result.escalate = True

        if result.verdict in (Verdict.TRUE_POSITIVE, Verdict.NEEDS_HUMAN) and not result.escalate:
            overrides.append(f"verdict '{result.verdict.value}' requires escalation")
            result.escalate = True

        threshold = cfg.get("auto_close_min_confidence", 0.85)
        if not result.escalate and result.confidence < threshold:
            overrides.append(
                f"auto-close confidence {result.confidence:.2f} below floor {threshold:.2f}: escalation forced"
            )
            result.escalate = True

        result.overrides = overrides
        return result

    # ---- action checks ------------------------------------------------------------------

    def check(self, request: ActionRequest, report: InvestigationReport, prior_actions: int) -> PolicyCheck:
        action = request.action
        if action in self.config.get("forbidden_actions", []):
            return PolicyCheck(False, None, f"'{action}' is forbidden by policy")
        spec = self.actions.get(action)
        if spec is None:
            return PolicyCheck(False, None, f"'{action}' is not an allow-listed action (default deny)")

        limit = self.config.get("limits", {}).get("max_actions_per_incident", 5)
        if prior_actions >= limit:
            return PolicyCheck(False, None, f"per-incident action limit ({limit}) reached")

        ok, why = self._validate_target(spec["target_type"], request.target.strip())
        if not ok:
            return PolicyCheck(False, None, why)

        if spec.get("containment"):
            floor = self.config.get("limits", {}).get("min_confidence_for_containment", 0.7)
            if report.verdict != Verdict.TRUE_POSITIVE:
                return PolicyCheck(
                    False, None, f"containment requires a true_positive verdict (got {report.verdict.value})"
                )
            if report.confidence < floor:
                return PolicyCheck(
                    False, None, f"confidence {report.confidence:.2f} below containment floor {floor:.2f}"
                )

        return PolicyCheck(True, spec["tier"], "passed policy checks")

    def _validate_target(self, target_type: str, target: str) -> tuple[bool, str]:
        if target_type == "ip":
            try:
                addr = ipaddress.ip_address(target)
            except ValueError:
                return False, f"'{target}' is not a valid IP address"
            for net in self._cidrs:
                if addr in net:
                    return False, f"{target} is inside protected range {net}"
            return True, ""
        if target_type == "user":
            key = target.lower()
            if key in self._users:
                return False, f"identity '{target}' is protected (break-glass/critical); human-only"
            if key not in self._known_users:
                return False, f"identity '{target}' not found in directory"
            return True, ""
        if target_type == "host":
            key = target.lower()
            if key in self._hosts:
                return False, f"host '{target}' is protected; human-only"
            if key not in self._known_hosts:
                return False, f"host '{target}' not found in asset inventory"
            return True, ""
        if target_type == "access_key":
            if not ACCESS_KEY.match(target):
                return False, f"'{target}' is not a valid AWS access key ID"
            return True, ""
        if target_type == "indicator":
            if not INDICATOR.match(target):
                return False, "indicator contains unsupported characters"
            return True, ""
        if target_type == "free_text":
            return True, ""
        return False, f"unknown target type '{target_type}'"
