"""Loads the lab's synthetic SIEM, identity, asset and threat-intel fixtures."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agentic_soc.models import Alert


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


@dataclass
class LabData:
    logs: dict[str, list[dict[str, Any]]]
    intel: dict[str, dict[str, Any]]
    users: dict[str, dict[str, Any]]
    hosts: dict[str, dict[str, Any]]
    attack: dict[str, dict[str, Any]]
    alerts: list[Alert]

    @classmethod
    def load(cls, root: Path) -> LabData:
        logs = {p.stem: _read_jsonl(p) for p in sorted((root / "logs").glob("*.jsonl"))}
        ctx = root / "context"
        directory = json.loads((ctx / "directory.json").read_text(encoding="utf-8"))
        alerts = [
            Alert.model_validate_json(p.read_text(encoding="utf-8")) for p in sorted((root / "alerts").glob("*.json"))
        ]
        return cls(
            logs=logs,
            intel=json.loads((ctx / "threat_intel.json").read_text(encoding="utf-8")),
            users=directory["users"],
            hosts=directory["hosts"],
            attack=json.loads((ctx / "attack_techniques.json").read_text(encoding="utf-8")),
            alerts=alerts,
        )
