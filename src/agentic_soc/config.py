"""Runtime settings from environment variables (see .env.example)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    model: str
    data_dir: Path
    policy_path: Path
    runs_dir: Path
    max_steps: int

    @classmethod
    def from_env(cls) -> Settings:
        root = Path(os.getenv("AGENTIC_SOC_ROOT", Path.cwd()))
        return cls(
            model=os.getenv("AGENTIC_SOC_MODEL", "claude-sonnet-5-5"),
            data_dir=Path(os.getenv("AGENTIC_SOC_DATA_DIR", root / "data")),
            policy_path=Path(os.getenv("AGENTIC_SOC_POLICY", root / "config" / "policy.yaml")),
            runs_dir=Path(os.getenv("AGENTIC_SOC_RUNS_DIR", root / "runs")),
            max_steps=int(os.getenv("AGENTIC_SOC_MAX_STEPS", "16")),
        )
