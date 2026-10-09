"""Hash-chained, append-only audit log.

Every model call outcome, tool invocation, policy decision and approval is recorded.
Each record carries the SHA-256 of the previous record, so any edit, deletion or
reordering breaks verification. This is tamper-evident, not tamper-proof: anchor the
head hash somewhere the pipeline cannot write (e.g. S3 Object Lock) for real use.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _digest(record: dict[str, Any]) -> str:
    body = {k: v for k, v in record.items() if k != "hash"}
    return hashlib.sha256(_canonical(body).encode()).hexdigest()


class AuditLog:
    def __init__(self, path: Path, run_id: str) -> None:
        self.path = path
        self.run_id = run_id
        path.parent.mkdir(parents=True, exist_ok=True)
        self._prev, self._seq = self._tail()

    def _tail(self) -> tuple[str, int]:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return GENESIS, 0
        last = self.path.read_text(encoding="utf-8").strip().splitlines()[-1]
        rec = json.loads(last)
        return rec["hash"], rec["seq"]

    def record(self, event: str, **data: Any) -> dict[str, Any]:
        rec: dict[str, Any] = {
            "seq": self._seq + 1,
            "ts": datetime.now(UTC).isoformat(),
            "run_id": self.run_id,
            "event": event,
            "data": json.loads(_canonical(data)),
            "prev_hash": self._prev,
        }
        rec["hash"] = _digest(rec)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(_canonical(rec) + "\n")
        self._prev, self._seq = rec["hash"], rec["seq"]
        return rec


def verify(path: Path) -> tuple[bool, str]:
    prev, expected_seq = GENESIS, 1
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        rec = json.loads(line)
        if rec.get("seq") != expected_seq:
            return False, f"line {line_no}: sequence gap (expected {expected_seq}, got {rec.get('seq')})"
        if rec.get("prev_hash") != prev:
            return False, f"line {line_no}: chain broken (prev_hash mismatch)"
        if _digest(rec) != rec.get("hash"):
            return False, f"line {line_no}: record content modified (hash mismatch)"
        prev, expected_seq = rec["hash"], expected_seq + 1
    return True, f"{expected_seq - 1} records verified, head={prev[:16]}"
