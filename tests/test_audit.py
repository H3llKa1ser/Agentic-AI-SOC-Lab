import json

from agentic_soc.guardrails.audit import AuditLog, verify


def test_chain_verifies_and_survives_reopen(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, "r1")
    log.record("a", x=1)
    log.record("b", y=[1, 2])
    AuditLog(path, "r2").record("c", z="resumed")
    ok, msg = verify(path)
    assert ok and msg.startswith("3 records")


def test_tampering_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, "r1")
    for i in range(3):
        log.record("action_decision", decision="blocked_by_policy", i=i)
    lines = path.read_text().splitlines()
    rec = json.loads(lines[1])
    rec["data"]["decision"] = "approved_executed"
    lines[1] = json.dumps(rec)
    path.write_text("\n".join(lines) + "\n")
    ok, msg = verify(path)
    assert not ok and "line 2" in msg


def test_deletion_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, "r1")
    for i in range(3):
        log.record("e", i=i)
    lines = path.read_text().splitlines()
    path.write_text("\n".join([lines[0], lines[2]]) + "\n")
    assert not verify(path)[0]
