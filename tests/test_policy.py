import pytest

from agentic_soc.models import ActionRequest, GuardReport, InjectionHit, TriageResult, Verdict


def req(action, target):
    return ActionRequest(action=action, target=target, justification="test justification text")


@pytest.mark.parametrize(
    "action,target,reason_part",
    [
        ("block_ip", "10.20.0.5", "protected range"),
        ("block_ip", "198.51.100.20", "protected range"),
        ("block_ip", "not-an-ip", "not a valid IP"),
        ("disable_user", "breakglass-01@luckylynx.example", "protected"),
        ("disable_user", "ghost@luckylynx.example", "not found"),
        ("isolate_host", "dc01", "protected"),
        ("disable_access_key", "AKIA123", "not a valid AWS access key"),
        ("delete_logs", "org-trail", "forbidden"),
        ("run_command", "rm -rf /", "forbidden"),
        ("wipe_everything", "x", "default deny"),
    ],
)
def test_blocked(policy, tp_report, action, target, reason_part):
    result = policy.check(req(action, target), tp_report, prior_actions=0)
    assert not result.allowed
    assert reason_part in result.reason


def test_allowed_tiers(policy, tp_report):
    assert policy.check(req("block_ip", "203.0.113.99"), tp_report, 0).tier == "approval"
    assert policy.check(req("create_ticket", "SQLi probing"), tp_report, 0).tier == "auto"
    assert policy.check(req("disable_access_key", "AKIAEXAMPLEBKP00002X"), tp_report, 0).allowed


def test_containment_needs_confident_true_positive(policy, tp_report):
    low = tp_report.model_copy(update={"confidence": 0.4})
    assert "below containment floor" in policy.check(req("block_ip", "203.0.113.99"), low, 0).reason
    unsure = tp_report.model_copy(update={"verdict": Verdict.NEEDS_HUMAN})
    assert not policy.check(req("block_ip", "203.0.113.99"), unsure, 0).allowed
    # non-containment actions remain available
    assert policy.check(req("create_ticket", "x"), unsure, 0).allowed


def test_action_limit(policy, tp_report):
    assert "limit" in policy.check(req("create_ticket", "x"), tp_report, prior_actions=6).reason


def _triage(**kw):
    base = dict(
        alert_id="A",
        verdict=Verdict.FALSE_POSITIVE,
        severity="low",
        confidence=0.95,
        summary="Looks like a scheduled test.",
        escalate=False,
    )
    return TriageResult(**{**base, **kw})


def test_injection_forces_escalation_and_replaces_benign_verdict(policy):
    guard = GuardReport(suspected=True, hits=[InjectionHit(path="$.raw", rule="verdict_steering", excerpt="x")])
    out = policy.apply_triage_floor(_triage(), guard)
    assert out.escalate and out.injection_suspected
    assert out.verdict == Verdict.NEEDS_HUMAN
    assert len(out.overrides) == 2


def test_low_confidence_close_is_overridden(policy):
    out = policy.apply_triage_floor(_triage(confidence=0.6), GuardReport(suspected=False))
    assert out.escalate and "below floor" in out.overrides[0]


def test_confident_benign_close_is_respected(policy):
    out = policy.apply_triage_floor(_triage(), GuardReport(suspected=False))
    assert not out.escalate and out.overrides == []
