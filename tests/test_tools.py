import json


def test_search_logs_filters_and_spotlights(registry):
    out, err = registry.execute("search_logs", {"source": "web", "filters": {"username": "player-48213"}})
    assert not err
    assert out.startswith("<<UNTRUSTED:") and "<<END_UNTRUSTED:" in out
    body = json.loads(out.split("\n", 1)[1].rsplit("\n<<END_UNTRUSTED", 1)[0])
    assert body["total_matches"] == 4
    assert {e["path"] for e in body["events"]} >= {"/api/account/payout-method", "/api/withdrawals"}


def test_summarize_counts_stuffing_burst(registry):
    out, _ = registry.execute(
        "summarize_logs",
        {
            "source": "web",
            "group_by": "client_ip",
            "filters": {"status": "401"},
            "start": "2026-09-14T02:00:00Z",
            "end": "2026-09-14T02:30:00+00:00",
        },
    )
    assert '"total_matches": 240' in out and "203.0.113.12" in out


def test_tool_output_injection_gets_trusted_guard_note(registry):
    out, _ = registry.execute("search_logs", {"source": "web", "filters": {"client_ip": "203.0.113.99"}, "limit": 1})
    assert "GUARD (trusted)" in out


def test_ip_reputation_matches_corporate_range(registry):
    out, _ = registry.execute("lookup_ip_reputation", {"ip": "198.51.100.20"})
    assert "corporate-vpn-egress" in out and "198.51.100.16/28" in out


def test_trusted_context_is_not_wrapped(registry):
    out, _ = registry.execute("get_user_context", {"user": "BREAKGLASS-01@luckylynx.example"})
    assert not out.startswith("<<UNTRUSTED") and '"break_glass": true' in out


def test_errors_are_returned_not_raised(registry):
    out, err = registry.execute("search_logs", {"source": "nope"})
    assert err and "unknown source" in out
    out, err = registry.execute("search_logs", {"sourcee": "web"})
    assert err
    out, err = registry.execute("disable_user", {"user": "x"})
    assert err and "not available" in out
