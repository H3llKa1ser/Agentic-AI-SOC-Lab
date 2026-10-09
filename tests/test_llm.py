from types import SimpleNamespace

from agentic_soc.llm import AnthropicClient


def test_anthropic_client_maps_blocks_and_passes_tools(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    client = AnthropicClient("claude-test-model")
    seen = {}

    def fake_create(**kwargs):
        seen.update(kwargs)
        return SimpleNamespace(
            stop_reason="tool_use",
            content=[
                SimpleNamespace(type="text", text="Checking reputation."),
                SimpleNamespace(
                    type="tool_use", id="toolu_1", name="lookup_ip_reputation", input={"ip": "203.0.113.10"}
                ),
                SimpleNamespace(type="thinking", thinking="ignored"),
            ],
        )

    monkeypatch.setattr(client._client.messages, "create", fake_create)
    tools = [{"name": "lookup_ip_reputation", "description": "d", "input_schema": {"type": "object"}}]
    resp = client.complete(system="sys", messages=[{"role": "user", "content": "hi"}], tools=tools)

    assert seen["model"] == "claude-test-model" and seen["tools"] == tools and seen["system"] == "sys"
    assert resp.text == "Checking reputation."
    assert [c.name for c in resp.tool_calls] == ["lookup_ip_reputation"]
    assert resp.tool_calls[0].input == {"ip": "203.0.113.10"}
    assert len(resp.content) == 2
