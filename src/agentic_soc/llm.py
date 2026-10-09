"""Minimal LLM abstraction so the pipeline is testable without network access.

`AnthropicClient` talks to the Claude Messages API with tool use. `ScriptedLLM` replays a
fixed sequence of responses, which lets the test-suite drive the full pipeline
deterministically, including the case where the model has been fully hijacked.
"""

from __future__ import annotations

import copy
import itertools
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

Message = dict[str, Any]


@dataclass
class ToolCall:
    id: str
    name: str
    input: dict[str, Any]


@dataclass
class LLMResponse:
    content: list[dict[str, Any]]
    stop_reason: str = "end_turn"

    @property
    def tool_calls(self) -> list[ToolCall]:
        return [
            ToolCall(b["id"], b["name"], dict(b.get("input") or {}))
            for b in self.content
            if b.get("type") == "tool_use"
        ]

    @property
    def text(self) -> str:
        return "\n".join(b["text"] for b in self.content if b.get("type") == "text")


class LLMClient(Protocol):
    def complete(self, *, system: str, messages: list[Message], tools: list[dict[str, Any]]) -> LLMResponse: ...


class AnthropicClient:
    def __init__(self, model: str, max_tokens: int = 4096) -> None:
        import anthropic  # imported lazily so offline commands work without the SDK

        self._client = anthropic.Anthropic()
        self.model = model
        self.max_tokens = max_tokens

    def complete(self, *, system: str, messages: list[Message], tools: list[dict[str, Any]]) -> LLMResponse:
        resp = self._client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=system,
            messages=messages,
            tools=tools,
        )
        content: list[dict[str, Any]] = []
        for block in resp.content:
            if block.type == "text":
                content.append({"type": "text", "text": block.text})
            elif block.type == "tool_use":
                content.append({"type": "tool_use", "id": block.id, "name": block.name, "input": block.input})
        return LLMResponse(content=content, stop_reason=resp.stop_reason or "end_turn")


Step = LLMResponse | Callable[[list[Message]], LLMResponse]


class ScriptedLLM:
    """Replays a script of responses. Records every call for assertions."""

    def __init__(self, script: list[Step]) -> None:
        self._script = list(script)
        self.calls: list[dict[str, Any]] = []

    def complete(self, *, system: str, messages: list[Message], tools: list[dict[str, Any]]) -> LLMResponse:
        self.calls.append({"system": system, "messages": copy.deepcopy(messages), "tools": [t["name"] for t in tools]})
        if not self._script:
            raise RuntimeError("ScriptedLLM script exhausted")
        step = self._script.pop(0)
        return step(messages) if callable(step) else step


_ids = itertools.count(1)


def tool_use(name: str, **tool_input: Any) -> LLMResponse:
    return LLMResponse(
        content=[{"type": "tool_use", "id": f"toolu_{next(_ids):05d}", "name": name, "input": tool_input}],
        stop_reason="tool_use",
    )


def text(message: str) -> LLMResponse:
    return LLMResponse(content=[{"type": "text", "text": message}])
