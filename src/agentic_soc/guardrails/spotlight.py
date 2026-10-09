"""Spotlighting: wrap untrusted data in unguessable boundary markers.

The boundary token is random per wrap, so attacker-controlled content cannot forge a
closing marker and "escape" into the instruction channel. This reduces, but does not
eliminate, prompt-injection risk; the hard guarantee comes from the policy engine.
"""

from __future__ import annotations

import secrets


def spotlight(data: str, source: str) -> str:
    token = secrets.token_hex(8)
    return f"<<UNTRUSTED:{token} source={source}>>\n{data}\n<<END_UNTRUSTED:{token}>>"
