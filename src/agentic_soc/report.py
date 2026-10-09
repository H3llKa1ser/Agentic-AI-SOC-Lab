"""Render a case file as an analyst-readable Markdown report."""

from __future__ import annotations

from agentic_soc.models import CaseFile

ICONS = {
    "auto_executed": "✅",
    "approved_executed": "✅",
    "pending_approval": "⏳",
    "denied": "✋",
    "blocked_by_policy": "⛔",
}


def render_markdown(case: CaseFile) -> str:
    a = case.alert
    out = [
        f"# {a.id}: {a.title}",
        "",
        f"**Outcome:** `{case.outcome}`  ",
        f"**Source:** {a.source}  **Detection severity:** {a.severity.value}  "
        f"**Created:** {a.created_at.isoformat()}  ",
        f"**Run:** `{case.run_id}`",
        "",
        "## Guard scan",
    ]
    if case.guard.suspected:
        out.append(f"⚠️ {len(case.guard.hits)} prompt-injection marker(s) found in alert fields:")
        out += [f"- `{h.path}` ({h.rule}): `{h.excerpt}`" for h in case.guard.hits]
    else:
        out.append("No injection markers in alert fields.")

    if case.triage:
        t = case.triage
        out += [
            "",
            "## Triage",
            f"**Verdict:** {t.verdict.value} · **Severity:** {t.severity.value} · "
            f"**Confidence:** {t.confidence:.2f} · **Escalate:** {t.escalate}",
            "",
            t.summary,
        ]
        if t.overrides:
            out += ["", "**Deterministic policy overrides:**"] + [f"- {o}" for o in t.overrides]

    if case.investigation:
        r = case.investigation
        out += [
            "",
            "## Investigation",
            f"**Verdict:** {r.verdict.value} · **Severity:** {r.severity.value} · **Confidence:** {r.confidence:.2f}",
            "",
            r.summary,
            "",
            "### Timeline",
        ]
        out += [f"- {line}" for line in r.timeline]
        out += ["", "### ATT&CK", ", ".join(f"`{t}`" for t in r.attack_techniques) or "_none_"]
        out += ["", "### Affected entities"]
        out += [f"- **{k}:** {', '.join(v)}" for k, v in r.affected_entities.items()]
        out += ["", "### Evidence"] + [f"- {e}" for e in r.evidence]
        if r.recommended_next_steps:
            out += ["", "### Recommended next steps"] + [f"- {s}" for s in r.recommended_next_steps]

    if case.actions or case.response_rationale:
        out += [
            "",
            "## Response",
            case.response_rationale or "",
            "",
            "| | Action | Target | Decision | Reason |",
            "|---|---|---|---|---|",
        ]
        for d in case.actions:
            out.append(
                f"| {ICONS.get(d.decision.value, '')} | `{d.request.action}` | `{d.request.target}` "
                f"| {d.decision.value} | {d.reason} |"
            )
    if case.error:
        out += ["", "## Pipeline error", f"`{case.error}`"]
    return "\n".join(out) + "\n"
