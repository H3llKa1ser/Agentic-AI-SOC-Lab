# Architecture

## Trust zones

| Zone | Contents | Treatment |
|---|---|---|
| Trusted code | orchestrator, policy engine, guard scanner, audit log, `config/policy.yaml` | Decides what happens. Never influenced by model output except through validated fields. |
| Trusted context | identity directory, asset inventory, local ATT&CK subset | Returned to agents unwrapped. In production these are systems of record and need their own integrity controls. |
| Untrusted data | alerts, log events, threat-intel responses, related alerts | Spotlighted, scanned, never interpreted as instructions. |
| Untrusted model output | every agent's free text and submissions | Schema-validated; passed downstream only inside untrusted boundaries; acted on only through policy. |

## Case lifecycle

1. **Guard scan.** Alert title, description, entities and raw payload are walked recursively and matched against injection heuristics (instruction override, role hijack, verdict steering, escalation suppression, tool invocation, delimiter spoofing, invisible Unicode). The result is a `GuardReport` with JSON paths to each hit.
2. **Triage.** Fast first pass with four read-only tools and a 6-step budget. Ends with `submit_triage`.
3. **Triage floor.** Deterministic overrides: injected alerts cannot be closed and benign verdicts on them become `needs_human`; true positives must escalate; low-confidence closes are escalated. Overrides are recorded on the case.
4. **Investigation.** Full read-only toolset, 16-step budget. The triage result is passed as untrusted model output to verify, not inherit. Ends with `submit_investigation`; ATT&CK IDs are format-validated and the model can check them against the local subset.
5. **Response planning.** Only for confirmed true positives. The responder gets context lookups and a `check_action_policy` dry-run tool, and returns proposals.
6. **Enforcement.** Each proposal is checked by the policy engine, then auto-executed (auto tier), sent to the approver (approval tier) or blocked with a reason. The non-interactive approver defers everything, so nothing gated runs without a human.
7. **Close.** The case file (JSON + Markdown) and audit chain are written to `runs/<run_id>/`.

## Policy checks, in order

1. Forbidden action list → block
2. Not in allow-list → block (default deny)
3. Per-incident action limit
4. Target validation by type: `ip` (valid, not in protected CIDRs), `user` (exists in directory, not break-glass/protected), `host` (exists, not protected), `access_key` (AWS key ID format), `indicator`, `free_text`
5. Containment actions require a `true_positive` verdict at or above the confidence floor
6. Tier decides auto-execute vs human approval

Protected identities and hosts are derived from the directory flags (`break_glass`, `protected`) as well as the explicit lists in `policy.yaml`, so newly flagged assets are covered without a policy change.

## Agent loop

`agents.Agent.run` is a plain Messages API tool-use loop:

- tools = agent's scoped registry + its submit tool
- model calls a submit tool → validate with Pydantic → return, or send the validation error back as `is_error` tool result
- model calls other tools → execute through the registry (errors become tool results, never exceptions)
- model replies in free text → nudge to submit
- step budget exceeded → `AgentBudgetExceeded`, case escalated to a human

## Extending

**A real log backend.** Implement `search_logs` and `summarize_logs` against Splunk, Sentinel or Databricks while keeping the same input schema. Translate the typed filters into a parameterised query server-side; do not let the model supply query text.

**A real executor.** Implement the `Executor` protocol in `response.py`, e.g. adding IPs to a Cloudflare IP list, revoking Entra ID sessions via Microsoft Graph, or deactivating an IAM access key. Keep it behind `Pipeline._enforce`; never give an agent the executor as a tool.

**A new action.** Add it to `config/policy.yaml` with a tier and target type. It appears in the responder's catalogue and submit schema automatically.

**A new scenario.** Add events to `scripts/generate_fixtures.py`, regenerate, and add expectations to `evals/scenarios.yaml`.
