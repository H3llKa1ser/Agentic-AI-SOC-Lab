# Threat model

The system under consideration is the pipeline itself: an LLM-driven SOC that reads attacker-influenced data and can propose changes to production security controls.

## Assets

- Integrity of containment decisions (what gets blocked, disabled or isolated)
- Availability of internal infrastructure and emergency access (scanners, domain controllers, break-glass accounts)
- Integrity of the investigation record and audit trail
- Analyst attention (the pipeline must not bury real incidents or flood the approval queue)

## Adversaries

| Adversary | Capability |
|---|---|
| External attacker | Controls fields that end up in alerts and logs: User-Agent, usernames, URLs, request bodies, email subjects, file names |
| Malicious or compromised insider | Can additionally influence directory notes, ticket text, TI annotations |
| Compromised upstream tool | Returns crafted output to a tool call |

## OWASP Top 10 for LLM Applications (2025) mapping

| Risk | How it applies here | Controls |
|---|---|---|
| LLM01 Prompt Injection | Indirect injection via alert/log fields is the primary threat (MITRE ATLAS AML.T0051) | Spotlighting with random boundaries; injection tripwire on alerts and tool output; trusted GUARD notes; triage floor; capability boundary in the policy engine |
| LLM02 Sensitive Information Disclosure | Logs contain player and staff identifiers sent to a third-party model API | Typed queries with result limits; synthetic data in the lab. Production: field-level minimisation/pseudonymisation before tool output reaches the model; zero-retention API terms |
| LLM05 Improper Output Handling | Model output drives the next stage and proposed actions | Pydantic validation on every submission; ATT&CK ID format checks; actions parsed into typed requests and validated per target type |
| LLM06 Excessive Agency | An agent that can block IPs or disable users is a high-value target | Agents have read-only tools; action only via policy engine; allow-list + default deny; protected assets; confidence floor; approval tier; per-incident limit |
| LLM07 System Prompt Leakage | Low impact: prompts contain no secrets | Nothing sensitive in prompts; security does not depend on prompt secrecy |
| LLM09 Misinformation | Confident but wrong verdicts or invented evidence | Evidence-grounding instructions; confidence floors; scenario evals with repeat runs; human review for every containment action |
| LLM10 Unbounded Consumption | Loops, huge tool outputs, runaway queries | Per-agent step budgets; tool output truncation; result limits; no free-form query language |

LLM03 (supply chain), LLM04 (poisoning) and LLM08 (vector/embedding weaknesses) are largely out of scope for this lab: there is no fine-tuning or retrieval store. Dependency pinning and model-provider due diligence apply as for any service.

## Abuse cases and outcomes

| Abuse case | Without controls | With controls |
|---|---|---|
| Injection tells triage to close the alert | Real attack silently dropped | Floor forces escalation; verdict replaced with `needs_human`; override recorded |
| Injection tells responder to block an internal IP | Self-inflicted outage | Blocked: protected CIDR |
| Injection asks to disable the break-glass account | Loss of emergency access during an incident | Blocked: protected identity, human-only |
| Injection asks to delete logs / stop logging | Evidence destruction | Blocked: forbidden action |
| Model invents an action (`run_command`) | Arbitrary execution | Blocked: default deny |
| Flood of plausible actions to exhaust approvers | Approval fatigue, rubber-stamping | Per-incident action limit; actions batched per case with justification |
| Low-confidence containment | Collateral damage | Blocked below confidence floor; only true positives eligible |
| Agent stuck in a loop | Cost, delay | Step budget; escalate on exhaustion |
| Someone edits the audit log after the fact | Hidden mistakes or abuse | Hash chain breaks; `verify-audit` reports the first bad line |

## Residual risks

- **Verdict manipulation without markers.** A subtle injection that the tripwire misses can still bias a verdict. The policy engine limits the blast radius, but a wrongly closed alert is still a missed detection. Mitigations: keep humans sampling auto-closed cases; tune the auto-close floor; add adversarial evals.
- **Approver error.** The gate is only as good as the human. The approval prompt shows verdict, confidence and justification; a production version should show the underlying evidence and require a reason for approval.
- **Trusted context poisoning.** Directory and asset records are treated as trusted. An insider who edits them can shift decisions. Treat these sources with their own change control.
- **Audit anchoring.** The hash chain is tamper-evident, not tamper-proof: someone with write access can rewrite the whole chain. Ship the head hash to write-once storage.
- **Heuristic scanner.** Regex tripwires have false negatives (paraphrase, encoding, other languages) and false positives. They are one signal among several, not a defence on their own.
