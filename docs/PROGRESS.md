# Progress

## Done (branch dev-day-0)
- Rule engine (`rules.py`): data-only YAML rules, Progent-style argument constraints plus CaMeL-style origin conditions, default deny, block/ask_user fallbacks. 21 tests pass.
- Z3 shadow check (`solver.py`): rejects allow rules that a deny rule makes dead.
- Provenance labels (`provenance.py`): deterministic, field-level, at the tool-call boundary.
- AgentDojo adapter (`env.py`): episodes, the enforcement checkpoint, offline trace replay with AgentDojo grading, ground-truth benign traces. All 16 banking ground-truth tasks replay with utility.
- LLM layer (`llm.py`): OpenRouter and Anthropic, a ledger of every call, budget stop at 80% of the cap.
- Live agent (`agent.py`, gpt-4o-mini): confirmed attackable by AgentDojo's built-in attack.
- Attack store (`attackdb.py`): SQLite.

## Blocked
- The attacker component (an LLM that writes new prompt injections) was not built. See the stop report in the session.

## Next (after the blocker is resolved)
Attacker, analyzer, updater, validation, loop, refusal probe, experiments A–F, report.
