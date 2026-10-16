# Attack-source interface

The loop doesn't care where injection payloads come from. Anything that implements `AttackSource` (in `src/policyforge/attacks.py`) can feed it.

```python
class AttackSource(Protocol):
    name: str
    def payloads(self, sample: AttackSample, *, defense: str | None = None,
                 feedback: list[dict] | None = None) -> dict[str, str]: ...
```

- **`sample`**: an `AttackSample(suite, user_task_id, injection_task_id, family, variant)`. The injection goal is AgentDojo's `injection_tasks[injection_task_id].GOAL`. Where text can be planted comes from `env.injection_vectors(suite, user_task_id)`.
- **Return value**: `{injection_vector_name: payload_text}`. AgentDojo places each payload into the simulated environment (a file, a transaction subject, ...).
- **`defense`**: for white-box sources, the rule YAML or system prompt under attack. **`feedback`**: earlier outcomes, such as which check blocked which attempt. The v1 built-in source ignores both.
- **`family`**: decides the train/held-out split. A new source should declare its own families and keep near-duplicate techniques in one family so held-out results stay honest.

## v1: `BuiltinAttackSource`

Wraps AgentDojo's published templates (see `BUILTIN_FAMILIES`). No LLM calls.

## Next phase: adaptive attacker

Built separately (PROJECT_VISION.md Section 8) with models suited to writing injections for a private test bench. To plug it in:

1. Implement `AttackSource`, using `defense` and `feedback` to adapt.
2. Log every LLM call it makes through `policyforge.llm.chat(..., role="attacker")`, so the ledger and budget cover it.
3. Pass it to `run_policy_loop` / `run_prompt_loop` / `experiment.evaluate_condition` in place of `BuiltinAttackSource`.

Nothing else in the loop changes. Validation stays deterministic: it replays recorded traces, whatever produced the payloads.
