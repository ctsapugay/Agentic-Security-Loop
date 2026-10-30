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

## Phase 2: `AdaptiveAttacker` (`policyforge.p2.attacker`)

An LLM `AttackSource` for AgentDojo banking. Families are mechanisms (`instruction`, `laundering`, `control_flow` train; `value_swap`, `chain` held-out), not v1 template names.

- Construct it with a `DefenseView` (current rules or prompt file) and a `FeedbackMemory` (the phase-2 store). The frozen loop can keep calling `payloads(sample)`; the attacker reads the handles itself. `defense=` / `feedback=` still work as a pass-through.
- White-box prompts include the full defense file. Black-box prompts are one template filled with goal, vectors, a **seed** strategy, and `{attempt, payload, success}` for earlier tries on that sample.
- Log calls with `role="attacker"`. The store records `gate_attacker_calls` so the phase-2 gate can re-render black-box prompts.
- The live loop is `Campaign` (`policyforge.p2.campaign`): *k* attempts, white-box stopping-check memory, librarian on success, then `harden()` into the frozen analyzer/updater. Validation stays deterministic replay of recorded traces.

Pass the attacker to `Campaign` (phase 2) or to `run_policy_loop` / eval in place of `BuiltinAttackSource`.
