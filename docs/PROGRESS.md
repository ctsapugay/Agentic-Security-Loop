# Progress

## Done (branch dev-day-0)
- **Rule language and engine** (`rules.py`): data-only YAML.
  - Progent-style argument constraints, plus CaMeL-style `origin`, `readers`, and private-control-flow conditions.
  - Default deny, with block / ask_user fallbacks.
  - Z3 shadowed-rule check (`solver.py`).
- **Protected agent on CaMeL's runtime** (`camel_runtime.py`): CaMeL's planner and quarantined extractor (deepseek-v4-pro), with our rules in CaMeL's policy hook. Every attempted call is recorded with CaMeL's dataflow labels.
- **Plain tool-calling agent** (`agent.py`, qwen3-235b) for conditions A and B.
- **AgentDojo adapter** (`env.py`): episodes, deterministic replay that halts at the first denial (like CaMeL), and AgentDojo grading.
- **Attack source** (`attacks.py`): pluggable interface. v1 uses AgentDojo's built-in templates; families are split into train and held-out. See `docs/ATTACK_SOURCE.md`.
- **Loop** (`loop.py`, `roles.py`, `validate.py`):
  - The trace bank is recorded once from CaMeL in observe mode.
  - The analyzer answers only in a strict schema.
  - The updater never sees payloads.
  - Deterministic validation replays every past attack and the benign bank, then accepts or rolls back.
  - The prompt-only loop (B) runs live.
- **Experiment runner** (`experiment.py`): resumable, writes `results/final/`. The replay CLI (`replay.py`) is what the gate re-runs.
- **Model choices by data:** `results/agent_probe.json`, `results/planner_probe.json`.

## Status
The full study is running or done; see `results/final/report.json` and `docs/REPORT.md`.

## Known problems / next
- AgentDojo's built-in attacks almost never get past CaMeL's isolation (1 of 210 loop attacks), so v1 can show little on the security side. The next-phase adaptive attacker (`docs/ATTACK_SOURCE.md`) is the main follow-up.
- The analyzer's strict schema sometimes rejects its output (e.g., an over-long value). The loop then proceeds with no diagnoses, and the updater works from validation feedback alone.
- Only the banking suite has been run.

## Phase 2 (branch phase-2-attacker)
- Plan and decisions: `docs/ADAPTIVE_ATTACKER_PLAN.md`. Charter: `GOAL_PHASE2.md`. Done check: `python3 -I scripts/gate_phase2.py`.
- Ledger routing, `CreditStop`, preflight, and attempt IDs are in. Preflight calls are in `results/phase2/ledger.jsonl`.
- **Adaptive attacker + campaign** (`src/policyforge/p2/`): White-box **hypothesizes** a new idea from the YAML + scoreboard + last miss, then plants text. A per-defense **fingerprint scoreboard** skips ideas that already missed (0 hits). Hits can become learned cards. `Campaign.harden` **retries the updater on the frozen log** (no new attacks) until replay covers every logged hit or attempts run out. Black-box is still seeds + success bits. Proven with fakes (`tests/test_p2_campaign.py`, `tests/test_p2_scoreboard.py`).
- **Cheap live smoke** (not the study, not the refusal probe): white-box against v1 F rules, one `user_task_0` / `injection_task_5` / `laundering` sample. `anthropic:claude-haiku-5-5` refused (empty hypothesis, then an explicit refusal on the plant). `or:qwen/qwen3-235b-a22b-2507` returned JSON and a bill payload; the following CaMeL episode did not send money. Spend is in `results/phase2/ledger.jsonl` (~$0.044 total phase 2 so far). Artifacts under `results/phase2/smoke/`.
- Not done: refusal probe (P3), retraining B/E/F, A–F eval, canary run, `docs/REPORT_PHASE2.md`.
- Phase 2 writes only under `results/phase2/`. v1's results, ledger, charter, and gate stay byte-identical.
