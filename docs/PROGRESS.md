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
