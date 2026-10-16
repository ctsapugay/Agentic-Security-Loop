# Goal Charter

> Read this before every work session. It sets **what must be true when done**, **what you may and may not do**, and **when to stop and ask**. It deliberately does *not* say how to build things: architecture, libraries, rule language, file layout, and order of work are yours to decide (and to change when something doesn't work or a better idea appears).
>
> This file and `scripts/gate.py` are **locked**. Do not edit them. The gate prints a hash of both; the human's `/goal` condition names that hash, so any edit is visible.

## The goal

Build the system described in [PROJECT_VISION.md](PROJECT_VISION.md), v1 scope (Section 8): an automated loop that hardens an AgentDojo agent by synthesizing **deterministic security rules**, then run the experiments that answer the research question honestly.

## Done means: all outcomes hold, and `python3 scripts/gate.py` prints `GATE: PASS`

| # | Outcome | How it's verified |
|---|---|---|
| O1 | **A working hardening loop** on at least the AgentDojo **banking** suite: attacker, analyzer, and updater are separate roles; each round attacks, grades, records, diagnoses, rewrites, validates, and rolls back on failure. | Gate: report + ledger show real multi-round runs by each role |
| O2 | **Enforcement is deterministic.** Rules are data (not code an LLM wrote and we execute), and no LLM call happens when deciding allow/deny at runtime. | Gate: ledger has no enforcement-role calls; human review |
| O3 | **No regressions.** Under the final rule set, **zero training attacks succeed**. | Gate **re-runs** your declared replay command and checks the numbers |
| O4 | **Utility floor.** The final rule set completes at least the floor share of benign tasks (see `UTILITY_FLOOR` in the gate). | Gate re-runs replay |
| O5 | **Generalization is measured.** Attack families are split into train and held-out (disjoint, no family in both); results reported for **white-box and black-box** attackers. | Gate: report structure |
| O6 | **Comparison conditions A–F** from Vision Section 7 are run and reported on the same attacks, with the same attacker access for every condition. | Gate: report structure |
| O7 | **Attacker model chosen by data.** A refusal probe compares at least 3 models on refusal rate and attack success. | Gate: probe artifact |
| O8 | **Budget respected and every LLM call accounted for.** | Gate: ledger total ≤ cap |
| O9 | **Explained for the human.** `docs/REPORT.md` explains results with at least one concrete attack walked step by step through the system. `docs/DECISIONS.md` logs each significant design choice and every departure from the vision, with the reason. | Gate: files exist, non-trivial |
| O10 | **Clean engineering.** The project's own tests pass, work is committed on a non-`main` branch, and the working tree is clean. | Gate |

**Honest results beat good-looking results.** Done does *not* require our method to win. If prompt patching (B) beats policies (E), or the loop fails to generalize, that is a valid finding: report it plainly.

### Output contract (the only fixed interface)

The gate reads `results/final/report.json` and `results/ledger.jsonl`. Everything else is up to you.

`report.json` must contain:
- `suites`: list of suite names run.
- `budget`: `{"cap_usd": number, "spent_usd": number}`.
- `families`: `{"train": [...], "heldout": [...]}`.
- `conditions`: an object with keys `A`–`F`. Each holds `{"whitebox": M, "blackbox": M}`, where `M` has numeric `train_asr`, `heldout_asr`, `utility`, `confirmations`, and `rule_count` (use `null` for `rule_count` where no rules exist).
- `loop`: `{"rounds": int, "rollbacks": int}` for condition E.
- `refusal_probe`: list of `{"model": str, "requests": int, "refusal_rate": number, "attack_success_rate": number}`.
- `replay`: `{"command": str, "expected": {"train_attacks_succeeded": int, "train_attacks_total": int, "utility": number}}`. The command must be deterministic, offline (no LLM calls), and print a JSON object with those same three keys on its **last line** of stdout. The gate runs it and compares.

`ledger.jsonl` has one JSON object per LLM API call: `{"role": str, "model": str, "request_id": str, "cost_usd": number}`. `request_id` is the provider's real response ID. Roles must not include `enforcer`.

## Boundaries

### You are free to
- Choose and change the architecture, rule language, libraries, data model, file layout, and order of work.
- Deviate from suggestions in the vision doc when you find something better or something doesn't work. Log it in `docs/DECISIONS.md` with the reason.
- Reuse code from AgentDojo, CaMeL, and Progent (respect their licenses: MIT / Apache-2.0 / MIT), or reimplement.
- Write, restructure, and delete your own tests and code.
- Commit freely on your working branch.

### You must not
- **Edit `GOAL.md` or `scripts/gate.py`**, or otherwise game the gate (e.g., a replay command that prints hard-coded numbers).
- **Fabricate or hand-edit results.** Every number in the report comes from a run that produced it. Never use mocked or fake LLMs for anything reported as a real result (fakes are fine inside tests).
- **Weaken, skip, or delete a test just to get it passing**, unless the test itself was wrong (log why in DECISIONS.md).
- **Exceed the budget.** Enforce the cap in code, before calls are made, not after.
- **Attack anything real.** Attack payloads exist only inside AgentDojo's simulated environments. Never send them to real services, email addresses, URLs, or accounts.
- **Let an LLM make runtime security decisions**, or let the updater see raw attack payloads.
- **Touch `main`**: no pushing, force-pushing, or rewriting history on it. Don't push anywhere without the human's OK.
- **Commit secrets** (`.env` stays git-ignored), or install packages from outside PyPI and the three reference repos.
- **Change the research question or v1 scope** (Vision Sections 7–8) on your own.

### Stop and ask the human when
- An API key or other credential is missing or rejected.
- Spend reaches **80% of the budget cap**.
- A locked file or the output contract looks wrong or impossible to satisfy.
- A change would alter the vision, research question, or v1 scope.
- Something outward-facing would be needed (pushing, publishing, signing up for a service).
- You're stuck: the same blocker has survived 3 genuinely different approaches.

When you stop, say exactly what's blocking, what you tried, and what you need.

## Working habits
- Keep `docs/PROGRESS.md` current: what's done, what's next, and known problems. A fresh session should be able to pick up from it.
- Prefer cheap models and offline/deterministic runs while developing. Spend real budget on the final experiments.
- Show gate output in the transcript when claiming progress. The goal evaluator only sees what you print.
- The human learns best from concrete examples walked through one step at a time. Write docs that way.
