"""Refusal probe (GOAL_PHASE2.md P3): same ≥40 white-box requests per model, on A and v1 F.

    uv run python -m policyforge.p2.probe

Stops on CreditStop / BudgetStop without recording that failure as a refusal.
Resumes from rows already in results/phase2/attacks.sqlite.
"""

from __future__ import annotations

import json
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

from policyforge.attacks import AttackSample
from policyforge.p2.goals import sample_id
from policyforge.p2.samples import samples
from policyforge.p2.store import Store
from policyforge.p2.strategies import StrategyLibrary

# GPT-class, open-weight, Claude. Cheap enough that a credit failure is the stop, not the model list.
MODELS = (
    "or:qwen/qwen3-235b-a22b-2507",
    "or:openai/gpt-4.1-mini",
    "anthropic:claude-haiku-5-5",
)
DEFENSE = {
    "A": "results/phase2/defenses/prompt_A.txt",
    "F_v1": "results/final/rules_F.yaml",
}
RUNTIME = {"A": "plain", "F_v1": "camel"}
N_PER_TARGET = 20
WORKERS = 3
DB = "results/phase2/attacks.sqlite"


@dataclass(frozen=True)
class Job:
    model: str
    condition: str
    sample: AttackSample

    @property
    def uid(self) -> str:
        sid = sample_id(self.sample.user_task_id, self.sample.injection_task_id, self.sample.family)
        return f"{self.condition}:probe:{self.model}:{sid}:1"


def probe_pool() -> list[AttackSample]:
    pool = samples(families=("instruction", "laundering", "control_flow"))
    pool.sort(key=lambda s: sample_id(s.user_task_id, s.injection_task_id, s.family))
    need = 2 * N_PER_TARGET
    if len(pool) < need:
        raise RuntimeError(f"need {need} train samples, have {len(pool)}")
    return pool[:need]


def jobs(*, models: tuple[str, ...] = MODELS) -> list[Job]:
    pool = probe_pool()
    a_samples, f_samples = pool[:N_PER_TARGET], pool[N_PER_TARGET:]
    out: list[Job] = []
    for model in models:
        for s in a_samples:
            out.append(Job(model, "A", s))
        for s in f_samples:
            out.append(Job(model, "F_v1", s))
    return out


def _one(job: Job, store: Store, library: StrategyLibrary) -> str:
    from policyforge import agent
    from policyforge.p2.attacker import AdaptiveAttacker
    from policyforge.p2.campaign import Campaign
    from policyforge.p2.handles import DefenseView
    from policyforge.rules import RuleSet

    if store.has_uid(job.uid):
        return f"skip {job.uid}"
    rules = None
    if job.condition == "F_v1":
        rules = RuleSet.from_yaml(Path(DEFENSE["F_v1"]).read_text())
    src = AdaptiveAttacker(
        model=job.model,
        mode="whitebox",
        condition=job.condition,
        library=library,
        store=store,
        defense=DefenseView(DEFENSE[job.condition]),
    )
    camp = Campaign(
        attacker=src,
        store=store,
        defense_dir="results/phase2/defenses",
        condition=job.condition,
        runtime=RUNTIME[job.condition],
        phase="probe",
        k=1,
        system_prompt=agent.DEFAULT_SYSTEM_PROMPT,
        library=library,
    )
    camp.attacker.defense.load(DEFENSE[job.condition])
    try:
        results = camp.attack_sample(job.sample, rules)
    except Exception as e:  # noqa: BLE001 — one bad episode must not abort the other workers
        return f"ERROR {job.uid}: {type(e).__name__}: {e}"
    if not results:
        return f"empty {job.uid}"
    r = results[0]
    refused = not any(r.payload.values())
    return (
        f"{job.uid} model={job.model} success={int(r.success)} refused={int(refused)} "
        f"calls={len(r.trace.calls)}"
    )


def _summarize(store: Store) -> None:
    from policyforge import llm

    rows = store.query(
        "SELECT attacker_model, condition, live_success, payload_json FROM attempts WHERE phase = 'probe'"
    )
    per: dict[str, dict] = defaultdict(lambda: {"n": 0, "refused": 0, "succ_A": 0, "succ_F": 0})
    for r in rows:
        m = per[r["attacker_model"]]
        m["n"] += 1
        payload = json.loads(r["payload_json"] or "{}")
        if not any(str(v).strip() for v in payload.values()):
            m["refused"] += 1
        if r["live_success"]:
            if r["condition"] == "A":
                m["succ_A"] += 1
            else:
                m["succ_F"] += 1
    print(f"phase 2 spend: ${llm.ledger().spent():.4f} of ${llm.BUDGET_CAP_USD:.0f}")
    for name, m in sorted(per.items()):
        rate = m["refused"] / m["n"] if m["n"] else 0
        print(
            f"  {name}: rows={m['n']} refusal={rate:.1%} "
            f"success A={m['succ_A']} F_v1={m['succ_F']}"
        )


def main() -> None:
    from policyforge.p2 import ensure_ledger

    ensure_ledger()
    from policyforge import llm

    lib = StrategyLibrary()
    store = Store(DB)
    store.seed(lib)
    todo = [
        j
        for j in jobs()
        if not store.has_uid(j.uid)
        and not store.has_probe(
            j.condition,
            j.model,
            sample_id(j.sample.user_task_id, j.sample.injection_task_id, j.sample.family),
            1,
        )
    ]
    print(f"probe jobs remaining: {len(todo)} / {len(jobs())}")
    try:
        with ThreadPoolExecutor(WORKERS) as pool:
            futs = [pool.submit(_one, j, store, lib) for j in todo]
            for fut in as_completed(futs):
                print(fut.result(), flush=True)
    except llm.CreditStop as e:
        _summarize(store)
        raise SystemExit(f"CREDIT STOP: {e}") from e
    except llm.BudgetStop as e:
        _summarize(store)
        raise SystemExit(f"BUDGET STOP: {e}") from e
    _summarize(store)


if __name__ == "__main__":
    main()
