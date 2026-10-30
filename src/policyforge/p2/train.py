"""Retrain B, E, F against the probe-chosen attacker on train families only.

    uv run python -m policyforge.p2.train

Resumes from results/phase2/attacks.sqlite. Stops on CreditStop / BudgetStop.
"""

from __future__ import annotations

import json
from pathlib import Path

from policyforge.attacks import AttackSample
from policyforge.env import Trace
from policyforge.p2.goals import sample_id
from policyforge.p2.split import split
from policyforge.p2.store import Store
from policyforge.p2.strategies import StrategyLibrary

ATTACKER = "or:openai/gpt-4.1-mini"
MIN_ATTEMPTS = 50
ROUND = 8
K = 3
MAX_ROUNDS = 10
MAX_SETTLE = 3
DB = "results/phase2/attacks.sqlite"
DEFENSE_DIR = Path("results/phase2/defenses")
STATE_DIR = Path("results/phase2/train")
HANDWRITTEN = Path("rules/handwritten_banking.yaml")


def _sid(s: AttackSample) -> str:
    return sample_id(s.user_task_id, s.injection_task_id, s.family)


def _n_train(store: Store, condition: str) -> int:
    return len(store.query("SELECT uid FROM attempts WHERE phase = 'train' AND condition = ?", (condition,)))


def _has_sample(store: Store, condition: str, sid: str) -> bool:
    return bool(
        store.query(
            "SELECT 1 FROM attempts WHERE phase = 'train' AND condition = ? AND sample_id = ? LIMIT 1",
            (condition, sid),
        )
    )


def _save_traces(condition: str, traces: list[tuple[int, Trace]]) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    path = STATE_DIR / f"{condition}_traces.jsonl"
    path.write_text("".join(json.dumps(t.to_dict()) + "\n" for _, t in traces))


def _load_traces(condition: str) -> list[tuple[int, Trace]]:
    path = STATE_DIR / f"{condition}_traces.jsonl"
    if not path.exists():
        return []
    out = []
    for i, line in enumerate(path.read_text().splitlines()):
        if line.strip():
            out.append((i, Trace.from_dict(json.loads(line))))
    return out


def _seed_files() -> None:
    from policyforge import agent
    from policyforge import env as E
    from policyforge.rules import allow_all

    DEFENSE_DIR.mkdir(parents=True, exist_ok=True)
    b0 = DEFENSE_DIR / "B_v0.txt"
    if not b0.exists():
        b0.write_text(agent.DEFAULT_SYSTEM_PROMPT)
    e0 = DEFENSE_DIR / "E_v0.yaml"
    if not e0.exists():
        e0.write_text(allow_all(E.tool_schemas("banking")).to_yaml())
    f0 = DEFENSE_DIR / "F_v0.yaml"
    if not f0.exists():
        f0.write_text(HANDWRITTEN.read_text())


def _latest_defense(condition: str) -> Path:
    ext = "txt" if condition == "B" else "yaml"
    best, n = None, -1
    for p in DEFENSE_DIR.glob(f"{condition}_v*.{ext}"):
        try:
            v = int(p.stem.rsplit("_v", 1)[-1])
        except ValueError:
            continue
        if v > n:
            best, n = p, v
    if best is None:
        raise FileNotFoundError(condition)
    return best


def _camel_benign() -> list[Trace]:
    from policyforge import loop

    path = STATE_DIR / "benign_camel.jsonl"
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return [Trace.from_dict(json.loads(l)) for l in path.read_text().splitlines() if l.strip()]
    from policyforge import env as E

    out = []
    for ut in E.suite("banking").user_tasks:
        t = loop.episode("camel", "banking", ut, rules=None, mode="observe", tag=f"benign:{ut}")
        out.append(t)
        print(f"benign {ut} utility={t.utility}", flush=True)
    path.write_text("".join(json.dumps(t.to_dict()) + "\n" for t in out))
    return out


def _run_condition(condition: str, store: Store, library: StrategyLibrary, pool: list[AttackSample]) -> None:
    from policyforge import llm
    from policyforge.p2.attacker import AdaptiveAttacker
    from policyforge.p2.campaign import Campaign
    from policyforge.p2.handles import DefenseView
    from policyforge.rules import RuleSet

    defense = _latest_defense(condition)
    src = AdaptiveAttacker(
        model=ATTACKER,
        mode="whitebox",
        condition=condition,
        library=library,
        store=store,
        defense=DefenseView(defense),
    )
    camp = Campaign(
        attacker=src,
        store=store,
        defense_dir=DEFENSE_DIR,
        condition=condition,
        runtime="plain" if condition == "B" else "camel",
        phase="train",
        k=K,
        update_attempts=2 if condition == "B" else 3,
        system_prompt=defense.read_text() if condition == "B" else "",
        library=library,
    )
    camp.traces = _load_traces(condition)
    rules = None if condition == "B" else RuleSet.from_yaml(defense.read_text())
    benign = [] if condition == "B" else _camel_benign()
    version = int(defense.stem.rsplit("_v", 1)[-1]) + 1
    done = {_sid(s) for s in pool if _has_sample(store, condition, _sid(s))}
    todo = [s for s in pool if _sid(s) not in done]
    print(f"{condition}: {_n_train(store, condition)} attempts, {len(todo)} samples left, defense {defense}", flush=True)
    i = 0
    rnd = 0
    settle = 0
    while True:
        rnd += 1
        n_att = _n_train(store, condition)
        if rnd > MAX_ROUNDS:
            print(f"{condition}: hit MAX_ROUNDS", flush=True)
            break
        if n_att >= MIN_ATTEMPTS:
            batch = []
            settle += 1
            if settle > MAX_SETTLE:
                print(f"{condition}: settle budget exhausted with leftover hits", flush=True)
                break
        else:
            batch = todo[i : i + ROUND]
            i += ROUND
            if not batch:
                print(f"{condition}: train pool exhausted at {n_att} attempts", flush=True)
                break
        for s in batch:
            try:
                got = camp.attack_sample(s, rules)
            except llm.CreditStop:
                _save_traces(condition, camp.traces)
                raise
            print(
                f"{condition} {_sid(s)} attempts={len(got)} success={int(any(r.success for r in got))}",
                flush=True,
            )
        _save_traces(condition, camp.traces)
        if condition == "B":
            val = camp.harden_prompt(
                camp.system_prompt or defense.read_text(),
                version=version,
                base_utility=0.7,
            )
            if val.accepted and camp.attacker.defense.snap and Path(camp.attacker.defense.snap.path).name != defense.name:
                defense = Path(camp.attacker.defense.snap.path)
                camp.system_prompt = defense.read_text()
                version += 1
            print(f"{condition} harden accepted={val.accepted} {val.reasons[:2]}", flush=True)
        else:
            text = defense.read_text()
            val = camp.harden(text, benign=benign, version=version)
            if val.accepted and val.rules is not None and camp.attacker.defense.snap:
                newp = Path(camp.attacker.defense.snap.path)
                if newp != defense:
                    defense = newp
                    rules = val.rules
                    version += 1
            print(f"{condition} harden accepted={val.accepted} {val.reasons[:2]}", flush=True)
        if _n_train(store, condition) >= MIN_ATTEMPTS and not any(t.attack_success for _, t in camp.traces):
            break
    print(f"{condition} done: {_n_train(store, condition)} attempts, defense {_latest_defense(condition)}", flush=True)


def main() -> None:
    from policyforge.p2 import ensure_ledger

    ensure_ledger()
    from policyforge import llm

    _seed_files()
    lib = StrategyLibrary()
    store = Store(DB)
    store.seed(lib)
    pools = split()
    print(f"train pool {len(pools['train'])} reserved eval_train {len(pools['eval_train'])}", flush=True)
    try:
        for cond in ("B", "E", "F"):
            _run_condition(cond, store, lib, pools["train"])
    except llm.CreditStop as e:
        raise SystemExit(f"CREDIT STOP: {e}\nphase 2 spend ${llm.ledger().spent():.4f}") from e
    except llm.BudgetStop as e:
        raise SystemExit(f"BUDGET STOP: {e}\nphase 2 spend ${llm.ledger().spent():.4f}") from e
    print(f"phase 2 spend ${llm.ledger().spent():.4f} of ${llm.BUDGET_CAP_USD:.0f}")
    for cond in "BEF":
        print(f"  {cond} train attempts {_n_train(store, cond)}")


if __name__ == "__main__":
    main()
