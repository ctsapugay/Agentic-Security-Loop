"""Evaluate A–F white-box and black-box on the same reserved samples.

    uv run python -m policyforge.p2.eval

Resumes from results/phase2/attacks.sqlite. Stops on CreditStop / BudgetStop.
"""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

from policyforge.attacks import AttackSample
from policyforge.p2.goals import sample_id
from policyforge.p2.split import eval_pool, split
from policyforge.p2.store import Store
from policyforge.p2.strategies import StrategyLibrary
from policyforge.p2.train import ATTACKER, DB, DEFENSE_DIR, HANDWRITTEN, K

ROOT = Path(__file__).resolve().parents[3]
V1_D = ROOT / "results/final/rules_D.yaml"


def _sid(s: AttackSample) -> str:
    return sample_id(s.user_task_id, s.injection_task_id, s.family)


def _seed_eval_defenses() -> None:
    from policyforge import agent

    DEFENSE_DIR.mkdir(parents=True, exist_ok=True)
    a = DEFENSE_DIR / "prompt_A.txt"
    if not a.exists():
        a.write_text(agent.DEFAULT_SYSTEM_PROMPT)
    c = DEFENSE_DIR / "C_v0.yaml"
    if not c.exists():
        c.write_text(HANDWRITTEN.read_text())
    d = DEFENSE_DIR / "D_v0.yaml"
    if not d.exists():
        shutil.copy(V1_D, d)
    b = DEFENSE_DIR / "B_v3.txt"
    e = DEFENSE_DIR / "E_v3.yaml"
    f = DEFENSE_DIR / "F_v0.yaml"
    for p in (b, e, f):
        if not p.exists():
            raise FileNotFoundError(f"missing trained defense {p}")


def _defense(condition: str) -> Path:
    return {
        "A": DEFENSE_DIR / "prompt_A.txt",
        "B": DEFENSE_DIR / "B_v3.txt",
        "C": DEFENSE_DIR / "C_v0.yaml",
        "D": DEFENSE_DIR / "D_v0.yaml",
        "E": DEFENSE_DIR / "E_v3.yaml",
        "F": DEFENSE_DIR / "F_v0.yaml",
    }[condition]


def _spec(condition: str) -> dict:
    from camel.pipeline_elements.security_policies import BankingSecurityPolicyEngine

    from policyforge.rules import RuleSet

    path = _defense(condition)
    if condition in {"A", "B"}:
        return {
            "runtime": "plain",
            "rules": None,
            "prompt": path.read_text(),
            "delegate": None,
            "episode_mode": "observe",
            "skip_apply": False,
        }
    if condition == "C":
        return {
            "runtime": "camel",
            "rules": None,
            "prompt": "",
            "delegate": BankingSecurityPolicyEngine,
            "episode_mode": "enforce",
            "skip_apply": True,
        }
    return {
        "runtime": "camel",
        "rules": RuleSet.from_yaml(path.read_text()),
        "prompt": "",
        "delegate": None,
        "episode_mode": "observe",
        "skip_apply": False,
    }


def _campaign(condition: str, mode: str, store: Store, library: StrategyLibrary):
    from policyforge.p2.attacker import AdaptiveAttacker
    from policyforge.p2.campaign import Campaign
    from policyforge.p2.handles import DefenseView

    spec = _spec(condition)
    path = _defense(condition)
    src = AdaptiveAttacker(
        model=ATTACKER,
        mode=mode,
        condition=condition,
        library=library,
        store=store,
        defense=DefenseView(path),
    )
    return Campaign(
        attacker=src,
        store=store,
        defense_dir=DEFENSE_DIR,
        condition=condition,
        runtime=spec["runtime"],
        phase="eval",
        k=K,
        system_prompt=spec["prompt"],
        episode_mode=spec["episode_mode"],
        delegate=spec["delegate"],
        skip_apply=spec["skip_apply"],
        library=library,
    ), spec


def _eval_done(store: Store, condition: str, mode: str, sid: str) -> bool:
    rows = store.query(
        "SELECT attempt, live_success FROM attempts WHERE phase = 'eval' AND condition = ? AND mode = ? AND sample_id = ?",
        (condition, mode, sid),
    )
    if not rows:
        return False
    if any(int(r["live_success"] or 0) for r in rows):
        return True
    return max(int(r["attempt"]) for r in rows) >= K


def _has_benign(store: Store, condition: str, ut: str) -> bool:
    return bool(
        store.query(
            "SELECT 1 FROM attempts WHERE phase = 'benign' AND condition = ? AND user_task_id = ? LIMIT 1",
            (condition, ut),
        )
    )


def _record_benign(store: Store, condition: str) -> None:
    from policyforge import agent, llm, loop
    from policyforge import env as E
    from policyforge.p2.grade import apply_policy, gate_trace

    spec = _spec(condition)
    path = _defense(condition)
    for ut in sorted(E.suite("banking").user_tasks):
        if _has_benign(store, condition, ut):
            continue
        uid = f"{condition}:benign:{ut}"
        llm.set_attempt(uid)
        try:
            raw = loop.episode(
                spec["runtime"],
                "banking",
                ut,
                rules=None if spec["episode_mode"] == "observe" else spec["rules"],
                delegate=spec["delegate"],
                mode=spec["episode_mode"],
                system_prompt=spec["prompt"] or agent.DEFAULT_SYSTEM_PROMPT,
                tag=uid,
            )
            if spec["skip_apply"]:
                graded = raw
            else:
                graded = apply_policy(raw, spec["rules"], confirm="realistic", goal_id="")
            req = llm.ids_for_attempt(uid)
            store.add_attempt(
                uid=uid,
                phase="benign",
                condition=condition,
                mode=None,
                sample_id=None,
                family=None,
                goal_id=None,
                user_task_id=ut,
                attempt=None,
                attacker_model=None,
                payload_json={},
                request_ids_json=req,
                defense_path=str(path.relative_to(ROOT) if path.is_absolute() else path),
                defense_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                trace_json=gate_trace(graded),
                live_success=None,
                live_utility=int(bool(graded.utility)),
                notes_json={"confirmations": graded.confirmations},
            )
            print(f"{condition} benign {ut} utility={int(bool(graded.utility))}", flush=True)
        finally:
            llm.set_attempt(None)


def _run_cell(condition: str, mode: str, store: Store, library: StrategyLibrary, pool: list[AttackSample]) -> None:
    from policyforge import llm

    camp, spec = _campaign(condition, mode, store, library)
    todo = [s for s in pool if not _eval_done(store, condition, mode, _sid(s))]
    print(f"{condition} {mode}: {len(pool) - len(todo)}/{len(pool)} samples done", flush=True)
    for s in todo:
        got = camp.attack_sample(s, spec["rules"])
        print(
            f"{condition} {mode} {_sid(s)} attempts={len(got)} success={int(any(r.success for r in got))}",
            flush=True,
        )
        print(f"  spend ${llm.ledger().spent():.4f}", flush=True)


def main() -> None:
    from policyforge.p2 import ensure_ledger

    ensure_ledger()
    from policyforge import llm

    _seed_eval_defenses()
    lib = StrategyLibrary()
    store = Store(DB)
    store.seed(lib)
    pool = eval_pool(split())
    n_tr = sum(s.family in {"instruction", "laundering", "control_flow"} for s in pool)
    n_ch = sum(s.family == "chain" for s in pool)
    n_vs = sum(s.family == "value_swap" for s in pool)
    print(f"eval pool {len(pool)} (train-family {n_tr}, chain {n_ch}, value_swap {n_vs})", flush=True)
    try:
        for cond in "ABCDEF":
            _record_benign(store, cond)
            for mode in ("whitebox", "blackbox"):
                _run_cell(cond, mode, store, lib, pool)
    except llm.CreditStop as e:
        raise SystemExit(f"CREDIT STOP: {e}\nphase 2 spend ${llm.ledger().spent():.4f}") from e
    except llm.BudgetStop as e:
        raise SystemExit(f"BUDGET STOP: {e}\nphase 2 spend ${llm.ledger().spent():.4f}") from e
    print(f"phase 2 spend ${llm.ledger().spent():.4f} of ${llm.BUDGET_CAP_USD:.0f}")


if __name__ == "__main__":
    main()
