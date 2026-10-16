"""Run the full study: build conditions A–F, evaluate each live on the same attacks, write the report.

Resumable: every step writes a checkpoint under results/final/ and is skipped if it exists.

    uv run python -m policyforge.experiment [--pilot]
"""

from __future__ import annotations

import argparse
import json
import random
import time
from pathlib import Path

from policyforge import agent, llm, roles
from policyforge import env as E
from policyforge.attackdb import AttackDB
from policyforge.attacks import HELDOUT_FAMILIES, TRAIN_FAMILIES, BuiltinAttackSource, partition, stratified
from policyforge.loop import LoopConfig, batches, run_attacks, run_benign, run_policy_loop, run_prompt_loop
from policyforge.rules import ParseError, RuleSet, allow_all, check_types
from policyforge.validate import evaluate

ROOT = Path(__file__).resolve().parents[2]


def log(msg: str) -> None:
    print(f"{time.strftime('%H:%M:%S')} {msg}", flush=True)


def checkpoint(path: Path, fn):
    if path.exists():
        return json.loads(path.read_text())
    out = fn()
    path.write_text(json.dumps(out, indent=1))
    return out


def build_d(suite: str) -> str:
    text = roles.one_shot_rules(suite, tag="D")
    for _ in range(2):
        try:
            rs = RuleSet.from_yaml(text)
            if not check_types(rs, E.tool_schemas(suite)):
                return text
        except ParseError:
            pass
        text = roles.one_shot_rules(suite, tag="D-retry")
    return text


def evaluate_condition(
    cond: str, suite: str, db: AttackDB, samples, *, rules: RuleSet | None, prompt: str, benign_reps: int
) -> dict:
    src = BuiltinAttackSource()
    out = run_attacks(samples, src, db, condition=cond, phase="eval", rules=rules, mode="enforce", system_prompt=prompt)
    ben = run_benign(suite, db, condition=cond, phase="eval", rules=rules, system_prompt=prompt, reps=benign_reps)

    def asr(split: str) -> tuple[float, int]:
        xs = [t.attack_success for s, (_, _, t) in zip(samples, out) if s.split == split]
        return (sum(xs) / len(xs) if xs else 0.0), len(xs)

    tr, ntr = asr("train")
    ho, nho = asr("heldout")
    per_family = {}
    for fam in TRAIN_FAMILIES + HELDOUT_FAMILIES:
        xs = [t.attack_success for s, (_, _, t) in zip(samples, out) if s.family == fam]
        per_family[fam] = sum(xs) / len(xs) if xs else None
    blocked = {}
    for s, (_, _, t) in zip(samples, out):
        for c in t.calls:
            if c.decision and not c.decision["allowed"]:
                blocked[c.decision["check"]] = blocked.get(c.decision["check"], 0) + 1
                break
    return {
        "train_asr": tr,
        "heldout_asr": ho,
        "utility": sum(t.utility for t in ben) / len(ben),
        "confirmations": sum(t.confirmations for t in ben) / len(ben),
        "rule_count": len(rules.rules) if rules is not None else None,
        "n_train_attacks": ntr,
        "n_heldout_attacks": nho,
        "n_benign": len(ben),
        "per_family_asr": per_family,
        "first_denial_by_check": blocked,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pilot", action="store_true", help="tiny end-to-end run into results/pilot/")
    args = ap.parse_args()
    suite = "banking"
    out_dir = ROOT / ("results/pilot" if args.pilot else "results/final")
    out_dir.mkdir(parents=True, exist_ok=True)
    db = AttackDB(out_dir / "attacks.sqlite")
    src = BuiltinAttackSource()
    cfg = LoopConfig(
        suite=suite,
        rounds=2 if args.pilot else 6,
        per_family=2 if args.pilot else 8,
        settle_iterations=1 if args.pilot else 3,
    )
    loop_pool, eval_train_pool, heldout_pool = partition(suite, cfg.seed)
    plan = batches(loop_pool, cfg)
    rng = random.Random(42)
    n_tr, n_ho = (2, 2) if args.pilot else (25, 30)
    eval_samples = stratified(eval_train_pool, n_tr, rng) + stratified(heldout_pool, n_ho, rng)
    benign_reps = 1 if args.pilot else 2
    schemas = E.tool_schemas(suite)
    log(f"budget: spent ${llm.ledger().spent():.4f} of ${llm.BUDGET_CAP_USD:.0f} (stop at {llm.STOP_FRACTION:.0%})")

    # ---- build defenses ----
    rules_c = RuleSet.from_yaml((ROOT / "rules/handwritten_banking.yaml").read_text())
    d_text = checkpoint(out_dir / "rules_D.json", lambda: {"yaml": build_d(suite)})["yaml"]
    (out_dir / "rules_D.yaml").write_text(d_text)
    rules_d = RuleSet.from_yaml(d_text)

    def loop_e():
        r = run_policy_loop("E", allow_all(schemas), db, src, plan, cfg, log)
        return {
            "yaml": r.final_text,
            "rounds": r.rounds,
            "rollbacks": r.rollbacks,
            "history": r.history,
            "version": r.final_version,
        }

    def loop_f():
        r = run_policy_loop("F", rules_c, db, src, plan, cfg, log)
        return {
            "yaml": r.final_text,
            "rounds": r.rounds,
            "rollbacks": r.rollbacks,
            "history": r.history,
            "version": r.final_version,
        }

    def loop_b():
        r = run_prompt_loop(db, src, plan, cfg, rounds=min(4, cfg.rounds), log=log)
        return {"prompt": r.final_text, "rounds": r.rounds, "rollbacks": r.rollbacks, "history": r.history}

    e = checkpoint(out_dir / "loop_E.json", loop_e)
    (out_dir / "rules_E.yaml").write_text(e["yaml"])
    f = checkpoint(out_dir / "loop_F.json", loop_f)
    (out_dir / "rules_F.yaml").write_text(f["yaml"])
    b = checkpoint(out_dir / "loop_B.json", loop_b)
    (out_dir / "prompt_B.txt").write_text(b["prompt"])

    defenses = {
        "A": (None, agent.DEFAULT_SYSTEM_PROMPT),
        "B": (None, b["prompt"]),
        "C": (rules_c, agent.DEFAULT_SYSTEM_PROMPT),
        "D": (rules_d, agent.DEFAULT_SYSTEM_PROMPT),
        "E": (RuleSet.from_yaml(e["yaml"]), agent.DEFAULT_SYSTEM_PROMPT),
        "F": (RuleSet.from_yaml(f["yaml"]), agent.DEFAULT_SYSTEM_PROMPT),
    }

    # ---- evaluate every condition live, on the same attacks ----
    conditions = {}
    for cond, (rules, prompt) in defenses.items():
        log(f"evaluating {cond} on {len(eval_samples)} attacks + benign x{benign_reps}")
        m = checkpoint(
            out_dir / f"eval_{cond}.json",
            lambda: evaluate_condition(
                cond, suite, db, eval_samples, rules=rules, prompt=prompt, benign_reps=benign_reps
            ),
        )
        conditions[cond] = {"blackbox": m}
        log(
            f"  {cond}: train_asr {m['train_asr']:.2f} heldout_asr {m['heldout_asr']:.2f} utility {m['utility']:.2f} conf {m['confirmations']:.2f}"
        )

    # ---- deterministic replay numbers (what the gate re-checks) ----
    from policyforge.loop import bank_traces

    traces = bank_traces(db, cfg.rounds)
    rep = {}
    for cond in ("C", "D", "E", "F"):
        ev = evaluate(defenses[cond][0], suite, traces)
        rep[cond] = {
            "train_attacks_succeeded": len(ev.attacks_succeeded),
            "train_attacks_total": ev.attacks_total,
            "utility": ev.utility,
            "confirmation_rate": ev.confirmation_rate,
        }
    rel = out_dir.relative_to(ROOT)
    report = {
        "suites": [suite],
        "budget": {"cap_usd": llm.BUDGET_CAP_USD, "spent_usd": round(llm.ledger().spent(), 6)},
        "attack_source": src.name,
        "families": {"train": TRAIN_FAMILIES, "heldout": HELDOUT_FAMILIES},
        "agent_model": agent.AGENT_MODEL,
        "analyzer_model": roles.ANALYZER_MODEL,
        "updater_model": roles.UPDATER_MODEL,
        "conditions": conditions,
        "loop": {"rounds": e["rounds"], "rollbacks": e["rollbacks"], "history": e["history"]},
        "loop_F": {"rounds": f["rounds"], "rollbacks": f["rollbacks"], "history": f["history"]},
        "loop_B": {"rounds": b["rounds"], "rollbacks": b["rollbacks"], "history": b["history"]},
        "replay_all": rep,
        "replay": {
            "command": f"uv run --frozen python -m policyforge.replay --db {rel}/attacks.sqlite --rules {rel}/rules_E.yaml --upto-round {cfg.rounds}",
            "expected": {k: rep["E"][k] for k in ("train_attacks_succeeded", "train_attacks_total", "utility")},
        },
    }
    report["budget"]["spent_usd"] = round(llm.ledger().spent(), 6)
    (out_dir / "report.json").write_text(json.dumps(report, indent=1))
    log(f"report written: {out_dir / 'report.json'}; spent ${llm.ledger().spent():.4f}")


if __name__ == "__main__":
    main()
