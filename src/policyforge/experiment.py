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

from policyforge import agent, camel_runtime, llm, roles
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


def build_d(suite: str, benign) -> str:
    text = roles.one_shot_rules(suite, benign, tag="D")
    for _ in range(2):
        try:
            rs = RuleSet.from_yaml(text)
            if not check_types(rs, E.tool_schemas(suite)):
                return text
        except ParseError:
            pass
        text = roles.one_shot_rules(suite, benign, tag="D-retry")
    return text


def evaluate_condition(
    cond: str,
    suite: str,
    db: AttackDB,
    samples,
    *,
    rules: RuleSet | None,
    prompt: str,
    benign_reps: int,
    runtime: str,
    delegate: type | None = None,
    src=None,
) -> dict:
    src = src or BuiltinAttackSource()
    kw = dict(rules=rules, system_prompt=prompt, runtime=runtime, delegate=delegate)
    out = run_attacks(samples, src, db, condition=cond, phase="eval", mode="enforce", **kw)
    ben = run_benign(suite, db, condition=cond, phase="eval", reps=benign_reps, **kw)

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
        "runtime": runtime,
        "crashes": sum(t.crashed is not None for _, _, t in out) + sum(t.crashed is not None for t in ben),
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
    from camel.pipeline_elements.security_policies import BankingSecurityPolicyEngine

    from policyforge.loop import benign_bank, ensure_benign_bank

    rules_c = RuleSet.from_yaml(
        (ROOT / "rules/handwritten_banking.yaml").read_text()
    )  # CaMeL's policy, translated (F's seed)
    ensure_benign_bank(db, suite)
    benign = benign_bank(db)
    log(f"benign bank: {len(benign)} of 16 tasks completed by unprotected CaMeL")
    d_text = checkpoint(out_dir / "rules_D.json", lambda: {"yaml": build_d(suite, benign)})["yaml"]
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

    # (rules, system prompt, runtime, CaMeL policy engine to delegate to)
    P = agent.DEFAULT_SYSTEM_PROMPT
    defenses = {
        "A": (None, P, "plain", None),  # undefended tool-calling agent
        "B": (None, b["prompt"], "plain", None),  # prompt-patching loop
        "C": (None, P, "camel", BankingSecurityPolicyEngine),  # CaMeL with its own hand-written policy
        "D": (rules_d, P, "camel", None),  # CaMeL + one-shot LLM rules
        "E": (RuleSet.from_yaml(e["yaml"]), P, "camel", None),  # CaMeL + our loop from zero
        "F": (RuleSet.from_yaml(f["yaml"]), P, "camel", None),  # CaMeL + our loop seeded from C
    }

    # ---- evaluate every condition live, on the same attacks ----
    conditions = {}
    for cond, (rules, prompt, runtime, delegate) in defenses.items():
        log(f"evaluating {cond} on {len(eval_samples)} attacks + benign x{benign_reps}")
        m = checkpoint(
            out_dir / f"eval_{cond}.json",
            lambda: evaluate_condition(
                cond,
                suite,
                db,
                eval_samples,
                rules=rules,
                prompt=prompt,
                benign_reps=benign_reps,
                runtime=runtime,
                delegate=delegate,
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
    replay_rules = {"C (translated)": rules_c, "D": rules_d, "E": defenses["E"][0], "F": defenses["F"][0]}
    for cond, rs in replay_rules.items():
        ev = evaluate(rs, suite, traces, benign)
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
        "benign_bank_tasks": [t.user_task_id for t in benign],
        "runtime": {
            "A,B": f"plain tool-calling agent ({agent.AGENT_MODEL})",
            "C-F": f"CaMeL (planner {camel_runtime.PLANNER_MODEL}, extractor {camel_runtime.EXTRACTOR_MODEL})",
        },
    }
    report["budget"]["spent_usd"] = round(llm.ledger().spent(), 6)
    (out_dir / "report.json").write_text(json.dumps(report, indent=1))
    log(f"report written: {out_dir / 'report.json'}; spent ${llm.ledger().spent():.4f}")


if __name__ == "__main__":
    main()
