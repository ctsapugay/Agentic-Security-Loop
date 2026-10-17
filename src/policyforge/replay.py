"""Offline, deterministic replay of a rule set against every recorded training attack and the benign bank.

Traces were recorded from the CaMeL runtime with their dataflow labels; replay re-decides each call under
the rules and re-executes allowed calls in AgentDojo's simulated environment.

No LLM calls. Prints progress, then one JSON line:
    {"train_attacks_succeeded": int, "train_attacks_total": int, "utility": float}

    uv run python -m policyforge.replay --db results/final/attacks.sqlite --rules results/final/rules_E.yaml --upto-round 6
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from policyforge.attackdb import AttackDB
from policyforge.loop import bank_traces, benign_bank
from policyforge.rules import RuleSet
from policyforge.validate import evaluate


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--rules", required=True)
    ap.add_argument("--upto-round", type=int, required=True)
    ap.add_argument("--suite", default="banking")
    a = ap.parse_args()
    if not Path(a.db).exists():
        raise SystemExit(f"no database at {a.db}")
    rules = RuleSet.from_yaml(Path(a.rules).read_text())
    db = AttackDB(a.db)
    traces = bank_traces(db, a.upto_round)
    ev = evaluate(rules, a.suite, traces, benign_bank(db))
    print(f"replayed {ev.attacks_total} attack traces and {len(ev.benign_replays)} benign tasks under {a.rules}")
    for i in ev.attacks_succeeded:
        print(f"  attack run {i} succeeds")
    print(
        json.dumps(
            {
                "train_attacks_succeeded": len(ev.attacks_succeeded),
                "train_attacks_total": ev.attacks_total,
                "utility": ev.utility,
            }
        )
    )


if __name__ == "__main__":
    main()
