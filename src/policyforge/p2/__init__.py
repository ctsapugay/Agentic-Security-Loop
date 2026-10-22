"""Phase 2: the adaptive LLM attacker and the re-run of the study (docs/ADAPTIVE_ATTACKER_PLAN.md, GOAL_PHASE2.md).

Importing this package routes every LLM call to phase 2's own ledger and budget, so v1's ledger stays frozen.
"""

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
P2 = ROOT / "results/phase2"
LEDGER_PATH = P2 / "ledger.jsonl"
BUDGET_USD = 75.0

os.environ["POLICYFORGE_LEDGER"] = str(LEDGER_PATH)
os.environ["POLICYFORGE_BUDGET_USD"] = str(BUDGET_USD)

from policyforge import llm  # noqa: E402

if Path(llm.LEDGER_PATH) != LEDGER_PATH or llm.BUDGET_CAP_USD != BUDGET_USD:
    raise RuntimeError("policyforge.llm was imported before policyforge.p2; phase 2 calls would hit v1's ledger")
