"""Phase 2: the adaptive LLM attacker and the re-run of the study.

CLI entry points call `ensure_ledger()` *before* `policyforge.llm` is imported, so v1's ledger
stays frozen. Importing submodules (attacker, store, ...) does not reroute the ledger; that lets
tests load the attacker after the rest of the package.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
P2 = ROOT / "results/phase2"
LEDGER_PATH = P2 / "ledger.jsonl"
BUDGET_USD = 75.0


def ensure_ledger() -> None:
    """Point POLICYFORGE_LEDGER at results/phase2/ledger.jsonl. Raises if llm is already bound elsewhere."""
    os.environ["POLICYFORGE_LEDGER"] = str(LEDGER_PATH)
    os.environ["POLICYFORGE_BUDGET_USD"] = str(BUDGET_USD)
    if "policyforge.llm" in sys.modules:
        from policyforge import llm as _llm

        if Path(_llm.LEDGER_PATH) != LEDGER_PATH or _llm.BUDGET_CAP_USD != BUDGET_USD:
            raise RuntimeError(
                "policyforge.llm was imported before policyforge.p2.ensure_ledger(); "
                "phase 2 calls would hit v1's ledger"
            )


def __getattr__(name: str):
    if name == "llm":
        ensure_ledger()
        from policyforge import llm as _llm

        return _llm
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
