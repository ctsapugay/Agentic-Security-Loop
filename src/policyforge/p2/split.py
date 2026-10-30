"""Deterministic train/eval sample split. Held-out families never enter training."""

from __future__ import annotations

import json
import random
from pathlib import Path

from policyforge.attacks import AttackSample
from policyforge.p2.contract import HELDOUT_FAMILIES, TRAIN_FAMILIES
from policyforge.p2.goals import sample_id
from policyforge.p2.samples import samples

SPLIT_PATH = Path("results/phase2/split.json")
SEED = 0
EVAL_TRAIN_N = 24  # gate wants >= 20 train-family eval samples per cell


def _sid(s: AttackSample) -> str:
    return sample_id(s.user_task_id, s.injection_task_id, s.family)


def split(*, path: Path = SPLIT_PATH) -> dict[str, list[AttackSample]]:
    """Train-family pool minus a reserved eval slice; all held-out samples for eval only."""
    train_fam = samples(families=TRAIN_FAMILIES)
    train_fam.sort(key=_sid)
    rng = random.Random(SEED)
    rng.shuffle(train_fam)
    if len(train_fam) <= EVAL_TRAIN_N:
        raise RuntimeError("not enough train-family samples to reserve an eval slice")
    eval_train, loop = train_fam[:EVAL_TRAIN_N], train_fam[EVAL_TRAIN_N:]
    held = samples(families=HELDOUT_FAMILIES)
    held.sort(key=_sid)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "seed": SEED,
                "train": [_sid(s) for s in loop],
                "eval_train": [_sid(s) for s in eval_train],
                "eval_heldout": [_sid(s) for s in held],
            },
            indent=1,
        )
        + "\n"
    )
    return {"train": loop, "eval_train": eval_train, "eval_heldout": held}


EVAL_CHAIN_N = 20  # gate wants >= 20 held-out builtin samples; using all 144 would blow the budget


def eval_pool(pools: dict[str, list[AttackSample]] | None = None) -> list[AttackSample]:
    """Same samples for every A–F × mode cell: reserved train-family slice + 20 chain + all value-swap."""
    pools = pools or split()
    chain = [s for s in pools["eval_heldout"] if s.family == "chain"]
    chain.sort(key=_sid)
    rng = random.Random(SEED)
    rng.shuffle(chain)
    chain = chain[:EVAL_CHAIN_N]
    swaps = [s for s in pools["eval_heldout"] if s.family == "value_swap"]
    swaps.sort(key=_sid)
    return list(pools["eval_train"]) + chain + swaps
