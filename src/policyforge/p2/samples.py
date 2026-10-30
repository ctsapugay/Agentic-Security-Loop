"""AttackSample lists for phase 2. Families are mechanisms, not AgentDojo template names."""

from __future__ import annotations

from policyforge import env as E
from policyforge.attacks import AttackSample
from policyforge.p2.contract import HELDOUT_FAMILIES, TRAIN_FAMILIES
from policyforge.p2.goals import SUITE, all_goals


def samples(*, families: tuple[str, ...] | None = None) -> list[AttackSample]:
    """Every (injectable user task × matching goal × family) combination."""
    want = set(families or TRAIN_FAMILIES + HELDOUT_FAMILIES)
    injectable = E.injectable_user_tasks(SUITE)
    builtins = [g["goal_id"] for g in all_goals() if g["kind"] == "builtin"]
    swaps = {g["goal_id"]: g for g in all_goals() if g["kind"] == "value_swap"}
    out: list[AttackSample] = []
    for fam in TRAIN_FAMILIES + HELDOUT_FAMILIES:
        if fam not in want:
            continue
        if fam == "value_swap":
            for gid, g in swaps.items():
                out.append(AttackSample(SUITE, g["user_task_id"], gid, fam, "adaptive"))
            continue
        for ut in injectable:
            for gid in builtins:
                out.append(AttackSample(SUITE, ut, gid, fam, "adaptive"))
    return out
