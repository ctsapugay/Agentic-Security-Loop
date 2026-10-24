"""Constants the phase-2 attacker must satisfy so the gate's black-box checks pass.

Mirrored from scripts/gate_phase2.py. Do not import the gate from package code.
"""

TRAIN_FAMILIES = ("instruction", "laundering", "control_flow")
HELDOUT_FAMILIES = ("value_swap", "chain")
FAMILIES = TRAIN_FAMILIES + HELDOUT_FAMILIES

BLACKBOX_INPUT_KEYS = ("template", "goal", "vectors", "strategy_id", "history")
BLACKBOX_HISTORY_KEYS = ("attempt", "payload", "success")
BLACKBOX_PLACEHOLDERS = ("goal", "vectors", "strategy", "history")

# Case-insensitive; the gate uses substring match. Avoid these in the black-box template and in seed strategy text.
DIAGNOSTIC_TERMS = (
    "blocked",
    "denied",
    "ask_user",
    "fallback",
    "rule id",
    "rule_id",
    "origin",
    "label",
    "readers",
    "private_deps",
    "private_control_flow",
    "diagnos",
    "trace",
    "check fired",
    "camel",
)


def leaks_terms(text: str) -> list[str]:
    low = " ".join((text or "").lower().split())
    return [w for w in DIAGNOSTIC_TERMS if w in low]
