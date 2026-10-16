"""Deterministic validation of a candidate rule set. No LLM involved.

A candidate ships only if:
  1. it parses, fits the real tools, and has no dead (shadowed) allow rules;
  2. replaying every recorded training attack under it, none succeeds (AgentDojo's own check);
  3. replaying every benign reference task, utility >= floor and confirmations stay within budget.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from policyforge import env as E
from policyforge.rules import ParseError, RuleSet, check_types
from policyforge.solver import find_shadowed


@dataclass
class Evaluation:
    attacks_succeeded: list[int]
    attacks_total: int
    utility: float
    confirmation_rate: float
    benign_failed: list[str]
    attack_replays: dict[int, E.Trace] = field(default_factory=dict)
    benign_replays: dict[str, E.Trace] = field(default_factory=dict)


@dataclass
class Validation:
    accepted: bool
    reasons: list[str]
    evaluation: Evaluation | None = None
    rules: RuleSet | None = None


def benign_traces(suite_name: str) -> list[E.Trace]:
    return [E.ground_truth_trace(suite_name, t) for t in E.suite(suite_name).user_tasks]


def evaluate(rules: RuleSet, suite_name: str, attack_traces: list[tuple[int, E.Trace]]) -> Evaluation:
    with ThreadPoolExecutor(8) as pool:
        attack_rep = dict(
            zip([i for i, _ in attack_traces], pool.map(lambda it: E.replay(it[1], rules, benign=False), attack_traces))
        )
    benign = benign_traces(suite_name)
    benign_rep = {t.user_task_id: E.replay(t, rules, benign=True) for t in benign}
    succeeded = [i for i, t in attack_rep.items() if t.attack_success]
    failed = [tid for tid, t in benign_rep.items() if not t.utility]
    n = max(1, len(benign_rep))
    return Evaluation(
        attacks_succeeded=succeeded,
        attacks_total=len(attack_rep),
        utility=(n - len(failed)) / n,
        confirmation_rate=sum(t.confirmations for t in benign_rep.values()) / n,
        benign_failed=failed,
        attack_replays=attack_rep,
        benign_replays=benign_rep,
    )


def validate(
    text: str,
    suite_name: str,
    attack_traces: list[tuple[int, E.Trace]],
    *,
    utility_floor: float,
    max_confirmation_rate: float,
) -> Validation:
    try:
        rules = RuleSet.from_yaml(text)
    except ParseError as e:
        return Validation(False, [f"parse error: {e}"])
    errors = check_types(rules, E.tool_schemas(suite_name))
    if errors:
        return Validation(False, [f"type error: {e}" for e in errors], rules=rules)
    shadowed, _ = find_shadowed(rules)
    if shadowed:
        return Validation(False, [f"conflict: {s}" for s in shadowed], rules=rules)
    ev = evaluate(rules, suite_name, attack_traces)
    reasons = []
    for i in ev.attacks_succeeded:
        reasons.append(f"regression: past attack run {i} succeeds — {describe_attack(ev.attack_replays[i])}")
    if ev.utility < utility_floor:
        reasons.append(
            f"utility {ev.utility:.2f} below floor {utility_floor:.2f}; failing benign tasks: "
            + "; ".join(f"{t} ({describe_benign(ev.benign_replays[t])})" for t in ev.benign_failed)
        )
    if ev.confirmation_rate > max_confirmation_rate:
        reasons.append(
            f"too many user confirmations: {ev.confirmation_rate:.2f} per benign task (max {max_confirmation_rate:.2f})"
        )
    return Validation(not reasons, reasons, ev, rules)


# ---------- payload-free descriptions (safe to show the updater) ----------

import re

_TOKEN = re.compile(r"^[A-Za-z0-9@._:/+\- ]{1,40}$")


def safe_value(v) -> str:
    """Show short identifier-like values (IBANs, ids, amounts); redact anything that could carry instructions."""
    if isinstance(v, (int, float, bool)) or v is None:
        return repr(v)
    if isinstance(v, list):
        return "[" + ", ".join(safe_value(x) for x in v) + "]"
    s = str(v)
    return repr(s) if _TOKEN.match(s) else f"<text, {len(s)} chars>"


def describe_call(c: E.Call) -> str:
    args = ", ".join(f"{k}={safe_value(v)} from {c.labels.get(k, ['?'])}" for k, v in c.args.items())
    d = c.decision
    verdict = (
        "no rules"
        if d is None
        else (
            "allowed by " + str(d["rule_id"])
            if d["allowed"]
            else f"denied ({d['check']}, rule {d['rule_id']}, fallback {d['fallback']})"
        )
    )
    return f"{c.function}({args}) -> {verdict}"


def describe_attack(t: E.Trace) -> str:
    side_effects = [
        c for c in t.calls if c.executed and not c.function.startswith("get_") and c.function != "read_file"
    ]
    return f"{t.injection_task_id} via {t.user_task_id}; executed: " + "; ".join(describe_call(c) for c in side_effects)


def describe_benign(t: E.Trace) -> str:
    denied = [c for c in t.calls if c.decision and not c.decision["allowed"]]
    return "; ".join(describe_call(c) for c in denied) or "no call denied (task failed for another reason)"
