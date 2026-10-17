"""Deterministic provenance labels for tool-call arguments.

CaMeL tracks where every value came from through its own interpreter. We get the
same *kind* of answer at the tool-call boundary with plain code: for each argument
value, look for it in what the agent has seen so far.

- Found in the user's prompt              -> {"user"}
- Otherwise found in tool output fields   -> {"<tool>:<field.path>", ...} for each field containing it
- Otherwise (the model produced it)       -> {"unknown"}

Example: the user says "pay the bill in bill.txt"; the bill (attacker-edited) contains
"IBAN: US1330...". When the agent calls send_money(recipient="US1330..."), the value is
not in the prompt but is inside read_file's output, so recipient is labeled
{"read_file:content"}. A rule saying `origin: {recipient: [user]}` then blocks it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel

UNKNOWN = "unknown"
MIN_MATCH_LEN = 2


@dataclass
class ProvenanceTracker:
    user_prompt: str
    observations: list[tuple[str, str]] = field(default_factory=list)  # (source label, text)

    def observe(self, tool: str, result: Any) -> None:
        """Record a tool's raw (pre-formatting) return value, split into labeled fields."""
        for path, text in _flatten(result, ""):
            self.observations.append((f"{tool}:{path}" if path else f"{tool}:value", text))

    def label_value(self, value: Any) -> set[str]:
        needles = [_norm(v) for v in _scalars(value)]
        needles = [n for n in needles if n]
        if not needles:
            return {UNKNOWN}
        labels: set[str] = set()
        for n in needles:
            labels |= self._label_scalar(n)
        return labels

    def label_args(self, args: dict[str, Any]) -> dict[str, set[str]]:
        return {k: self.label_value(v) for k, v in args.items() if v is not None}

    def _label_scalar(self, needle: str) -> set[str]:
        if _contains(self.user_prompt, needle):
            return {"user"}
        found = {label for label, text in self.observations if _contains(text, needle)}
        return found or {UNKNOWN}


def _contains(haystack: str, needle: str) -> bool:
    if len(needle) < MIN_MATCH_LEN:
        return needle == haystack.strip()
    return needle.lower() in haystack.lower()


def _norm(v: Any) -> str:
    if isinstance(v, bool):
        return str(v).lower()
    if isinstance(v, float) and v.is_integer():
        v = int(v)
    return str(v).strip()


def _scalars(v: Any) -> list[Any]:
    if isinstance(v, (list, tuple, set)):
        return [x for item in v for x in _scalars(item)]
    if isinstance(v, dict):
        return [x for item in v.values() for x in _scalars(item)]
    return [v]


def _flatten(v: Any, path: str) -> list[tuple[str, str]]:
    if isinstance(v, BaseModel):
        v = v.model_dump(mode="json")
    if isinstance(v, dict):
        return [p for k, x in v.items() for p in _flatten(x, f"{path}.{k}" if path else str(k))]
    if isinstance(v, (list, tuple)):
        return [p for x in v for p in _flatten(x, path)]
    if v is None:
        return []
    return [(path, _norm(v))]
