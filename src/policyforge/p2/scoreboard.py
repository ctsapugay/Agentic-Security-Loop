"""Per-defense scoreboard of attack *ideas* (not wordings), so white-box doesn't retry dead tricks."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

_JSON = re.compile(r"\{.*\}", re.DOTALL)

_SLUG = re.compile(r"[^a-z0-9]+")


def slug(text: str, n: int = 40) -> str:
    s = _SLUG.sub("-", (text or "").lower()).strip("-")
    return (s or "x")[:n]


def fingerprint(family: str, tool: str, arg: str, trick: str) -> str:
    return f"{slug(family)}|{slug(tool)}|{slug(arg)}|{slug(trick)}"


@dataclass(frozen=True)
class Hypothesis:
    family: str
    tool: str
    arg: str
    trick: str
    text: str
    hoped_source: str = ""

    @property
    def fp(self) -> str:
        return fingerprint(self.family, self.tool, self.arg, self.trick)

    def as_strategy_text(self) -> str:
        extra = f" Hoped source tag: {self.hoped_source}." if self.hoped_source else ""
        return f"Target {self.tool}.{self.arg} via {self.trick}.{extra} {self.text}".strip()


def parse_hypothesis(raw: str, *, family: str) -> Hypothesis | None:
    m = _JSON.search(raw or "")
    if not m:
        return None
    try:
        data = json.loads(m.group(0))
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    tool, arg, trick, text = data.get("tool"), data.get("arg"), data.get("trick"), data.get("text")
    if not all(isinstance(x, str) and x.strip() for x in (tool, arg, trick, text)):
        return None
    if len(text) < 12:
        return None
    fam = data.get("family") if isinstance(data.get("family"), str) else family
    if fam != family:
        fam = family
    hoped = data.get("hoped_source") if isinstance(data.get("hoped_source"), str) else ""
    return Hypothesis(fam, tool.strip(), arg.strip(), trick.strip(), text.strip(), hoped.strip())


def format_board(rows: list[dict], *, limit: int = 24) -> str:
    if not rows:
        return "(empty — no ideas scored under this defense yet)"
    lines = []
    for r in rows[:limit]:
        status = "dead" if int(r["hits"]) == 0 and int(r["misses"]) > 0 else "open"
        lines.append(
            f"{status} {r['fingerprint']} hits={r['hits']} misses={r['misses']} last_check={r.get('last_check') or '-'}"
        )
    return "\n".join(lines)
