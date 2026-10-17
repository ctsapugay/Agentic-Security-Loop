"""Z3-based static analysis of rule sets.

`find_shadowed` reports allow rules that can never fire because a deny rule
matches every call they would allow. That is almost always an updater mistake
(it meant to permit something and silently didn't), so validation rejects it.

Containment of one argument constraint in another is decided by asking Z3 for a
value that satisfies the allow constraint but not the deny constraint. No such
value means the allow rule is shadowed.
"""

from __future__ import annotations

import re
import re._parser as sre_parse  # type: ignore[import-not-found]  # Python 3.11+
from dataclasses import dataclass
from re._constants import (  # type: ignore[import-not-found]
    ANY,
    AT,
    AT_BEGINNING,
    AT_BEGINNING_STRING,
    AT_END,
    AT_END_STRING,
    BRANCH,
    CATEGORY,
    CATEGORY_DIGIT,
    CATEGORY_NOT_DIGIT,
    CATEGORY_NOT_SPACE,
    CATEGORY_NOT_WORD,
    CATEGORY_SPACE,
    CATEGORY_WORD,
    IN,
    LITERAL,
    MAX_REPEAT,
    MAXREPEAT,
    MIN_REPEAT,
    NEGATE,
    NOT_LITERAL,
    RANGE,
    SUBPATTERN,
)

import z3

from policyforge.rules import Rule, RuleSet


class Unsupported(Exception):
    pass


@dataclass(frozen=True)
class Shadowed:
    tool: str
    allow_rule: str
    deny_rule: str

    def __str__(self) -> str:
        return f"allow rule '{self.allow_rule}' on {self.tool} can never fire: deny rule '{self.deny_rule}' covers it"


def find_shadowed(rs: RuleSet) -> tuple[list[Shadowed], list[str]]:
    """Return (shadowed allow rules, warnings for constraints too complex to analyze)."""
    shadowed: list[Shadowed] = []
    warnings: list[str] = []
    for tool, rules in rs.tools.items():
        denies = [r for r in rules if r.effect == "deny"]
        for a in (r for r in rules if r.effect == "allow"):
            for d in denies:
                try:
                    if _rule_contained(a, d):
                        shadowed.append(Shadowed(tool, a.id, d.id))
                        break
                except Unsupported as e:
                    warnings.append(f"could not analyze {a.id} vs {d.id}: {e}")
    return shadowed, warnings


def _rule_contained(a: Rule, d: Rule) -> bool:
    """Every argument tuple matching allow rule `a` also matches deny rule `d`."""
    for arg, d_schema in d.args.items():
        a_schema = a.args.get(arg)
        if a_schema is None:
            return False  # a leaves arg free, d restricts it: some value escapes d
        if not schema_contained(a_schema, d_schema):
            return False
    return True


def schema_contained(a: dict, d: dict) -> bool:
    """Is every value satisfying JSON-schema `a` also satisfying `d`? (supported subset only)"""
    kind = _kind(a) or _kind(d)
    if kind == "array":
        ai, di = a.get("items"), d.get("items")
        if di is None:
            return True
        if ai is None:
            return False
        return schema_contained(ai, di)
    if kind is None:
        return _kind(d) is None and not d  # unconstrained a is contained only in unconstrained d
    x = z3.String("x") if kind == "string" else z3.Real("x")
    s = z3.Solver()
    s.set("timeout", 5000)
    s.add(_constraint(x, a, kind), z3.Not(_constraint(x, d, kind)))
    res = s.check()
    if res == z3.unknown:
        raise Unsupported("solver timeout")
    return res == z3.unsat


def _kind(schema: dict) -> str | None:
    t = schema.get("type")
    if t == "array" or "items" in schema:
        return "array"
    if t == "string" or "pattern" in schema or "maxLength" in schema or "minLength" in schema:
        return "string"
    if t in ("number", "integer") or "minimum" in schema or "maximum" in schema:
        return "number"
    vals = schema.get("enum", []) + ([schema["const"]] if "const" in schema else [])
    if vals:
        return "string" if all(isinstance(v, str) for v in vals) else "number"
    if "not" in schema:
        return _kind(schema["not"])
    return None


def _constraint(x, schema: dict, kind: str):
    cs = []
    if "enum" in schema or "const" in schema:
        vals = schema.get("enum", []) + ([schema["const"]] if "const" in schema else [])
        cs.append(z3.Or([x == (z3.StringVal(v) if kind == "string" else z3.RealVal(v)) for v in vals]))
    if kind == "string":
        if "pattern" in schema:
            cs.append(z3.InRe(x, regex_to_z3(schema["pattern"])))
        if "maxLength" in schema:
            cs.append(z3.Length(x) <= schema["maxLength"])
        if "minLength" in schema:
            cs.append(z3.Length(x) >= schema["minLength"])
    else:
        if "minimum" in schema:
            cs.append(x >= schema["minimum"])
        if "maximum" in schema:
            cs.append(x <= schema["maximum"])
    if "not" in schema:
        cs.append(z3.Not(_constraint(x, schema["not"], kind)))
    return z3.And(cs) if cs else z3.BoolVal(True)


# ---------- regex (Python `re.search` semantics) -> Z3 ----------

_RE = z3.ReSort(z3.StringSort())


def _all() -> z3.ReRef:
    return z3.Full(_RE)


def _any_char() -> z3.ReRef:
    return z3.AllChar(_RE)


def regex_to_z3(pattern: str) -> z3.ReRef:
    """Translate a regex to a Z3 regular expression matching every string that `re.search` accepts."""
    try:
        parsed = list(sre_parse.parse(pattern))
    except re.error as e:
        raise Unsupported(str(e)) from e
    anchored_start = bool(parsed) and parsed[0][0] == AT and parsed[0][1] in (AT_BEGINNING, AT_BEGINNING_STRING)
    anchored_end = bool(parsed) and parsed[-1][0] == AT and parsed[-1][1] in (AT_END, AT_END_STRING)
    if anchored_start:
        parsed = parsed[1:]
    if anchored_end:
        parsed = parsed[:-1]
    body = _seq(parsed)
    parts = ([] if anchored_start else [_all()]) + [body] + ([] if anchored_end else [_all()])
    return z3.Concat(*parts) if len(parts) > 1 else parts[0]


def _seq(items) -> z3.ReRef:
    parts = [_node(op, av) for op, av in items]
    if not parts:
        return z3.Re(z3.StringVal(""))
    return z3.Concat(*parts) if len(parts) > 1 else parts[0]


def _char(c: int) -> z3.ReRef:
    return z3.Re(z3.StringVal(chr(c)))


def _range(lo: int, hi: int) -> z3.ReRef:
    return z3.Range(chr(lo), chr(hi))


def _category(cat) -> z3.ReRef:
    digit = _range(48, 57)
    word = z3.Union(_range(97, 122), _range(65, 90), digit, _char(95))
    space = z3.Union(*[_char(c) for c in (32, 9, 10, 11, 12, 13)])
    table = {
        CATEGORY_DIGIT: digit,
        CATEGORY_WORD: word,
        CATEGORY_SPACE: space,
        CATEGORY_NOT_DIGIT: _complement_char(digit),
        CATEGORY_NOT_WORD: _complement_char(word),
        CATEGORY_NOT_SPACE: _complement_char(space),
    }
    if cat not in table:
        raise Unsupported(f"category {cat}")
    return table[cat]


def _complement_char(r: z3.ReRef) -> z3.ReRef:
    return z3.Intersect(_any_char(), z3.Complement(r))


def _node(op, av) -> z3.ReRef:
    if op == LITERAL:
        return _char(av)
    if op == NOT_LITERAL:
        return _complement_char(_char(av))
    if op == ANY:
        return _complement_char(_char(10))  # '.' excludes newline
    if op == IN:
        negate = False
        alts = []
        for sub_op, sub_av in av:
            if sub_op == NEGATE:
                negate = True
            elif sub_op == LITERAL:
                alts.append(_char(sub_av))
            elif sub_op == RANGE:
                alts.append(_range(*sub_av))
            elif sub_op == CATEGORY:
                alts.append(_category(sub_av))
            else:
                raise Unsupported(f"class item {sub_op}")
        u = z3.Union(*alts) if len(alts) > 1 else alts[0]
        return _complement_char(u) if negate else u
    if op in (MAX_REPEAT, MIN_REPEAT):
        lo, hi, sub = av
        inner = _seq(sub)
        if hi == MAXREPEAT:
            if lo == 0:
                return z3.Star(inner)
            return z3.Concat(*([inner] * lo), z3.Star(inner)) if lo > 0 else z3.Star(inner)
        return z3.Loop(inner, lo, hi)
    if op == SUBPATTERN:
        return _seq(av[-1])
    if op == BRANCH:
        alts = [_seq(b) for b in av[1]]
        return z3.Union(*alts) if len(alts) > 1 else alts[0]
    if op == CATEGORY:
        return _category(av)
    raise Unsupported(f"regex construct {op}")
