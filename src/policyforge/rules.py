"""The rule language: data-only security rules checked deterministically before every tool call.

A rule file is YAML (or the equivalent dict):

    version: 1
    default_fallback: block          # what happens when a call is denied: block | ask_user
    sources:                         # labeling config: named groups of trusted data sources
      bank_records: ["get_most_recent_transactions:recipient", "get_iban:*"]
    tools:
      send_money:
        - id: pay-known-recipient
          effect: allow              # allow | deny
          args:                      # Progent-style: JSON-Schema constraint per argument
            recipient: {type: string, pattern: "^GB"}
          origin:                    # CaMeL-style: where each argument's value may come from
            recipient: [user, bank_records]
          fallback: ask_user

Evaluation of a call to tool T:
  1. T has no rules                       -> deny  (check="default")
  2. a deny rule's args all match         -> deny  (check="action")
  3. an allow rule's args match and its origin condition holds -> allow
  4. an allow rule's args match but origin fails             -> deny  (check="origin")
  5. otherwise                            -> deny  (check="action")
Constraints apply only to arguments present in the call (absent or None = not supplied).
"""

from __future__ import annotations

import copy
import fnmatch
import re
from dataclasses import dataclass, field
from typing import Any, Literal

import jsonschema
import yaml

Effect = Literal["allow", "deny"]
Fallback = Literal["block", "ask_user"]
Check = Literal["allow", "default", "action", "origin"]

EFFECTS = ("allow", "deny")
FALLBACKS = ("block", "ask_user")
RULE_KEYS = {"id", "effect", "args", "origin", "fallback"}
TOP_KEYS = {"version", "default_fallback", "sources", "tools"}
SCHEMA_KEYS = {"type", "pattern", "enum", "const", "minimum", "maximum", "maxLength", "minLength", "items", "not"}
USER = "user"


class ParseError(ValueError):
    pass


@dataclass(frozen=True)
class Rule:
    id: str
    tool: str
    effect: Effect
    args: dict[str, dict] = field(default_factory=dict)
    origin: dict[str, list[str]] = field(default_factory=dict)
    fallback: Fallback | None = None

    def to_dict(self) -> dict:
        d: dict[str, Any] = {"id": self.id, "effect": self.effect}
        if self.args:
            d["args"] = copy.deepcopy(self.args)
        if self.origin:
            d["origin"] = {k: list(v) for k, v in self.origin.items()}
        if self.fallback:
            d["fallback"] = self.fallback
        return d


@dataclass(frozen=True)
class Decision:
    allowed: bool
    check: Check
    rule_id: str | None
    fallback: Fallback | None
    reason: str


@dataclass
class RuleSet:
    tools: dict[str, list[Rule]]
    sources: dict[str, list[str]] = field(default_factory=dict)
    default_fallback: Fallback = "block"

    # ---------- construction ----------
    @classmethod
    def from_yaml(cls, text: str) -> RuleSet:
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as e:
            raise ParseError(f"invalid YAML: {e}") from e
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: Any) -> RuleSet:
        if not isinstance(data, dict):
            raise ParseError("rule file must be a mapping")
        extra = set(data) - TOP_KEYS
        if extra:
            raise ParseError(f"unknown top-level keys: {sorted(extra)}")
        if data.get("version", 1) != 1:
            raise ParseError("unsupported version")
        default_fallback = data.get("default_fallback", "block")
        if default_fallback not in FALLBACKS:
            raise ParseError(f"default_fallback must be one of {FALLBACKS}")
        sources = data.get("sources") or {}
        if not isinstance(sources, dict) or not all(
            isinstance(k, str) and isinstance(v, list) and all(isinstance(s, str) for s in v)
            for k, v in sources.items()
        ):
            raise ParseError("sources must map names to lists of source patterns")
        if USER in sources:
            raise ParseError("'user' is a reserved source name")
        tools_raw = data.get("tools") or {}
        if not isinstance(tools_raw, dict):
            raise ParseError("tools must be a mapping")
        seen: set[str] = set()
        tools: dict[str, list[Rule]] = {}
        for tool, rules in tools_raw.items():
            if not isinstance(rules, list):
                raise ParseError(f"rules for {tool!r} must be a list")
            tools[tool] = []
            for r in rules:
                rule = _parse_rule(tool, r)
                if rule.id in seen:
                    raise ParseError(f"duplicate rule id {rule.id!r}")
                seen.add(rule.id)
                tools[tool].append(rule)
        return cls(tools=tools, sources={k: list(v) for k, v in sources.items()}, default_fallback=default_fallback)

    def to_dict(self) -> dict:
        d: dict[str, Any] = {"version": 1, "default_fallback": self.default_fallback}
        if self.sources:
            d["sources"] = {k: list(v) for k, v in self.sources.items()}
        d["tools"] = {t: [r.to_dict() for r in rs] for t, rs in self.tools.items()}
        return d

    def to_yaml(self) -> str:
        return yaml.safe_dump(self.to_dict(), sort_keys=False, width=120)

    @property
    def rules(self) -> list[Rule]:
        return [r for rs in self.tools.values() for r in rs]

    def rule_ids(self) -> set[str]:
        return {r.id for r in self.rules}

    # ---------- evaluation ----------
    def evaluate(self, tool: str, args: dict[str, Any], labels: dict[str, set[str]] | None = None) -> Decision:
        """Decide one tool call. `labels` maps argument name -> set of source labels of its value."""
        rules = self.tools.get(tool)
        if not rules:
            return Decision(False, "default", None, self.default_fallback, f"no rule covers tool '{tool}'")
        present = {k: v for k, v in args.items() if v is not None}
        for r in rules:
            if r.effect == "deny" and _args_match(r, present):
                return Decision(False, "action", r.id, r.fallback or self.default_fallback, f"denied by rule '{r.id}'")
        origin_fail: Rule | None = None
        for r in rules:
            if r.effect != "allow" or not _args_match(r, present):
                continue
            if self._origin_ok(r, present, labels or {}):
                return Decision(True, "allow", r.id, None, f"allowed by rule '{r.id}'")
            origin_fail = origin_fail or r
        if origin_fail is not None:
            return Decision(
                False,
                "origin",
                origin_fail.id,
                origin_fail.fallback or self.default_fallback,
                f"argument origin not permitted by rule '{origin_fail.id}'",
            )
        allow_rules = [r for r in rules if r.effect == "allow"]
        fallback = (allow_rules[0].fallback if allow_rules else None) or self.default_fallback
        return Decision(False, "action", None, fallback, f"arguments not permitted by any allow rule for '{tool}'")

    def expand_sources(self, allowed: list[str]) -> list[str]:
        out: list[str] = []
        for a in allowed:
            out.extend(self.sources.get(a, [a]))
        return out

    def _origin_ok(self, rule: Rule, args: dict[str, Any], labels: dict[str, set[str]]) -> bool:
        for arg, allowed in rule.origin.items():
            if arg not in args:
                continue
            arg_labels = labels.get(arg)
            if not arg_labels:
                return False  # fail closed: unlabeled value
            patterns = self.expand_sources(allowed)
            if not all(any(fnmatch.fnmatchcase(lbl, p) for p in patterns) for lbl in arg_labels):
                return False
        return True


def _args_match(rule: Rule, args: dict[str, Any]) -> bool:
    for arg, schema in rule.args.items():
        if arg in args and not _validates(args[arg], schema):
            return False
    return True


def _validates(value: Any, schema: dict) -> bool:
    try:
        jsonschema.validate(value, schema)
        return True
    except jsonschema.ValidationError:
        return False


def _parse_rule(tool: str, r: Any) -> Rule:
    if not isinstance(r, dict):
        raise ParseError(f"rule under {tool!r} must be a mapping")
    extra = set(r) - RULE_KEYS
    if extra:
        raise ParseError(f"rule under {tool!r} has unknown keys {sorted(extra)}")
    rid = r.get("id")
    if not isinstance(rid, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", rid):
        raise ParseError(f"rule under {tool!r} needs an id of [A-Za-z0-9_.-]")
    effect = r.get("effect")
    if effect not in EFFECTS:
        raise ParseError(f"rule {rid!r}: effect must be one of {EFFECTS}")
    fallback = r.get("fallback")
    if fallback is not None and fallback not in FALLBACKS:
        raise ParseError(f"rule {rid!r}: fallback must be one of {FALLBACKS}")
    args = r.get("args") or {}
    if not isinstance(args, dict):
        raise ParseError(f"rule {rid!r}: args must be a mapping")
    for name, schema in args.items():
        _check_schema(rid, name, schema)
    origin = r.get("origin") or {}
    if not isinstance(origin, dict) or not all(
        isinstance(v, list) and v and all(isinstance(s, str) for s in v) for v in origin.values()
    ):
        raise ParseError(f"rule {rid!r}: origin must map argument names to non-empty lists of sources")
    if effect == "deny" and origin:
        raise ParseError(f"rule {rid!r}: deny rules cannot have origin conditions")
    return Rule(id=rid, tool=tool, effect=effect, args=args, origin=origin, fallback=fallback)


def _check_schema(rid: str, name: str, schema: Any) -> None:
    if not isinstance(schema, dict):
        raise ParseError(f"rule {rid!r}: constraint for {name!r} must be a mapping")
    extra = set(schema) - SCHEMA_KEYS
    if extra:
        raise ParseError(f"rule {rid!r}: constraint for {name!r} uses unsupported keys {sorted(extra)}")
    try:
        jsonschema.Draft202012Validator.check_schema(schema)
    except jsonschema.SchemaError as e:
        raise ParseError(f"rule {rid!r}: invalid constraint for {name!r}: {e.message}") from e
    if "pattern" in schema:
        try:
            re.compile(schema["pattern"])
        except re.error as e:
            raise ParseError(f"rule {rid!r}: bad regex for {name!r}: {e}") from e
    if "items" in schema:
        _check_schema(rid, f"{name}[]", schema["items"])
    if "not" in schema:
        _check_schema(rid, f"not {name}", schema["not"])


# ---------- static checks against the tool catalogue ----------

JSON_TYPES = {"string", "number", "integer", "boolean", "array", "object", "null"}


def check_types(rs: RuleSet, tool_schemas: dict[str, dict]) -> list[str]:
    """Return human-readable errors for rules that don't fit the real tools."""
    errors: list[str] = []
    known_sources_tools = set(tool_schemas)
    for name, pats in rs.sources.items():
        for p in pats:
            tool = p.split(":", 1)[0]
            if tool != USER and not any(fnmatch.fnmatchcase(t, tool) for t in known_sources_tools):
                errors.append(f"source group {name!r}: pattern {p!r} names no known tool")
    for tool, rules in rs.tools.items():
        if tool not in tool_schemas:
            errors.append(f"unknown tool {tool!r}")
            continue
        props = tool_schemas[tool].get("properties", {})
        for r in rules:
            for arg, schema in r.args.items():
                if arg not in props:
                    errors.append(f"rule {r.id!r}: tool {tool!r} has no argument {arg!r}")
                    continue
                want = _json_types(props[arg])
                have = schema.get("type")
                if have and want and not (set(have if isinstance(have, list) else [have]) & want):
                    errors.append(f"rule {r.id!r}: {arg!r} is {sorted(want)} but constraint says {have!r}")
            for arg, allowed in r.origin.items():
                if arg not in props:
                    errors.append(f"rule {r.id!r}: origin names unknown argument {arg!r}")
                for a in allowed:
                    if a != USER and a not in rs.sources and ":" not in a and a not in tool_schemas:
                        errors.append(
                            f"rule {r.id!r}: origin source {a!r} is not 'user', a source group, or tool:field"
                        )
    return errors


def _json_types(prop: dict) -> set[str]:
    out: set[str] = set()
    if "type" in prop:
        t = prop["type"]
        out |= set(t if isinstance(t, list) else [t])
    for key in ("anyOf", "oneOf"):
        for sub in prop.get(key, []):
            out |= _json_types(sub)
    if "number" in out:
        out.add("integer")
    if "integer" in out:
        out.add("number")
    return out & JSON_TYPES


def allow_all(tool_schemas: dict[str, dict]) -> RuleSet:
    """An undefended rule set: every tool allowed with any arguments."""
    return RuleSet(tools={t: [Rule(id=f"allow-{t}", tool=t, effect="allow")] for t in tool_schemas})
