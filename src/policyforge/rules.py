"""The rule language: data-only security rules checked deterministically before every tool call.

A rule file is YAML (or the equivalent dict):

    version: 1
    default_fallback: block          # what happens when a call is denied: block | ask_user
    sources:                         # labeling config: named groups of source labels
      trusted_records: ["*:trusted"]
    read_only: [get_balance, read_file]  # tools exempt from the private-control-flow check
    private_control_flow: deny       # deny | allow: state-changing calls whose control flow depended on private data
    tools:
      send_money:
        - id: pay-known-recipient
          effect: allow              # allow | deny
          args:                      # Progent-style: JSON-Schema constraint per argument
            recipient: {type: string, pattern: "^GB"}
          origin:                    # CaMeL-style: where each argument's value may come from
            recipient: [user, trusted_records]
          readers:                   # CaMeL-style: the value of arg `recipient` must be allowed to read `subject`
            subject: recipient
          fallback: ask_user

Evaluation of a call to tool T:
  1. T has no rules                       -> deny  (check="default")
  2. a deny rule's args all match         -> deny  (check="action")
  3. T is not read_only, private_control_flow is deny, and the call's control flow
     depended on private (non-public) data -> deny (check="control_flow")
  4. an allow rule's args match, its origin holds, and its readers hold -> allow
  5. an allow rule's args match but origin fails  -> deny (check="origin")
  6. args and origin match but readers fail        -> deny (check="readers")
  7. otherwise                            -> deny  (check="action")
Constraints apply only to arguments present in the call (absent or None = not supplied).
Labels and readers come from the runtime (CaMeL's dataflow tracking); missing info fails closed.
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
Check = Literal["allow", "default", "action", "origin", "readers", "control_flow"]

EFFECTS = ("allow", "deny")
FALLBACKS = ("block", "ask_user")
RULE_KEYS = {"id", "effect", "args", "origin", "readers", "fallback"}
TOP_KEYS = {"version", "default_fallback", "sources", "read_only", "private_control_flow", "tools"}
SCHEMA_KEYS = {"type", "pattern", "enum", "const", "minimum", "maximum", "maxLength", "minLength", "items", "not"}
USER = "user"
# Labels produced by the CaMeL runtime: user, assistant (the planner's own literals), camel (interpreter),
# trusted_tool, "<tool>" (untrusted tool data), "<tool>:trusted" (tool data CaMeL marks as trusted).
SPECIAL_SOURCES = {"user", "assistant", "camel", "trusted_tool", "unknown"}


class ParseError(ValueError):
    pass


@dataclass(frozen=True)
class Rule:
    id: str
    tool: str
    effect: Effect
    args: dict[str, dict] = field(default_factory=dict)
    origin: dict[str, list[str]] = field(default_factory=dict)
    readers: dict[str, str] = field(default_factory=dict)
    fallback: Fallback | None = None

    def to_dict(self) -> dict:
        d: dict[str, Any] = {"id": self.id, "effect": self.effect}
        if self.args:
            d["args"] = copy.deepcopy(self.args)
        if self.origin:
            d["origin"] = {k: list(v) for k, v in self.origin.items()}
        if self.readers:
            d["readers"] = dict(self.readers)
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
    read_only: list[str] = field(default_factory=list)
    private_control_flow: Literal["deny", "allow"] = "deny"

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
        read_only = data.get("read_only") or []
        if not isinstance(read_only, list) or not all(isinstance(t, str) for t in read_only):
            raise ParseError("read_only must be a list of tool names")
        pcf = data.get("private_control_flow", "deny")
        if pcf not in ("deny", "allow"):
            raise ParseError("private_control_flow must be deny or allow")
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
        return cls(
            tools=tools,
            sources={k: list(v) for k, v in sources.items()},
            default_fallback=default_fallback,
            read_only=list(read_only),
            private_control_flow=pcf,
        )

    def to_dict(self) -> dict:
        d: dict[str, Any] = {"version": 1, "default_fallback": self.default_fallback}
        if self.sources:
            d["sources"] = {k: list(v) for k, v in self.sources.items()}
        if self.read_only:
            d["read_only"] = list(self.read_only)
        d["private_control_flow"] = self.private_control_flow
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
    def evaluate(
        self,
        tool: str,
        args: dict[str, Any],
        labels: dict[str, set[str]] | None = None,
        readers: dict[str, list[str] | None] | None = None,
        private_deps: bool = False,
    ) -> Decision:
        """Decide one tool call.

        labels:  argument -> set of source labels of its value
        readers: argument -> who may read its value (None = public); missing info fails closed
        private_deps: whether the call's control flow depended on non-public data
        """
        rules = self.tools.get(tool)
        if not rules:
            return Decision(False, "default", None, self.default_fallback, f"no rule covers tool '{tool}'")
        present = {k: v for k, v in args.items() if v is not None}
        for r in rules:
            if r.effect == "deny" and _args_match(r, present):
                return Decision(False, "action", r.id, r.fallback or self.default_fallback, f"denied by rule '{r.id}'")
        if private_deps and self.private_control_flow == "deny" and tool not in self.read_only:
            return Decision(
                False,
                "control_flow",
                None,
                self.default_fallback,
                f"'{tool}' changes state and its control flow depended on private data",
            )
        origin_fail: Rule | None = None
        readers_fail: Rule | None = None
        for r in rules:
            if r.effect != "allow" or not _args_match(r, present):
                continue
            if not self._origin_ok(r, present, labels or {}):
                origin_fail = origin_fail or r
                continue
            if not _readers_ok(r, present, readers):
                readers_fail = readers_fail or r
                continue
            return Decision(True, "allow", r.id, None, f"allowed by rule '{r.id}'")
        if origin_fail is not None:
            return Decision(
                False,
                "origin",
                origin_fail.id,
                origin_fail.fallback or self.default_fallback,
                f"argument origin not permitted by rule '{origin_fail.id}'",
            )
        if readers_fail is not None:
            return Decision(
                False,
                "readers",
                readers_fail.id,
                readers_fail.fallback or self.default_fallback,
                f"a recipient may not read data it would receive (rule '{readers_fail.id}')",
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


def _readers_ok(rule: Rule, args: dict[str, Any], readers: dict[str, list[str] | None] | None) -> bool:
    for data_arg, reader_arg in rule.readers.items():
        if data_arg not in args or reader_arg not in args:
            continue
        if readers is None or data_arg not in readers:
            return False  # fail closed: no reader information
        allowed = readers[data_arg]
        if allowed is None:
            continue  # public
        who = args[reader_arg]
        who = who if isinstance(who, list) else [who]
        if not all(str(w) in allowed for w in who):
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
    readers = r.get("readers") or {}
    if not isinstance(readers, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in readers.items()):
        raise ParseError(f"rule {rid!r}: readers must map a data argument to the argument naming its reader")
    if effect == "deny" and (origin or readers):
        raise ParseError(f"rule {rid!r}: deny rules cannot have origin or readers conditions")
    return Rule(id=rid, tool=tool, effect=effect, args=args, origin=origin, readers=readers, fallback=fallback)


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
            if tool not in SPECIAL_SOURCES and not any(fnmatch.fnmatchcase(t, tool) for t in known_sources_tools):
                errors.append(f"source group {name!r}: pattern {p!r} names no known tool")
    for t in rs.read_only:
        if t not in tool_schemas:
            errors.append(f"read_only names unknown tool {t!r}")
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
            for data_arg, reader_arg in r.readers.items():
                for a in (data_arg, reader_arg):
                    if a not in props:
                        errors.append(f"rule {r.id!r}: readers names unknown argument {a!r}")
            for arg, allowed in r.origin.items():
                if arg not in props:
                    errors.append(f"rule {r.id!r}: origin names unknown argument {arg!r}")
                for a in allowed:
                    base = a.split(":", 1)[0]
                    if (
                        a not in SPECIAL_SOURCES
                        and a not in rs.sources
                        and not any(fnmatch.fnmatchcase(t, base) for t in tool_schemas)
                    ):
                        errors.append(f"rule {r.id!r}: origin source {a!r} is not a known label, source group, or tool")
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
    return RuleSet(
        tools={t: [Rule(id=f"allow-{t}", tool=t, effect="allow")] for t in tool_schemas}, private_control_flow="allow"
    )
