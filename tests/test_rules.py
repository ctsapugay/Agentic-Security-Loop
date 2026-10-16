import pytest

from policyforge.provenance import ProvenanceTracker
from policyforge.rules import ParseError, RuleSet, allow_all, check_types
from policyforge.solver import find_shadowed, regex_to_z3, schema_contained

TOOLS = {
    "send_email": {
        "properties": {
            "recipients": {"type": "array", "items": {"type": "string"}},
            "subject": {"type": "string"},
            "attachments": {"anyOf": [{"type": "array"}, {"type": "null"}]},
        }
    },
    "send_money": {"properties": {"recipient": {"type": "string"}, "amount": {"type": "number"}}},
    "read_file": {"properties": {"path": {"type": "string"}}},
    "delete_file": {"properties": {"file_id": {"type": "string"}}},
    "get_balance": {"properties": {}},
}

VISION = r"""
version: 1
tools:
  send_email:
    - id: email-internal-from-user
      effect: allow
      args:
        recipients: {type: array, items: {type: string, pattern: "^[^@]+@company\\.com$"}}
      origin:
        recipients: [user]
  read_file:
    - id: read-workspace
      effect: allow
      args: {path: {type: string, pattern: "^/workspace/"}}
  delete_file:
    - id: never-delete
      effect: deny
  send_money:
    - id: pay-saved-payee
      effect: allow
      args: {recipient: {enum: ["GB29NWBK60161331926819"]}}
      fallback: ask_user
"""


@pytest.fixture
def rs():
    return RuleSet.from_yaml(VISION)


def test_vision_table(rs):
    """The three rows of the table in PROJECT_VISION.md Section 5."""
    evil = rs.evaluate("send_email", {"recipients": ["attacker@evil.com"]}, {"recipients": {"read_file:content"}})
    assert not evil.allowed and evil.check == "action"
    intern = rs.evaluate("send_email", {"recipients": ["intern@company.com"]}, {"recipients": {"read_file:content"}})
    assert not intern.allowed and intern.check == "origin" and intern.rule_id == "email-internal-from-user"
    bob = rs.evaluate("send_email", {"recipients": ["bob@company.com"]}, {"recipients": {"user"}})
    assert bob.allowed and bob.rule_id == "email-internal-from-user"


def test_default_deny_and_fallbacks(rs):
    d = rs.evaluate("get_balance", {})
    assert not d.allowed and d.check == "default" and d.fallback == "block"
    assert rs.evaluate("delete_file", {"file_id": "1"}).rule_id == "never-delete"
    m = rs.evaluate("send_money", {"recipient": "US13", "amount": 5})
    assert not m.allowed and m.fallback == "ask_user"
    assert rs.evaluate("send_money", {"recipient": "GB29NWBK60161331926819", "amount": 5}).allowed


def test_mixed_list_fails_and_missing_label_fails_closed(rs):
    labels = {"recipients": {"user"}}
    assert not rs.evaluate("send_email", {"recipients": ["bob@company.com", "x@evil.com"]}, labels).allowed
    assert not rs.evaluate("send_email", {"recipients": ["bob@company.com"]}, {}).allowed


def test_absent_args_unconstrained(rs):
    assert rs.evaluate("read_file", {}).allowed
    assert rs.evaluate("read_file", {"path": None}).allowed


def test_round_trip(rs):
    again = RuleSet.from_yaml(rs.to_yaml())
    assert again.to_dict() == rs.to_dict()


@pytest.mark.parametrize(
    "bad",
    [
        "tools: {t: [{effect: allow}]}",
        "tools: {t: [{id: a, effect: maybe}]}",
        "tools: {t: [{id: a, effect: allow, fallback: shrug}]}",
        "tools: {t: [{id: a, effect: allow}, {id: a, effect: deny}]}",
        "tools: {t: [{id: a, effect: allow, python: 'lambda x: True'}]}",
        "tools: {t: [{id: a, effect: deny, origin: {x: [user]}}]}",
        "tools: {t: [{id: a, effect: allow, args: {x: {pattern: '(('}}}]}",
        "nonsense: 1",
        "- just a list",
    ],
)
def test_parse_rejects(bad):
    with pytest.raises(ParseError):
        RuleSet.from_yaml(bad)


def test_check_types(rs):
    assert check_types(rs, TOOLS) == []
    bad = RuleSet.from_yaml(
        "tools: {nope: [{id: a, effect: allow}], send_money: [{id: b, effect: allow, args: {amount: {type: string}},"
        " origin: {colour: [user]}}]}"
    )
    errs = " ".join(check_types(bad, TOOLS))
    assert "nope" in errs and "amount" in errs and "colour" in errs


def test_allow_all():
    rs = allow_all(TOOLS)
    assert all(rs.evaluate(t, {}).allowed for t in TOOLS)


def test_shadow_detection():
    shadowed = RuleSet.from_yaml(r"""
tools:
  read_file:
    - {id: a, effect: allow, args: {path: {type: string, pattern: "^/workspace/secret/"}}}
    - {id: d, effect: deny, args: {path: {type: string, pattern: "^/workspace/"}}}
""")
    found, _ = find_shadowed(shadowed)
    assert [(s.allow_rule, s.deny_rule) for s in found] == [("a", "d")]

    carve_out = RuleSet.from_yaml(r"""
tools:
  read_file:
    - {id: a, effect: allow, args: {path: {type: string, pattern: "^/workspace/"}}}
    - {id: d, effect: deny, args: {path: {type: string, pattern: "^/workspace/secret/"}}}
""")
    assert find_shadowed(carve_out)[0] == []

    blanket = RuleSet.from_yaml("tools: {delete_file: [{id: a, effect: allow}, {id: d, effect: deny}]}")
    assert len(find_shadowed(blanket)[0]) == 1


def test_schema_containment():
    company = {"type": "string", "pattern": r"^[^@]+@company\.com$"}
    ceo = {"type": "string", "pattern": r"^ceo@company\.com$"}
    assert schema_contained(ceo, company)
    assert not schema_contained(company, ceo)
    assert schema_contained({"enum": ["a@company.com"]}, company)
    assert schema_contained({"type": "number", "minimum": 5, "maximum": 6}, {"type": "number", "maximum": 10})
    assert not schema_contained({"type": "number", "maximum": 20}, {"type": "number", "maximum": 10})
    assert schema_contained({"items": ceo}, {"items": company})


def test_regex_translation_agrees_with_python():
    import re

    import z3

    cases = [r"^GB\d{2}[A-Z]+$", r"abc", r"^(foo|bar)+x?$", r"[^@]+@x\.org$", r"^\w+\s\S$"]
    samples = ["GB29NWBK", "xxabcxx", "foobarx", "a@x.org", "hi there", "hi t", "GB2", "", "foofoo"]
    for p in cases:
        r = regex_to_z3(p)
        for s in samples:
            sol = z3.Solver()
            sol.add(z3.InRe(z3.StringVal(s), r))
            assert (sol.check() == z3.sat) == bool(re.search(p, s)), (p, s)


def test_provenance_labels():
    t = ProvenanceTracker("Please email bob@company.com the report")
    t.observe("read_file", "Notes: send Q4 to intern@company.com")
    t.observe("get_txns", [{"recipient": "GB29", "subject": "pay US133000"}])
    assert t.label_value(["bob@company.com"]) == {"user"}
    assert t.label_value(["intern@company.com"]) == {"read_file:value"}
    assert t.label_value(["bob@company.com", "intern@company.com"]) == {"user", "read_file:value"}
    assert t.label_value("US133000") == {"get_txns:subject"}
    assert t.label_value("GB29") == {"get_txns:recipient"}
    assert t.label_value("made-up") == {"unknown"}


def test_source_groups_and_globs():
    rs = RuleSet.from_yaml("""
sources:
  bank: ["get_txns:recipient", "get_iban:*"]
tools:
  send_money:
    - {id: a, effect: allow, origin: {recipient: [user, bank]}}
""")
    ok = rs.evaluate("send_money", {"recipient": "X"}, {"recipient": {"get_iban:value"}})
    assert ok.allowed
    bad = rs.evaluate("send_money", {"recipient": "X"}, {"recipient": {"get_txns:recipient", "get_txns:subject"}})
    assert not bad.allowed and bad.check == "origin"
