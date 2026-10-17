"""The protected agent's runtime: CaMeL (google-research/camel-prompt-injection, Apache-2.0).

CaMeL splits the agent in two:
  - the **planner** (privileged LLM) sees ONLY the user's request and writes a Python-like plan;
  - the **quarantined extractor** has no tools; it turns untrusted text into schema-checked values.
CaMeL's interpreter runs the plan and tracks, for every value, where it came from (sources)
and who may read it (readers). Before each tool call it asks a policy engine.

This module plugs our data-only rules into that hook (`PolicyForgeEngine`), so the rules
check CaMeL's real dataflow labels. It also routes both LLMs through our ledger, and records
every attempted tool call with its labels, so traces can be replayed offline under other rules.

Label vocabulary (what rules' `origin` lists refer to):
  user          the user's request
  assistant     a literal the planner wrote (the planner never sees data, so this is trusted)
  camel         produced by the interpreter itself
  trusted_tool  a field CaMeL's tool wrappers mark as trusted
  <tool>        data returned by <tool> (untrusted)
  <tool>:trusted  data returned by <tool> that CaMeL marks as coming from trusted parties
                (e.g. a transaction the user sent themselves)
"""

from __future__ import annotations

import contextvars
import json
import re
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

import agentdojo.task_suite.load_suites  # noqa: F401  (must import before camel: avoids an import cycle)
import camel.custom_yaml  # noqa: F401  (registers CaMeL's YAML representers)
from agentdojo.agent_pipeline import AgentPipeline, InitQuery, OpenAILLM
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.task_suite.task_suite import functions_stack_trace_from_messages
from agentdojo.types import get_text_content_as_str
from camel import quarantined_llm
from camel.capabilities import readers as R
from camel.capabilities import sources as S
from camel.capabilities.utils import get_all_readers, get_all_sources, is_public
from camel.pipeline_elements import privileged_llm as _pl
from camel.pipeline_elements.privileged_llm import PrivilegedLLM
from camel.pipeline_elements.security_policies import AgentDojoSecurityPolicyEngine
from camel.security_policy import Allowed, Denied
from pydantic import BaseModel, Field, ValidationError, create_model

from policyforge import env as E
from policyforge import llm
from policyforge.llm import chat as _chat
from policyforge.rules import RuleSet

PLANNER_MODEL = "or:deepseek/deepseek-v4-pro"
EXTRACTOR_MODEL = PLANNER_MODEL
NO_SIDE_EFFECT = {"query_ai_assistant"}
_TRUSTED = {S.SourceEnum.User, S.SourceEnum.CaMeL, S.SourceEnum.Assistant, S.SourceEnum.TrustedToolSource}

_pl.print = lambda *a, **k: None  # CaMeL prints every generated plan; keep logs readable


@dataclass
class _Episode:
    rules: RuleSet | None
    delegate: type | None  # a CaMeL policy engine class to decide instead of `rules` (condition C)
    mode: str  # enforce | observe
    benign: bool
    planner: str
    extractor: str
    tag: str
    tool_names: frozenset[str] = frozenset()
    calls: list[E.Call] = field(default_factory=list)
    confirmations: int = 0


_current: contextvars.ContextVar[_Episode] = contextvars.ContextVar("policyforge_camel_episode")


# ---------------- labels ----------------


def source_label(s: Any) -> str:
    if s == S.SourceEnum.User:
        return "user"
    if s == S.SourceEnum.Assistant:
        return "assistant"
    if s == S.SourceEnum.CaMeL:
        return "camel"
    if s == S.SourceEnum.TrustedToolSource:
        return "trusted_tool"
    if isinstance(s, S.Tool):
        trusted = bool(s.inner_sources) and set(s.inner_sources) <= _TRUSTED
        return f"{s.tool_name}:trusted" if trusted else s.tool_name
    return "unknown"


def value_labels(v) -> list[str]:
    return sorted({source_label(s) for s in get_all_sources(v)[0]}) or ["unknown"]


def value_readers(v) -> list[str] | None:
    rd = get_all_readers(v)[0]
    if isinstance(rd, R.Public):
        return None
    return sorted("user" if r == S.SourceEnum.User else str(r) for r in rd)


def _jsonable(x):
    if isinstance(x, BaseModel):
        return x.model_dump(mode="json")
    if isinstance(x, (list, tuple, set)):
        return [_jsonable(i) for i in x]
    if isinstance(x, dict):
        return {str(k): _jsonable(v) for k, v in x.items()}
    if isinstance(x, (str, int, float, bool)) or x is None:
        return x
    return str(x)


# ---------------- the policy hook ----------------


class PolicyForgeEngine(AgentDojoSecurityPolicyEngine):
    """CaMeL calls `check_policy` before every tool call. We record the call with its labels, then decide."""

    def __init__(self, env) -> None:
        super().__init__(env)
        self.policies = []
        self.no_side_effect_tools = set(NO_SIDE_EFFECT)
        self.ep = _current.get()
        self.delegate = self.ep.delegate(env) if self.ep.delegate else None

    def check_policy(self, tool_name, kwargs, dependencies):
        if tool_name in NO_SIDE_EFFECT or tool_name not in self.ep.tool_names:
            return Allowed()  # the extractor and interpreter built-ins (str, len, ...) are not environment tools
        ep = self.ep
        args = {k: _jsonable(v.raw) for k, v in kwargs.items()}
        labels = {k: value_labels(v) for k, v in kwargs.items()}
        readers = {k: value_readers(v) for k, v in kwargs.items()}
        private_deps = any(not is_public(d) for d in dependencies)
        call = E.Call(tool_name, args, labels, readers=readers, private_deps=private_deps)
        decision = None
        if self.delegate is not None:
            res = self.delegate.check_policy(tool_name, kwargs, dependencies)
            ok = isinstance(res, Allowed)
            decision = {
                "allowed": ok,
                "check": "allow" if ok else "camel_policy",
                "rule_id": None,
                "fallback": None if ok else "block",
                "reason": "" if ok else res.reason,
            }
        elif ep.rules is not None:
            d = ep.rules.evaluate(tool_name, args, {k: set(v) for k, v in labels.items()}, readers, private_deps)
            decision = d.__dict__
        call.decision = decision
        ep.calls.append(call)
        if decision is None or decision["allowed"] or ep.mode == "observe":
            call.executed = True
            return Allowed()
        if decision["fallback"] == "ask_user":
            ep.confirmations += 1
            if ep.benign:
                call.executed = True
                return Allowed()
            return Denied(f"The user declined this action when asked to confirm it ({decision['reason']}).")
        return Denied(decision["reason"])


# ---------------- the quarantined extractor, routed through our ledger ----------------


def _extract_json(text: str) -> str:
    m = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.DOTALL) or re.search(r"(\{.*\})", text, re.DOTALL)
    return m.group(1) if m else text


def query_quarantined_llm(llm, query: str, output_schema, retries: int = 3):
    # Same contract as camel.quarantined_llm.query_quarantined_llm: no tools, schema-checked output,
    # and NotEnoughInformationError when the data doesn't contain the answer.
    ep = _current.get()
    enough = (
        bool,
        Field(
            description="Whether the prompt provided you enough information to perform the task. "
            "Set this to false if you don't have enough information. Do not make assumptions."
        ),
    )
    is_model = isinstance(output_schema, type) and issubclass(output_schema, BaseModel)
    if is_model:
        out_model = create_model(output_schema.__name__, __base__=output_schema, have_enough_information=enough)
    else:
        out_model = create_model(
            "Result", output=(output_schema, Field(description="The requested value")), have_enough_information=enough
        )
    schema = json.dumps(out_model.model_json_schema())
    messages = [
        {
            "role": "system",
            "content": quarantined_llm._SYSTEM_PROMPT
            + "\nReply with ONLY a JSON object that conforms to this JSON schema:\n"
            + schema,
        },
        {"role": "user", "content": query},
    ]
    for _ in range(max(1, min(retries, 3))):
        comp = _chat(ep.extractor, messages, role="extractor", max_tokens=1500, tag=ep.tag)
        try:
            res = out_model.model_validate_json(_extract_json(comp.text))
            break
        except ValidationError as e:
            messages = [
                *messages,
                comp.raw_message,
                {"role": "user", "content": f"That did not validate: {str(e)[:500]}. Reply with only the JSON object."},
            ]
    else:
        raise quarantined_llm.NotEnoughInformationError()
    if not res.have_enough_information:
        raise quarantined_llm.NotEnoughInformationError()
    return res if is_model else res.output


# CaMeL shows the planner this function's docstring as its documentation: keep CaMeL's original text.
query_quarantined_llm.__doc__ = quarantined_llm.query_quarantined_llm.__doc__
quarantined_llm.query_quarantined_llm = query_quarantined_llm


# ---------------- the planner's client, routed through our ledger ----------------


class _LedgeredCompletions:
    def __init__(self, model: str, tag: str) -> None:
        self.model, self.tag = model, tag

    def create(self, **kwargs):
        return llm.openai_create("planner", self.model, kwargs, tag=self.tag)


def _planner_client(model: str, tag: str):
    return SimpleNamespace(chat=SimpleNamespace(completions=_LedgeredCompletions(model, tag)))


# ---------------- running an episode ----------------


def run_camel_episode(
    suite_name: str,
    user_task_id: str,
    *,
    rules: RuleSet | None = None,
    delegate: type | None = None,
    injection_task_id: str | None = None,
    injections: dict[str, str] | None = None,
    mode: str = "enforce",
    planner: str = PLANNER_MODEL,
    extractor: str | None = None,
    tag: str = "",
    max_attempts: int = 5,
) -> E.Trace:
    """One task through CaMeL. mode="observe": record decisions, block nothing."""
    s = E.suite(suite_name)
    task = s.user_tasks[user_task_id]
    inj_task = s.injection_tasks[injection_task_id] if injection_task_id else None
    env = task.init_environment(s.load_and_inject_default_environment(injections or {}))
    pre = env.model_copy(deep=True)
    runtime = FunctionsRuntime(s.tools)
    llm_el = OpenAILLM(_planner_client(planner, tag), planner.split(":", 1)[1], temperature=0.0)  # type: ignore[arg-type]
    llm_el.name = planner.split(":", 1)[1]
    pipeline = AgentPipeline(
        [InitQuery(), PrivilegedLLM(llm_el, PolicyForgeEngine, "openai:unused", max_attempts=max_attempts)]
    )
    ep = _Episode(
        rules,
        delegate,
        mode,
        inj_task is None,
        planner,
        extractor or EXTRACTOR_MODEL,
        tag,
        frozenset(f.name for f in s.tools),
    )
    token = _current.set(ep)
    crashed = None
    messages: list = []
    try:
        _, _, env, messages, _ = pipeline.query(task.PROMPT, runtime, env)
    except llm.BudgetStop:
        raise
    except Exception as e:  # noqa: BLE001 - CaMeL's README warns its interpreter can raise uncaught exceptions
        crashed = f"{type(e).__name__}: {e}"[:300]
    finally:
        _current.reset(token)
    output_blocks = (
        messages[-1]["content"] if messages and messages[-1]["role"] == "assistant" and messages[-1]["content"] else []
    )
    stack = functions_stack_trace_from_messages(messages) if messages else []
    utility = s._check_user_task_utility(task, output_blocks, pre, env, stack)
    attack = s._check_injection_task_security(inj_task, output_blocks, pre, env, stack) if inj_task else None
    return E.Trace(
        suite_name,
        user_task_id,
        injection_task_id,
        injections or {},
        ep.calls,
        get_text_content_as_str(output_blocks) if output_blocks else "",
        bool(utility),
        None if attack is None else bool(attack),
        ep.confirmations,
        runtime="camel",
        crashed=crashed,
    )
