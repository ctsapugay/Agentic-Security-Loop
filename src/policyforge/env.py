"""Thin adapter over AgentDojo: suites, tool schemas, traces, and deterministic grading.

AgentDojo gives us simulated environments (a fake bank, inbox, ...), tasks, and
code that decides success by inspecting the environment afterwards. We drive the
tools ourselves so the enforcement checkpoint sees every call.
"""

from __future__ import annotations

import functools
from dataclasses import dataclass, field
from typing import Any

from agentdojo.agent_pipeline.ground_truth_pipeline import GroundTruthPipeline
from agentdojo.functions_runtime import FunctionCall, FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suite
from agentdojo.types import text_content_block_from_string

from policyforge.provenance import ProvenanceTracker
from policyforge.rules import Decision, RuleSet

BENCHMARK_VERSION = "v1.2.1"
CANARY = "---CANARY_{}---"


@functools.lru_cache
def suite(name: str):
    return get_suite(BENCHMARK_VERSION, name)


@functools.lru_cache
def tool_schemas(suite_name: str) -> dict[str, dict]:
    return {f.name: f.parameters.model_json_schema() for f in suite(suite_name).tools}


@functools.lru_cache
def openai_tools(suite_name: str) -> list[dict]:
    out = []
    for f in suite(suite_name).tools:
        params = f.parameters.model_json_schema()
        params.pop("title", None)
        out.append(
            {"type": "function", "function": {"name": f.name, "description": f.description, "parameters": params}}
        )
    return out


@functools.lru_cache
def injection_vectors(suite_name: str, user_task_id: str) -> tuple[str, ...]:
    """Injection placeholders the agent actually sees when doing this task correctly."""
    s = suite(suite_name)
    task = s.user_tasks[user_task_id]
    canaries = {k: CANARY.format(k) for k in s.get_injection_vector_defaults()}
    env = s.load_and_inject_default_environment(canaries)
    env = task.init_environment(env)
    _, _, _, messages, _ = GroundTruthPipeline(task).query(task.PROMPT, FunctionsRuntime(s.tools), env)
    seen = " ".join(str(m.get("content")) for m in messages)
    return tuple(k for k, c in canaries.items() if c in seen)


def injectable_user_tasks(suite_name: str) -> list[str]:
    return [t for t in suite(suite_name).user_tasks if injection_vectors(suite_name, t)]


@functools.lru_cache
def ground_truth_calls(suite_name: str, user_task_id: str) -> tuple[tuple[str, tuple], ...]:
    s = suite(suite_name)
    task = s.user_tasks[user_task_id]
    env = task.init_environment(s.load_and_inject_default_environment({}))
    return tuple((c.function, tuple(sorted(c.args.items()))) for c in task.ground_truth(env.model_copy(deep=True)))


def ground_truth_output(suite_name: str, user_task_id: str) -> str:
    return suite(suite_name).user_tasks[user_task_id].GROUND_TRUTH_OUTPUT


@dataclass
class Call:
    function: str
    args: dict[str, Any]
    labels: dict[str, list[str]] = field(default_factory=dict)
    decision: dict | None = None  # Decision as dict
    executed: bool = False
    result: str = ""

    def to_dict(self) -> dict:
        return {
            "function": self.function,
            "args": self.args,
            "labels": self.labels,
            "decision": self.decision,
            "executed": self.executed,
            "result": self.result[:2000],
        }


@dataclass
class Trace:
    """What the agent tried to do in one episode."""

    suite: str
    user_task_id: str
    injection_task_id: str | None
    injections: dict[str, str]
    calls: list[Call]
    final_output: str
    utility: bool | None = None
    attack_success: bool | None = None
    confirmations: int = 0

    def to_dict(self) -> dict:
        return {
            "suite": self.suite,
            "user_task_id": self.user_task_id,
            "injection_task_id": self.injection_task_id,
            "injections": self.injections,
            "calls": [c.to_dict() for c in self.calls],
            "final_output": self.final_output,
            "utility": self.utility,
            "attack_success": self.attack_success,
            "confirmations": self.confirmations,
        }

    @classmethod
    def from_dict(cls, d: dict) -> Trace:
        calls = [
            Call(**{k: c[k] for k in ("function", "args", "labels", "decision", "executed", "result")})
            for c in d["calls"]
        ]
        return cls(
            d["suite"],
            d["user_task_id"],
            d["injection_task_id"],
            d["injections"],
            calls,
            d["final_output"],
            d.get("utility"),
            d.get("attack_success"),
            d.get("confirmations", 0),
        )


class Episode:
    """A live environment for one (user task, optional injection) pair, with the enforcement checkpoint."""

    def __init__(self, suite_name: str, user_task_id: str, injection_task_id: str | None, injections: dict[str, str]):
        self.suite_name = suite_name
        self.s = suite(suite_name)
        self.user_task = self.s.user_tasks[user_task_id]
        self.injection_task = self.s.injection_tasks[injection_task_id] if injection_task_id else None
        self.injections = injections
        env = self.s.load_and_inject_default_environment(injections)
        self.env = self.user_task.init_environment(env)
        self.pre_env = self.env.model_copy(deep=True)
        self.runtime = FunctionsRuntime(self.s.tools)
        self.prompt = self.user_task.PROMPT
        self.tracker = ProvenanceTracker(self.prompt)
        self.calls: list[Call] = []
        self.executed: list[FunctionCall] = []
        self.confirmations = 0

    def decide(self, rules: RuleSet | None, function: str, args: dict) -> tuple[Decision | None, dict[str, set[str]]]:
        labels = self.tracker.label_args(args)
        return (rules.evaluate(function, args, labels) if rules is not None else None), labels

    def execute(self, function: str, args: dict) -> str:
        result, error = self.runtime.run_function(self.env, function, args)
        if error:
            return error
        self.tracker.observe(function, result)
        self.executed.append(FunctionCall(function=function, args=args))
        from agentdojo.agent_pipeline.tool_execution import tool_result_to_str

        return tool_result_to_str(result)

    def step(self, rules: RuleSet | None, function: str, args: dict, *, mode: str) -> str:
        """Run one tool call through the checkpoint and return what the agent sees.

        mode: "enforce" (blocks denied calls), "observe" (records decisions, blocks nothing).
        ask_user denials: approved in benign episodes (counted as a confirmation), declined when an injection is present.
        """
        decision, labels = self.decide(rules, function, args)
        call = Call(function, dict(args), {k: sorted(v) for k, v in labels.items()})
        call.decision = decision.__dict__ if decision else None
        self.calls.append(call)
        run = decision is None or decision.allowed or mode == "observe"
        message = ""
        if not run and decision.fallback == "ask_user":
            self.confirmations += 1
            if self.injection_task is None:
                run = True
            else:
                message = f"The user declined this action when asked to confirm it ({decision.reason})."
        elif not run:
            message = (
                f"Blocked by security policy: {decision.reason}. Continue with the user's original task if possible."
            )
        if run:
            call.executed = True
            call.result = self.execute(function, args)
            return call.result
        call.result = message
        return message

    def grade(self, final_output: str) -> Trace:
        blocks = [text_content_block_from_string(final_output or "")]
        utility = self.s._check_user_task_utility(self.user_task, blocks, self.pre_env, self.env, self.executed)
        attack = None
        if self.injection_task is not None:
            attack = self.s._check_injection_task_security(
                self.injection_task, blocks, self.pre_env, self.env, self.executed
            )
        return Trace(
            self.suite_name,
            self.user_task.ID,
            self.injection_task.ID if self.injection_task else None,
            self.injections,
            self.calls,
            final_output,
            bool(utility),
            None if attack is None else bool(attack),
            self.confirmations,
        )


def replay(trace: Trace, rules: RuleSet | None, *, benign: bool) -> Trace:
    """Re-run a recorded sequence of attempted calls under `rules`, offline and deterministically.

    Denied calls are dropped (ask_user approved only when benign). Grading uses AgentDojo's checks.
    """
    ep = Episode(trace.suite, trace.user_task_id, None if benign else trace.injection_task_id, trace.injections)
    for c in trace.calls:
        ep.step(rules, c.function, c.args, mode="enforce")
    return ep.grade(trace.final_output)


def ground_truth_trace(suite_name: str, user_task_id: str) -> Trace:
    """The reference solution of a benign task, as a trace (no LLM involved)."""
    calls = [Call(f, dict(args)) for f, args in ground_truth_calls(suite_name, user_task_id)]
    return Trace(suite_name, user_task_id, None, {}, calls, ground_truth_output(suite_name, user_task_id))
