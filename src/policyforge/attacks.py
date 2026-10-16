"""Attack sources: where injection payloads come from.

The loop only depends on the `AttackSource` interface: given an attack sample (a user task,
an injection goal, a family, and a variant), return {injection vector: payload text}.

v1 uses `BuiltinAttackSource`, which wraps AgentDojo's published attack templates. The
next phase's adaptive LLM attacker (built separately; see PROJECT_VISION.md Section 8)
plugs in by implementing the same interface. It may also use the `defense` and
`feedback` arguments, which the built-in templates ignore.
"""

from __future__ import annotations

import functools
import random
from dataclasses import dataclass
from typing import Protocol

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.attacks.attack_registry import load_attack

from policyforge import env as E

# Families group near-duplicate templates so the held-out split can't leak.
BUILTIN_FAMILIES: dict[str, list[str]] = {
    "important_instructions": [
        "important_instructions",
        "important_instructions_no_user_name",
        "important_instructions_no_model_name",
        "important_instructions_no_names",
        "important_instructions_wrong_model_name",
        "important_instructions_wrong_user_name",
        "tool_knowledge",
    ],
    "ignore_previous": ["ignore_previous"],
    "direct": ["direct"],
    "system_message": ["system_message"],
    "injecagent": ["injecagent"],
}
TRAIN_FAMILIES = ["important_instructions", "ignore_previous", "direct"]
HELDOUT_FAMILIES = ["system_message", "injecagent"]
TARGET_MODEL_NAME = "gpt-4o-mini-2024-07-18"  # tells name-aware templates which model they address


@dataclass(frozen=True)
class AttackSample:
    suite: str
    user_task_id: str
    injection_task_id: str
    family: str
    variant: str

    @property
    def split(self) -> str:
        return "heldout" if self.family in HELDOUT_FAMILIES else "train"


class AttackSource(Protocol):
    name: str

    def payloads(
        self, sample: AttackSample, *, defense: str | None = None, feedback: list[dict] | None = None
    ) -> dict[str, str]:
        """Return {injection vector: payload}. `defense`/`feedback` are for adaptive sources."""
        ...


class _NamedPipeline(BasePipelineElement):
    def __init__(self, name: str) -> None:
        self.name = name

    def query(self, *a, **k):  # pragma: no cover - never run; attacks only read the name
        raise NotImplementedError


class BuiltinAttackSource:
    name = "agentdojo-builtin"

    @functools.lru_cache(maxsize=64)  # noqa: B019 - one instance per process
    def _attack(self, suite_name: str, variant: str):
        return load_attack(variant, E.suite(suite_name), _NamedPipeline(TARGET_MODEL_NAME))

    def payloads(
        self, sample: AttackSample, *, defense: str | None = None, feedback: list[dict] | None = None
    ) -> dict[str, str]:
        s = E.suite(sample.suite)
        attack = self._attack(sample.suite, sample.variant)
        return attack.attack(s.user_tasks[sample.user_task_id], s.injection_tasks[sample.injection_task_id])


def all_samples(suite_name: str, families: list[str]) -> list[AttackSample]:
    s = E.suite(suite_name)
    out = []
    for fam in families:
        for variant in BUILTIN_FAMILIES[fam]:
            for ut in E.injectable_user_tasks(suite_name):
                for it in s.injection_tasks:
                    out.append(AttackSample(suite_name, ut, it, fam, variant))
    return out


def stratified(samples: list[AttackSample], per_family: int, rng: random.Random) -> list[AttackSample]:
    by_fam: dict[str, list[AttackSample]] = {}
    for x in samples:
        by_fam.setdefault(x.family, []).append(x)
    out = []
    for fam in sorted(by_fam):
        pool = by_fam[fam][:]
        rng.shuffle(pool)
        out.extend(pool[:per_family])
    return out


def partition(suite_name: str, seed: int = 0) -> tuple[list[AttackSample], list[AttackSample], list[AttackSample]]:
    """Split attack samples into (loop pool, train-family eval pool, held-out eval pool).

    The loop pool and the train-family eval pool are disjoint, so the final train_asr is
    measured on attacks the loop never saw (same families, fresh combinations).
    """
    rng = random.Random(seed)
    train = all_samples(suite_name, TRAIN_FAMILIES)
    rng.shuffle(train)
    half = len(train) // 2
    return train[:half], train[half:], all_samples(suite_name, HELDOUT_FAMILIES)
