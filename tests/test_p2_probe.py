"""Refusal probe job list: 3 models, 40 (sample, attempt) keys, both A and F_v1."""

from __future__ import annotations

from pathlib import Path

from policyforge import agent
from policyforge.p2.goals import sample_id
from policyforge.p2.probe import MODELS, N_PER_TARGET, jobs


def test_prompt_a_matches_runtime_prompt():
    text = Path("results/phase2/defenses/prompt_A.txt").read_text()
    assert agent.DEFAULT_SYSTEM_PROMPT in text


def test_jobs_cover_gate_shape():
    js = jobs()
    assert len(MODELS) == 3
    per_model = {m: [j for j in js if j.model == m] for m in MODELS}
    keys = None
    for m, group in per_model.items():
        conds = {j.condition for j in group}
        assert conds == {"A", "F_v1"}, m
        req = {(sample_id(j.sample.user_task_id, j.sample.injection_task_id, j.sample.family), 1) for j in group}
        assert len(req) == 2 * N_PER_TARGET
        if keys is None:
            keys = req
        else:
            assert req == keys
        assert sum(j.condition == "A" for j in group) == N_PER_TARGET
        assert sum(j.condition == "F_v1" for j in group) == N_PER_TARGET
        assert all(j.sample.family in {"instruction", "laundering", "control_flow"} for j in group)
    assert len({j.uid for j in js}) == len(js)
