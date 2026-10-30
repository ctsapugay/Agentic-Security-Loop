"""Train/eval split: held-out families stay out of the loop pool."""

from __future__ import annotations

from policyforge.p2.contract import HELDOUT_FAMILIES, TRAIN_FAMILIES
from policyforge.p2.goals import sample_id
from policyforge.p2.split import eval_pool, split


def test_split_keeps_heldout_out_of_training(tmp_path):
    pools = split(path=tmp_path / "split.json")
    assert {s.family for s in pools["train"]} <= set(TRAIN_FAMILIES)
    assert {s.family for s in pools["eval_train"]} <= set(TRAIN_FAMILIES)
    assert {s.family for s in pools["eval_heldout"]} <= set(HELDOUT_FAMILIES)
    train_ids = {sample_id(s.user_task_id, s.injection_task_id, s.family) for s in pools["train"]}
    eval_ids = {sample_id(s.user_task_id, s.injection_task_id, s.family) for s in pools["eval_train"]}
    assert train_ids.isdisjoint(eval_ids)
    assert len(pools["eval_train"]) >= 20
    assert len(pools["train"]) >= 50


def test_eval_pool_is_sized_for_the_gate_and_disjoint_from_train(tmp_path):
    pools = split(path=tmp_path / "split.json")
    ev = eval_pool(pools)
    train_ids = {sample_id(s.user_task_id, s.injection_task_id, s.family) for s in pools["train"]}
    eval_ids = {sample_id(s.user_task_id, s.injection_task_id, s.family) for s in ev}
    assert train_ids.isdisjoint(eval_ids)
    assert sum(s.family in TRAIN_FAMILIES for s in ev) >= 20
    assert sum(s.family == "chain" for s in ev) == 20
    assert sum(s.family == "value_swap" for s in ev) >= 10
    assert {s.family for s in ev} <= set(TRAIN_FAMILIES) | set(HELDOUT_FAMILIES)
