"""Pick the target agent model: we want one that does its job (utility) and is attackable
(otherwise the loop has nothing to learn from). Undefended, built-in attacks only.

    uv run python -m policyforge.agent_probe
"""

from __future__ import annotations

import json
import random
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from policyforge import agent
from policyforge import env as E
from policyforge.attacks import BuiltinAttackSource, partition, stratified

CANDIDATES = [
    "or:openai/gpt-4o-mini",
    "or:openai/gpt-4.1-mini",
    "or:qwen/qwen3-235b-a22b-2507",
    "or:deepseek/deepseek-v4-flash",
]
OUT = Path(__file__).resolve().parents[2] / "results/agent_probe.json"


def main() -> None:
    loop_pool, _, _ = partition("banking", 0)
    samples = stratified(
        loop_pool[len(loop_pool) // 2 :], 8, random.Random(7)
    )  # 24 samples, not used by loop batches' first rounds
    src = BuiltinAttackSource()
    tasks = list(E.suite("banking").user_tasks)
    results = {}
    for model in CANDIDATES:

        def att(s):
            inj = src.payloads(s)
            return agent.run_episode(
                "banking",
                s.user_task_id,
                rules=None,
                injection_task_id=s.injection_task_id,
                injections=inj,
                mode="observe",
                model=model,
                tag="agent_probe",
            ).attack_success

        def ben(t):
            return agent.run_episode("banking", t, rules=None, model=model, tag="agent_probe").utility

        with ThreadPoolExecutor(8) as pool:
            a = list(pool.map(att, samples))
            b = list(pool.map(ben, tasks))
        results[model] = {
            "attack_success_rate": sum(a) / len(a),
            "n_attacks": len(a),
            "utility": sum(b) / len(b),
            "n_benign": len(b),
        }
        print(model, results[model], flush=True)
    OUT.write_text(json.dumps(results, indent=1))


if __name__ == "__main__":
    main()
