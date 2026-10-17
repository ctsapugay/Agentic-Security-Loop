"""Pick CaMeL's planner model by data: benign utility on banking with no policy (observe mode).

uv run python -m policyforge.planner_probe
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from policyforge import camel_runtime as C
from policyforge import env as E
from policyforge import llm

CANDIDATES = [
    "or:qwen/qwen3-235b-a22b-2507",
    "or:anthropic/claude-haiku-5.5",
    "or:openai/gpt-4.1-mini",
    "or:openai/gpt-5.6-luna",
    "or:deepseek/deepseek-v4-pro",
]
OUT = Path(__file__).resolve().parents[2] / "results/planner_probe.json"


def main() -> None:
    results = json.loads(OUT.read_text()) if OUT.exists() else {}
    tasks = list(E.suite("banking").user_tasks)
    for model in CANDIDATES:
        if model in results:
            continue
        before = llm.ledger().spent()

        def one(t, model=model):
            return C.run_camel_episode(
                "banking", t, mode="observe", planner=model, extractor=model, tag="planner_probe"
            )

        with ThreadPoolExecutor(8) as pool:
            traces = list(pool.map(one, tasks))
        results[model] = {
            "utility": sum(t.utility for t in traces) / len(traces),
            "crashes": sum(t.crashed is not None for t in traces),
            "failed_tasks": [t.user_task_id for t in traces if not t.utility],
            "cost_usd": round(llm.ledger().spent() - before, 4),
        }
        print(model, results[model], flush=True)
        OUT.write_text(json.dumps(results, indent=1))


if __name__ == "__main__":
    main()
