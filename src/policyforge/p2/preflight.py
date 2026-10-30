"""One cheap call per provider before any other phase 2 call (GOAL_PHASE2.md). A billing failure stops here.

    uv run python -m policyforge.p2.preflight
"""

from __future__ import annotations

from policyforge.p2 import ensure_ledger

ensure_ledger()

from policyforge import llm

CHECKS = {"or": "or:qwen/qwen3-235b-a22b-2507", "anthropic": "anthropic:claude-haiku-5-5"}


def main() -> None:
    for provider, model in CHECKS.items():
        try:
            c = llm.chat(
                model, [{"role": "user", "content": "Reply with the single word: ok"}], role="preflight", max_tokens=5
            )
        except llm.CreditStop as e:
            raise SystemExit(f"PREFLIGHT FAILED (credits) for provider {provider}: {e}") from e
        print(f"preflight {provider}: {model} -> {c.text.strip()!r} (${c.cost_usd:.6f}, {c.request_id})")
    print(f"phase 2 spend so far: ${llm.ledger().spent():.4f} of ${llm.BUDGET_CAP_USD:.0f}")


if __name__ == "__main__":
    main()
