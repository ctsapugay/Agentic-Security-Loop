"""Re-run condition C with CaMeL's policy violations treated as confirmation requests, like D/E/F's ask_user.

v1's C ended an episode whenever CaMeL's banking policy fired. The CaMeL paper (arXiv 2503.18813, §5.4) treats a
violation as "requires user confirmation". Here a trigger is approved in benign runs (counted as a confirmation)
and declined in attacked runs, exactly as D/E/F's ask_user. Same policy code, models, 135 attacks and benign x2.

    POLICYFORGE_LEDGER=results/c_fair/ledger.jsonl POLICYFORGE_BUDGET_USD=5 \
        uv run python -m policyforge.c_fair
"""

from __future__ import annotations

import json
import random

from policyforge import agent, camel_runtime, llm  # camel_runtime first: agentdojo must load before camel
from policyforge.attackdb import AttackDB
from policyforge.attacks import partition, stratified
from policyforge.experiment import ROOT, evaluate_condition, log
from policyforge.loop import LoopConfig

from camel.pipeline_elements.security_policies import BankingSecurityPolicyEngine  # noqa: E402,I001


class ConfirmingBankingPolicyEngine(BankingSecurityPolicyEngine):
    """CaMeL's banking policies, unchanged; a violation asks the user instead of blocking."""

    fallback = "ask_user"


def eval_samples(suite: str):
    # Mirrors experiment.main exactly, so these are v1's 135 evaluation attacks.
    cfg = LoopConfig(suite=suite, rounds=6, per_family=12, settle_iterations=3)
    _, eval_train_pool, heldout_pool = partition(suite, cfg.seed)
    rng = random.Random(42)
    return stratified(eval_train_pool, 25, rng) + stratified(heldout_pool, 30, rng)


def preflight() -> None:
    # One cheap call per provider this run uses (only OpenRouter: planner and extractor are both deepseek-v4-pro).
    for model in sorted({camel_runtime.PLANNER_MODEL, camel_runtime.EXTRACTOR_MODEL}):
        c = llm.chat(model, [{"role": "user", "content": "Reply with: ok"}], role="test", max_tokens=8, tag="preflight")
        log(f"preflight {model}: {c.text.strip()[:20]!r}")


def main() -> None:
    suite = "banking"
    out_dir = ROOT / "results/c_fair"
    out_dir.mkdir(parents=True, exist_ok=True)
    assert llm.LEDGER_PATH.resolve() == (out_dir / "ledger.jsonl").resolve(), "set POLICYFORGE_LEDGER"
    log(f"budget: spent ${llm.ledger().spent():.4f} of ${llm.BUDGET_CAP_USD:.0f} (stop at {llm.STOP_FRACTION:.0%})")
    preflight()
    samples = eval_samples(suite)
    db = AttackDB(out_dir / "attacks.sqlite")
    log(f"evaluating C (confirm) on {len(samples)} attacks + benign x2")
    m = evaluate_condition(
        "C",
        suite,
        db,
        samples,
        rules=None,
        prompt=agent.DEFAULT_SYSTEM_PROMPT,
        benign_reps=2,
        runtime="camel",
        delegate=ConfirmingBankingPolicyEngine,
    )
    m["policy_violation"] = "ask_user (approved if benign, declined if attacked)"
    m["planner_model"] = camel_runtime.PLANNER_MODEL
    m["extractor_model"] = camel_runtime.EXTRACTOR_MODEL
    m["spent_usd"] = round(llm.ledger().spent(), 6)
    (out_dir / "eval_C.json").write_text(json.dumps(m, indent=1))
    log(
        f"  C (confirm): train_asr {m['train_asr']:.2f} heldout_asr {m['heldout_asr']:.2f} "
        f"utility {m['utility']:.2f} conf {m['confirmations']:.2f}; spent ${m['spent_usd']:.4f}"
    )


if __name__ == "__main__":
    main()
