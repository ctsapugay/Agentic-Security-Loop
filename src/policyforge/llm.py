"""LLM access with a hard budget and a ledger of every call.

Models are named "<provider>:<model id>", e.g. "or:openai/gpt-4o-mini" (OpenRouter)
or "anthropic:claude-sonnet-5-5" (Anthropic API).

Before each call we estimate its worst-case cost; if that could push spending past the
stop threshold (80% of the cap, per GOAL.md) we raise BudgetStop instead of calling.
After each call we append the provider's request id and actual cost to the ledger.
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[2]
load_dotenv(ROOT / ".env")

LEDGER_PATH = Path(os.environ.get("POLICYFORGE_LEDGER", ROOT / "results/ledger.jsonl"))
BUDGET_CAP_USD = float(os.environ.get("POLICYFORGE_BUDGET_USD", "50"))
STOP_FRACTION = 0.8

# USD per million tokens (input, output) for Anthropic direct; OpenRouter prices are fetched live.
ANTHROPIC_PRICES = {
    "claude-sonnet-5-5": (2.0, 10.0),
    "claude-haiku-5-5": (0.10, 0.50),
    "claude-opus-5-5": (4.0, 20.0),
}
ROLES = {"agent", "attacker", "analyzer", "updater", "baseline", "probe", "test"}


class BudgetStop(RuntimeError):
    """Spending would cross the stop threshold. Stop and ask the human (GOAL.md)."""


class LLMError(RuntimeError):
    pass


@dataclass
class Completion:
    text: str
    tool_calls: list[dict]  # [{"id", "name", "arguments": dict}]
    raw_message: dict  # assistant message in OpenAI chat format, for appending to history
    cost_usd: float
    request_id: str


class Ledger:
    def __init__(self, path: Path = LEDGER_PATH, cap: float = BUDGET_CAP_USD) -> None:
        self.path = path
        self.cap = cap
        self.lock = threading.Lock()
        self.reserved = 0.0
        path.parent.mkdir(parents=True, exist_ok=True)

    def spent(self) -> float:
        if not self.path.exists():
            return 0.0
        return sum(json.loads(line)["cost_usd"] for line in self.path.read_text().splitlines() if line.strip())

    def reserve(self, estimate: float) -> None:
        with self.lock:
            if self.spent() + self.reserved + estimate > self.cap * STOP_FRACTION:
                raise BudgetStop(
                    f"spent ${self.spent():.2f} + pending ${self.reserved + estimate:.2f} would cross "
                    f"{STOP_FRACTION:.0%} of the ${self.cap:.0f} cap"
                )
            self.reserved += estimate

    def record(self, role: str, model: str, request_id: str, cost: float, estimate: float, tag: str = "") -> None:
        with self.lock:
            self.reserved = max(0.0, self.reserved - estimate)
            row = {"role": role, "model": model, "request_id": request_id, "cost_usd": round(cost, 8), "tag": tag}
            with self.path.open("a") as f:
                f.write(json.dumps(row) + "\n")

    def release(self, estimate: float) -> None:
        with self.lock:
            self.reserved = max(0.0, self.reserved - estimate)


_LEDGER: Ledger | None = None
_OR_PRICES: dict[str, tuple[float, float]] | None = None
_clients: dict[str, Any] = {}
_init_lock = threading.Lock()


def ledger() -> Ledger:
    global _LEDGER
    if _LEDGER is None:
        _LEDGER = Ledger()
    return _LEDGER


def _or_prices() -> dict[str, tuple[float, float]]:
    global _OR_PRICES
    with _init_lock:
        if _OR_PRICES is None:
            import httpx

            data = httpx.get("https://openrouter.ai/api/v1/models", timeout=30).json()["data"]
            _OR_PRICES = {
                m["id"]: (float(m["pricing"]["prompt"]) * 1e6, float(m["pricing"]["completion"]) * 1e6) for m in data
            }
    return _OR_PRICES


def price(model: str) -> tuple[float, float]:
    provider, mid = model.split(":", 1)
    if provider == "anthropic":
        return ANTHROPIC_PRICES[mid]
    if provider == "or":
        return _or_prices()[mid]
    raise LLMError(f"unknown provider in {model!r}")


def _client(provider: str):
    with _init_lock:
        if provider not in _clients:
            if provider == "or":
                from openai import OpenAI

                _clients[provider] = OpenAI(
                    base_url="https://openrouter.ai/api/v1", api_key=os.environ["OPENROUTER_API_KEY"], max_retries=0
                )
            elif provider == "anthropic":
                from anthropic import Anthropic

                _clients[provider] = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"], max_retries=0)
        return _clients[provider]


def chat(
    model: str,
    messages: list[dict],
    *,
    role: str,
    tools: list[dict] | None = None,
    max_tokens: int = 1024,
    temperature: float = 0.0,
    tag: str = "",
) -> Completion:
    """One chat completion. `messages` use OpenAI chat format (system message first, optional)."""
    if role not in ROLES:
        raise LLMError(f"unknown role {role!r}")
    p_in, p_out = price(model)
    chars = sum(len(json.dumps(m)) for m in messages) + (len(json.dumps(tools)) if tools else 0)
    estimate = (chars / 2.5 * p_in + max_tokens * p_out) / 1e6
    led = ledger()
    led.reserve(estimate)
    provider, mid = model.split(":", 1)
    try:
        for attempt in range(5):
            try:
                comp = _call(provider, mid, messages, tools, max_tokens, temperature, p_in, p_out)
                break
            except BudgetStop:
                raise
            except Exception as e:  # transient provider errors: back off and retry
                if attempt == 4 or not _transient(e):
                    raise LLMError(f"{model}: {e}") from e
                time.sleep(2**attempt + 0.5)
    except BaseException:
        led.release(estimate)
        raise
    led.record(role, model, comp.request_id, comp.cost_usd, estimate, tag)
    return comp


def _transient(e: Exception) -> bool:
    s = f"{type(e).__name__} {e}".lower()
    return any(k in s for k in ("rate", "429", "timeout", "overloaded", "529", "500", "502", "503", "connection"))


def _call(provider, mid, messages, tools, max_tokens, temperature, p_in, p_out) -> Completion:
    if provider == "or":
        kwargs: dict[str, Any] = dict(
            model=mid,
            messages=messages,
            max_tokens=max_tokens,
            temperature=temperature,
            extra_body={"usage": {"include": True}},
            timeout=120,
        )
        if tools:
            kwargs["tools"] = tools
        r = _client("or").chat.completions.create(**kwargs)
        if not r.choices:
            raise LLMError(f"empty response: {r}")
        msg = r.choices[0].message
        usage = r.usage
        cost = getattr(usage, "cost", None) if usage else None
        if cost is None:
            cost = (
                (usage.prompt_tokens if usage else 0) * p_in + (usage.completion_tokens if usage else 0) * p_out
            ) / 1e6
        calls = []
        for tc in msg.tool_calls or []:
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {"__unparseable__": tc.function.arguments}
            calls.append({"id": tc.id, "name": tc.function.name, "arguments": args})
        raw = {"role": "assistant", "content": msg.content or ""}
        if msg.tool_calls:
            raw["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {"name": tc.function.name, "arguments": tc.function.arguments},
                }
                for tc in msg.tool_calls
            ]
        return Completion(msg.content or "", calls, raw, float(cost), r.id)
    if provider == "anthropic":
        if tools:
            raise LLMError("tool use via the Anthropic provider is not wired up; use OpenRouter for agents")
        system = "\n\n".join(m["content"] for m in messages if m["role"] == "system")
        conv = [{"role": m["role"], "content": m["content"]} for m in messages if m["role"] != "system"]
        kwargs = dict(model=mid, max_tokens=max_tokens, messages=conv)
        if system:
            kwargs["system"] = system
        r = _client("anthropic").messages.create(**kwargs, timeout=300)
        text = "".join(b.text for b in r.content if getattr(b, "type", "") == "text")
        cost = (r.usage.input_tokens * p_in + r.usage.output_tokens * p_out) / 1e6
        return Completion(text, [], {"role": "assistant", "content": text}, cost, r.id)
    raise LLMError(f"unknown provider {provider!r}")
