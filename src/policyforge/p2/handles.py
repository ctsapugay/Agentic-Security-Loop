"""Read-only handles the attacker reads itself, so the frozen loop need not pass defense/feedback."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from policyforge.p2.store import Store

ROOT = Path(__file__).resolve().parents[3]


@dataclass
class DefenseSnapshot:
    path: str  # repo-relative
    text: str
    sha256: str


class DefenseView:
    """Current defense file. The experiment updates `.load(path)` when the rule set or prompt changes."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.snap: DefenseSnapshot | None = None
        if path is not None:
            self.load(path)

    def load(self, path: str | Path) -> DefenseSnapshot:
        p = Path(path)
        if not p.is_absolute():
            p = ROOT / p
        raw = p.read_bytes()
        text = raw.decode()
        resolved = p.resolve()
        try:
            rel = str(resolved.relative_to(ROOT.resolve()))
        except ValueError:
            rel = str(resolved)
        self.snap = DefenseSnapshot(rel, text, hashlib.sha256(raw).hexdigest())
        return self.snap

    def require(self) -> DefenseSnapshot:
        if self.snap is None:
            raise RuntimeError("DefenseView has no file loaded")
        return self.snap


class FeedbackMemory:
    def __init__(self, store: Store, condition: str) -> None:
        self.store = store
        self.condition = condition

    def history(self, sample_id: str, mode: str, before_attempt: int) -> list[dict]:
        if mode == "blackbox":
            return self.store.blackbox_history(self.condition, sample_id, before_attempt)
        return self.store.whitebox_notes(self.condition, sample_id, before_attempt)
