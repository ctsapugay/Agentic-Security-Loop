"""SQLite store for attacks, episode traces, rule-set versions, and diagnoses."""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

from policyforge.env import Trace

SCHEMA = """
CREATE TABLE IF NOT EXISTS attacks (
    id INTEGER PRIMARY KEY,
    condition TEXT NOT NULL,       -- which experiment condition generated it (B, E, F, eval, probe)
    phase TEXT NOT NULL,           -- loop | eval | probe
    round INTEGER,
    family TEXT NOT NULL,          -- attack strategy family (held-out split is by family)
    split TEXT NOT NULL,           -- train | heldout
    access TEXT NOT NULL,          -- whitebox | blackbox
    suite TEXT NOT NULL,
    user_task_id TEXT NOT NULL,
    injection_task_id TEXT NOT NULL,
    payload TEXT NOT NULL,
    attacker_model TEXT NOT NULL,
    refused INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY,
    attack_id INTEGER REFERENCES attacks(id),
    condition TEXT NOT NULL,
    phase TEXT NOT NULL,
    kind TEXT NOT NULL,            -- attack | benign
    mode TEXT NOT NULL,            -- observe | enforce
    ruleset_version INTEGER,
    user_task_id TEXT NOT NULL,
    utility INTEGER,
    attack_success INTEGER,
    confirmations INTEGER,
    blocked_by TEXT,               -- first denying check/rule, e.g. "origin:pay-from-user"
    trace TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS rulesets (
    version INTEGER PRIMARY KEY,
    condition TEXT NOT NULL,
    parent INTEGER,
    round INTEGER,
    status TEXT NOT NULL,          -- seed | accepted | rejected
    body TEXT NOT NULL,            -- rules YAML (or system prompt for condition B)
    notes TEXT
);
CREATE TABLE IF NOT EXISTS diagnoses (
    id INTEGER PRIMARY KEY,
    condition TEXT NOT NULL,
    round INTEGER NOT NULL,
    body TEXT NOT NULL
);
"""


class AttackDB:
    def __init__(self, path: str | Path) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.lock = threading.Lock()

    def _exec(self, sql: str, params: tuple = ()) -> int:
        with self.lock:
            cur = self.conn.execute(sql, params)
            self.conn.commit()
            return cur.lastrowid or 0

    def query(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        with self.lock:
            return self.conn.execute(sql, params).fetchall()

    def add_attack(self, **f) -> int:
        cols = ", ".join(f)
        return self._exec(f"INSERT INTO attacks ({cols}) VALUES ({', '.join('?' * len(f))})", tuple(f.values()))

    def add_run(
        self,
        trace: Trace,
        *,
        condition: str,
        phase: str,
        kind: str,
        mode: str,
        attack_id: int | None = None,
        ruleset_version: int | None = None,
    ) -> int:
        blocked = next(
            (
                f"{c.decision['check']}:{c.decision['rule_id']}"
                for c in trace.calls
                if c.decision and not c.decision["allowed"]
            ),
            None,
        )
        return self._exec(
            "INSERT INTO runs (attack_id, condition, phase, kind, mode, ruleset_version, user_task_id, utility,"
            " attack_success, confirmations, blocked_by, trace) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                attack_id,
                condition,
                phase,
                kind,
                mode,
                ruleset_version,
                trace.user_task_id,
                trace.utility,
                trace.attack_success,
                trace.confirmations,
                blocked,
                json.dumps(trace.to_dict()),
            ),
        )

    def add_ruleset(
        self, condition: str, body: str, *, parent: int | None, round: int | None, status: str, notes: str = ""
    ) -> int:
        return self._exec(
            "INSERT INTO rulesets (condition, parent, round, status, body, notes) VALUES (?,?,?,?,?,?)",
            (condition, parent, round, status, body, notes),
        )

    def add_diagnoses(self, condition: str, round: int, diagnoses: list[dict]) -> None:
        self._exec(
            "INSERT INTO diagnoses (condition, round, body) VALUES (?,?,?)", (condition, round, json.dumps(diagnoses))
        )

    def loop_attack_traces(self, condition: str, split: str = "train") -> list[tuple[int, Trace]]:
        """Observe-mode traces of loop attacks: what the agent tried to do with nothing blocked."""
        rows = self.query(
            "SELECT r.id, r.trace FROM runs r JOIN attacks a ON r.attack_id = a.id"
            " WHERE r.condition = ? AND r.phase = 'loop' AND r.kind = 'attack' AND r.mode = 'observe' AND a.split = ?"
            " ORDER BY r.id",
            (condition, split),
        )
        return [(row["id"], Trace.from_dict(json.loads(row["trace"]))) for row in rows]
