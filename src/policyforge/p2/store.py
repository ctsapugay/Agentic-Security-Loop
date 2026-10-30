"""SQLite store exposing the gate_* views from GOAL_PHASE2.md."""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

from policyforge.p2.goals import all_goals
from policyforge.p2.strategies import Strategy, StrategyLibrary

SCHEMA = """
CREATE TABLE IF NOT EXISTS goals (
    goal_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    user_task_id TEXT,
    attacker_iban TEXT,
    goal_text TEXT
);
CREATE TABLE IF NOT EXISTS attacker_calls (
    request_id TEXT PRIMARY KEY,
    mode TEXT NOT NULL,
    prompt TEXT NOT NULL,
    response TEXT NOT NULL,
    input_json TEXT
);
CREATE TABLE IF NOT EXISTS strategies (
    strategy_id TEXT PRIMARY KEY,
    family TEXT NOT NULL,
    origin TEXT NOT NULL,
    text TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS fingerprints (
    defense_sha256 TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    family TEXT,
    tool TEXT,
    arg TEXT,
    trick TEXT,
    last_check TEXT,
    hits INTEGER NOT NULL DEFAULT 0,
    misses INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (defense_sha256, fingerprint)
);
CREATE TABLE IF NOT EXISTS attempts (
    uid TEXT PRIMARY KEY,
    phase TEXT,
    condition TEXT,
    mode TEXT,
    sample_id TEXT,
    family TEXT,
    goal_id TEXT,
    user_task_id TEXT,
    attempt INTEGER,
    attacker_model TEXT,
    payload_json TEXT,
    request_ids_json TEXT,
    defense_path TEXT,
    defense_sha256 TEXT,
    trace_json TEXT,
    live_success INTEGER,
    live_utility INTEGER,
    notes_json TEXT
);
CREATE VIEW IF NOT EXISTS gate_goals AS
    SELECT goal_id, kind, user_task_id, attacker_iban, goal_text FROM goals;
CREATE VIEW IF NOT EXISTS gate_attacker_calls AS
    SELECT request_id, mode, prompt, response, input_json FROM attacker_calls;
CREATE VIEW IF NOT EXISTS gate_strategies AS
    SELECT strategy_id, family, origin, text FROM strategies;
CREATE VIEW IF NOT EXISTS gate_attempts AS
    SELECT uid, phase, condition, mode, sample_id, family, goal_id, user_task_id, attempt,
           attacker_model, payload_json, request_ids_json, defense_path, defense_sha256,
           trace_json, live_success, live_utility FROM attempts;
"""


class Store:
    def __init__(self, path: str | Path) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.path = Path(path)
        self.conn = sqlite3.connect(str(path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.lock = threading.Lock()

    def _exec(self, sql: str, params: tuple = ()) -> None:
        with self.lock:
            self.conn.execute(sql, params)
            self.conn.commit()

    def query(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        with self.lock:
            return self.conn.execute(sql, params).fetchall()

    def seed(self, library: StrategyLibrary) -> None:
        for g in all_goals():
            self._exec(
                "INSERT OR REPLACE INTO goals(goal_id, kind, user_task_id, attacker_iban, goal_text) VALUES (?,?,?,?,?)",
                (g["goal_id"], g["kind"], g["user_task_id"], g["attacker_iban"], g["goal_text"]),
            )
        for s in library.all():
            self.upsert_strategy(s)

    def upsert_strategy(self, s: Strategy) -> None:
        self._exec(
            "INSERT OR REPLACE INTO strategies(strategy_id, family, origin, text) VALUES (?,?,?,?)",
            (s.strategy_id, s.family, s.origin, s.text),
        )

    def log_attacker_call(
        self, request_id: str, mode: str, prompt: str, response: str, input_json: dict | None
    ) -> None:
        raw = json.dumps(input_json) if input_json is not None else None
        self._exec(
            "INSERT OR REPLACE INTO attacker_calls(request_id, mode, prompt, response, input_json) VALUES (?,?,?,?,?)",
            (request_id, mode, prompt, response, raw),
        )

    def has_uid(self, uid: str) -> bool:
        return bool(self.query("SELECT 1 FROM attempts WHERE uid = ? LIMIT 1", (uid,)))

    def has_probe(self, condition: str, model: str, sample_id: str, attempt: int) -> bool:
        """True if this model already probed the sample, including older uid formats."""
        return bool(
            self.query(
                "SELECT 1 FROM attempts WHERE phase = 'probe' AND condition = ? AND attacker_model = ? "
                "AND sample_id = ? AND attempt = ? LIMIT 1",
                (condition, model, sample_id, attempt),
            )
        )

    def add_attempt(self, **row) -> None:
        cols = (
            "uid",
            "phase",
            "condition",
            "mode",
            "sample_id",
            "family",
            "goal_id",
            "user_task_id",
            "attempt",
            "attacker_model",
            "payload_json",
            "request_ids_json",
            "defense_path",
            "defense_sha256",
            "trace_json",
            "live_success",
            "live_utility",
            "notes_json",
        )
        vals = []
        for c in cols:
            v = row.get(c)
            if c in {"payload_json", "request_ids_json", "trace_json", "notes_json"} and v is not None and not isinstance(
                v, str
            ):
                v = json.dumps(v)
            vals.append(v)
        q = ",".join(cols)
        self._exec(f"INSERT OR REPLACE INTO attempts ({q}) VALUES ({','.join('?' * len(cols))})", tuple(vals))

    def blackbox_history(self, condition: str, sample_id: str, before_attempt: int) -> list[dict]:
        rows = self.query(
            "SELECT attempt, payload_json, live_success FROM attempts "
            "WHERE condition = ? AND sample_id = ? AND mode = 'blackbox' AND attempt < ? "
            "ORDER BY attempt",
            (condition, sample_id, before_attempt),
        )
        hist = []
        for r in rows:
            hist.append(
                {
                    "attempt": int(r["attempt"]),
                    "payload": json.loads(r["payload_json"] or "{}"),
                    "success": bool(r["live_success"]),
                }
            )
        return hist

    def whitebox_notes(self, condition: str, sample_id: str, before_attempt: int) -> list[dict]:
        """Prior payloads, success bits, and the stopping check. No raw traces, no strategy catalog."""
        rows = self.query(
            "SELECT attempt, payload_json, live_success, notes_json FROM attempts "
            "WHERE condition = ? AND sample_id = ? AND mode = 'whitebox' AND attempt < ? "
            "ORDER BY attempt",
            (condition, sample_id, before_attempt),
        )
        hist = []
        for r in rows:
            notes = json.loads(r["notes_json"] or "{}")
            hist.append(
                {
                    "attempt": int(r["attempt"]),
                    "payload": json.loads(r["payload_json"] or "{}"),
                    "success": bool(r["live_success"]),
                    "stopped_by": notes.get("stopped_by"),
                }
            )
        return hist

    def is_dead(self, defense_sha256: str, fingerprint: str) -> bool:
        rows = self.query(
            "SELECT hits, misses FROM fingerprints WHERE defense_sha256 = ? AND fingerprint = ?",
            (defense_sha256, fingerprint),
        )
        if not rows:
            return False
        return int(rows[0]["hits"]) == 0 and int(rows[0]["misses"]) > 0

    def hits_of(self, defense_sha256: str, fingerprint: str) -> int:
        rows = self.query(
            "SELECT hits FROM fingerprints WHERE defense_sha256 = ? AND fingerprint = ?",
            (defense_sha256, fingerprint),
        )
        return int(rows[0]["hits"]) if rows else 0

    def board(self, defense_sha256: str) -> list[dict]:
        rows = self.query(
            "SELECT fingerprint, family, tool, arg, trick, last_check, hits, misses FROM fingerprints "
            "WHERE defense_sha256 = ? ORDER BY misses + hits DESC",
            (defense_sha256,),
        )
        return [dict(r) for r in rows]

    def record_fingerprint(
        self,
        defense_sha256: str,
        fp: str,
        *,
        family: str,
        tool: str,
        arg: str,
        trick: str,
        last_check: str | None,
        hit: bool,
    ) -> None:
        self._exec(
            "INSERT INTO fingerprints(defense_sha256, fingerprint, family, tool, arg, trick, last_check, hits, misses) "
            "VALUES (?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(defense_sha256, fingerprint) DO UPDATE SET "
            "last_check = excluded.last_check, "
            "hits = hits + excluded.hits, "
            "misses = misses + excluded.misses",
            (defense_sha256, fp, family, tool, arg, trick, last_check, int(hit), int(not hit)),
        )
