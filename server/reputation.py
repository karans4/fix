"""Reputation tracking for fix platform.

SQLite-backed reputation stats per pubkey.
"""

import sqlite3
import json
from dataclasses import dataclass, field
from decimal import Decimal


@dataclass
class ReputationStats:
    """Reputation data model for an agent or principal."""
    agent_fulfilled: int = 0
    agent_canceled: int = 0
    agent_backed_out: int = 0
    principal_fulfilled: int = 0
    principal_canceled: int = 0
    disputes_won: int = 0
    disputes_lost: int = 0
    evil_flags: int = 0
    total_earned: Decimal = field(default_factory=lambda: Decimal("0"))
    total_spent: Decimal = field(default_factory=lambda: Decimal("0"))

    def completion_rate(self) -> float:
        total = self.agent_fulfilled + self.agent_canceled + self.agent_backed_out
        if total == 0:
            return 1.0
        return self.agent_fulfilled / total

    def total_jobs(self) -> int:
        return self.agent_fulfilled + self.agent_canceled + self.agent_backed_out

    def to_dict(self) -> dict:
        return {
            "as_agent": {
                "fulfilled": self.agent_fulfilled,
                "canceled": self.agent_canceled,
                "backed_out": self.agent_backed_out,
            },
            "as_principal": {
                "fulfilled": self.principal_fulfilled,
                "canceled": self.principal_canceled,
            },
            "disputes_won": self.disputes_won,
            "disputes_lost": self.disputes_lost,
            "evil_flags": self.evil_flags,
            "total_earned": str(self.total_earned),
            "total_spent": str(self.total_spent),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ReputationStats":
        agent = d.get("as_agent", {})
        principal = d.get("as_principal", {})
        return cls(
            agent_fulfilled=agent.get("fulfilled", 0),
            agent_canceled=agent.get("canceled", 0),
            agent_backed_out=agent.get("backed_out", 0),
            principal_fulfilled=principal.get("fulfilled", 0),
            principal_canceled=principal.get("canceled", 0),
            disputes_won=d.get("disputes_won", 0),
            disputes_lost=d.get("disputes_lost", 0),
            evil_flags=d.get("evil_flags", 0),
            total_earned=Decimal(d.get("total_earned", "0")),
            total_spent=Decimal(d.get("total_spent", "0")),
        )


class ReputationManager:
    """SQLite-backed reputation tracker."""

    def __init__(self, db_path: str = ":memory:"):
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self):
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS reputation (
                pubkey TEXT PRIMARY KEY,
                stats TEXT NOT NULL DEFAULT '{}'
            )
        """)
        self.db.commit()

    def record(self, pubkey: str, role: str, outcome: str, amount: Decimal = Decimal("0")) -> None:
        """Record a contract outcome for a pubkey."""
        stats = self.query(pubkey)
        if role == "agent":
            if outcome == "fulfilled":
                stats.agent_fulfilled += 1
                stats.total_earned += amount
            elif outcome == "canceled":
                stats.agent_canceled += 1
            elif outcome == "backed_out":
                stats.agent_backed_out += 1
            elif outcome == "dispute_won":
                stats.disputes_won += 1
                stats.total_earned += amount
            elif outcome == "dispute_lost":
                stats.disputes_lost += 1
            elif outcome == "evil_flag":
                stats.evil_flags += 1
        elif role == "principal":
            if outcome == "fulfilled":
                stats.principal_fulfilled += 1
                stats.total_spent += amount
            elif outcome == "canceled":
                stats.principal_canceled += 1
            elif outcome == "dispute_won":
                stats.disputes_won += 1
            elif outcome == "dispute_lost":
                stats.disputes_lost += 1
                stats.total_spent += amount
            elif outcome == "evil_flag":
                stats.evil_flags += 1

        self.db.execute(
            "INSERT INTO reputation (pubkey, stats) VALUES (?, ?) ON CONFLICT(pubkey) DO UPDATE SET stats = ?",
            (pubkey, json.dumps(stats.to_dict()), json.dumps(stats.to_dict())),
        )
        self.db.commit()

    def query(self, pubkey: str) -> ReputationStats:
        """Get reputation stats for a pubkey."""
        row = self.db.execute("SELECT stats FROM reputation WHERE pubkey = ?", (pubkey,)).fetchone()
        if not row:
            return ReputationStats()
        return ReputationStats.from_dict(json.loads(row["stats"]))

    def meets_threshold(self, pubkey: str, min_rate: float = 0.9, max_flags: int = 0) -> bool:
        stats = self.query(pubkey)
        if stats.evil_flags > max_flags:
            return False
        if stats.total_jobs() > 0 and stats.completion_rate() < min_rate:
            return False
        return True

    def close(self):
        self.db.close()
