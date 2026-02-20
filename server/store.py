"""Contract storage and matchmaking for fix platform.

SQLite-backed CRUD + query by status for agents browsing work.
Stores full transcript (messages between principal and agent).
"""

import sqlite3
import json
import time
import uuid


class ContractStore:
    """SQLite-backed contract storage."""

    def __init__(self, db_path: str = ":memory:"):
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self):
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS contracts (
                id TEXT PRIMARY KEY,
                status TEXT NOT NULL DEFAULT 'open',
                contract TEXT NOT NULL,
                principal_pubkey TEXT,
                agent_pubkey TEXT,
                judge_pubkey TEXT,
                execution_mode TEXT NOT NULL DEFAULT 'supervised',
                review_expires_at REAL,
                last_investigation_at REAL,
                transcript TEXT NOT NULL DEFAULT '[]',
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            )
        """)
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_status ON contracts(status)")
        self.db.commit()

    def create(self, contract: dict, principal_pubkey: str = "") -> str:
        """Store a new contract. Returns contract ID."""
        contract_id = uuid.uuid4().hex[:16]
        now = time.time()

        # Extract judge and execution mode from contract
        judge_pubkey = contract.get("judge", {}).get("pubkey", "")
        execution_mode = contract.get("execution", {}).get("mode", "supervised")

        self.db.execute(
            "INSERT INTO contracts (id, status, contract, principal_pubkey, judge_pubkey, execution_mode, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (contract_id, "open", json.dumps(contract), principal_pubkey, judge_pubkey, execution_mode, now, now),
        )
        self.db.commit()
        return contract_id

    def get(self, contract_id: str) -> dict | None:
        """Get a contract by ID."""
        row = self.db.execute("SELECT * FROM contracts WHERE id = ?", (contract_id,)).fetchone()
        if not row:
            return None
        return self._row_to_dict(row)

    def list_by_status(self, status: str = "open", limit: int = 50) -> list[dict]:
        """List contracts by status for matchmaking."""
        rows = self.db.execute(
            "SELECT * FROM contracts WHERE status = ? ORDER BY created_at DESC LIMIT ?",
            (status, limit),
        ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def update_status(self, contract_id: str, status: str) -> bool:
        """Update contract status."""
        now = time.time()
        cursor = self.db.execute(
            "UPDATE contracts SET status = ?, updated_at = ? WHERE id = ?",
            (status, now, contract_id),
        )
        self.db.commit()
        return cursor.rowcount > 0

    def assign_agent(self, contract_id: str, agent_pubkey: str, from_status: str = "open") -> bool:
        """Assign an agent to a contract. Transitions to in_progress."""
        now = time.time()
        cursor = self.db.execute(
            "UPDATE contracts SET agent_pubkey = ?, status = 'in_progress', updated_at = ? WHERE id = ? AND status = ?",
            (agent_pubkey, now, contract_id, from_status),
        )
        self.db.commit()
        return cursor.rowcount > 0

    def set_review_expires(self, contract_id: str, expires_at: float) -> bool:
        """Set review window expiry for autonomous mode."""
        now = time.time()
        cursor = self.db.execute(
            "UPDATE contracts SET review_expires_at = ?, updated_at = ? WHERE id = ?",
            (expires_at, now, contract_id),
        )
        self.db.commit()
        return cursor.rowcount > 0

    def set_last_investigation(self, contract_id: str, ts: float) -> bool:
        """Record timestamp of last investigation command (rate limiting)."""
        cursor = self.db.execute(
            "UPDATE contracts SET last_investigation_at = ? WHERE id = ?",
            (ts, contract_id),
        )
        self.db.commit()
        return cursor.rowcount > 0

    def append_message(self, contract_id: str, message: dict) -> bool:
        """Append a message to the contract transcript."""
        row = self.db.execute("SELECT transcript FROM contracts WHERE id = ?", (contract_id,)).fetchone()
        if not row:
            return False
        transcript = json.loads(row["transcript"])
        message["timestamp"] = time.time()
        transcript.append(message)
        now = time.time()
        self.db.execute(
            "UPDATE contracts SET transcript = ?, updated_at = ? WHERE id = ?",
            (json.dumps(transcript), now, contract_id),
        )
        self.db.commit()
        return True

    def update_contract_data(self, contract_id: str, contract: dict) -> bool:
        """Update the contract data."""
        now = time.time()
        cursor = self.db.execute(
            "UPDATE contracts SET contract = ?, updated_at = ? WHERE id = ?",
            (json.dumps(contract), now, contract_id),
        )
        self.db.commit()
        return cursor.rowcount > 0

    def _row_to_dict(self, row) -> dict:
        return {
            "id": row["id"],
            "status": row["status"],
            "contract": json.loads(row["contract"]),
            "principal_pubkey": row["principal_pubkey"],
            "agent_pubkey": row["agent_pubkey"],
            "judge_pubkey": row["judge_pubkey"],
            "execution_mode": row["execution_mode"],
            "review_expires_at": row["review_expires_at"],
            "last_investigation_at": row["last_investigation_at"],
            "transcript": json.loads(row["transcript"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def close(self):
        self.db.close()
