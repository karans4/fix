"""Contract storage and matchmaking for fix platform.

SQLite-backed CRUD + query by status for agents browsing work.
Stores full transcript as a signed message chain.
"""

import sqlite3
import json
import threading
import time
import uuid

from protocol import ContractState, STATE_TRANSITIONS, SERVER_ENTRY_TYPES
from crypto import chain_entry_hash, verify_chain_entry, hash_chain_init


class ContractStore:
    """SQLite-backed contract storage with state machine enforcement."""

    def __init__(self, db_path: str = ":memory:"):
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        # Enable WAL mode for safe concurrent reads during writes
        self.db.execute("PRAGMA journal_mode=WAL")
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
                chain_head TEXT NOT NULL DEFAULT '',
                server_pubkey TEXT NOT NULL DEFAULT '',
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            )
        """)
        self.db.execute("CREATE INDEX IF NOT EXISTS idx_status ON contracts(status)")
        self.db.commit()

    def create(self, contract: dict, principal_pubkey: str = "", server_pubkey: str = "") -> str:
        """Store a new contract. Returns contract ID."""
        contract_id = uuid.uuid4().hex[:16]
        now = time.time()

        # Extract judge and execution mode from contract
        judge_pubkey = contract.get("judge", {}).get("pubkey", "")
        execution_mode = contract.get("execution", {}).get("mode", "supervised")

        # Genesis chain head
        chain_head = hash_chain_init()

        self.db.execute(
            "INSERT INTO contracts (id, status, contract, principal_pubkey, judge_pubkey, execution_mode, chain_head, server_pubkey, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (contract_id, "open", json.dumps(contract), principal_pubkey, judge_pubkey, execution_mode, chain_head, server_pubkey, now, now),
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
        """Update contract status with state machine enforcement."""
        with self._lock:
            row = self.db.execute("SELECT status FROM contracts WHERE id = ?", (contract_id,)).fetchone()
            if not row:
                return False

            current = row["status"]
            # Validate transition
            try:
                current_state = ContractState(current)
                new_state = ContractState(status)
            except ValueError:
                raise ValueError(f"Invalid state: {current} -> {status}")

            valid_next = STATE_TRANSITIONS.get(current_state, set())
            if new_state not in valid_next:
                raise ValueError(f"Invalid state transition: {current} -> {status}")

            now = time.time()
            cursor = self.db.execute(
                "UPDATE contracts SET status = ?, updated_at = ? WHERE id = ? AND status = ?",
                (status, now, contract_id, current),
            )
            self.db.commit()
            return cursor.rowcount > 0

    def assign_agent(self, contract_id: str, agent_pubkey: str, from_status: str = "open") -> bool:
        """Assign an agent to a contract. Transitions to in_progress."""
        with self._lock:
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
        """Append a raw message to the transcript (for server-signed entries).

        For chain entries with signatures, use append_chain_entry instead.
        """
        with self._lock:
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

    def append_chain_entry(self, contract_id: str, entry: dict) -> tuple[bool, str]:
        """Append a signed chain entry to the transcript.

        Validates: seq == len(transcript), prev_hash matches chain_head, valid signature.
        Updates chain_head after append.

        Returns (ok, error_message).
        """
        with self._lock:
            row = self.db.execute(
                "SELECT transcript, chain_head, server_pubkey FROM contracts WHERE id = ?",
                (contract_id,),
            ).fetchone()
            if not row:
                return False, "Contract not found"

            transcript = json.loads(row["transcript"])
            current_head = row["chain_head"]

            # Validate sequence number
            expected_seq = len(transcript)
            if entry.get("seq") != expected_seq:
                return False, f"Seq conflict: expected {expected_seq}, got {entry.get('seq')}"

            # Validate prev_hash
            if entry.get("prev_hash") != current_head:
                return False, f"prev_hash mismatch: expected {current_head[:16]}..., got {entry.get('prev_hash', '')[:16]}..."

            # Enforce server-only entry types: only the server can sign rulings etc.
            entry_type = entry.get("type", "")
            if entry_type in SERVER_ENTRY_TYPES:
                # Verify the author is the server for this contract
                server_pub = row["server_pubkey"] if "server_pubkey" in row.keys() else ""
                author = entry.get("author", "")
                # Author is fix_<hex>, server_pubkey is raw hex
                author_hex = author[4:] if author.startswith("fix_") else author
                if not server_pub or author_hex != server_pub:
                    return False, f"Entry type '{entry_type}' is server-only but author is not the server"

            # Verify signature
            ok, err = verify_chain_entry(entry)
            if not ok:
                return False, f"Signature verification failed: {err}"

            # Append and update chain head
            transcript.append(entry)
            new_head = chain_entry_hash(entry)
            now = time.time()

            cursor = self.db.execute(
                "UPDATE contracts SET transcript = ?, chain_head = ?, updated_at = ? WHERE id = ? AND chain_head = ?",
                (json.dumps(transcript), new_head, now, contract_id, current_head),
            )
            self.db.commit()
            if cursor.rowcount == 0:
                return False, "Concurrent modification"
            return True, ""

    def get_chain_head(self, contract_id: str) -> str | None:
        """Get the current chain head hash for a contract."""
        row = self.db.execute(
            "SELECT chain_head FROM contracts WHERE id = ?",
            (contract_id,),
        ).fetchone()
        if not row:
            return None
        return row["chain_head"]

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
            "chain_head": row["chain_head"],
            "server_pubkey": row["server_pubkey"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def close(self):
        self.db.close()
