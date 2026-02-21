"""Nano (XNO) payment backend for fix platform.

Key derivation: each contract gets a random 256-bit nonce stored in SQLite.
The private key is derived as blake2b(master_seed || nonce, digest_size=32).
No nanohakase dependency -- uses ed25519-blake2b + raw RPC.

Security model (two independent secrets):
  - Seed leak alone: useless (nonces unknown, not derivable)
  - DB leak alone: useless (seed unknown, nonces are random bytes)
  - Both leak: full compromise (unavoidable with any scheme)
  - Contract IDs are public and NOT part of key derivation.

Backup requirement: the nonce DB MUST be backed up. Losing it means
losing access to all escrow funds (nonces are random, not reconstructable).
"""

import os
import hashlib
import secrets
import sqlite3
import threading
import requests
from abc import ABC, abstractmethod
from decimal import Decimal

try:
    import ed25519_blake2b
except ImportError:
    ed25519_blake2b = None  # StubBackend works without it


# 1 XNO = 10^30 raw
RAW_PER_XNO = 10**30

# Nano base32 alphabet (no 0, 2, l, v)
_NANO_ALPHABET = '13456789abcdefghijkmnopqrstuwxyz'


def xno_to_raw(amount: str | Decimal) -> int:
    """Convert XNO amount to raw (integer)."""
    result = Decimal(amount) * RAW_PER_XNO
    return int(result.to_integral_value())


def raw_to_xno(raw: int | str) -> Decimal:
    """Convert raw to XNO."""
    return Decimal(str(raw)) / RAW_PER_XNO


def _pubkey_to_address(pubkey_bytes: bytes) -> str:
    """Convert 32-byte Ed25519 public key to nano_ address."""
    # Encode 256-bit pubkey as 52 base32 chars (260 bits, 4 leading zero bits)
    val = int.from_bytes(pubkey_bytes, 'big')
    chars = []
    for _ in range(52):
        chars.append(_NANO_ALPHABET[val & 0x1f])
        val >>= 5
    chars.reverse()

    # Checksum: blake2b-40 of pubkey, bytes reversed, encoded as 8 base32 chars
    checksum = hashlib.blake2b(pubkey_bytes, digest_size=5).digest()[::-1]
    val = int.from_bytes(checksum, 'big')
    ck = []
    for _ in range(8):
        ck.append(_NANO_ALPHABET[val & 0x1f])
        val >>= 5
    ck.reverse()

    return 'nano_' + ''.join(chars) + ''.join(ck)


def validate_nano_address(address: str) -> tuple[bool, str]:
    """Validate a Nano address (nano_ or xrb_ prefix, base32, checksum).

    Returns (True, "") on success, or (False, "error message") on failure.
    """
    # Check prefix
    if address.startswith('nano_'):
        payload = address[5:]
        expected_len = 60  # 52 key + 8 checksum
    elif address.startswith('xrb_'):
        payload = address[4:]
        expected_len = 60
    else:
        return False, f"Invalid prefix: expected 'nano_' or 'xrb_', got '{address[:5]}'"

    # Check length of payload
    if len(payload) != expected_len:
        return False, f"Invalid length: expected {expected_len} chars after prefix, got {len(payload)}"

    # Check all chars are in Nano base32 alphabet
    for i, c in enumerate(payload):
        if c not in _NANO_ALPHABET:
            return False, f"Invalid character '{c}' at position {i} (not in Nano base32 alphabet)"

    # Decode public key from first 52 chars
    key_part = payload[:52]
    val = 0
    for c in key_part:
        val = (val << 5) | _NANO_ALPHABET.index(c)
    # 52 * 5 = 260 bits, top 4 bits should be zero (256-bit key)
    val &= (1 << 256) - 1
    pubkey_bytes = val.to_bytes(32, 'big')

    # Decode checksum from last 8 chars
    checksum_part = payload[52:]
    ck_val = 0
    for c in checksum_part:
        ck_val = (ck_val << 5) | _NANO_ALPHABET.index(c)
    # 8 * 5 = 40 bits = 5 bytes
    decoded_checksum = ck_val.to_bytes(5, 'big')

    # Compute expected checksum: blake2b-40 of pubkey, bytes reversed
    expected_checksum = hashlib.blake2b(pubkey_bytes, digest_size=5).digest()[::-1]

    if decoded_checksum != expected_checksum:
        return False, "Checksum mismatch: address is corrupted or invalid"

    return True, ""


def _address_to_pubkey(address: str) -> bytes:
    """Decode a nano_/xrb_ address to 32-byte public key."""
    if address.startswith('nano_'):
        addr = address[5:]
    elif address.startswith('xrb_'):
        addr = address[4:]
    else:
        raise ValueError(f"Invalid Nano address prefix: {address[:5]}")
    key_part = addr[:52]
    val = 0
    for c in key_part:
        val = (val << 5) | _NANO_ALPHABET.index(c)
    val &= (1 << 256) - 1
    return val.to_bytes(32, 'big')


def _compute_block_hash(account: bytes, previous: bytes, representative: bytes,
                        balance: int, link: bytes) -> bytes:
    """Compute Nano state block hash."""
    preamble = b'\x00' * 31 + b'\x06'
    h = hashlib.blake2b(digest_size=32)
    h.update(preamble)
    h.update(account)
    h.update(previous)
    h.update(representative)
    h.update(balance.to_bytes(16, 'big'))
    h.update(link)
    return h.digest()


class PaymentBackend(ABC):
    """Abstract payment backend. Platform injects one of these into EscrowManager."""

    @abstractmethod
    def create_escrow_account(self, contract_id: str) -> dict:
        """Create/derive an escrow account for a contract.
        Returns {"account": "nano_..."}
        No private keys in the return value.
        """
        ...

    @abstractmethod
    def check_deposit(self, contract_id: str, expected_xno: str) -> bool:
        """Check if the escrow account has received the expected deposit."""
        ...

    @abstractmethod
    def send(self, contract_id: str, to_account: str, amount_xno: str) -> str:
        """Send XNO from escrow account to destination.
        Returns block hash.
        """
        ...

    @abstractmethod
    def get_balance(self, contract_id: str) -> str:
        """Get escrow account balance in XNO."""
        ...


if ed25519_blake2b is not None:
    class NanoBackend(PaymentBackend):
        """Nano payment backend using ed25519-blake2b + raw RPC.

        Key derivation: blake2b(seed || random_nonce) -> 32-byte private key.
        The nonce is a random 256-bit value stored in SQLite per contract.

        Two independent secrets required to derive any key:
          1. Master seed (env var FIX_NANO_SEED)
          2. Per-contract nonce (SQLite DB)
        """

        DEFAULT_NODE = "https://proxy.nanos.cc/proxy"

        def __init__(self, seed: str | None = None, node_url: str | None = None,
                     charity_account: str | None = None, db_path: str = ""):
            self.seed = seed or os.environ.get("FIX_NANO_SEED", "")
            if not self.seed:
                raise ValueError("Nano seed required: set FIX_NANO_SEED env var or pass seed=")
            if len(self.seed) != 64 or not all(c in '0123456789abcdefABCDEF' for c in self.seed):
                raise ValueError("Nano seed must be 64 hex characters")
            self._seed_bytes = bytes.fromhex(self.seed)
            self.node_url = node_url or os.environ.get("FIX_NANO_NODE", self.DEFAULT_NODE)
            from protocol import CHARITY_ADDRESS
            self.charity_account = charity_account if charity_account is not None else CHARITY_ADDRESS

            # Nonce DB: random 256-bit nonce per contract
            nonce_db_path = db_path or os.environ.get("FIX_NANO_DB", ":memory:")
            self._db = sqlite3.connect(nonce_db_path, check_same_thread=False)
            self._lock = threading.Lock()
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("""
                CREATE TABLE IF NOT EXISTS nano_nonces (
                    contract_id TEXT PRIMARY KEY,
                    nonce BLOB NOT NULL
                )
            """)
            self._db.commit()

        def _rpc(self, action: str, **kwargs) -> dict:
            """Make a Nano RPC call."""
            resp = requests.post(self.node_url, json={"action": action, **kwargs}, timeout=30)
            resp.raise_for_status()
            result = resp.json()
            if "error" in result:
                raise RuntimeError(f"Nano RPC error: {result['error']}")
            return result

        def _get_nonce(self, contract_id: str) -> bytes:
            """Get or create a random nonce for a contract."""
            with self._lock:
                row = self._db.execute(
                    "SELECT nonce FROM nano_nonces WHERE contract_id = ?",
                    (contract_id,)
                ).fetchone()
                if row:
                    return row[0]
                nonce = secrets.token_bytes(32)
                self._db.execute(
                    "INSERT INTO nano_nonces (contract_id, nonce) VALUES (?, ?)",
                    (contract_id, nonce)
                )
                self._db.commit()
                return nonce

        def _derive_keypair(self, contract_id: str):
            """Derive ed25519 keypair from seed + nonce."""
            nonce = self._get_nonce(contract_id)
            priv_bytes = hashlib.blake2b(self._seed_bytes + nonce, digest_size=32).digest()
            sk = ed25519_blake2b.SigningKey(priv_bytes)
            vk = sk.get_verifying_key()
            return sk, vk

        def _get_account(self, contract_id: str) -> str:
            """Get the nano address for a contract's escrow account."""
            _, vk = self._derive_keypair(contract_id)
            return _pubkey_to_address(vk.to_bytes())

        def create_escrow_account(self, contract_id: str) -> dict:
            account = self._get_account(contract_id)
            return {"account": account}

        def check_deposit(self, contract_id: str, expected_xno: str) -> bool:
            # Receive pending blocks first
            self._receive_all(contract_id)
            account = self._get_account(contract_id)
            balance_info = self._rpc("account_balance", account=account)
            balance_raw = int(balance_info.get("balance", "0"))
            expected_raw = xno_to_raw(expected_xno)
            return balance_raw >= expected_raw

        def _receive_all(self, contract_id: str):
            """Pocket all pending blocks for a contract's account."""
            sk, vk = self._derive_keypair(contract_id)
            account = self._get_account(contract_id)
            pubkey = vk.to_bytes()

            try:
                receivable = self._rpc("receivable", account=account, count="50")
                blocks = receivable.get("blocks", {})
                if isinstance(blocks, str):  # empty string means none
                    return
                if isinstance(blocks, list):
                    block_hashes = blocks
                else:
                    block_hashes = list(blocks.keys()) if isinstance(blocks, dict) else []
            except Exception:
                return

            for block_hash in block_hashes:
                try:
                    self._receive_block(sk, pubkey, account, block_hash)
                except Exception:
                    continue

        def _receive_block(self, sk, pubkey: bytes, account: str, send_hash: str):
            """Create and publish a receive block."""
            # Get current account state
            try:
                info = self._rpc("account_info", account=account, representative="true")
                previous = bytes.fromhex(info["frontier"])
                rep = _address_to_pubkey(info.get("representative", account))
                balance = int(info["balance"])
            except RuntimeError:
                # Account not opened yet
                previous = b'\x00' * 32
                rep = pubkey  # self as rep for new accounts
                balance = 0

            # Get the amount from the send block
            block_info = self._rpc("block_info", json_block="true", hash=send_hash)
            amount = int(block_info.get("amount", "0"))
            new_balance = balance + amount

            link = bytes.fromhex(send_hash)
            block_hash = _compute_block_hash(pubkey, previous, rep, new_balance, link)
            sig = sk.sign(block_hash)

            # Get work
            work_hash = previous if previous != b'\x00' * 32 else pubkey
            work_resp = self._rpc("work_generate", hash=work_hash.hex())

            block = {
                "type": "state",
                "account": account,
                "previous": previous.hex().upper(),
                "representative": _pubkey_to_address(rep),
                "balance": str(new_balance),
                "link": send_hash.upper(),
                "signature": sig.hex().upper(),
                "work": work_resp["work"],
            }
            self._rpc("process", json_block="true", subtype="receive",
                       block=block)

        def send(self, contract_id: str, to_account: str, amount_xno: str) -> str:
            raw = xno_to_raw(amount_xno)
            if raw == 0:
                return "noop_zero_amount"

            # Receive pending blocks first
            self._receive_all(contract_id)

            sk, vk = self._derive_keypair(contract_id)
            pubkey = vk.to_bytes()
            account = self._get_account(contract_id)

            # Get account state
            info = self._rpc("account_info", account=account, representative="true")
            previous = bytes.fromhex(info["frontier"])
            rep = _address_to_pubkey(info.get("representative", account))
            balance = int(info["balance"])

            if balance < raw:
                raise ValueError(
                    f"Insufficient balance: have {raw_to_xno(balance)} XNO, "
                    f"need {amount_xno} XNO (contract {contract_id})"
                )

            new_balance = balance - raw
            dest_pubkey = _address_to_pubkey(to_account)
            block_hash = _compute_block_hash(pubkey, previous, rep, new_balance, dest_pubkey)
            sig = sk.sign(block_hash)

            # Get work
            work_resp = self._rpc("work_generate", hash=previous.hex())

            block = {
                "type": "state",
                "account": account,
                "previous": previous.hex().upper(),
                "representative": _pubkey_to_address(rep),
                "balance": str(new_balance),
                "link": dest_pubkey.hex().upper(),
                "signature": sig.hex().upper(),
                "work": work_resp["work"],
            }
            result = self._rpc("process", json_block="true", subtype="send",
                                block=block)
            return result.get("hash", str(result))

        def get_balance(self, contract_id: str) -> str:
            account = self._get_account(contract_id)
            try:
                balance_info = self._rpc("account_balance", account=account)
                balance_raw = int(balance_info.get("balance", "0"))
                return str(raw_to_xno(balance_raw))
            except Exception:
                return "0"


class StubBackend(PaymentBackend):
    """No-op backend for testing. All operations succeed immediately."""

    def __init__(self):
        self.accounts: dict[str, dict] = {}
        self.sends: list[dict] = []  # log of sends for test assertions

    def create_escrow_account(self, contract_id: str) -> dict:
        account = f"nano_stub_{contract_id[:16]}"
        self.accounts[contract_id] = {"account": account, "balance": "0"}
        return {"account": account}

    def check_deposit(self, contract_id: str, expected_xno: str) -> bool:
        return True  # Always pretend deposit arrived

    def send(self, contract_id: str, to_account: str, amount_xno: str) -> str:
        self.sends.append({
            "contract_id": contract_id,
            "to": to_account,
            "amount": amount_xno,
        })
        return f"stub_hash_{len(self.sends)}"

    def get_balance(self, contract_id: str) -> str:
        return self.accounts.get(contract_id, {}).get("balance", "0")


class SimBackend(PaymentBackend):
    """Simulated payment backend for development/integration testing.

    Tracks real balances in SQLite. Enforces:
    - No zero-amount sends (matches Nano protocol)
    - Insufficient balance errors
    - Deposit verification against actual received funds
    - Full transaction log with deterministic hashes

    Uses real ed25519-blake2b key derivation (if available) so escrow
    addresses are valid nano_ addresses. Falls back to deterministic
    fake addresses if ed25519_blake2b is not installed.

    Usage:
        sim = SimBackend(seed="aa" * 32)
        sim.fund("nano_...", "10.0")  # fund an external account
        sim.create_escrow_account("contract1")
        sim.deposit("contract1", "0.5")  # simulate principal's deposit
        sim.send("contract1", "nano_...", "0.5")  # pay the agent
    """

    def __init__(self, seed: str | None = None, db_path: str = ":memory:",
                 charity_account: str | None = None,
                 allow_zero_sends: bool = False):
        self._seed_bytes = bytes.fromhex(seed or "aa" * 32)
        self.allow_zero_sends = allow_zero_sends
        from protocol import CHARITY_ADDRESS
        self.charity_account = charity_account if charity_account is not None else CHARITY_ADDRESS

        self._db = sqlite3.connect(db_path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._init_db()

        # Track nonces for key derivation (same as NanoBackend)
        self._nonces: dict[str, bytes] = {}
        self._tx_counter = 0

    def _init_db(self):
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS sim_accounts (
                address TEXT PRIMARY KEY,
                balance_raw TEXT NOT NULL DEFAULT '0'
            )
        """)
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS sim_transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hash TEXT NOT NULL UNIQUE,
                from_account TEXT NOT NULL,
                to_account TEXT NOT NULL,
                amount_raw TEXT NOT NULL,
                amount_xno TEXT NOT NULL,
                contract_id TEXT,
                tx_type TEXT NOT NULL,
                timestamp REAL NOT NULL
            )
        """)
        # Contract -> escrow account mapping
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS sim_escrows (
                contract_id TEXT PRIMARY KEY,
                account TEXT NOT NULL,
                nonce BLOB NOT NULL
            )
        """)
        self._db.commit()

    def _get_balance_raw(self, address: str) -> int:
        """Get balance in raw for an address."""
        row = self._db.execute(
            "SELECT balance_raw FROM sim_accounts WHERE address = ?",
            (address,),
        ).fetchone()
        return int(row["balance_raw"]) if row else 0

    def _set_balance_raw(self, address: str, raw: int):
        """Set balance in raw, creating account if needed."""
        self._db.execute(
            "INSERT INTO sim_accounts (address, balance_raw) VALUES (?, ?) "
            "ON CONFLICT(address) DO UPDATE SET balance_raw = ?",
            (address, str(raw), str(raw)),
        )

    def _record_tx(self, from_acc: str, to_acc: str, raw: int,
                   xno: str, contract_id: str, tx_type: str) -> str:
        """Record a transaction and return its hash."""
        import time as _t
        self._tx_counter += 1
        tx_hash = hashlib.blake2b(
            f"{self._tx_counter}:{from_acc}:{to_acc}:{raw}".encode(),
            digest_size=32,
        ).hexdigest().upper()
        self._db.execute(
            "INSERT INTO sim_transactions (hash, from_account, to_account, "
            "amount_raw, amount_xno, contract_id, tx_type, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (tx_hash, from_acc, to_acc, str(raw), xno, contract_id, tx_type, _t.time()),
        )
        return tx_hash

    def _derive_account(self, contract_id: str) -> str:
        """Derive a nano address for a contract (same scheme as NanoBackend)."""
        if contract_id in self._nonces:
            nonce = self._nonces[contract_id]
        else:
            nonce = secrets.token_bytes(32)
            self._nonces[contract_id] = nonce

        priv_bytes = hashlib.blake2b(self._seed_bytes + nonce, digest_size=32).digest()

        if ed25519_blake2b is not None:
            sk = ed25519_blake2b.SigningKey(priv_bytes)
            pub_bytes = sk.get_verifying_key().to_bytes()
        else:
            # Deterministic fake: hash the private key to get a "pubkey"
            pub_bytes = hashlib.blake2b(priv_bytes, digest_size=32).digest()

        return _pubkey_to_address(pub_bytes)

    # --- PaymentBackend interface ---

    def create_escrow_account(self, contract_id: str) -> dict:
        with self._lock:
            address = self._derive_account(contract_id)
            self._set_balance_raw(address, 0)
            self._db.execute(
                "INSERT OR IGNORE INTO sim_escrows (contract_id, account, nonce) VALUES (?, ?, ?)",
                (contract_id, address, self._nonces[contract_id]),
            )
            self._db.commit()
            return {"account": address}

    def check_deposit(self, contract_id: str, expected_xno: str) -> bool:
        with self._lock:
            row = self._db.execute(
                "SELECT account FROM sim_escrows WHERE contract_id = ?",
                (contract_id,),
            ).fetchone()
            if not row:
                return False
            balance = self._get_balance_raw(row["account"])
            expected = xno_to_raw(expected_xno)
            return balance >= expected

    def send(self, contract_id: str, to_account: str, amount_xno: str) -> str:
        raw = xno_to_raw(amount_xno)
        if raw == 0:
            if self.allow_zero_sends:
                return "sim_noop_zero"
            return "noop_zero_amount"

        with self._lock:
            row = self._db.execute(
                "SELECT account FROM sim_escrows WHERE contract_id = ?",
                (contract_id,),
            ).fetchone()
            if not row:
                raise ValueError(f"No escrow account for contract {contract_id}")

            from_account = row["account"]
            balance = self._get_balance_raw(from_account)

            if balance < raw:
                raise ValueError(
                    f"Insufficient balance: have {raw_to_xno(balance)} XNO, "
                    f"need {amount_xno} XNO (contract {contract_id})"
                )

            # Atomic transfer
            self._set_balance_raw(from_account, balance - raw)
            to_balance = self._get_balance_raw(to_account)
            self._set_balance_raw(to_account, to_balance + raw)
            tx_hash = self._record_tx(from_account, to_account, raw,
                                       amount_xno, contract_id, "send")
            self._db.commit()
            return tx_hash

    def get_balance(self, contract_id: str) -> str:
        with self._lock:
            row = self._db.execute(
                "SELECT account FROM sim_escrows WHERE contract_id = ?",
                (contract_id,),
            ).fetchone()
            if not row:
                return "0"
            raw = self._get_balance_raw(row["account"])
            return str(raw_to_xno(raw))

    # --- SimBackend-only methods (for test setup) ---

    def fund(self, address: str, amount_xno: str):
        """Credit an account with funds (simulates external deposit)."""
        raw = xno_to_raw(amount_xno)
        with self._lock:
            balance = self._get_balance_raw(address)
            self._set_balance_raw(address, balance + raw)
            self._record_tx("faucet", address, raw, amount_xno, "", "fund")
            self._db.commit()

    def deposit(self, contract_id: str, amount_xno: str):
        """Simulate a principal depositing into escrow."""
        raw = xno_to_raw(amount_xno)
        with self._lock:
            row = self._db.execute(
                "SELECT account FROM sim_escrows WHERE contract_id = ?",
                (contract_id,),
            ).fetchone()
            if not row:
                raise ValueError(f"No escrow account for contract {contract_id}")
            address = row["account"]
            balance = self._get_balance_raw(address)
            self._set_balance_raw(address, balance + raw)
            self._record_tx("principal", address, raw, amount_xno,
                           contract_id, "deposit")
            self._db.commit()

    def get_account_balance(self, address: str) -> str:
        """Get balance of any address (not just escrow)."""
        with self._lock:
            raw = self._get_balance_raw(address)
            return str(raw_to_xno(raw))

    def get_transactions(self, contract_id: str = "") -> list[dict]:
        """Get transaction log, optionally filtered by contract."""
        with self._lock:
            if contract_id:
                rows = self._db.execute(
                    "SELECT * FROM sim_transactions WHERE contract_id = ? ORDER BY id",
                    (contract_id,),
                ).fetchall()
            else:
                rows = self._db.execute(
                    "SELECT * FROM sim_transactions ORDER BY id"
                ).fetchall()
            return [dict(r) for r in rows]
