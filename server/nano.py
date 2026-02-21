"""Nano (XNO) payment backend for fix platform.

HD wallet design: one master seed (from env/config), derive per-contract
keypairs deterministically. No private keys stored in the database.
"""

import os
import hashlib
from abc import ABC, abstractmethod
from decimal import Decimal

try:
    import nanohakase as nano
except ImportError:
    nano = None  # StubBackend works without it


# 1 XNO = 10^30 raw
RAW_PER_XNO = 10**30


def xno_to_raw(amount: str | Decimal) -> int:
    """Convert XNO amount to raw (integer)."""
    return int(Decimal(amount) * RAW_PER_XNO)


def raw_to_xno(raw: int | str) -> Decimal:
    """Convert raw to XNO."""
    return Decimal(str(raw)) / RAW_PER_XNO


class PaymentBackend(ABC):
    """Abstract payment backend. Platform injects one of these into EscrowManager."""

    @abstractmethod
    def create_escrow_account(self, contract_id: str) -> dict:
        """Create/derive an escrow account for a contract.
        Returns {"account": "nano_...", "index": int}
        No private keys in the return value -- they're derived on demand.
        """
        ...

    @abstractmethod
    def check_deposit(self, contract_id: str, expected_xno: str) -> bool:
        """Check if the escrow account has received the expected deposit.
        Pockets any pending blocks first.
        """
        ...

    @abstractmethod
    def send(self, contract_id: str, to_account: str, amount_xno: str) -> str:
        """Send XNO from escrow account to destination.
        Returns block hash or receipt ID.
        """
        ...

    @abstractmethod
    def get_balance(self, contract_id: str) -> str:
        """Get escrow account balance in XNO."""
        ...


if nano is not None:
    class NanoBackend(PaymentBackend):
        """Real Nano payment backend using nanohakase.

        Master seed stored in env var FIX_NANO_SEED or passed directly.
        Each contract gets a deterministic keypair: seed + index.
        Index is derived from contract_id via hash to avoid collisions.
        """

        DEFAULT_NODE = "https://proxy.nanos.cc/proxy"

        def __init__(self, seed: str | None = None, node_url: str | None = None,
                     charity_account: str | None = None):
            self.seed = seed or os.environ.get("FIX_NANO_SEED", "")
            if not self.seed:
                raise ValueError("Nano seed required: set FIX_NANO_SEED env var or pass seed=")
            if len(self.seed) != 64:
                raise ValueError("Nano seed must be 64 hex characters")
            self.node_url = node_url or os.environ.get("FIX_NANO_NODE", self.DEFAULT_NODE)
            from protocol import CHARITY_ADDRESS
            self.charity_account = charity_account if charity_account is not None else CHARITY_ADDRESS
            self.rpc = nano.RPC(self.node_url)
            self._index_cache: dict[str, int] = {}

        def _derive_index(self, contract_id: str) -> int:
            """Deterministic index from contract_id. Uses first 4 bytes of SHA-256."""
            h = hashlib.sha256(contract_id.encode()).digest()
            return int.from_bytes(h[:4], "big") & 0x7FFFFFFF

        def _get_wallet(self, contract_id: str):
            """Get a nanohakase Wallet for a contract's escrow account."""
            idx = self._derive_index(contract_id)
            return nano.Wallet(self.rpc, seed=self.seed, index=idx)

        def _get_account(self, contract_id: str) -> str:
            """Get the nano address for a contract's escrow account."""
            idx = self._derive_index(contract_id)
            priv = nano.get_private_key_from_seed(self.seed, idx)
            pub = nano.get_public_key_from_private_key(priv)
            return nano.get_address_from_public_key(pub)

        def create_escrow_account(self, contract_id: str) -> dict:
            idx = self._derive_index(contract_id)
            account = self._get_account(contract_id)
            return {"account": account, "index": idx}

        def check_deposit(self, contract_id: str, expected_xno: str) -> bool:
            wallet = self._get_wallet(contract_id)
            try:
                wallet.receive_all()
            except Exception:
                pass
            account = self._get_account(contract_id)
            balance_info = self.rpc.get_account_balance(account)
            balance_raw = int(balance_info.get("balance", "0"))
            expected_raw = xno_to_raw(expected_xno)
            return balance_raw >= expected_raw

        def send(self, contract_id: str, to_account: str, amount_xno: str) -> str:
            raw = xno_to_raw(amount_xno)
            if raw == 0:
                return "noop_zero_amount"
            wallet = self._get_wallet(contract_id)
            result = wallet.send(to_account, str(raw))
            if isinstance(result, dict):
                return result.get("hash", str(result))
            return str(result)

        def get_balance(self, contract_id: str) -> str:
            account = self._get_account(contract_id)
            try:
                balance_info = self.rpc.get_account_balance(account)
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
        return {"account": account, "index": 0}

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
