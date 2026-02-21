"""Integration tests for NanoBackend against the local Nano dev network.

Requires:
  - ed25519-blake2b pip package
  - nano-dev Docker container running with RPC at localhost:17076
  - Genesis wallet pre-loaded in the node

Tests are skipped automatically if either dependency is missing.
Run with: pytest -m nano tests/test_nano_integration.py -v
"""

import hashlib
import time
import pytest
import requests

# --- Skip conditions ---

try:
    import ed25519_blake2b
    HAS_ED25519 = True
except ImportError:
    HAS_ED25519 = False

DEV_NODE_URL = "http://localhost:17076"
GENESIS_WALLET = "0A68A23D4EDDF00A790FE3E8F9F58A1C5B579252C44BD1E7BBEB3091F0365BA1"
GENESIS_ACCOUNT = "nano_3e3j5tkog48pnny9dmfzj1r16pg8t1e76dz5tmac6iq689wyjfpiij4txtdo"


def _node_reachable():
    try:
        r = requests.post(DEV_NODE_URL, json={"action": "version"}, timeout=5)
        return r.status_code == 200
    except Exception:
        return False


skip_no_ed25519 = pytest.mark.skipif(
    not HAS_ED25519, reason="ed25519-blake2b not installed"
)
skip_no_node = pytest.mark.skipif(
    not _node_reachable(), reason=f"Nano dev node not reachable at {DEV_NODE_URL}"
)

pytestmark = [pytest.mark.nano, skip_no_ed25519, skip_no_node]


# --- Helpers ---

# Block confirmation delay on QEMU-emulated dev node (seconds).
# The process RPC returns immediately but account_balance lags.
CONFIRM_DELAY = 3


def _make_seed(name: str) -> str:
    """Deterministic 64-hex-char seed from a test name."""
    return hashlib.sha256(name.encode()).hexdigest()


def _send_from_genesis(destination: str, amount_raw: int) -> str:
    """Send from genesis wallet via RPC. Returns block hash."""
    resp = requests.post(DEV_NODE_URL, json={
        "action": "send",
        "wallet": GENESIS_WALLET,
        "source": GENESIS_ACCOUNT,
        "destination": destination,
        "amount": str(amount_raw),
    }, timeout=30)
    data = resp.json()
    if "error" in data:
        raise RuntimeError(f"Genesis send failed: {data['error']}")
    return data["block"]


def _make_backend(test_name: str):
    """Create a NanoBackend for a test with a unique seed."""
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from server.nano import NanoBackend
    seed = _make_seed(test_name)
    return NanoBackend(
        seed=seed,
        node_url=DEV_NODE_URL,
        charity_account=GENESIS_ACCOUNT,  # use genesis as charity placeholder
    )


def _fund_and_receive(backend, contract_id: str, amount_xno: str):
    """Fund an escrow from genesis and receive the pending block.

    Handles the confirmation delay on the QEMU dev node: after _receive_all
    publishes the receive block, account_balance takes a few seconds to update.
    """
    escrow_addr = backend._get_account(contract_id)
    amount_raw = int(__import__("decimal").Decimal(amount_xno) * RAW_PER_XNO)
    _send_from_genesis(escrow_addr, amount_raw)
    time.sleep(CONFIRM_DELAY)
    # Pocket the pending block
    backend._receive_all(contract_id)
    # Wait for the receive block to be confirmed on the dev node
    time.sleep(CONFIRM_DELAY)


# 1 XNO = 10^30 raw
RAW_PER_XNO = 10**30


# --- Tests ---

class TestNanoIntegration:

    def test_create_escrow_account(self):
        """Create an escrow account and verify it returns a valid nano_ address."""
        backend = _make_backend("test_create_escrow_account")
        result = backend.create_escrow_account("contract_create_1")
        account = result["account"]
        assert account.startswith("nano_"), f"Expected nano_ prefix, got: {account}"
        assert len(account) == 65, f"Expected 65 chars, got {len(account)}"
        # Verify via address validation
        from server.nano import validate_nano_address
        valid, err = validate_nano_address(account)
        assert valid, f"Invalid address: {err}"

    def test_fund_and_check_deposit(self):
        """Fund an escrow from genesis, then verify check_deposit returns True."""
        backend = _make_backend("test_fund_and_check_deposit")
        contract_id = "contract_deposit_1"
        result = backend.create_escrow_account(contract_id)
        escrow_addr = result["account"]

        # Fund and receive (handles dev node confirmation delay)
        _fund_and_receive(backend, contract_id, "1")

        # check_deposit should see the balance now
        deposited = backend.check_deposit(contract_id, "1")
        assert deposited, "check_deposit should return True after funding 1 XNO"

    def test_send_from_escrow(self):
        """Fund an escrow, send from it, verify block hash and balance decrease."""
        backend = _make_backend("test_send_from_escrow")
        contract_id = "contract_send_1"
        result = backend.create_escrow_account(contract_id)

        # Fund with 2 XNO and receive
        _fund_and_receive(backend, contract_id, "2")

        # Send 1 XNO back to genesis
        send_hash = backend.send(contract_id, GENESIS_ACCOUNT, "1")
        assert send_hash, "send() should return a block hash"
        assert len(send_hash) == 64, f"Block hash should be 64 hex chars, got {len(send_hash)}"

        # Wait for confirmation then check balance
        time.sleep(CONFIRM_DELAY)
        from decimal import Decimal
        balance = Decimal(backend.get_balance(contract_id))
        assert balance == Decimal("1"), f"Expected 1 XNO remaining, got {balance}"

    def test_insufficient_balance(self):
        """Sending more than the balance should raise ValueError."""
        backend = _make_backend("test_insufficient_balance")
        contract_id = "contract_insuff_1"
        result = backend.create_escrow_account(contract_id)

        # Fund with 0.5 XNO and receive
        _fund_and_receive(backend, contract_id, "0.5")

        # Try to send 10 XNO -- should fail
        with pytest.raises(ValueError, match="Insufficient balance"):
            backend.send(contract_id, GENESIS_ACCOUNT, "10")

    def test_full_escrow_lifecycle(self):
        """Complete lifecycle: create -> fund -> check -> pay agent -> verify remainder."""
        backend = _make_backend("test_full_escrow_lifecycle")
        contract_id = "contract_lifecycle_1"

        # 1. Create escrow
        result = backend.create_escrow_account(contract_id)
        escrow_addr = result["account"]
        assert escrow_addr.startswith("nano_")

        # 2. Fund escrow (simulating principal deposit) -- 5 XNO
        _fund_and_receive(backend, contract_id, "5")

        # 3. Check deposit
        assert backend.check_deposit(contract_id, "5"), "Should see 5 XNO deposit"

        # 4. Send 3 XNO to "agent" (genesis account standing in as agent)
        payout_hash = backend.send(contract_id, GENESIS_ACCOUNT, "3")
        assert payout_hash and len(payout_hash) == 64
        time.sleep(CONFIRM_DELAY)

        # 5. Verify remainder is 2 XNO
        from decimal import Decimal
        balance = Decimal(backend.get_balance(contract_id))
        assert balance == Decimal("2"), f"Expected 2 XNO remainder, got {balance}"

        # 6. Send remaining 2 XNO (e.g. refund to principal)
        refund_hash = backend.send(contract_id, GENESIS_ACCOUNT, "2")
        assert refund_hash and len(refund_hash) == 64
        time.sleep(CONFIRM_DELAY)

        # 7. Final balance should be 0
        final_balance = Decimal(backend.get_balance(contract_id))
        assert final_balance == Decimal("0"), f"Expected 0 XNO final balance, got {final_balance}"
