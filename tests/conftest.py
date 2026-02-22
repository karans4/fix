import sys
import os
import json
import time
import requests

# Ensure fix/ root is on the path for all tests
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from crypto import (
    generate_ed25519_keypair, ed25519_privkey_to_pubkey, pubkey_to_fix_id,
    sign_request_ed25519,
)
from server.nano import NanoBackend, xno_to_raw


# --- Nano dev node ---
# Dev node blocks aren't immediately "confirmed" — use include_only_confirmed=false
os.environ.setdefault("FIX_NANO_DEV", "1")

DEV_NODE = "http://localhost:17076"
GENESIS_KEY = "34F0A37AAD20F4A260F0A5B3CB3D7FB50673212263E58A380BC10474BB039CE4"
GENESIS_ACCOUNT = "nano_3e3j5tkog48pnny9dmfzj1r16pg8t1e76dz5tmac6iq689wyjfpiij4txtdo"
TEST_SEED = "aa" * 32

_wallet_id = None


def _dev_rpc(action, **kwargs):
    resp = requests.post(DEV_NODE, json={"action": action, **kwargs}, timeout=10)
    resp.raise_for_status()
    return resp.json()


def _ensure_wallet():
    global _wallet_id
    if _wallet_id is not None:
        return _wallet_id
    result = _dev_rpc("wallet_create")
    _wallet_id = result["wallet"]
    _dev_rpc("wallet_add", wallet=_wallet_id, key=GENESIS_KEY)
    return _wallet_id


def fund_account(dest_address: str, amount_xno: str):
    """Send XNO from genesis to dest on dev node. Waits for propagation."""
    wallet = _ensure_wallet()
    raw = str(xno_to_raw(amount_xno))
    result = _dev_rpc("send", wallet=wallet, source=GENESIS_ACCOUNT,
                      destination=dest_address, amount=raw)
    block_hash = result.get("hash") or result.get("block")
    if not block_hash:
        raise RuntimeError(f"Fund failed: {result}")
    for _ in range(10):
        time.sleep(0.5)
        recv = _dev_rpc("receivable", account=dest_address, count="1",
                        include_only_confirmed="false")
        blocks = recv.get("blocks", "")
        if blocks and blocks != "":
            break
    return block_hash


def make_nano_backend(seed=None):
    """Create a NanoBackend pointed at the dev node."""
    return NanoBackend(seed=seed or TEST_SEED, node_url=DEV_NODE, db_path=":memory:")


def set_funded_accounts(mgr, cid, principal_addr, agent_addr):
    """Set real nano addresses on an escrow contract (bypasses validation)."""
    mgr.db.execute(
        "UPDATE escrows SET principal_account = ?, agent_account = ? WHERE contract_id = ?",
        (principal_addr, agent_addr, cid),
    )
    mgr.db.commit()


# Pre-derived test payout addresses (deterministic, real nano addresses)
_PRINCIPAL_NANO = make_nano_backend(seed="cc" * 32)
_p_info = _PRINCIPAL_NANO.create_escrow_account("test_principal")
TEST_PRINCIPAL_ADDR = _p_info["account"]

_AGENT_NANO = make_nano_backend(seed="dd" * 32)
_a_info = _AGENT_NANO.create_escrow_account("test_agent")
TEST_AGENT_ADDR = _a_info["account"]


def fund_escrow(mgr, cid, amount_xno="0.67"):
    """Fund an escrow account from genesis and receive the pending blocks."""
    escrow = mgr.get(cid)
    escrow_addr = escrow["escrow_account"]
    fund_account(escrow_addr, amount_xno)
    mgr.payment._receive_all(cid)
    return escrow_addr


# Monotonic counter to ensure unique timestamps across rapid test calls.
# Each call gets a unique second offset so Ed25519 signatures differ.
_nonce_counter = 0

# Pre-generated test keypairs for deterministic tests
_PRINCIPAL_PRIV, _PRINCIPAL_PUB = generate_ed25519_keypair()
_AGENT_PRIV, _AGENT_PUB = generate_ed25519_keypair()
_SERVER_PRIV, _SERVER_PUB = generate_ed25519_keypair()

PRINCIPAL_PUBKEY = pubkey_to_fix_id(_PRINCIPAL_PUB)
AGENT_PUBKEY = pubkey_to_fix_id(_AGENT_PUB)
SERVER_PUBKEY = pubkey_to_fix_id(_SERVER_PUB)

PRINCIPAL_PRIV = _PRINCIPAL_PRIV
AGENT_PRIV = _AGENT_PRIV
SERVER_PRIV = _SERVER_PRIV

PRINCIPAL_PUB_HEX = _PRINCIPAL_PUB.hex()
AGENT_PUB_HEX = _AGENT_PUB.hex()
SERVER_PUB_HEX = _SERVER_PUB.hex()


def signed_post(client, path, data, pubkey, privkey_bytes):
    """Make an Ed25519-signed POST request for tests.

    Uses a nonce embedded in the body to ensure unique signatures even when
    the same endpoint+body is called multiple times in the same second
    (prevents replay guard false positives in tests).
    """
    global _nonce_counter
    _nonce_counter += 1
    data_with_nonce = {**data, "_nonce": _nonce_counter}
    body = json.dumps(data_with_nonce)
    pub_hex = pubkey[4:] if pubkey.startswith("fix_") else pubkey
    auth_headers = sign_request_ed25519(privkey_bytes, pub_hex, "POST", path, body)
    return client.post(path, content=body, headers={
        "Content-Type": "application/json",
        **auth_headers,
    })


def signed_headers(pubkey, privkey_bytes, method, path, body=""):
    """Generate Ed25519 auth headers for a request."""
    pub_hex = pubkey[4:] if pubkey.startswith("fix_") else pubkey
    return sign_request_ed25519(privkey_bytes, pub_hex, method, path, body)
