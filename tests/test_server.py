"""Tests for server/app.py endpoints."""

import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.dirname(__file__))

import pytest
from starlette.testclient import TestClient
from server.app import create_app
from server.store import ContractStore
from server.escrow import EscrowManager
from crypto import generate_ed25519_keypair, pubkey_to_fix_id
from conftest import (
    signed_post, PRINCIPAL_PUBKEY, AGENT_PUBKEY,
    PRINCIPAL_PRIV, AGENT_PRIV, AGENT_PUB_HEX, PRINCIPAL_PUB_HEX,
    SERVER_PRIV, make_nano_backend, set_funded_accounts, fund_escrow,
    TEST_PRINCIPAL_ADDR, TEST_AGENT_ADDR,
)

# Ad-hoc keypairs for tests that need extra identities
_a2_priv, _a2_pub = generate_ed25519_keypair()
AGENT2_PUBKEY = pubkey_to_fix_id(_a2_pub)
AGENT2_PRIV = _a2_priv

_x_priv, _x_pub = generate_ed25519_keypair()
X_PUBKEY = pubkey_to_fix_id(_x_pub)
X_PRIV = _x_priv


def _set_test_accounts(app, cid):
    """Set real nano payout addresses in escrow DB and fund the escrow."""
    set_funded_accounts(app.state.escrow, cid, TEST_PRINCIPAL_ADDR, TEST_AGENT_ADDR)
    fund_escrow(app.state.escrow, cid)


SAMPLE_CONTRACT = {
    "version": 2, "protocol": "fix",
    "task": {"type": "fix_command", "command": "make", "error": "gcc error"},
    "environment": {"os": "Linux", "arch": "aarch64", "package_managers": ["apt"]},
    "capabilities": {},
    "verification": [{"method": "exit_code", "expected": 0}],
    "execution": {"sandbox": False, "root": None, "max_attempts": 5, "investigation_rounds": 5, "timeout": 300},
    "escrow": {"bounty": "0.50", "currency": "XNO", "chain": "nano"},
    "terms": {"cancellation": {"grace_period": 30}},
}


@pytest.fixture
def app():
    """Fresh app with in-memory stores for each test."""
    store = ContractStore(":memory:")
    escrow_mgr = EscrowManager(":memory:", payment_backend=make_nano_backend())
    return create_app(store=store, escrow_mgr=escrow_mgr, server_privkey=SERVER_PRIV)


@pytest.fixture
def client(app):
    return TestClient(app)


def _create_contract(client, contract=None):
    """Helper: post a contract, return response JSON."""
    resp = signed_post(client, "/contracts", {
        "contract": contract or SAMPLE_CONTRACT,
        "principal_pubkey": PRINCIPAL_PUBKEY,
    }, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
    assert resp.status_code == 200
    return resp.json()


def _accept_contract(client, contract_id, agent_pubkey=AGENT_PUBKEY, agent_priv=AGENT_PRIV):
    """Helper: accept a contract via signed request."""
    path = f"/contracts/{contract_id}/accept"
    data = {"agent_pubkey": agent_pubkey}
    resp = signed_post(client, path, data, agent_pubkey, agent_priv)
    assert resp.status_code == 200
    return resp.json()


# --- POST /contracts ---

def test_post_contract_returns_id(client):
    data = _create_contract(client)
    assert "contract_id" in data
    assert data["status"] == "open"


def test_post_contract_locks_escrow(app, client):
    data = _create_contract(client)
    escrow = app.state.escrow.get(data["contract_id"])
    assert escrow is not None
    assert escrow["locked"] is True
    assert escrow["bounty"] == "0.50"


# --- GET /contracts ---

def test_list_contracts_returns_open(client):
    _create_contract(client)
    _create_contract(client)
    resp = client.get("/contracts")
    assert resp.status_code == 200
    contracts = resp.json()["contracts"]
    assert len(contracts) == 2
    assert all(c["status"] == "open" for c in contracts)


def test_list_contracts_empty(client):
    resp = client.get("/contracts")
    assert resp.status_code == 200
    assert resp.json()["contracts"] == []


# --- GET /contracts/{id} ---

def test_get_contract(client):
    data = _create_contract(client)
    cid = data["contract_id"]
    resp = client.get(f"/contracts/{cid}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == cid
    assert body["status"] == "open"
    assert body["contract"]["protocol"] == "fix"


def test_get_contract_404(client):
    resp = client.get("/contracts/nonexistent")
    assert resp.status_code == 404


# --- POST /contracts/{id}/accept ---

def test_accept_contract(client):
    data = _create_contract(client)
    cid = data["contract_id"]
    result = _accept_contract(client, cid)
    assert result["status"] == "in_progress"

    # Verify status changed in store
    resp = client.get(f"/contracts/{cid}")
    assert resp.json()["status"] == "in_progress"
    assert resp.json()["agent_pubkey"] == AGENT_PUBKEY


def test_accept_non_open_contract_409(client):
    data = _create_contract(client)
    cid = data["contract_id"]
    _accept_contract(client, cid)

    # Try to accept again -- should 409
    path = f"/contracts/{cid}/accept"
    resp = signed_post(client, path, {"agent_pubkey": AGENT2_PUBKEY}, AGENT2_PUBKEY, AGENT2_PRIV)
    assert resp.status_code == 409


def test_accept_nonexistent_404(client):
    path = "/contracts/nonexistent/accept"
    resp = signed_post(client, path, {"agent_pubkey": X_PUBKEY}, X_PUBKEY, X_PRIV)
    assert resp.status_code == 404


# --- POST /contracts/{id}/investigate ---

def test_investigate(client):
    data = _create_contract(client)
    cid = data["contract_id"]
    _accept_contract(client, cid)

    path = f"/contracts/{cid}/investigate"
    resp = signed_post(client, path, {
        "command": "ls -la",
        "agent_pubkey": AGENT_PUBKEY,
    }, AGENT_PUBKEY, AGENT_PRIV)
    assert resp.status_code == 200
    assert resp.json()["status"] == "pending_result"
    assert resp.json()["command"] == "ls -la"


def test_investigate_wrong_status_409(client):
    data = _create_contract(client)
    cid = data["contract_id"]
    # Contract is "open", not "in_progress"
    path = f"/contracts/{cid}/investigate"
    resp = signed_post(client, path, {
        "command": "ls",
        "agent_pubkey": AGENT_PUBKEY,
    }, AGENT_PUBKEY, AGENT_PRIV)
    assert resp.status_code == 409


# --- POST /contracts/{id}/result ---

def test_submit_result(client):
    data = _create_contract(client)
    cid = data["contract_id"]
    _accept_contract(client, cid)

    path = f"/contracts/{cid}/result"
    resp = signed_post(client, path, {
        "command": "ls -la",
        "output": "total 0\ndrwxr-xr-x  2 root root 40 Jan  1 00:00 .",
        "principal_pubkey": PRINCIPAL_PUBKEY,
    }, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"

    # Check transcript
    contract = client.get(f"/contracts/{cid}").json()
    result_msgs = [m for m in contract["transcript"] if m["type"] == "result"]
    assert len(result_msgs) == 1
    assert result_msgs[0]["data"]["output"].startswith("total 0")


# --- POST /contracts/{id}/fix ---

def test_submit_fix(client):
    data = _create_contract(client)
    cid = data["contract_id"]
    _accept_contract(client, cid)

    path = f"/contracts/{cid}/fix"
    resp = signed_post(client, path, {
        "fix": "apt install gcc",
        "explanation": "missing compiler",
        "agent_pubkey": AGENT_PUBKEY,
    }, AGENT_PUBKEY, AGENT_PRIV)
    assert resp.status_code == 200
    assert resp.json()["status"] == "pending_verification"


def test_submit_fix_wrong_status_409(client):
    data = _create_contract(client)
    cid = data["contract_id"]
    # Still "open" — agent not assigned, so 403 (not a party)
    path = f"/contracts/{cid}/fix"
    resp = signed_post(client, path, {
        "fix": "echo hi",
        "agent_pubkey": AGENT_PUBKEY,
    }, AGENT_PUBKEY, AGENT_PRIV)
    assert resp.status_code == 403


# --- POST /contracts/{id}/verify ---

def test_verify_success_fulfills(app, client):
    data = _create_contract(client)
    cid = data["contract_id"]
    _accept_contract(client, cid)
    signed_post(client, f"/contracts/{cid}/fix", {
        "fix": "apt install gcc", "agent_pubkey": AGENT_PUBKEY,
    }, AGENT_PUBKEY, AGENT_PRIV)

    _set_test_accounts(app, cid)
    path = f"/contracts/{cid}/verify"
    resp = signed_post(client, path, {
        "success": True,
        "explanation": "build passes now",
        "principal_pubkey": PRINCIPAL_PUBKEY,
    }, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
    assert resp.status_code == 200
    assert resp.json()["status"] == "fulfilled"

    # Contract status should be fulfilled
    contract = client.get(f"/contracts/{cid}").json()
    assert contract["status"] == "fulfilled"


def test_verify_failure_retries(client):
    data = _create_contract(client)
    cid = data["contract_id"]
    _accept_contract(client, cid)
    signed_post(client, f"/contracts/{cid}/fix", {
        "fix": "echo nope", "agent_pubkey": AGENT_PUBKEY,
    }, AGENT_PUBKEY, AGENT_PRIV)

    path = f"/contracts/{cid}/verify"
    resp = signed_post(client, path, {
        "success": False,
        "explanation": "still broken",
        "principal_pubkey": PRINCIPAL_PUBKEY,
    }, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
    assert resp.status_code == 200
    assert resp.json()["status"] == "retry"

    # Contract stays in_progress for retry
    contract = client.get(f"/contracts/{cid}").json()
    assert contract["status"] == "in_progress"


def test_verify_failure_cancels_after_max_attempts(app, client):
    data = _create_contract(client)
    cid = data["contract_id"]
    _accept_contract(client, cid)
    _set_test_accounts(app, cid)

    # Exhaust all 5 attempts
    for i in range(5):
        signed_post(client, f"/contracts/{cid}/fix", {
            "fix": f"echo nope{i}", "agent_pubkey": AGENT_PUBKEY,
        }, AGENT_PUBKEY, AGENT_PRIV)
        resp = signed_post(client, f"/contracts/{cid}/verify", {
            "success": False,
            "explanation": f"still broken attempt {i+1}",
            "principal_pubkey": PRINCIPAL_PUBKEY,
        }, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)

    assert resp.json()["status"] == "canceled"
    contract = client.get(f"/contracts/{cid}").json()
    assert contract["status"] == "canceled"


def test_verify_resolves_escrow(app, client):
    data = _create_contract(client)
    cid = data["contract_id"]
    _accept_contract(client, cid)
    signed_post(client, f"/contracts/{cid}/fix", {
        "fix": "apt install gcc", "agent_pubkey": AGENT_PUBKEY,
    }, AGENT_PUBKEY, AGENT_PRIV)
    _set_test_accounts(app, cid)
    signed_post(client, f"/contracts/{cid}/verify", {
        "success": True, "principal_pubkey": PRINCIPAL_PUBKEY,
    }, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)

    escrow = app.state.escrow.get(cid)
    assert escrow["resolved"] is True


# --- GET /reputation/{pubkey} (bond-as-reputation) ---

def test_get_reputation_returns_bond_note(client):
    resp = client.get("/reputation/unknown_key")
    assert resp.status_code == 200
    body = resp.json()
    assert body["pubkey"] == "unknown_key"
    assert "on-chain balance" in body["note"]


# --- 404 on nonexistent contract for various endpoints ---

def test_result_nonexistent_404(client):
    path = "/contracts/nope/result"
    resp = signed_post(client, path, {
        "command": "ls", "output": "hi", "principal_pubkey": PRINCIPAL_PUBKEY,
    }, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
    assert resp.status_code == 404


def test_fix_nonexistent_404(client):
    path = "/contracts/nope/fix"
    resp = signed_post(client, path, {
        "fix": "echo", "agent_pubkey": X_PUBKEY,
    }, X_PUBKEY, X_PRIV)
    assert resp.status_code == 404


def test_verify_nonexistent_404(client):
    path = "/contracts/nope/verify"
    resp = signed_post(client, path, {
        "success": True, "principal_pubkey": PRINCIPAL_PUBKEY,
    }, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
    assert resp.status_code == 404
