"""Tests for server/app.py endpoints."""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from starlette.testclient import TestClient
from server.app import create_app
from server.store import ContractStore
from server.escrow import EscrowManager
from server.reputation import ReputationManager


SAMPLE_CONTRACT = {
    "version": 2, "protocol": "fix",
    "task": {"type": "fix_command", "command": "make", "error": "gcc error"},
    "environment": {"os": "Linux", "arch": "aarch64", "package_managers": ["apt"]},
    "capabilities": {},
    "verification": [{"method": "exit_code", "expected": 0}],
    "execution": {"sandbox": False, "root": None, "max_attempts": 3, "investigation_rounds": 5, "timeout": 300},
    "escrow": {"bounty": "0.05", "currency": "USDC", "chain": "base"},
    "terms": {"cancellation": {"agent_fee": "0.002", "principal_fee": "0.002", "grace_period": 30}},
}


@pytest.fixture
def app():
    """Fresh app with in-memory stores for each test."""
    store = ContractStore(":memory:")
    escrow_mgr = EscrowManager(":memory:")
    reputation_mgr = ReputationManager(":memory:")
    return create_app(store=store, escrow_mgr=escrow_mgr, reputation_mgr=reputation_mgr)


@pytest.fixture
def client(app):
    return TestClient(app)


def _create_contract(client, contract=None):
    """Helper: post a contract, return response JSON."""
    resp = client.post("/contracts", json={
        "contract": contract or SAMPLE_CONTRACT,
        "principal_pubkey": "principal_abc",
    })
    assert resp.status_code == 200
    return resp.json()


def _accept_contract(client, contract_id, agent="agent_xyz"):
    """Helper: accept a contract."""
    resp = client.post(f"/contracts/{contract_id}/accept", json={
        "agent_pubkey": agent,
    })
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
    assert escrow["bounty"] == "0.05"


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
    assert resp.json()["agent_pubkey"] == "agent_xyz"


def test_accept_non_open_contract_409(client):
    data = _create_contract(client)
    cid = data["contract_id"]
    _accept_contract(client, cid)

    # Try to accept again -- should 409
    resp = client.post(f"/contracts/{cid}/accept", json={"agent_pubkey": "agent_2"})
    assert resp.status_code == 409


def test_accept_nonexistent_404(client):
    resp = client.post("/contracts/nonexistent/accept", json={"agent_pubkey": "x"})
    assert resp.status_code == 404


# --- POST /contracts/{id}/investigate ---

def test_investigate(client):
    data = _create_contract(client)
    cid = data["contract_id"]
    _accept_contract(client, cid)

    resp = client.post(f"/contracts/{cid}/investigate", json={
        "command": "ls -la",
        "agent_pubkey": "agent_xyz",
    })
    assert resp.status_code == 200
    assert resp.json()["status"] == "pending_result"
    assert resp.json()["command"] == "ls -la"


def test_investigate_wrong_status_409(client):
    data = _create_contract(client)
    cid = data["contract_id"]
    # Contract is "open", not "in_progress"
    resp = client.post(f"/contracts/{cid}/investigate", json={
        "command": "ls",
        "agent_pubkey": "agent_xyz",
    })
    assert resp.status_code == 409


# --- POST /contracts/{id}/result ---

def test_submit_result(client):
    data = _create_contract(client)
    cid = data["contract_id"]
    _accept_contract(client, cid)

    resp = client.post(f"/contracts/{cid}/result", json={
        "command": "ls -la",
        "output": "total 0\ndrwxr-xr-x  2 root root 40 Jan  1 00:00 .",
    })
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"

    # Check transcript
    contract = client.get(f"/contracts/{cid}").json()
    result_msgs = [m for m in contract["transcript"] if m["type"] == "result"]
    assert len(result_msgs) == 1
    assert result_msgs[0]["output"].startswith("total 0")


# --- POST /contracts/{id}/fix ---

def test_submit_fix(client):
    data = _create_contract(client)
    cid = data["contract_id"]
    _accept_contract(client, cid)

    resp = client.post(f"/contracts/{cid}/fix", json={
        "fix": "apt install gcc",
        "explanation": "missing compiler",
        "agent_pubkey": "agent_xyz",
    })
    assert resp.status_code == 200
    assert resp.json()["status"] == "pending_verification"


def test_submit_fix_wrong_status_409(client):
    data = _create_contract(client)
    cid = data["contract_id"]
    # Still "open"
    resp = client.post(f"/contracts/{cid}/fix", json={
        "fix": "echo hi",
        "agent_pubkey": "agent_xyz",
    })
    assert resp.status_code == 409


# --- POST /contracts/{id}/verify ---

def test_verify_success_fulfills(client):
    data = _create_contract(client)
    cid = data["contract_id"]
    _accept_contract(client, cid)
    client.post(f"/contracts/{cid}/fix", json={
        "fix": "apt install gcc", "agent_pubkey": "agent_xyz",
    })

    resp = client.post(f"/contracts/{cid}/verify", json={
        "success": True,
        "explanation": "build passes now",
    })
    assert resp.status_code == 200
    assert resp.json()["status"] == "fulfilled"

    # Contract status should be fulfilled
    contract = client.get(f"/contracts/{cid}").json()
    assert contract["status"] == "fulfilled"


def test_verify_failure_cancels(client):
    data = _create_contract(client)
    cid = data["contract_id"]
    _accept_contract(client, cid)
    client.post(f"/contracts/{cid}/fix", json={
        "fix": "echo nope", "agent_pubkey": "agent_xyz",
    })

    resp = client.post(f"/contracts/{cid}/verify", json={
        "success": False,
        "explanation": "still broken",
    })
    assert resp.status_code == 200
    assert resp.json()["status"] == "canceled"

    contract = client.get(f"/contracts/{cid}").json()
    assert contract["status"] == "canceled"


def test_verify_resolves_escrow(app, client):
    data = _create_contract(client)
    cid = data["contract_id"]
    _accept_contract(client, cid)
    client.post(f"/contracts/{cid}/fix", json={
        "fix": "apt install gcc", "agent_pubkey": "agent_xyz",
    })
    client.post(f"/contracts/{cid}/verify", json={"success": True})

    escrow = app.state.escrow.get(cid)
    assert escrow["resolved"] is True


# --- GET /reputation/{pubkey} ---

def test_get_reputation_empty(client):
    resp = client.get("/reputation/unknown_key")
    assert resp.status_code == 200
    body = resp.json()
    assert "as_agent" in body
    assert "as_principal" in body


def test_reputation_after_fulfillment(client):
    data = _create_contract(client)
    cid = data["contract_id"]
    _accept_contract(client, cid)
    client.post(f"/contracts/{cid}/fix", json={
        "fix": "apt install gcc", "agent_pubkey": "agent_xyz",
    })
    client.post(f"/contracts/{cid}/verify", json={"success": True})

    agent_rep = client.get("/reputation/agent_xyz").json()
    assert agent_rep["as_agent"]["fulfilled"] == 1

    principal_rep = client.get("/reputation/principal_abc").json()
    assert principal_rep["as_principal"]["fulfilled"] == 1


# --- 404 on nonexistent contract for various endpoints ---

def test_result_nonexistent_404(client):
    resp = client.post("/contracts/nope/result", json={
        "command": "ls", "output": "hi",
    })
    assert resp.status_code == 404


def test_fix_nonexistent_404(client):
    resp = client.post("/contracts/nope/fix", json={
        "fix": "echo", "agent_pubkey": "x",
    })
    assert resp.status_code == 404


def test_verify_nonexistent_404(client):
    resp = client.post("/contracts/nope/verify", json={
        "success": True,
    })
    assert resp.status_code == 404
