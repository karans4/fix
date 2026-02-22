"""Tests for client-signed chain entries.

Verifies that:
- Client-signed entries are accepted and appended correctly
- Wrong author (key mismatch) is rejected
- Wrong entry type is rejected
- Stale seq returns 409 with updated chain head
- Server-only types from clients are rejected
- Role violations are rejected (agent submits principal-only type, etc.)
- E2E lifecycle produces a chain signed by actual parties, not server
"""

import sys, os, json, time
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.dirname(__file__))

import pytest
from starlette.testclient import TestClient
from server.app import create_app
from server.store import ContractStore
from server.escrow import EscrowManager
from crypto import (
    generate_ed25519_keypair, pubkey_to_fix_id, build_chain_entry,
    verify_chain, chain_entry_hash,
)
from conftest import (
    signed_post, signed_post_with_entry, build_client_chain_entry,
    PRINCIPAL_PUBKEY, AGENT_PUBKEY, PRINCIPAL_PRIV, AGENT_PRIV, SERVER_PRIV,
    make_nano_backend, set_funded_accounts, fund_escrow,
    TEST_PRINCIPAL_ADDR, TEST_AGENT_ADDR,
)


SAMPLE_CONTRACT = {
    "version": 2, "protocol": "fix",
    "task": {"type": "fix_command", "command": "make", "error": "gcc error"},
    "environment": {"os": "Linux", "arch": "aarch64", "package_managers": ["apt"]},
    "capabilities": {},
    "verification": [{"method": "exit_code", "expected": 0}],
    "execution": {"sandbox": False, "root": None, "max_attempts": 5,
                  "investigation_rounds": 5, "timeout": 300},
    "escrow": {"bounty": "0.50", "currency": "XNO", "chain": "nano"},
    "terms": {"cancellation": {"grace_period": 30}},
}


@pytest.fixture
def app():
    store = ContractStore(":memory:")
    escrow_mgr = EscrowManager(":memory:", payment_backend=make_nano_backend())
    return create_app(store=store, escrow_mgr=escrow_mgr, server_privkey=SERVER_PRIV)


@pytest.fixture
def client(app):
    return TestClient(app)


def _create_contract(client):
    resp = signed_post(client, "/contracts", {
        "contract": SAMPLE_CONTRACT,
        "principal_pubkey": PRINCIPAL_PUBKEY,
    }, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
    assert resp.status_code == 200
    return resp.json()


def _set_test_accounts(app, cid):
    set_funded_accounts(app.state.escrow, cid, TEST_PRINCIPAL_ADDR, TEST_AGENT_ADDR)
    fund_escrow(app.state.escrow, cid)


# --- Happy path: client-signed entries accepted ---

def test_client_signed_bond(client):
    """Client-signed bond entry is accepted."""
    data = _create_contract(client)
    cid = data["contract_id"]

    entry = build_client_chain_entry(client, cid, "bond",
        {"agent_pubkey": AGENT_PUBKEY}, AGENT_PUBKEY, AGENT_PRIV)
    resp = signed_post(client, f"/contracts/{cid}/bond", {
        "agent_pubkey": AGENT_PUBKEY,
        "chain_entry": entry,
    }, AGENT_PUBKEY, AGENT_PRIV)
    assert resp.status_code == 200
    assert resp.json()["status"] == "investigating"

    # Verify the chain entry is in the transcript
    contract = client.get(f"/contracts/{cid}").json()
    bond_entries = [e for e in contract["transcript"] if e["type"] == "bond"]
    assert len(bond_entries) == 1
    assert bond_entries[0]["author"] == AGENT_PUBKEY


def test_client_signed_accept(client):
    """Client-signed accept entry is accepted."""
    data = _create_contract(client)
    cid = data["contract_id"]

    # Bond first (server-signed for simplicity)
    signed_post(client, f"/contracts/{cid}/bond", {"agent_pubkey": AGENT_PUBKEY}, AGENT_PUBKEY, AGENT_PRIV)

    entry = build_client_chain_entry(client, cid, "accept",
        {"agent_pubkey": AGENT_PUBKEY}, AGENT_PUBKEY, AGENT_PRIV)
    resp = signed_post(client, f"/contracts/{cid}/accept", {
        "agent_pubkey": AGENT_PUBKEY,
        "chain_entry": entry,
    }, AGENT_PUBKEY, AGENT_PRIV)
    assert resp.status_code == 200
    assert resp.json()["status"] == "in_progress"


def test_client_signed_fix(client):
    """Client-signed fix entry is accepted."""
    data = _create_contract(client)
    cid = data["contract_id"]
    signed_post(client, f"/contracts/{cid}/accept", {"agent_pubkey": AGENT_PUBKEY}, AGENT_PUBKEY, AGENT_PRIV)

    entry = build_client_chain_entry(client, cid, "fix",
        {"fix": "apt install gcc", "explanation": "missing compiler", "from": "agent"},
        AGENT_PUBKEY, AGENT_PRIV)
    resp = signed_post(client, f"/contracts/{cid}/fix", {
        "fix": "apt install gcc",
        "explanation": "missing compiler",
        "agent_pubkey": AGENT_PUBKEY,
        "chain_entry": entry,
    }, AGENT_PUBKEY, AGENT_PRIV)
    assert resp.status_code == 200

    contract = client.get(f"/contracts/{cid}").json()
    fix_entries = [e for e in contract["transcript"] if e["type"] == "fix"]
    assert len(fix_entries) == 1
    assert fix_entries[0]["author"] == AGENT_PUBKEY


def test_client_signed_verify(app, client):
    """Client-signed verify entry is accepted."""
    data = _create_contract(client)
    cid = data["contract_id"]
    signed_post(client, f"/contracts/{cid}/accept", {"agent_pubkey": AGENT_PUBKEY}, AGENT_PUBKEY, AGENT_PRIV)
    signed_post(client, f"/contracts/{cid}/fix", {"fix": "apt install gcc", "agent_pubkey": AGENT_PUBKEY}, AGENT_PUBKEY, AGENT_PRIV)

    _set_test_accounts(app, cid)
    entry = build_client_chain_entry(client, cid, "verify",
        {"success": True, "explanation": "works", "from": "principal"},
        PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
    resp = signed_post(client, f"/contracts/{cid}/verify", {
        "success": True,
        "explanation": "works",
        "principal_pubkey": PRINCIPAL_PUBKEY,
        "chain_entry": entry,
    }, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
    assert resp.status_code == 200
    assert resp.json()["status"] == "fulfilled"


def test_client_signed_chat(client):
    """Client-signed chat entry is accepted."""
    data = _create_contract(client)
    cid = data["contract_id"]
    signed_post(client, f"/contracts/{cid}/accept", {"agent_pubkey": AGENT_PUBKEY}, AGENT_PUBKEY, AGENT_PRIV)

    entry = build_client_chain_entry(client, cid, "ask",
        {"message": "What version of gcc?", "from": "agent"},
        AGENT_PUBKEY, AGENT_PRIV)
    resp = signed_post(client, f"/contracts/{cid}/chat", {
        "message": "What version of gcc?",
        "from_side": "agent",
        "msg_type": "ask",
        "pubkey": AGENT_PUBKEY,
        "chain_entry": entry,
    }, AGENT_PUBKEY, AGENT_PRIV)
    assert resp.status_code == 200

    contract = client.get(f"/contracts/{cid}").json()
    ask_entries = [e for e in contract["transcript"] if e["type"] == "ask"]
    assert len(ask_entries) == 1
    assert ask_entries[0]["author"] == AGENT_PUBKEY


# --- Security: wrong author rejected ---

def test_wrong_author_rejected(client):
    """Chain entry signed by wrong key is rejected."""
    data = _create_contract(client)
    cid = data["contract_id"]

    # Build entry with PRINCIPAL key but claiming to be AGENT
    third_priv, third_pub = generate_ed25519_keypair()
    third_id = pubkey_to_fix_id(third_pub)

    store = client.app.state.store
    contract_data = store.get(cid)
    entry = build_chain_entry(
        entry_type="bond",
        data={"agent_pubkey": AGENT_PUBKEY},
        seq=len(contract_data["transcript"]),
        author=third_id,  # wrong author
        prev_hash=contract_data["chain_head"],
        privkey_bytes=third_priv,
    )

    # Try to bond with mismatched author
    resp = signed_post(client, f"/contracts/{cid}/bond", {
        "agent_pubkey": AGENT_PUBKEY,
        "chain_entry": entry,
    }, AGENT_PUBKEY, AGENT_PRIV)
    assert resp.status_code == 400
    assert "Author mismatch" in resp.json()["detail"]


# --- Security: wrong entry type rejected ---

def test_wrong_entry_type_rejected(client):
    """Chain entry with wrong type for the endpoint is rejected."""
    data = _create_contract(client)
    cid = data["contract_id"]

    # Build a "fix" entry but send it to /bond
    entry = build_client_chain_entry(client, cid, "fix",
        {"fix": "malicious", "from": "agent"}, AGENT_PUBKEY, AGENT_PRIV)
    resp = signed_post(client, f"/contracts/{cid}/bond", {
        "agent_pubkey": AGENT_PUBKEY,
        "chain_entry": entry,
    }, AGENT_PUBKEY, AGENT_PRIV)
    assert resp.status_code == 400
    assert "type mismatch" in resp.json()["detail"]


# --- Security: stale seq returns 409 with chain head ---

def test_stale_seq_returns_409(client):
    """Submitting entry with stale seq returns 409 with current head."""
    data = _create_contract(client)
    cid = data["contract_id"]

    # Build entry with current head
    entry = build_client_chain_entry(client, cid, "bond",
        {"agent_pubkey": AGENT_PUBKEY}, AGENT_PUBKEY, AGENT_PRIV)

    # Now make a server-signed entry to advance the chain
    signed_post(client, f"/contracts/{cid}/bond",
        {"agent_pubkey": AGENT_PUBKEY}, AGENT_PUBKEY, AGENT_PRIV)

    # Decline to reset to open
    signed_post(client, f"/contracts/{cid}/decline",
        {"agent_pubkey": AGENT_PUBKEY}, AGENT_PUBKEY, AGENT_PRIV)

    # Try to use the stale entry (seq is now wrong)
    _a2_priv, _a2_pub = generate_ed25519_keypair()
    a2_pubkey = pubkey_to_fix_id(_a2_pub)
    resp = signed_post(client, f"/contracts/{cid}/bond", {
        "agent_pubkey": a2_pubkey,
        "chain_entry": entry,  # stale: wrong seq and prev_hash
    }, a2_pubkey, _a2_priv)
    assert resp.status_code == 409
    body = resp.json()["detail"]
    assert body["error"] == "chain_conflict"
    assert "chain_head" in body
    assert "seq" in body


# --- Security: server-only type from client rejected ---

def test_server_only_type_from_client_rejected(client):
    """Client cannot submit a 'ruling' chain entry."""
    data = _create_contract(client)
    cid = data["contract_id"]
    signed_post(client, f"/contracts/{cid}/accept", {"agent_pubkey": AGENT_PUBKEY}, AGENT_PUBKEY, AGENT_PRIV)

    # Build a "ruling" entry
    entry = build_client_chain_entry(client, cid, "ruling",
        {"outcome": "fulfilled", "reasoning": "hacked"},
        AGENT_PUBKEY, AGENT_PRIV)

    # Try to submit via fix endpoint (will fail on type mismatch first)
    resp = signed_post(client, f"/contracts/{cid}/fix", {
        "fix": "echo hacked",
        "agent_pubkey": AGENT_PUBKEY,
        "chain_entry": entry,
    }, AGENT_PUBKEY, AGENT_PRIV)
    assert resp.status_code == 400


# --- Security: role violation ---

def test_agent_cannot_submit_verify(client):
    """Agent cannot submit a 'verify' entry (principal-only type)."""
    data = _create_contract(client)
    cid = data["contract_id"]
    signed_post(client, f"/contracts/{cid}/accept", {"agent_pubkey": AGENT_PUBKEY}, AGENT_PUBKEY, AGENT_PRIV)
    signed_post(client, f"/contracts/{cid}/fix", {"fix": "apt install gcc", "agent_pubkey": AGENT_PUBKEY}, AGENT_PUBKEY, AGENT_PRIV)

    # Agent tries to build and submit a verify entry
    entry = build_client_chain_entry(client, cid, "verify",
        {"success": True, "explanation": "I say it works", "from": "principal"},
        AGENT_PUBKEY, AGENT_PRIV)

    # Agent signs the HTTP request too
    resp = signed_post(client, f"/contracts/{cid}/verify", {
        "success": True,
        "explanation": "I say it works",
        "principal_pubkey": AGENT_PUBKEY,  # pretending to be principal
        "chain_entry": entry,
    }, AGENT_PUBKEY, AGENT_PRIV)
    # Should get 403 (role check) or 403 (party check from _check_party)
    assert resp.status_code == 403


def test_principal_cannot_submit_bond(client):
    """Principal cannot submit a 'bond' entry (agent-only type)."""
    data = _create_contract(client)
    cid = data["contract_id"]

    entry = build_client_chain_entry(client, cid, "bond",
        {"agent_pubkey": PRINCIPAL_PUBKEY}, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
    resp = signed_post(client, f"/contracts/{cid}/bond", {
        "agent_pubkey": PRINCIPAL_PUBKEY,
        "chain_entry": entry,
    }, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
    assert resp.status_code == 403


# --- Timestamp: server is sole time authority ---

def test_server_overwrites_client_timestamp(client):
    """Server sets the timestamp, ignoring whatever the client sends."""
    data = _create_contract(client)
    cid = data["contract_id"]

    store = client.app.state.store
    contract_data = store.get(cid)
    # Build entry with a bogus timestamp
    entry = build_chain_entry(
        entry_type="bond",
        data={"agent_pubkey": AGENT_PUBKEY},
        seq=len(contract_data["transcript"]),
        author=AGENT_PUBKEY,
        prev_hash=contract_data["chain_head"],
        privkey_bytes=AGENT_PRIV,
        timestamp=1,  # epoch + 1 second — obviously wrong
    )
    resp = signed_post(client, f"/contracts/{cid}/bond", {
        "agent_pubkey": AGENT_PUBKEY,
        "chain_entry": entry,
    }, AGENT_PUBKEY, AGENT_PRIV)
    assert resp.status_code == 200

    # Verify stored timestamp is server-set, not the client's value
    data = store.get(cid)
    bond = [e for e in data["transcript"] if e["type"] == "bond"][0]
    assert bond["timestamp"] != 1
    assert abs(bond["timestamp"] - time.time()) < 5


# --- E2E: full lifecycle with client-signed entries ---

def test_e2e_client_signed_lifecycle(app, client):
    """Full lifecycle: post -> bond -> accept -> investigate -> result -> fix -> verify -> fulfilled.
    All client actions should be signed by clients, not the server."""
    data = _create_contract(client)
    cid = data["contract_id"]
    server_fix_id = app.state.server_fix_id

    # Agent bonds (client-signed)
    entry = build_client_chain_entry(client, cid, "bond",
        {"agent_pubkey": AGENT_PUBKEY}, AGENT_PUBKEY, AGENT_PRIV)
    resp = signed_post(client, f"/contracts/{cid}/bond", {
        "agent_pubkey": AGENT_PUBKEY, "chain_entry": entry,
    }, AGENT_PUBKEY, AGENT_PRIV)
    assert resp.status_code == 200

    # Agent accepts (client-signed)
    entry = build_client_chain_entry(client, cid, "accept",
        {"agent_pubkey": AGENT_PUBKEY}, AGENT_PUBKEY, AGENT_PRIV)
    resp = signed_post(client, f"/contracts/{cid}/accept", {
        "agent_pubkey": AGENT_PUBKEY, "chain_entry": entry,
    }, AGENT_PUBKEY, AGENT_PRIV)
    assert resp.status_code == 200

    # Agent investigates (client-signed)
    entry = build_client_chain_entry(client, cid, "investigate",
        {"command": "ls -la", "from": "agent"}, AGENT_PUBKEY, AGENT_PRIV)
    resp = signed_post(client, f"/contracts/{cid}/investigate", {
        "command": "ls -la", "agent_pubkey": AGENT_PUBKEY, "chain_entry": entry,
    }, AGENT_PUBKEY, AGENT_PRIV)
    assert resp.status_code == 200

    # Principal returns result (client-signed)
    entry = build_client_chain_entry(client, cid, "result",
        {"command": "ls -la", "output": "Makefile\nsrc/", "from": "principal"},
        PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
    resp = signed_post(client, f"/contracts/{cid}/result", {
        "command": "ls -la", "output": "Makefile\nsrc/",
        "principal_pubkey": PRINCIPAL_PUBKEY, "chain_entry": entry,
    }, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
    assert resp.status_code == 200

    # Agent submits fix (client-signed)
    entry = build_client_chain_entry(client, cid, "fix",
        {"fix": "apt install gcc", "explanation": "missing compiler", "from": "agent"},
        AGENT_PUBKEY, AGENT_PRIV)
    resp = signed_post(client, f"/contracts/{cid}/fix", {
        "fix": "apt install gcc", "explanation": "missing compiler",
        "agent_pubkey": AGENT_PUBKEY, "chain_entry": entry,
    }, AGENT_PUBKEY, AGENT_PRIV)
    assert resp.status_code == 200

    # Principal verifies (client-signed)
    _set_test_accounts(app, cid)
    entry = build_client_chain_entry(client, cid, "verify",
        {"success": True, "explanation": "build passes", "from": "principal"},
        PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
    resp = signed_post(client, f"/contracts/{cid}/verify", {
        "success": True, "explanation": "build passes",
        "principal_pubkey": PRINCIPAL_PUBKEY, "chain_entry": entry,
    }, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
    assert resp.status_code == 200
    assert resp.json()["status"] == "fulfilled"

    # Verify the chain: all client actions signed by actual parties
    contract = client.get(f"/contracts/{cid}").json()
    transcript = contract["transcript"]

    # Check authors
    for entry in transcript:
        etype = entry["type"]
        author = entry["author"]
        if etype in ("bond", "accept", "investigate", "fix"):
            assert author == AGENT_PUBKEY, f"{etype} should be signed by agent, got {author}"
        elif etype in ("result", "verify"):
            assert author == PRINCIPAL_PUBKEY, f"{etype} should be signed by principal, got {author}"

    # Full chain verification should pass
    chain_entries = [e for e in transcript if "signature" in e]
    ok, err = verify_chain(chain_entries)
    assert ok, f"Chain verification failed: {err}"


# --- Free mode: no judge, no escrow, no disputes ---

FREE_CONTRACT = {
    "version": 2, "protocol": "fix",
    "task": {"type": "fix_command", "command": "make", "error": "gcc error"},
    "environment": {"os": "Linux", "arch": "aarch64", "package_managers": ["apt"]},
    "capabilities": {},
    "verification": [{"method": "exit_code", "expected": 0}],
    "execution": {"sandbox": False, "root": None, "max_attempts": 3,
                  "investigation_rounds": 5, "timeout": 300},
    # No escrow, no judge — free mode
}


def _create_free_contract(client):
    resp = signed_post(client, "/contracts", {
        "contract": FREE_CONTRACT,
        "principal_pubkey": PRINCIPAL_PUBKEY,
    }, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
    assert resp.status_code == 200
    return resp.json()


def test_free_mode_e2e_client_signed(client):
    """Free mode lifecycle: post -> accept -> fix -> verify -> fulfilled.
    No bonds, no judge. All client-signed. Dispute must be impossible."""
    data = _create_free_contract(client)
    cid = data["contract_id"]

    # Agent accepts directly (no bond needed in free mode)
    entry = build_client_chain_entry(client, cid, "accept",
        {"agent_pubkey": AGENT_PUBKEY}, AGENT_PUBKEY, AGENT_PRIV)
    resp = signed_post(client, f"/contracts/{cid}/accept", {
        "agent_pubkey": AGENT_PUBKEY, "chain_entry": entry,
    }, AGENT_PUBKEY, AGENT_PRIV)
    assert resp.status_code == 200
    assert resp.json()["status"] == "in_progress"

    # Agent submits fix (client-signed)
    entry = build_client_chain_entry(client, cid, "fix",
        {"fix": "apt install gcc", "explanation": "missing compiler", "from": "agent"},
        AGENT_PUBKEY, AGENT_PRIV)
    resp = signed_post(client, f"/contracts/{cid}/fix", {
        "fix": "apt install gcc", "explanation": "missing compiler",
        "agent_pubkey": AGENT_PUBKEY, "chain_entry": entry,
    }, AGENT_PUBKEY, AGENT_PRIV)
    assert resp.status_code == 200
    assert resp.json()["status"] == "pending_verification"

    # Principal verifies success (client-signed)
    entry = build_client_chain_entry(client, cid, "verify",
        {"success": True, "explanation": "build passes", "from": "principal"},
        PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
    resp = signed_post(client, f"/contracts/{cid}/verify", {
        "success": True, "explanation": "build passes",
        "principal_pubkey": PRINCIPAL_PUBKEY, "chain_entry": entry,
    }, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
    assert resp.status_code == 200
    assert resp.json()["status"] == "fulfilled"

    # Contract is fulfilled
    contract = client.get(f"/contracts/{cid}").json()
    assert contract["status"] == "fulfilled"

    # Verify chain: all entries signed by actual parties
    transcript = contract["transcript"]
    for e in transcript:
        if e["type"] == "accept":
            assert e["author"] == AGENT_PUBKEY
        elif e["type"] == "fix":
            assert e["author"] == AGENT_PUBKEY
        elif e["type"] == "verify":
            assert e["author"] == PRINCIPAL_PUBKEY

    chain_entries = [e for e in transcript if "signature" in e]
    ok, err = verify_chain(chain_entries)
    assert ok, f"Chain verification failed: {err}"


def test_free_mode_dispute_rejected(client):
    """Free mode: dispute is rejected because no judge is configured."""
    data = _create_free_contract(client)
    cid = data["contract_id"]

    # Accept
    signed_post(client, f"/contracts/{cid}/accept",
        {"agent_pubkey": AGENT_PUBKEY}, AGENT_PUBKEY, AGENT_PRIV)

    # Try to dispute — should be rejected
    entry = build_client_chain_entry(client, cid, "dispute_filed",
        {"argument": "I want a refund", "side": "principal"},
        PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
    resp = signed_post(client, f"/contracts/{cid}/dispute", {
        "argument": "I want a refund",
        "side": "principal",
        "pubkey": PRINCIPAL_PUBKEY,
        "chain_entry": entry,
    }, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
    assert resp.status_code == 400
    assert "no judge" in resp.json()["detail"].lower() or "free-mode" in resp.json()["detail"].lower()


def test_free_mode_chat_works(client):
    """Free mode: chat still works without bonds/escrow."""
    data = _create_free_contract(client)
    cid = data["contract_id"]

    # Accept
    signed_post(client, f"/contracts/{cid}/accept",
        {"agent_pubkey": AGENT_PUBKEY}, AGENT_PUBKEY, AGENT_PRIV)

    # Agent asks a question (client-signed)
    entry = build_client_chain_entry(client, cid, "ask",
        {"message": "What OS?", "from": "agent"},
        AGENT_PUBKEY, AGENT_PRIV)
    resp = signed_post(client, f"/contracts/{cid}/chat", {
        "message": "What OS?", "from_side": "agent", "msg_type": "ask",
        "pubkey": AGENT_PUBKEY, "chain_entry": entry,
    }, AGENT_PUBKEY, AGENT_PRIV)
    assert resp.status_code == 200

    # Principal answers (client-signed)
    entry = build_client_chain_entry(client, cid, "answer",
        {"message": "Ubuntu 24.04", "from": "principal"},
        PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
    resp = signed_post(client, f"/contracts/{cid}/chat", {
        "message": "Ubuntu 24.04", "from_side": "principal", "msg_type": "answer",
        "pubkey": PRINCIPAL_PUBKEY, "chain_entry": entry,
    }, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
    assert resp.status_code == 200

    # Verify chat in transcript
    contract = client.get(f"/contracts/{cid}").json()
    asks = [e for e in contract["transcript"] if e["type"] == "ask"]
    answers = [e for e in contract["transcript"] if e["type"] == "answer"]
    assert len(asks) == 1 and asks[0]["author"] == AGENT_PUBKEY
    assert len(answers) == 1 and answers[0]["author"] == PRINCIPAL_PUBKEY


def test_free_mode_verify_failure_retry_then_cancel(client):
    """Free mode: verify fails, agent retries, exhausts attempts, contract canceled."""
    data = _create_free_contract(client)
    cid = data["contract_id"]

    signed_post(client, f"/contracts/{cid}/accept",
        {"agent_pubkey": AGENT_PUBKEY}, AGENT_PUBKEY, AGENT_PRIV)

    # 3 attempts (max_attempts=3 in FREE_CONTRACT)
    for i in range(3):
        # Agent submits fix (client-signed)
        entry = build_client_chain_entry(client, cid, "fix",
            {"fix": f"echo attempt{i}", "explanation": "", "from": "agent"},
            AGENT_PUBKEY, AGENT_PRIV)
        resp = signed_post(client, f"/contracts/{cid}/fix", {
            "fix": f"echo attempt{i}", "agent_pubkey": AGENT_PUBKEY,
            "chain_entry": entry,
        }, AGENT_PUBKEY, AGENT_PRIV)
        assert resp.status_code == 200

        # Principal rejects (client-signed)
        entry = build_client_chain_entry(client, cid, "verify",
            {"success": False, "explanation": f"still broken {i}", "from": "principal"},
            PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
        resp = signed_post(client, f"/contracts/{cid}/verify", {
            "success": False, "explanation": f"still broken {i}",
            "principal_pubkey": PRINCIPAL_PUBKEY, "chain_entry": entry,
        }, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
        assert resp.status_code == 200

    # After 3 failures, should be canceled
    assert resp.json()["status"] == "canceled"
    contract = client.get(f"/contracts/{cid}").json()
    assert contract["status"] == "canceled"

    # All entries should be client-signed
    for e in contract["transcript"]:
        if e["type"] in ("fix",):
            assert e["author"] == AGENT_PUBKEY
        elif e["type"] in ("verify",):
            assert e["author"] == PRINCIPAL_PUBKEY


# --- Convenience helper test ---

def test_signed_post_with_entry_helper(client):
    """Test the signed_post_with_entry convenience helper."""
    data = _create_contract(client)
    cid = data["contract_id"]

    resp = signed_post_with_entry(
        client, f"/contracts/{cid}/bond",
        {"agent_pubkey": AGENT_PUBKEY},
        AGENT_PUBKEY, AGENT_PRIV,
        contract_id=cid, entry_type="bond",
        entry_data={"agent_pubkey": AGENT_PUBKEY},
    )
    assert resp.status_code == 200

    contract = client.get(f"/contracts/{cid}").json()
    bond_entries = [e for e in contract["transcript"] if e["type"] == "bond"]
    assert bond_entries[0]["author"] == AGENT_PUBKEY
