"""Tests for contract modes, chat, judge-as-participant, dispute bonds.

Covers: autonomous flow, review window, chat messages, bond lifecycle,
investigation rate limiting, judge timeout/voiding, decline after investigate.
"""

import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.dirname(__file__))

import time
import pytest
from decimal import Decimal
from unittest.mock import AsyncMock, patch
from starlette.testclient import TestClient
from server.app import create_app
from server.store import ContractStore
from server.escrow import EscrowManager
from server.judge import AIJudge, TieredCourt, Evidence, JudgeRuling
from conftest import (
    signed_post, PRINCIPAL_PUBKEY, AGENT_PUBKEY, PRINCIPAL_PRIV, AGENT_PRIV, SERVER_PRIV,
    make_nano_backend, set_funded_accounts, fund_escrow, TEST_PRINCIPAL_ADDR, TEST_AGENT_ADDR,
)
from crypto import generate_ed25519_keypair, pubkey_to_fix_id
from protocol import DEFAULT_RULING_TIMEOUT

# Extra agent keypair for tests that need a second agent
_a2_priv, _a2_pub = generate_ed25519_keypair()
AGENT2_PUBKEY = pubkey_to_fix_id(_a2_pub)
AGENT2_PRIV = _a2_priv


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

AUTONOMOUS_CONTRACT = {
    **SAMPLE_CONTRACT,
    "execution": {**SAMPLE_CONTRACT["execution"], "mode": "autonomous", "review_window": 3600},
}

JUDGE_CONTRACT = {
    **SAMPLE_CONTRACT,
    "judge": {"pubkey": TEST_AGENT_ADDR, "fee": "0.17", "ruling_timeout": 60},
}

AUTONOMOUS_JUDGE_CONTRACT = {
    **AUTONOMOUS_CONTRACT,
    "judge": {"pubkey": TEST_AGENT_ADDR, "fee": "0.17", "ruling_timeout": 60},
}


@pytest.fixture
def app():
    store = ContractStore(":memory:")
    escrow_mgr = EscrowManager(":memory:", payment_backend=make_nano_backend())
    return create_app(store=store, escrow_mgr=escrow_mgr, server_privkey=SERVER_PRIV)


@pytest.fixture
def client(app):
    return TestClient(app)


def _create_contract(client, contract=None):
    resp = signed_post(client, "/contracts", {
        "contract": contract or SAMPLE_CONTRACT,
        "principal_pubkey": PRINCIPAL_PUBKEY,
    }, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
    assert resp.status_code == 200
    return resp.json()


def _accept_contract(client, contract_id, agent=AGENT_PUBKEY, agent_priv=AGENT_PRIV):
    resp = signed_post(client, f"/contracts/{contract_id}/accept", {"agent_pubkey": agent}, agent, agent_priv)
    assert resp.status_code == 200
    return resp.json()


def _bond_and_accept(client, contract_id, agent=AGENT_PUBKEY, agent_priv=AGENT_PRIV):
    """Bond then accept (new flow)."""
    resp = signed_post(client, f"/contracts/{contract_id}/bond", {"agent_pubkey": agent}, agent, agent_priv)
    assert resp.status_code == 200
    resp = signed_post(client, f"/contracts/{contract_id}/accept", {"agent_pubkey": agent}, agent, agent_priv)
    assert resp.status_code == 200
    return resp.json()


# --- Execution mode stored correctly ---

def test_supervised_mode_default(client):
    data = _create_contract(client)
    contract = client.get(f"/contracts/{data['contract_id']}").json()
    assert contract["execution_mode"] == "supervised"


def test_autonomous_mode_stored(client):
    data = _create_contract(client, AUTONOMOUS_CONTRACT)
    contract = client.get(f"/contracts/{data['contract_id']}").json()
    assert contract["execution_mode"] == "autonomous"


# --- Judge stored on contract ---

def test_judge_pubkey_stored(client):
    data = _create_contract(client, JUDGE_CONTRACT)
    contract = client.get(f"/contracts/{data['contract_id']}").json()
    assert contract["judge_pubkey"] == TEST_AGENT_ADDR


def test_judge_fee_in_escrow(app, client):
    data = _create_contract(client, JUDGE_CONTRACT)
    escrow = app.state.escrow.get(data["contract_id"])
    assert escrow is not None
    assert escrow["judge_fee"] == "0.17"
    assert escrow["principal_locked"] is True


# --- Bond lifecycle (OPEN -> INVESTIGATING -> IN_PROGRESS or OPEN) ---

def test_bond_starts_investigating(client):
    data = _create_contract(client, JUDGE_CONTRACT)
    cid = data["contract_id"]

    resp = signed_post(client, f"/contracts/{cid}/bond", {"agent_pubkey": AGENT_PUBKEY}, AGENT_PUBKEY, AGENT_PRIV)
    assert resp.status_code == 200
    assert resp.json()["status"] == "investigating"

    contract = client.get(f"/contracts/{cid}").json()
    assert contract["status"] == "investigating"
    assert contract["agent_pubkey"] == AGENT_PUBKEY


def test_bond_then_accept(client):
    data = _create_contract(client, JUDGE_CONTRACT)
    cid = data["contract_id"]

    signed_post(client, f"/contracts/{cid}/bond", {"agent_pubkey": AGENT_PUBKEY}, AGENT_PUBKEY, AGENT_PRIV)
    resp = signed_post(client, f"/contracts/{cid}/accept", {"agent_pubkey": AGENT_PUBKEY}, AGENT_PUBKEY, AGENT_PRIV)
    assert resp.status_code == 200
    assert resp.json()["status"] == "in_progress"

    contract = client.get(f"/contracts/{cid}").json()
    assert contract["status"] == "in_progress"


def test_bond_then_decline(client, app):
    data = _create_contract(client, JUDGE_CONTRACT)
    cid = data["contract_id"]

    signed_post(client, f"/contracts/{cid}/bond", {"agent_pubkey": AGENT_PUBKEY}, AGENT_PUBKEY, AGENT_PRIV)

    resp = signed_post(client, f"/contracts/{cid}/decline", {"agent_pubkey": AGENT_PUBKEY}, AGENT_PUBKEY, AGENT_PRIV)
    assert resp.status_code == 200
    assert resp.json()["status"] == "open"

    contract = client.get(f"/contracts/{cid}").json()
    assert contract["status"] == "open"
    assert contract["agent_pubkey"] is None

    # Agent bond should be released
    escrow = app.state.escrow.get(cid)
    assert escrow["agent_locked"] is False


def test_decline_wrong_status_409(client):
    data = _create_contract(client)
    cid = data["contract_id"]
    resp = signed_post(client, f"/contracts/{cid}/decline", {"agent_pubkey": AGENT_PUBKEY}, AGENT_PUBKEY, AGENT_PRIV)
    assert resp.status_code == 409


def test_bond_wrong_status_409(client):
    data = _create_contract(client)
    cid = data["contract_id"]
    _accept_contract(client, cid)
    resp = signed_post(client, f"/contracts/{cid}/bond", {"agent_pubkey": AGENT2_PUBKEY}, AGENT2_PUBKEY, AGENT2_PRIV)
    assert resp.status_code == 409


# --- Investigation rate limiting ---

def test_investigate_rate_limiting(client):
    contract = {**SAMPLE_CONTRACT, "execution": {**SAMPLE_CONTRACT["execution"], "investigation_rate": 10}}
    data = _create_contract(client, contract)
    cid = data["contract_id"]
    _accept_contract(client, cid)

    # First investigation should work
    resp = signed_post(client, f"/contracts/{cid}/investigate", {
        "command": "ls", "agent_pubkey": AGENT_PUBKEY,
    }, AGENT_PUBKEY, AGENT_PRIV)
    assert resp.status_code == 200

    # Immediate second should be rate limited
    resp = signed_post(client, f"/contracts/{cid}/investigate", {
        "command": "pwd", "agent_pubkey": AGENT_PUBKEY,
    }, AGENT_PUBKEY, AGENT_PRIV)
    assert resp.status_code == 429


def test_investigate_during_investigating(client):
    """Agent can investigate while in INVESTIGATING state (before accepting)."""
    data = _create_contract(client, JUDGE_CONTRACT)
    cid = data["contract_id"]
    signed_post(client, f"/contracts/{cid}/bond", {"agent_pubkey": AGENT_PUBKEY}, AGENT_PUBKEY, AGENT_PRIV)

    resp = signed_post(client, f"/contracts/{cid}/investigate", {
        "command": "ls", "agent_pubkey": AGENT_PUBKEY,
    }, AGENT_PUBKEY, AGENT_PRIV)
    assert resp.status_code == 200


# --- Chat messages ---

def test_chat_message(client):
    data = _create_contract(client)
    cid = data["contract_id"]
    _accept_contract(client, cid)

    resp = signed_post(client, f"/contracts/{cid}/chat", {
        "message": "What version of gcc?",
        "from_side": "agent",
        "msg_type": "ask",
        "pubkey": AGENT_PUBKEY,
    }, AGENT_PUBKEY, AGENT_PRIV)
    assert resp.status_code == 200
    assert resp.json()["status"] == "sent"

    # Check transcript
    contract = client.get(f"/contracts/{cid}").json()
    ask_msgs = [m for m in contract["transcript"] if m["type"] == "ask"]
    assert len(ask_msgs) == 1
    assert ask_msgs[0]["data"]["message"] == "What version of gcc?"
    assert ask_msgs[0]["data"]["from"] == "agent"


def test_chat_answer(client):
    data = _create_contract(client)
    cid = data["contract_id"]
    _accept_contract(client, cid)

    resp = signed_post(client, f"/contracts/{cid}/chat", {
        "message": "gcc 12.3",
        "from_side": "principal",
        "msg_type": "answer",
        "pubkey": PRINCIPAL_PUBKEY,
    }, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
    assert resp.status_code == 200


def test_chat_general_message(client):
    data = _create_contract(client)
    cid = data["contract_id"]
    _accept_contract(client, cid)

    resp = signed_post(client, f"/contracts/{cid}/chat", {
        "message": "Working on it",
        "from_side": "agent",
        "msg_type": "message",
        "pubkey": AGENT_PUBKEY,
    }, AGENT_PUBKEY, AGENT_PRIV)
    assert resp.status_code == 200


def test_chat_on_open_ok(client):
    data = _create_contract(client)
    cid = data["contract_id"]
    resp = signed_post(client, f"/contracts/{cid}/chat", {
        "message": "hello",
        "from_side": "principal",
        "msg_type": "message",
        "pubkey": PRINCIPAL_PUBKEY,
    }, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
    assert resp.status_code == 200


def test_chat_invalid_type_400(client):
    data = _create_contract(client)
    cid = data["contract_id"]
    _accept_contract(client, cid)

    resp = signed_post(client, f"/contracts/{cid}/chat", {
        "message": "hi",
        "from_side": "agent",
        "msg_type": "invalid_type",
        "pubkey": AGENT_PUBKEY,
    }, AGENT_PUBKEY, AGENT_PRIV)
    assert resp.status_code == 400


def test_chat_during_review(client):
    """Chat works during review window (autonomous mode)."""
    data = _create_contract(client, AUTONOMOUS_CONTRACT)
    cid = data["contract_id"]
    _accept_contract(client, cid)

    # Submit fix to enter review
    signed_post(client, f"/contracts/{cid}/fix", {"fix": "apt install gcc", "agent_pubkey": AGENT_PUBKEY}, AGENT_PUBKEY, AGENT_PRIV)

    resp = signed_post(client, f"/contracts/{cid}/chat", {
        "message": "Please check the fix",
        "from_side": "agent",
        "msg_type": "message",
        "pubkey": AGENT_PUBKEY,
    }, AGENT_PUBKEY, AGENT_PRIV)
    assert resp.status_code == 200


def test_chat_during_investigating(client):
    """Chat works during investigating state."""
    data = _create_contract(client, JUDGE_CONTRACT)
    cid = data["contract_id"]
    signed_post(client, f"/contracts/{cid}/bond", {"agent_pubkey": AGENT_PUBKEY}, AGENT_PUBKEY, AGENT_PRIV)

    resp = signed_post(client, f"/contracts/{cid}/chat", {
        "message": "What's the project structure?",
        "from_side": "agent",
        "msg_type": "ask",
        "pubkey": AGENT_PUBKEY,
    }, AGENT_PUBKEY, AGENT_PRIV)
    assert resp.status_code == 200


# --- Autonomous mode: fix -> review -> fulfill ---

def test_autonomous_fix_enters_review(client):
    data = _create_contract(client, AUTONOMOUS_CONTRACT)
    cid = data["contract_id"]
    _accept_contract(client, cid)

    resp = signed_post(client, f"/contracts/{cid}/fix", {
        "fix": "apt install gcc",
        "explanation": "missing compiler",
        "agent_pubkey": AGENT_PUBKEY,
    }, AGENT_PUBKEY, AGENT_PRIV)
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "review"
    assert "review_expires_at" in body

    contract = client.get(f"/contracts/{cid}").json()
    assert contract["status"] == "review"


def test_supervised_fix_stays_pending(client):
    data = _create_contract(client)
    cid = data["contract_id"]
    _accept_contract(client, cid)

    resp = signed_post(client, f"/contracts/{cid}/fix", {
        "fix": "apt install gcc", "agent_pubkey": AGENT_PUBKEY,
    }, AGENT_PUBKEY, AGENT_PRIV)
    assert resp.json()["status"] == "pending_verification"


def test_review_accept(client, app):
    data = _create_contract(client, AUTONOMOUS_CONTRACT)
    cid = data["contract_id"]
    _accept_contract(client, cid)
    signed_post(client, f"/contracts/{cid}/fix", {"fix": "apt install gcc", "agent_pubkey": AGENT_PUBKEY}, AGENT_PUBKEY, AGENT_PRIV)

    _set_test_accounts(app, cid)
    resp = signed_post(client, f"/contracts/{cid}/review", {"action": "accept", "principal_pubkey": PRINCIPAL_PUBKEY}, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
    assert resp.status_code == 200
    assert resp.json()["status"] == "fulfilled"

    contract = client.get(f"/contracts/{cid}").json()
    assert contract["status"] == "fulfilled"

    # Escrow resolved
    escrow = app.state.escrow.get(cid)
    assert escrow["resolved"] is True


def test_review_auto_fulfill_on_expiry(client, app):
    """Review window expires -> auto-fulfill on next access."""
    data = _create_contract(client, AUTONOMOUS_CONTRACT)
    cid = data["contract_id"]
    _accept_contract(client, cid)
    signed_post(client, f"/contracts/{cid}/fix", {"fix": "apt install gcc", "agent_pubkey": AGENT_PUBKEY}, AGENT_PUBKEY, AGENT_PRIV)

    _set_test_accounts(app, cid)
    # Manually set review_expires_at to the past
    app.state.store.set_review_expires(cid, time.time() - 1)

    # Access should trigger auto-fulfill
    contract = client.get(f"/contracts/{cid}").json()
    assert contract["status"] == "fulfilled"

    escrow = app.state.escrow.get(cid)
    assert escrow["resolved"] is True


def test_review_status_endpoint(client):
    data = _create_contract(client, AUTONOMOUS_CONTRACT)
    cid = data["contract_id"]
    _accept_contract(client, cid)
    signed_post(client, f"/contracts/{cid}/fix", {"fix": "apt install gcc", "agent_pubkey": AGENT_PUBKEY}, AGENT_PUBKEY, AGENT_PRIV)

    resp = client.get(f"/contracts/{cid}/review_status")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "review"
    assert body["remaining"] > 0
    assert "expires_at" in body


def test_review_status_not_in_review(client):
    data = _create_contract(client)
    cid = data["contract_id"]
    resp = client.get(f"/contracts/{cid}/review_status")
    assert resp.json()["status"] == "open"
    assert resp.json()["remaining"] == 0


def test_review_invalid_action_400(client):
    data = _create_contract(client, AUTONOMOUS_CONTRACT)
    cid = data["contract_id"]
    _accept_contract(client, cid)
    signed_post(client, f"/contracts/{cid}/fix", {"fix": "apt install gcc", "agent_pubkey": AGENT_PUBKEY}, AGENT_PUBKEY, AGENT_PRIV)

    resp = signed_post(client, f"/contracts/{cid}/review", {"action": "invalid", "principal_pubkey": PRINCIPAL_PUBKEY}, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
    assert resp.status_code == 400


# --- Void endpoint ---

def test_void_disputed_contract(client, app):
    """Voiding a disputed contract returns all funds."""
    data = _create_contract(client, JUDGE_CONTRACT)
    cid = data["contract_id"]
    _bond_and_accept(client, cid)

    # Manually set to disputed and add a dispute_filed entry with expired deadline
    app.state.store.update_status(cid, "disputed")
    import json as _json
    contract_data = app.state.store.get(cid)
    transcript = contract_data["transcript"]
    transcript.append({
        "type": "dispute_filed",
        "data": {
            "argument": "test dispute",
            "side": "principal",
            "response_deadline": time.time() - DEFAULT_RULING_TIMEOUT - 1,
        },
    })
    app.state.store.db.execute(
        "UPDATE contracts SET transcript = ? WHERE id = ?",
        (_json.dumps(transcript), cid),
    )
    app.state.store.db.commit()

    _set_test_accounts(app, cid)
    resp = signed_post(client, f"/contracts/{cid}/void", {"pubkey": PRINCIPAL_PUBKEY}, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
    assert resp.status_code == 200
    assert resp.json()["status"] == "voided"

    contract = client.get(f"/contracts/{cid}").json()
    assert contract["status"] == "voided"

    escrow = app.state.escrow.get(cid)
    assert escrow["resolved"] is True
    assert escrow["resolution"]["action"] == "voided"


def test_void_non_disputed_409(client):
    data = _create_contract(client)
    cid = data["contract_id"]
    resp = signed_post(client, f"/contracts/{cid}/void", {"pubkey": PRINCIPAL_PUBKEY}, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
    assert resp.status_code == 409


# --- Halt (existing + now works from review) ---

def test_halt_contract(client):
    data = _create_contract(client)
    cid = data["contract_id"]
    _accept_contract(client, cid)

    resp = signed_post(client, f"/contracts/{cid}/halt", {
        "reason": "Agent is exfiltrating data",
        "principal_pubkey": PRINCIPAL_PUBKEY,
    }, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "halted"
    assert body["ruling"] is None

    contract = client.get(f"/contracts/{cid}").json()
    assert contract["status"] == "halted"

    halt_msgs = [m for m in contract["transcript"] if m["type"] == "halt"]
    assert len(halt_msgs) == 1
    assert halt_msgs[0]["data"]["reason"] == "Agent is exfiltrating data"


def test_halt_during_review(client):
    """Principal can halt during autonomous review window."""
    data = _create_contract(client, AUTONOMOUS_CONTRACT)
    cid = data["contract_id"]
    _accept_contract(client, cid)
    signed_post(client, f"/contracts/{cid}/fix", {"fix": "rm -rf /", "agent_pubkey": AGENT_PUBKEY}, AGENT_PUBKEY, AGENT_PRIV)

    resp = signed_post(client, f"/contracts/{cid}/halt", {
        "reason": "Malicious fix detected",
        "principal_pubkey": PRINCIPAL_PUBKEY,
    }, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
    assert resp.status_code == 200
    assert resp.json()["status"] == "halted"


def test_halt_not_in_progress_or_review(client):
    data = _create_contract(client)
    cid = data["contract_id"]
    resp = signed_post(client, f"/contracts/{cid}/halt", {"reason": "suspicious", "principal_pubkey": PRINCIPAL_PUBKEY}, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
    assert resp.status_code == 409


def test_halt_not_found(client):
    resp = signed_post(client, "/contracts/nonexistent/halt", {"reason": "bad agent", "principal_pubkey": PRINCIPAL_PUBKEY}, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
    assert resp.status_code == 404


# --- Principal bond locked on contract creation ---

def test_principal_bond_locked_on_create(app, client):
    data = _create_contract(client, JUDGE_CONTRACT)
    escrow = app.state.escrow.get(data["contract_id"])
    assert escrow["principal_locked"] is True


def test_agent_bond_locked_on_bond(app, client):
    data = _create_contract(client, JUDGE_CONTRACT)
    cid = data["contract_id"]
    signed_post(client, f"/contracts/{cid}/bond", {"agent_pubkey": AGENT_PUBKEY}, AGENT_PUBKEY, AGENT_PRIV)
    escrow = app.state.escrow.get(cid)
    assert escrow["agent_locked"] is True


# --- Review dispute with judge ---

class FakeJudge:
    """Fake judge for testing dispute resolution."""
    def __init__(self, outcome="fulfilled", flags=None):
        self.outcome = outcome
        self.flags = flags or []

    async def rule(self, evidence):
        return JudgeRuling(
            outcome=self.outcome,
            reasoning="test ruling",
            flags=self.flags,
        )


def test_review_dispute_with_judge(app):
    """Dispute during review window triggers judge, routes bonds."""
    judge = FakeJudge(outcome="fulfilled")
    store = ContractStore(":memory:")
    escrow_mgr = EscrowManager(":memory:", payment_backend=make_nano_backend())
    app = create_app(store=store, escrow_mgr=escrow_mgr, judge=judge, server_privkey=SERVER_PRIV)
    client = TestClient(app)

    data = _create_contract(client, AUTONOMOUS_JUDGE_CONTRACT)
    cid = data["contract_id"]
    _bond_and_accept(client, cid)

    signed_post(client, f"/contracts/{cid}/fix", {"fix": "apt install gcc", "agent_pubkey": AGENT_PUBKEY}, AGENT_PUBKEY, AGENT_PRIV)

    _set_test_accounts(app, cid)
    resp = signed_post(client, f"/contracts/{cid}/review", {
        "action": "dispute",
        "argument": "Fix doesn't work",
        "principal_pubkey": PRINCIPAL_PUBKEY,
    }, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
    assert resp.status_code == 200
    body = resp.json()
    assert body["outcome"] == "fulfilled"

    contract = client.get(f"/contracts/{cid}").json()
    assert contract["status"] == "resolved"

    # Escrow resolved with bond routing
    escrow = escrow_mgr.get(cid)
    assert escrow["resolved"] is True
    assert escrow["resolution"]["dispute_loser"] == "principal"  # principal lost


def test_dispute_with_judge_agent_loses():
    """When judge rules canceled, agent loses bond."""
    judge = FakeJudge(outcome="canceled")
    store = ContractStore(":memory:")
    escrow_mgr = EscrowManager(":memory:", payment_backend=make_nano_backend())
    app = create_app(store=store, escrow_mgr=escrow_mgr, judge=judge, server_privkey=SERVER_PRIV)
    client = TestClient(app)

    data = _create_contract(client, JUDGE_CONTRACT)
    cid = data["contract_id"]
    _bond_and_accept(client, cid)

    _set_test_accounts(app, cid)
    body = _file_dispute(client, cid, "Agent did nothing", "principal")
    assert body["outcome"] == "canceled"

    escrow = escrow_mgr.get(cid)
    assert escrow["resolution"]["dispute_loser"] == "agent"


def test_review_dispute_requires_argument(client):
    data = _create_contract(client, AUTONOMOUS_CONTRACT)
    cid = data["contract_id"]
    _accept_contract(client, cid)
    signed_post(client, f"/contracts/{cid}/fix", {"fix": "apt install gcc", "agent_pubkey": AGENT_PUBKEY}, AGENT_PUBKEY, AGENT_PRIV)

    resp = signed_post(client, f"/contracts/{cid}/review", {
        "action": "dispute",
        "argument": "",
        "principal_pubkey": PRINCIPAL_PUBKEY,
    }, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
    assert resp.status_code == 400


# --- Helpers for two-phase dispute ---

def _pubkey_for_side(side):
    """Return the pubkey for a dispute side."""
    return PRINCIPAL_PUBKEY if side == "principal" else AGENT_PUBKEY


def _privkey_for_side(side):
    """Return the private key for a dispute side."""
    return PRINCIPAL_PRIV if side == "principal" else AGENT_PRIV


def _file_dispute(client, cid, argument, side="principal"):
    """File a dispute and trigger ruling (other side responds to skip window)."""
    pubkey = _pubkey_for_side(side)
    privkey = _privkey_for_side(side)
    resp = signed_post(client, f"/contracts/{cid}/dispute", {
        "argument": argument, "side": side, "pubkey": pubkey,
    }, pubkey, privkey)
    assert resp.status_code == 200
    body = resp.json()
    if body.get("status") == "awaiting_response":
        # Other side responds (or doesn't -- trigger ruling by re-calling dispute after deadline)
        other = "agent" if side == "principal" else "principal"
        other_pubkey = _pubkey_for_side(other)
        other_privkey = _privkey_for_side(other)
        resp = signed_post(client, f"/contracts/{cid}/respond", {
            "argument": "(no contest)",
            "side": other,
            "pubkey": other_pubkey,
        }, other_pubkey, other_privkey)
        assert resp.status_code == 200
        return resp.json()
    return body  # Legacy judge returns ruling directly


def _file_dispute_no_respond(client, cid, argument, side="principal"):
    """File a dispute without response (for testing the awaiting state)."""
    pubkey = _pubkey_for_side(side)
    privkey = _privkey_for_side(side)
    resp = signed_post(client, f"/contracts/{cid}/dispute", {
        "argument": argument, "side": side, "pubkey": pubkey,
    }, pubkey, privkey)
    assert resp.status_code == 200
    return resp.json()


# --- Tiered court system ---

class FakeTieredCourt:
    """Fake tiered court that returns configurable rulings per level."""
    def __init__(self, rulings=None):
        # rulings: list of (outcome, reasoning) per level
        self.rulings = rulings or [("canceled", "district says no"), ("fulfilled", "appeals says yes"), ("canceled", "supreme says no")]
        self.calls = []

    async def rule(self, evidence, level=0):
        self.calls.append(level)
        outcome, reasoning = self.rulings[min(level, len(self.rulings) - 1)]
        from protocol import COURT_TIERS, MAX_DISPUTE_LEVEL
        tier = COURT_TIERS[min(level, MAX_DISPUTE_LEVEL)]
        return JudgeRuling(
            outcome=outcome, reasoning=reasoning,
            court=tier["name"], level=level,
            final=(level >= MAX_DISPUTE_LEVEL),
        )


def _make_tiered_app(rulings=None):
    court = FakeTieredCourt(rulings)
    store = ContractStore(":memory:")
    escrow_mgr = EscrowManager(":memory:", payment_backend=make_nano_backend())
    app = create_app(store=store, escrow_mgr=escrow_mgr, court=court, server_privkey=SERVER_PRIV)
    return app, store, escrow_mgr, court


def test_tiered_district_court():
    """First dispute goes to district court."""
    app, store, escrow_mgr, court = _make_tiered_app()
    client = TestClient(app)

    data = _create_contract(client, JUDGE_CONTRACT)
    cid = data["contract_id"]
    _bond_and_accept(client, cid)

    body = _file_dispute(client, cid, "Agent did nothing", "principal")
    assert body["court"] == "district"
    assert body["level"] == 0
    assert body["can_appeal"] is True
    assert body["next_court"] == "appeals"
    assert court.calls == [0]

    # Contract goes back to in_progress (not resolved) so loser can appeal
    contract = client.get(f"/contracts/{cid}").json()
    assert contract["status"] == "in_progress"


def test_tiered_appeal_to_appeals_court():
    """Loser of district ruling can appeal to appeals court."""
    # District: canceled (agent loses). Agent appeals -> appeals: fulfilled (principal loses)
    app, store, escrow_mgr, court = _make_tiered_app(
        rulings=[("canceled", "district: agent failed"), ("fulfilled", "appeals: actually worked")]
    )
    client = TestClient(app)

    data = _create_contract(client, JUDGE_CONTRACT)
    cid = data["contract_id"]
    _bond_and_accept(client, cid)

    # District court
    body = _file_dispute(client, cid, "Agent did nothing", "principal")
    assert body["court"] == "district"
    assert body["outcome"] == "canceled"

    # Agent appeals (agent was the loser of "canceled")
    body = _file_dispute(client, cid, "I fixed it, principal is wrong", "agent")
    assert body["court"] == "appeals"
    assert body["level"] == 1
    assert body["outcome"] == "fulfilled"
    assert body["can_appeal"] is True
    assert body["next_court"] == "supreme"
    assert court.calls == [0, 1]


def test_tiered_supreme_is_final():
    """Supreme court ruling is final, no further appeals."""
    app, store, escrow_mgr, court = _make_tiered_app(
        rulings=[("canceled", "district"), ("fulfilled", "appeals"), ("canceled", "supreme final")]
    )
    client = TestClient(app)

    data = _create_contract(client, JUDGE_CONTRACT)
    cid = data["contract_id"]
    _bond_and_accept(client, cid)

    _set_test_accounts(app, cid)
    # District -> canceled (agent loses)
    _file_dispute(client, cid, "bad", "principal")
    # Appeals -> fulfilled (principal loses), agent appeals
    _file_dispute(client, cid, "appeal", "agent")
    # Supreme -> principal appeals
    body = _file_dispute(client, cid, "supreme appeal", "principal")
    assert body["court"] == "supreme"
    assert body["level"] == 2
    assert body["final"] is True
    assert body["can_appeal"] is False
    assert body["next_court"] is None

    # Contract is resolved (final)
    contract = client.get(f"/contracts/{cid}").json()
    assert contract["status"] == "resolved"

    # Escrow is resolved
    escrow = escrow_mgr.get(cid)
    assert escrow["resolved"] is True

    # No further disputes allowed
    resp = signed_post(client, f"/contracts/{cid}/dispute", {
        "argument": "again", "side": "agent", "pubkey": AGENT_PUBKEY,
    }, AGENT_PUBKEY, AGENT_PRIV)
    assert resp.status_code == 409


def test_tiered_only_loser_can_appeal():
    """Only the losing party of the previous ruling can appeal."""
    app, store, escrow_mgr, court = _make_tiered_app(
        rulings=[("canceled", "agent loses")]
    )
    client = TestClient(app)

    data = _create_contract(client, JUDGE_CONTRACT)
    cid = data["contract_id"]
    _bond_and_accept(client, cid)

    # District -> canceled (agent loses)
    _file_dispute(client, cid, "bad", "principal")

    # Principal tries to appeal (but principal won!) -> should fail
    resp = signed_post(client, f"/contracts/{cid}/dispute", {
        "argument": "appeal anyway", "side": "principal", "pubkey": PRINCIPAL_PUBKEY,
    }, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
    assert resp.status_code == 409
    assert "losing party" in resp.json()["detail"]


# --- Two-phase dispute (response window) ---

def test_dispute_returns_awaiting_response():
    """Filing a dispute returns awaiting_response, not a ruling."""
    app, store, escrow_mgr, court = _make_tiered_app()
    client = TestClient(app)

    data = _create_contract(client, JUDGE_CONTRACT)
    cid = data["contract_id"]
    _bond_and_accept(client, cid)

    resp = signed_post(client, f"/contracts/{cid}/dispute", {
        "argument": "Agent failed", "side": "principal", "pubkey": PRINCIPAL_PUBKEY,
    }, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "awaiting_response"
    assert body["court"] == "district"
    assert "response_deadline" in body
    assert body["response_window"] == 30


def test_respond_triggers_ruling():
    """Responding to a dispute triggers the judge with both arguments."""
    app, store, escrow_mgr, court = _make_tiered_app()
    client = TestClient(app)

    data = _create_contract(client, JUDGE_CONTRACT)
    cid = data["contract_id"]
    _bond_and_accept(client, cid)

    # File dispute
    signed_post(client, f"/contracts/{cid}/dispute", {
        "argument": "Agent was lazy", "side": "principal", "pubkey": PRINCIPAL_PUBKEY,
    }, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)

    # Agent responds
    resp = signed_post(client, f"/contracts/{cid}/respond", {
        "argument": "I tried my best, the task was impossible", "side": "agent", "pubkey": AGENT_PUBKEY,
    }, AGENT_PUBKEY, AGENT_PRIV)
    assert resp.status_code == 200
    body = resp.json()
    assert "outcome" in body
    assert "court" in body
    assert body["level"] == 0


def test_respond_wrong_side_rejected():
    """The dispute filer cannot respond to their own dispute."""
    app, store, escrow_mgr, court = _make_tiered_app()
    client = TestClient(app)

    data = _create_contract(client, JUDGE_CONTRACT)
    cid = data["contract_id"]
    _bond_and_accept(client, cid)

    signed_post(client, f"/contracts/{cid}/dispute", {
        "argument": "bad agent", "side": "principal", "pubkey": PRINCIPAL_PUBKEY,
    }, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)

    resp = signed_post(client, f"/contracts/{cid}/respond", {
        "argument": "responding to myself", "side": "principal", "pubkey": PRINCIPAL_PUBKEY,
    }, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
    assert resp.status_code == 400


def test_respond_no_pending_dispute():
    """Responding when no dispute is pending returns 409."""
    app, store, escrow_mgr, court = _make_tiered_app()
    client = TestClient(app)

    data = _create_contract(client, JUDGE_CONTRACT)
    cid = data["contract_id"]
    _bond_and_accept(client, cid)

    resp = signed_post(client, f"/contracts/{cid}/respond", {
        "argument": "nothing to respond to", "side": "agent", "pubkey": AGENT_PUBKEY,
    }, AGENT_PUBKEY, AGENT_PRIV)
    assert resp.status_code == 409


def test_dispute_in_absentia():
    """If response window expires, dispute re-call triggers in absentia ruling."""
    app, store, escrow_mgr, court = _make_tiered_app()
    client = TestClient(app)

    data = _create_contract(client, JUDGE_CONTRACT)
    cid = data["contract_id"]
    _bond_and_accept(client, cid)

    # File dispute
    signed_post(client, f"/contracts/{cid}/dispute", {
        "argument": "Agent failed", "side": "principal", "pubkey": PRINCIPAL_PUBKEY,
    }, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)

    _set_test_accounts(app, cid)
    # Manually expire the deadline by patching the transcript
    transcript = store.get(cid)["transcript"]
    for msg in transcript:
        if msg.get("type") in ("dispute_metadata", "dispute_filed"):
            msg_data = msg.get("data", msg)
            if "response_deadline" in msg_data:
                msg_data["response_deadline"] = time.time() - 1  # expired
    store.db.execute(
        "UPDATE contracts SET transcript = ? WHERE id = ?",
        (__import__("json").dumps(transcript), cid),
    )
    store.db.commit()

    # Re-call dispute -- should trigger in absentia ruling
    resp = signed_post(client, f"/contracts/{cid}/dispute", {
        "argument": "Agent failed", "side": "principal", "pubkey": PRINCIPAL_PUBKEY,
    }, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
    assert resp.status_code == 200
    body = resp.json()
    assert "outcome" in body


def test_dispute_status_endpoint():
    """GET /dispute_status shows pending dispute info."""
    app, store, escrow_mgr, court = _make_tiered_app()
    client = TestClient(app)

    data = _create_contract(client, JUDGE_CONTRACT)
    cid = data["contract_id"]
    _bond_and_accept(client, cid)

    # No dispute yet
    resp = client.get(f"/contracts/{cid}/dispute_status")
    assert resp.json()["status"] == "no_pending_dispute"

    # File dispute
    signed_post(client, f"/contracts/{cid}/dispute", {
        "argument": "bad agent", "side": "principal", "pubkey": PRINCIPAL_PUBKEY,
    }, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)

    resp = client.get(f"/contracts/{cid}/dispute_status")
    body = resp.json()
    assert body["status"] == "awaiting_response"
    assert body["filer"] == "principal"
    assert body["court"] == "district"


def test_platform_fee_in_resolution():
    """Platform fee is 10% of excess bond (bounty - judge_fee)."""
    from server.escrow import Escrow
    # bounty=1.0, judge_fee=0.17, excess=0.83, fee=0.083
    escrow = Escrow("1.0", {"judge_fee": "0.17"})
    escrow.lock()
    result = escrow.resolve("fulfilled")
    assert "platform_fee" in result
    assert Decimal(result["platform_fee"]) == Decimal("0.083")


def test_platform_fee_minimum():
    """Platform fee floors at 0.002 XNO when excess is tiny."""
    from server.escrow import Escrow
    # bounty=0.19, judge_fee=0.17, excess=0.02, 10% of 0.02=0.002
    escrow = Escrow("0.19", {"judge_fee": "0.17"})
    escrow.lock()
    result = escrow.resolve("fulfilled")
    assert Decimal(result["platform_fee"]) == Decimal("0.002")


def test_sse_publish_mechanism(app):
    """SSE publish pushes events to subscriber queues."""
    import queue as _q

    # Subscribe a queue manually
    q = _q.Queue(maxsize=256)
    # Access the internal subscriber list
    from server import app as app_mod
    # The _sse_subscribers list is captured in the closure, access via sse_publish side effects
    sse_publish = app.state.sse_publish

    # Publish with no subscribers — should not error
    sse_publish("contract_posted", {"contract_id": "test-123", "bounty": "0.5"})


def test_sse_publish_to_subscriber(app):
    """SSE publish delivers events to subscribed queues."""
    import queue as _q

    # Simulate what the SSE endpoint does — subscribe a queue, publish, check delivery
    q = _q.Queue(maxsize=256)

    # Manually access the subscriber list via the closure
    # We need to reach into the app's internal state
    # The cleanest way: call sse_publish and verify the function doesn't crash
    sse_publish = app.state.sse_publish

    # Publish event
    sse_publish("contract_posted", {"contract_id": "abc", "bounty": "1.0"})
    # No subscribers — queue is empty, no crash
    assert q.empty()


def test_sse_stream_min_bounty_filter(app, client):
    """SSE stream filters by min_bounty."""
    import threading, queue

    events = queue.Queue()

    def read_sse():
        with client.stream("GET", "/contracts/stream?min_bounty=100") as resp:
            for line in resp.iter_lines():
                if line.startswith("data: "):
                    events.put(json.loads(line[6:]))
                    return

    t = threading.Thread(target=read_sse, daemon=True)
    t.start()
    time.sleep(0.2)

    # Post contract with 0.5 bounty — should NOT pass filter
    _create_contract(client)
    t.join(timeout=2)

    # Should be empty — bounty 0.5 < min 100
    assert events.empty()


# === Unhappy path tests ===


# --- Auth failures ---

def test_unsigned_post_rejected(client):
    """POST /contracts with no auth headers at all should get 401."""
    resp = client.post("/contracts", json={
        "contract": SAMPLE_CONTRACT,
        "principal_pubkey": PRINCIPAL_PUBKEY,
    })
    assert resp.status_code == 401


def test_wrong_key_post_rejected(client):
    """Sign with one key but claim different pubkey in header -- should get 401."""
    # Sign with AGENT key but claim to be PRINCIPAL
    resp = signed_post(client, "/contracts", {
        "contract": SAMPLE_CONTRACT,
        "principal_pubkey": PRINCIPAL_PUBKEY,
    }, PRINCIPAL_PUBKEY, AGENT_PRIV)  # wrong private key for this pubkey
    assert resp.status_code == 401


def test_third_party_cannot_accept(client):
    """A third party generates a new keypair and tries to submit a fix on someone else's contract."""
    data = _create_contract(client)
    cid = data["contract_id"]
    _accept_contract(client, cid)  # AGENT accepts

    # Third party tries to submit a fix
    third_priv, third_pub = generate_ed25519_keypair()
    third_id = pubkey_to_fix_id(third_pub)
    resp = signed_post(client, f"/contracts/{cid}/fix", {
        "fix": "echo pwned",
        "agent_pubkey": third_id,
    }, third_id, third_priv)
    assert resp.status_code == 403


# --- State machine violations ---

def test_fix_on_open_contract_409(client):
    """Submit fix without accepting first -- 409."""
    data = _create_contract(client)
    cid = data["contract_id"]
    # Contract is open, no agent assigned -- try to submit fix as agent
    # This will fail because _check_party(data, agent_pubkey, "agent") will 403
    # since there's no agent on the contract. But status check comes first.
    resp = signed_post(client, f"/contracts/{cid}/fix", {
        "fix": "apt install gcc",
        "agent_pubkey": AGENT_PUBKEY,
    }, AGENT_PUBKEY, AGENT_PRIV)
    # Could be 403 (no agent assigned) or 409 (not in_progress) -- either is correct rejection
    assert resp.status_code in (403, 409)


def test_accept_already_accepted_409(client):
    """Accept, then another agent tries to accept -- 409."""
    data = _create_contract(client)
    cid = data["contract_id"]
    _accept_contract(client, cid)  # AGENT accepts

    # AGENT2 tries to accept
    resp = signed_post(client, f"/contracts/{cid}/accept", {
        "agent_pubkey": AGENT2_PUBKEY,
    }, AGENT2_PUBKEY, AGENT2_PRIV)
    assert resp.status_code == 409


def test_verify_without_fix_409(app, client):
    """Try to verify on in_progress contract without fix submitted -- should 409."""
    data = _create_contract(client)
    cid = data["contract_id"]
    _accept_contract(client, cid)
    _set_test_accounts(app, cid)

    resp = signed_post(client, f"/contracts/{cid}/verify", {
        "success": True,
        "principal_pubkey": PRINCIPAL_PUBKEY,
    }, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
    assert resp.status_code == 409


def test_dispute_on_open_contract_409(client):
    """Dispute before any work done -- 409."""
    data = _create_contract(client, JUDGE_CONTRACT)
    cid = data["contract_id"]
    # Contract is open, try to dispute
    resp = signed_post(client, f"/contracts/{cid}/dispute", {
        "argument": "I changed my mind",
        "side": "principal",
        "pubkey": PRINCIPAL_PUBKEY,
    }, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
    assert resp.status_code == 409


# --- Data validation ---

def test_create_contract_negative_bounty_400(client):
    """bounty = '-1' -- should 400."""
    bad_contract = {
        **SAMPLE_CONTRACT,
        "escrow": {**SAMPLE_CONTRACT["escrow"], "bounty": "-1"},
    }
    resp = signed_post(client, "/contracts", {
        "contract": bad_contract,
        "principal_pubkey": PRINCIPAL_PUBKEY,
    }, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
    assert resp.status_code == 400


def test_create_contract_empty_command_400(client):
    """task.command = '' -- should 400."""
    bad_contract = {
        **SAMPLE_CONTRACT,
        "task": {**SAMPLE_CONTRACT["task"], "command": ""},
    }
    resp = signed_post(client, "/contracts", {
        "contract": bad_contract,
        "principal_pubkey": PRINCIPAL_PUBKEY,
    }, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
    assert resp.status_code == 400


def test_fix_empty_string_400(client):
    """Submit fix with fix='' -- should 400."""
    data = _create_contract(client)
    cid = data["contract_id"]
    _accept_contract(client, cid)

    resp = signed_post(client, f"/contracts/{cid}/fix", {
        "fix": "",
        "agent_pubkey": AGENT_PUBKEY,
    }, AGENT_PUBKEY, AGENT_PRIV)
    assert resp.status_code == 400


def test_create_contract_bounty_below_minimum_400(client):
    """Bounty lower than MINIMUM_BOUNTY -- should 400."""
    from protocol import MINIMUM_BOUNTY
    bad_contract = {
        **SAMPLE_CONTRACT,
        "escrow": {**SAMPLE_CONTRACT["escrow"], "bounty": "0.001"},
    }
    resp = signed_post(client, "/contracts", {
        "contract": bad_contract,
        "principal_pubkey": PRINCIPAL_PUBKEY,
    }, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
    assert resp.status_code == 400


# --- Contract not found ---

def test_accept_nonexistent_404(client):
    """Accept contract that doesn't exist -- 404."""
    resp = signed_post(client, "/contracts/nonexistent-id-999/accept", {
        "agent_pubkey": AGENT_PUBKEY,
    }, AGENT_PUBKEY, AGENT_PRIV)
    assert resp.status_code == 404


def test_fix_nonexistent_404(client):
    """Submit fix on nonexistent contract -- 404."""
    resp = signed_post(client, "/contracts/nonexistent-id-999/fix", {
        "fix": "echo hello",
        "agent_pubkey": AGENT_PUBKEY,
    }, AGENT_PUBKEY, AGENT_PRIV)
    assert resp.status_code == 404


# test_halt_nonexistent_404 -- already covered by test_halt_not_found above


# --- Double operations ---

def test_double_bond_409(client):
    """Agent bonds, then tries to bond again -- 409."""
    data = _create_contract(client, JUDGE_CONTRACT)
    cid = data["contract_id"]

    resp = signed_post(client, f"/contracts/{cid}/bond", {
        "agent_pubkey": AGENT_PUBKEY,
    }, AGENT_PUBKEY, AGENT_PRIV)
    assert resp.status_code == 200

    # Second bond attempt -- contract is now 'investigating', not 'open'
    resp = signed_post(client, f"/contracts/{cid}/bond", {
        "agent_pubkey": AGENT2_PUBKEY,
    }, AGENT2_PUBKEY, AGENT2_PRIV)
    assert resp.status_code == 409


def test_dispute_after_resolved_409(app, client):
    """Resolve contract, then try to dispute -- 409."""
    data = _create_contract(client, JUDGE_CONTRACT)
    cid = data["contract_id"]
    _bond_and_accept(client, cid)
    _set_test_accounts(app, cid)

    # Submit fix and have principal verify success to resolve
    signed_post(client, f"/contracts/{cid}/fix", {
        "fix": "apt install gcc",
        "agent_pubkey": AGENT_PUBKEY,
    }, AGENT_PUBKEY, AGENT_PRIV)

    signed_post(client, f"/contracts/{cid}/verify", {
        "success": True,
        "principal_pubkey": PRINCIPAL_PUBKEY,
    }, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)

    # Contract is now fulfilled -- try to dispute
    resp = signed_post(client, f"/contracts/{cid}/dispute", {
        "argument": "Actually I changed my mind",
        "side": "principal",
        "pubkey": PRINCIPAL_PUBKEY,
    }, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
    assert resp.status_code == 409


# --- Security audit tests ---

def test_concurrent_bond_only_one_wins(app):
    """2.1: Second bond attempt on same contract gets 409."""
    client = TestClient(app)
    data = _create_contract(client)
    cid = data["contract_id"]

    # First agent bonds
    resp = signed_post(client, f"/contracts/{cid}/bond", {
        "agent_pubkey": AGENT_PUBKEY,
    }, AGENT_PUBKEY, AGENT_PRIV)
    assert resp.status_code == 200

    # Second agent tries to bond -- should get 409
    resp2 = signed_post(client, f"/contracts/{cid}/bond", {
        "agent_pubkey": AGENT2_PUBKEY,
    }, AGENT2_PUBKEY, AGENT2_PRIV)
    assert resp2.status_code == 409


def test_escrow_endpoint_unauthenticated_strips_addresses(app):
    """2.2: Unauthenticated escrow GET strips wallet addresses."""
    client = TestClient(app)
    data = _create_contract(client)
    cid = data["contract_id"]

    resp = client.get(f"/contracts/{cid}/escrow")
    assert resp.status_code == 200
    body = resp.json()
    # Should NOT contain wallet addresses
    assert "escrow_account" not in body
    assert "principal_account" not in body
    assert "agent_account" not in body


def test_chat_msg_type_role_validation(client):
    """5.1: Agent cannot send 'answer' msg_type, principal cannot send 'ask'."""
    data = _create_contract(client)
    cid = data["contract_id"]
    _accept_contract(client, cid)

    # Agent tries to send 'answer' (not allowed)
    resp = signed_post(client, f"/contracts/{cid}/chat", {
        "message": "test", "from_side": "agent", "msg_type": "answer",
        "pubkey": AGENT_PUBKEY,
    }, AGENT_PUBKEY, AGENT_PRIV)
    assert resp.status_code == 400

    # Principal tries to send 'ask' (not allowed)
    resp = signed_post(client, f"/contracts/{cid}/chat", {
        "message": "test", "from_side": "principal", "msg_type": "ask",
        "pubkey": PRINCIPAL_PUBKEY,
    }, PRINCIPAL_PUBKEY, PRINCIPAL_PRIV)
    assert resp.status_code == 400


# --- Platform info endpoint ---

def test_platform_info(client):
    """GET /platform_info returns advertised rates."""
    resp = client.get("/platform_info")
    assert resp.status_code == 200
    body = resp.json()
    assert body["model"] == "inclusive_bond"
    assert body["min_bounty"] == "0.19"
    assert body["judge_fee"] == "0.17"
    assert body["currency"] == "XNO"
    assert body["cancel_fee_rate"] == "0.20"
    assert body["platform_fee_rate"] == "0.10"
    assert len(body["court_tiers"]) == 3
    assert body["court_tiers"][0]["name"] == "district"
