"""Tests for contract modes, chat, judge-as-participant, dispute bonds.

Covers: autonomous flow, review window, chat messages, bond lifecycle,
investigation rate limiting, judge timeout/voiding, decline after investigate.
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import time
import pytest
from unittest.mock import AsyncMock, patch
from starlette.testclient import TestClient
from server.app import create_app
from server.store import ContractStore
from server.escrow import EscrowManager
from server.reputation import ReputationManager
from server.judge import AIJudge, TieredCourt, Evidence, JudgeRuling


SAMPLE_CONTRACT = {
    "version": 2, "protocol": "fix",
    "task": {"type": "fix_command", "command": "make", "error": "gcc error"},
    "environment": {"os": "Linux", "arch": "aarch64", "package_managers": ["apt"]},
    "capabilities": {},
    "verification": [{"method": "exit_code", "expected": 0}],
    "execution": {"sandbox": False, "root": None, "max_attempts": 5, "investigation_rounds": 5, "timeout": 300},
    "escrow": {"bounty": "0.05", "currency": "XNO", "chain": "nano"},
    "terms": {"cancellation": {"agent_fee": "0.002", "principal_fee": "0.002", "grace_period": 30}},
}

AUTONOMOUS_CONTRACT = {
    **SAMPLE_CONTRACT,
    "execution": {**SAMPLE_CONTRACT["execution"], "mode": "autonomous", "review_window": 3600},
}

JUDGE_CONTRACT = {
    **SAMPLE_CONTRACT,
    "judge": {"pubkey": "judge_abc", "fee": "0.005", "ruling_timeout": 60},
}

AUTONOMOUS_JUDGE_CONTRACT = {
    **AUTONOMOUS_CONTRACT,
    "judge": {"pubkey": "judge_abc", "fee": "0.005", "ruling_timeout": 60},
}


@pytest.fixture
def app():
    store = ContractStore(":memory:")
    escrow_mgr = EscrowManager(":memory:")
    reputation_mgr = ReputationManager(":memory:")
    return create_app(store=store, escrow_mgr=escrow_mgr, reputation_mgr=reputation_mgr)


@pytest.fixture
def client(app):
    return TestClient(app)


def _create_contract(client, contract=None):
    resp = client.post("/contracts", json={
        "contract": contract or SAMPLE_CONTRACT,
        "principal_pubkey": "principal_abc",
    })
    assert resp.status_code == 200
    return resp.json()


def _accept_contract(client, contract_id, agent="agent_xyz"):
    resp = client.post(f"/contracts/{contract_id}/accept", json={"agent_pubkey": agent})
    assert resp.status_code == 200
    return resp.json()


def _bond_and_accept(client, contract_id, agent="agent_xyz"):
    """Bond then accept (new flow)."""
    resp = client.post(f"/contracts/{contract_id}/bond", json={"agent_pubkey": agent})
    assert resp.status_code == 200
    resp = client.post(f"/contracts/{contract_id}/accept", json={"agent_pubkey": agent})
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
    assert contract["judge_pubkey"] == "judge_abc"


def test_judge_fee_in_escrow(app, client):
    data = _create_contract(client, JUDGE_CONTRACT)
    escrow = app.state.escrow.get(data["contract_id"])
    assert escrow is not None
    assert escrow["judge_fee"] == "0.005"
    assert escrow["judge_account"] == "judge_abc"
    assert escrow["principal_bond_locked"] is True


# --- Bond lifecycle (OPEN -> INVESTIGATING -> IN_PROGRESS or OPEN) ---

def test_bond_starts_investigating(client):
    data = _create_contract(client, JUDGE_CONTRACT)
    cid = data["contract_id"]

    resp = client.post(f"/contracts/{cid}/bond", json={"agent_pubkey": "agent_xyz"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "investigating"

    contract = client.get(f"/contracts/{cid}").json()
    assert contract["status"] == "investigating"
    assert contract["agent_pubkey"] == "agent_xyz"


def test_bond_then_accept(client):
    data = _create_contract(client, JUDGE_CONTRACT)
    cid = data["contract_id"]

    client.post(f"/contracts/{cid}/bond", json={"agent_pubkey": "agent_xyz"})
    resp = client.post(f"/contracts/{cid}/accept", json={"agent_pubkey": "agent_xyz"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "in_progress"

    contract = client.get(f"/contracts/{cid}").json()
    assert contract["status"] == "in_progress"


def test_bond_then_decline(client, app):
    data = _create_contract(client, JUDGE_CONTRACT)
    cid = data["contract_id"]

    client.post(f"/contracts/{cid}/bond", json={"agent_pubkey": "agent_xyz"})

    resp = client.post(f"/contracts/{cid}/decline")
    assert resp.status_code == 200
    assert resp.json()["status"] == "open"

    contract = client.get(f"/contracts/{cid}").json()
    assert contract["status"] == "open"
    assert contract["agent_pubkey"] is None

    # Agent bond should be released
    escrow = app.state.escrow.get(cid)
    assert escrow["agent_bond_locked"] is False


def test_decline_wrong_status_409(client):
    data = _create_contract(client)
    cid = data["contract_id"]
    resp = client.post(f"/contracts/{cid}/decline")
    assert resp.status_code == 409


def test_bond_wrong_status_409(client):
    data = _create_contract(client)
    cid = data["contract_id"]
    _accept_contract(client, cid)
    resp = client.post(f"/contracts/{cid}/bond", json={"agent_pubkey": "agent_2"})
    assert resp.status_code == 409


# --- Investigation rate limiting ---

def test_investigate_rate_limiting(client):
    contract = {**SAMPLE_CONTRACT, "execution": {**SAMPLE_CONTRACT["execution"], "investigation_rate": 10}}
    data = _create_contract(client, contract)
    cid = data["contract_id"]
    _accept_contract(client, cid)

    # First investigation should work
    resp = client.post(f"/contracts/{cid}/investigate", json={
        "command": "ls", "agent_pubkey": "agent_xyz",
    })
    assert resp.status_code == 200

    # Immediate second should be rate limited
    resp = client.post(f"/contracts/{cid}/investigate", json={
        "command": "pwd", "agent_pubkey": "agent_xyz",
    })
    assert resp.status_code == 429


def test_investigate_during_investigating(client):
    """Agent can investigate while in INVESTIGATING state (before accepting)."""
    data = _create_contract(client, JUDGE_CONTRACT)
    cid = data["contract_id"]
    client.post(f"/contracts/{cid}/bond", json={"agent_pubkey": "agent_xyz"})

    resp = client.post(f"/contracts/{cid}/investigate", json={
        "command": "ls", "agent_pubkey": "agent_xyz",
    })
    assert resp.status_code == 200


# --- Chat messages ---

def test_chat_message(client):
    data = _create_contract(client)
    cid = data["contract_id"]
    _accept_contract(client, cid)

    resp = client.post(f"/contracts/{cid}/chat", json={
        "message": "What version of gcc?",
        "from_side": "agent",
        "msg_type": "ask",
    })
    assert resp.status_code == 200
    assert resp.json()["status"] == "sent"

    # Check transcript
    contract = client.get(f"/contracts/{cid}").json()
    ask_msgs = [m for m in contract["transcript"] if m["type"] == "ask"]
    assert len(ask_msgs) == 1
    assert ask_msgs[0]["message"] == "What version of gcc?"
    assert ask_msgs[0]["from"] == "agent"


def test_chat_answer(client):
    data = _create_contract(client)
    cid = data["contract_id"]
    _accept_contract(client, cid)

    resp = client.post(f"/contracts/{cid}/chat", json={
        "message": "gcc 12.3",
        "from_side": "principal",
        "msg_type": "answer",
    })
    assert resp.status_code == 200


def test_chat_general_message(client):
    data = _create_contract(client)
    cid = data["contract_id"]
    _accept_contract(client, cid)

    resp = client.post(f"/contracts/{cid}/chat", json={
        "message": "Working on it",
        "from_side": "agent",
        "msg_type": "message",
    })
    assert resp.status_code == 200


def test_chat_on_open_ok(client):
    data = _create_contract(client)
    cid = data["contract_id"]
    resp = client.post(f"/contracts/{cid}/chat", json={
        "message": "hello",
        "from_side": "principal",
        "msg_type": "message",
    })
    assert resp.status_code == 200


def test_chat_invalid_type_400(client):
    data = _create_contract(client)
    cid = data["contract_id"]
    _accept_contract(client, cid)

    resp = client.post(f"/contracts/{cid}/chat", json={
        "message": "hi",
        "from_side": "agent",
        "msg_type": "invalid_type",
    })
    assert resp.status_code == 400


def test_chat_during_review(client):
    """Chat works during review window (autonomous mode)."""
    data = _create_contract(client, AUTONOMOUS_CONTRACT)
    cid = data["contract_id"]
    _accept_contract(client, cid)

    # Submit fix to enter review
    client.post(f"/contracts/{cid}/fix", json={"fix": "apt install gcc", "agent_pubkey": "agent_xyz"})

    resp = client.post(f"/contracts/{cid}/chat", json={
        "message": "Please check the fix",
        "from_side": "agent",
        "msg_type": "message",
    })
    assert resp.status_code == 200


def test_chat_during_investigating(client):
    """Chat works during investigating state."""
    data = _create_contract(client, JUDGE_CONTRACT)
    cid = data["contract_id"]
    client.post(f"/contracts/{cid}/bond", json={"agent_pubkey": "agent_xyz"})

    resp = client.post(f"/contracts/{cid}/chat", json={
        "message": "What's the project structure?",
        "from_side": "agent",
        "msg_type": "ask",
    })
    assert resp.status_code == 200


# --- Autonomous mode: fix -> review -> fulfill ---

def test_autonomous_fix_enters_review(client):
    data = _create_contract(client, AUTONOMOUS_CONTRACT)
    cid = data["contract_id"]
    _accept_contract(client, cid)

    resp = client.post(f"/contracts/{cid}/fix", json={
        "fix": "apt install gcc",
        "explanation": "missing compiler",
        "agent_pubkey": "agent_xyz",
    })
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

    resp = client.post(f"/contracts/{cid}/fix", json={
        "fix": "apt install gcc", "agent_pubkey": "agent_xyz",
    })
    assert resp.json()["status"] == "pending_verification"


def test_review_accept(client, app):
    data = _create_contract(client, AUTONOMOUS_CONTRACT)
    cid = data["contract_id"]
    _accept_contract(client, cid)
    client.post(f"/contracts/{cid}/fix", json={"fix": "apt install gcc", "agent_pubkey": "agent_xyz"})

    resp = client.post(f"/contracts/{cid}/review", json={"action": "accept"})
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
    client.post(f"/contracts/{cid}/fix", json={"fix": "apt install gcc", "agent_pubkey": "agent_xyz"})

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
    client.post(f"/contracts/{cid}/fix", json={"fix": "apt install gcc", "agent_pubkey": "agent_xyz"})

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
    client.post(f"/contracts/{cid}/fix", json={"fix": "apt install gcc", "agent_pubkey": "agent_xyz"})

    resp = client.post(f"/contracts/{cid}/review", json={"action": "invalid"})
    assert resp.status_code == 400


# --- Void endpoint ---

def test_void_disputed_contract(client, app):
    """Voiding a disputed contract returns all funds."""
    data = _create_contract(client, JUDGE_CONTRACT)
    cid = data["contract_id"]
    _bond_and_accept(client, cid)

    # Manually set to disputed (normally judge would do this)
    app.state.store.update_status(cid, "disputed")

    resp = client.post(f"/contracts/{cid}/void")
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
    resp = client.post(f"/contracts/{cid}/void")
    assert resp.status_code == 409


# --- Halt (existing + now works from review) ---

def test_halt_contract(client):
    data = _create_contract(client)
    cid = data["contract_id"]
    _accept_contract(client, cid)

    resp = client.post(f"/contracts/{cid}/halt", json={
        "reason": "Agent is exfiltrating data",
        "principal_pubkey": "principal_abc",
    })
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "halted"
    assert body["ruling"] is None

    contract = client.get(f"/contracts/{cid}").json()
    assert contract["status"] == "halted"

    halt_msgs = [m for m in contract["transcript"] if m["type"] == "halt"]
    assert len(halt_msgs) == 1
    assert halt_msgs[0]["reason"] == "Agent is exfiltrating data"


def test_halt_during_review(client):
    """Principal can halt during autonomous review window."""
    data = _create_contract(client, AUTONOMOUS_CONTRACT)
    cid = data["contract_id"]
    _accept_contract(client, cid)
    client.post(f"/contracts/{cid}/fix", json={"fix": "rm -rf /", "agent_pubkey": "agent_xyz"})

    resp = client.post(f"/contracts/{cid}/halt", json={
        "reason": "Malicious fix detected",
    })
    assert resp.status_code == 200
    assert resp.json()["status"] == "halted"


def test_halt_not_in_progress_or_review(client):
    data = _create_contract(client)
    cid = data["contract_id"]
    resp = client.post(f"/contracts/{cid}/halt", json={"reason": "suspicious"})
    assert resp.status_code == 409


def test_halt_not_found(client):
    resp = client.post("/contracts/nonexistent/halt", json={"reason": "bad agent"})
    assert resp.status_code == 404


# --- Principal bond locked on contract creation ---

def test_principal_bond_locked_on_create(app, client):
    data = _create_contract(client, JUDGE_CONTRACT)
    escrow = app.state.escrow.get(data["contract_id"])
    assert escrow["principal_bond_locked"] is True


def test_agent_bond_locked_on_bond(app, client):
    data = _create_contract(client, JUDGE_CONTRACT)
    cid = data["contract_id"]
    client.post(f"/contracts/{cid}/bond", json={"agent_pubkey": "agent_xyz"})
    escrow = app.state.escrow.get(cid)
    assert escrow["agent_bond_locked"] is True


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
    escrow_mgr = EscrowManager(":memory:")
    reputation_mgr = ReputationManager(":memory:")
    app = create_app(store=store, escrow_mgr=escrow_mgr, reputation_mgr=reputation_mgr, judge=judge)
    client = TestClient(app)

    data = _create_contract(client, AUTONOMOUS_JUDGE_CONTRACT)
    cid = data["contract_id"]
    _bond_and_accept(client, cid)

    client.post(f"/contracts/{cid}/fix", json={"fix": "apt install gcc", "agent_pubkey": "agent_xyz"})

    resp = client.post(f"/contracts/{cid}/review", json={
        "action": "dispute",
        "argument": "Fix doesn't work",
    })
    assert resp.status_code == 200
    body = resp.json()
    assert body["outcome"] == "fulfilled"

    contract = client.get(f"/contracts/{cid}").json()
    assert contract["status"] == "resolved"

    # Escrow resolved with bond routing
    escrow = escrow_mgr.get(cid)
    assert escrow["resolved"] is True
    assert escrow["resolution"]["bond_loser"] == "principal"  # principal lost


def test_dispute_with_judge_agent_loses():
    """When judge rules canceled, agent loses bond."""
    judge = FakeJudge(outcome="canceled")
    store = ContractStore(":memory:")
    escrow_mgr = EscrowManager(":memory:")
    reputation_mgr = ReputationManager(":memory:")
    app = create_app(store=store, escrow_mgr=escrow_mgr, reputation_mgr=reputation_mgr, judge=judge)
    client = TestClient(app)

    data = _create_contract(client, JUDGE_CONTRACT)
    cid = data["contract_id"]
    _bond_and_accept(client, cid)

    body = _file_dispute(client, cid, "Agent did nothing", "principal")
    assert body["outcome"] == "canceled"

    escrow = escrow_mgr.get(cid)
    assert escrow["resolution"]["bond_loser"] == "agent"


def test_review_dispute_requires_argument(client):
    data = _create_contract(client, AUTONOMOUS_CONTRACT)
    cid = data["contract_id"]
    _accept_contract(client, cid)
    client.post(f"/contracts/{cid}/fix", json={"fix": "apt install gcc", "agent_pubkey": "agent_xyz"})

    resp = client.post(f"/contracts/{cid}/review", json={
        "action": "dispute",
        "argument": "",
    })
    assert resp.status_code == 400


# --- Helpers for two-phase dispute ---

def _file_dispute(client, cid, argument, side="principal"):
    """File a dispute and trigger ruling (other side responds to skip window)."""
    resp = client.post(f"/contracts/{cid}/dispute", json={"argument": argument, "side": side})
    assert resp.status_code == 200
    body = resp.json()
    if body.get("status") == "awaiting_response":
        # Other side responds (or doesn't -- trigger ruling by re-calling dispute after deadline)
        other = "agent" if side == "principal" else "principal"
        resp = client.post(f"/contracts/{cid}/respond", json={
            "argument": "(no contest)",
            "side": other,
        })
        assert resp.status_code == 200
        return resp.json()
    return body  # Legacy judge returns ruling directly


def _file_dispute_no_respond(client, cid, argument, side="principal"):
    """File a dispute without response (for testing the awaiting state)."""
    resp = client.post(f"/contracts/{cid}/dispute", json={"argument": argument, "side": side})
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
    escrow_mgr = EscrowManager(":memory:")
    reputation_mgr = ReputationManager(":memory:")
    app = create_app(store=store, escrow_mgr=escrow_mgr, reputation_mgr=reputation_mgr, court=court)
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
    resp = client.post(f"/contracts/{cid}/dispute", json={"argument": "again", "side": "agent"})
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
    resp = client.post(f"/contracts/{cid}/dispute", json={"argument": "appeal anyway", "side": "principal"})
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

    resp = client.post(f"/contracts/{cid}/dispute", json={
        "argument": "Agent failed", "side": "principal",
    })
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
    client.post(f"/contracts/{cid}/dispute", json={
        "argument": "Agent was lazy", "side": "principal",
    })

    # Agent responds
    resp = client.post(f"/contracts/{cid}/respond", json={
        "argument": "I tried my best, the task was impossible", "side": "agent",
    })
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

    client.post(f"/contracts/{cid}/dispute", json={
        "argument": "bad agent", "side": "principal",
    })

    resp = client.post(f"/contracts/{cid}/respond", json={
        "argument": "responding to myself", "side": "principal",
    })
    assert resp.status_code == 400


def test_respond_no_pending_dispute():
    """Responding when no dispute is pending returns 409."""
    app, store, escrow_mgr, court = _make_tiered_app()
    client = TestClient(app)

    data = _create_contract(client, JUDGE_CONTRACT)
    cid = data["contract_id"]
    _bond_and_accept(client, cid)

    resp = client.post(f"/contracts/{cid}/respond", json={
        "argument": "nothing to respond to", "side": "agent",
    })
    assert resp.status_code == 409


def test_dispute_in_absentia():
    """If response window expires, dispute re-call triggers in absentia ruling."""
    app, store, escrow_mgr, court = _make_tiered_app()
    client = TestClient(app)

    data = _create_contract(client, JUDGE_CONTRACT)
    cid = data["contract_id"]
    _bond_and_accept(client, cid)

    # File dispute
    client.post(f"/contracts/{cid}/dispute", json={
        "argument": "Agent failed", "side": "principal",
    })

    # Manually expire the deadline by patching the transcript
    transcript = store.get(cid)["transcript"]
    for msg in transcript:
        if msg.get("type") == "dispute_filed":
            msg["response_deadline"] = time.time() - 1  # expired
    store.db.execute(
        "UPDATE contracts SET transcript = ? WHERE id = ?",
        (__import__("json").dumps(transcript), cid),
    )
    store.db.commit()

    # Re-call dispute -- should trigger in absentia ruling
    resp = client.post(f"/contracts/{cid}/dispute", json={
        "argument": "Agent failed", "side": "principal",
    })
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
    client.post(f"/contracts/{cid}/dispute", json={
        "argument": "bad agent", "side": "principal",
    })

    resp = client.get(f"/contracts/{cid}/dispute_status")
    body = resp.json()
    assert body["status"] == "awaiting_response"
    assert body["filer"] == "principal"
    assert body["court"] == "district"


def test_platform_fee_in_resolution():
    """Platform fee is included in every escrow resolution."""
    from server.escrow import Escrow
    escrow = Escrow("1.0", {"judge_fee": "0.026"})
    escrow.lock()
    result = escrow.resolve("fulfilled")
    assert "platform_fee_per_side" in result
    assert result["platform_fee_per_side"] == "0.001"
