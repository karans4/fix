# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Karan Sharma
"""HTTP API for the fix platform (FastAPI).

Endpoints for contract lifecycle: post, browse, accept, investigate,
submit fix, verify, dispute, chat, bond, review, and reputation queries.

Ed25519 authentication: every mutating request must be signed.
Every transcript entry is a signed chain entry forming a tamper-evident log.

Two execution modes:
- supervised: principal stays connected, real-time verification
- autonomous: agent works independently, fix enters review window
"""

import sys
import os
import time
# Ensure parent directory is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import asyncio
import json as json_mod
from decimal import Decimal
from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from starlette.responses import StreamingResponse
from pydantic import BaseModel
from typing import Optional

from server.store import ContractStore
from server.escrow import EscrowManager
from server.nano import validate_nano_address
from server.judge import AIJudge, TieredCourt, Evidence, JudgeRuling
from crypto import (
    verify_request_ed25519, hash_chain_init, hash_chain_append,
    generate_ed25519_keypair, load_ed25519_key, save_ed25519_key,
    ed25519_privkey_to_pubkey, pubkey_to_fix_id,
    build_chain_entry, chain_entry_hash, verify_chain, canonical_json,
    sha256_hash, fix_id_to_pubkey, ReplayGuard,
)
from protocol import (
    DEFAULT_REVIEW_WINDOW, DEFAULT_INVESTIGATION_RATE, DEFAULT_RULING_TIMEOUT,
    MODE_SUPERVISED, MODE_AUTONOMOUS, COURT_TIERS, MAX_DISPUTE_LEVEL,
    DISPUTE_RESPONSE_WINDOW, PLATFORM_FEE_RATE, PLATFORM_FEE_MIN, MINIMUM_BOUNTY,
    SERVER_ENTRY_TYPES, CONTRACT_PICKUP_TIMEOUT, DISPUTE_BOND,
    MIN_BOUNTY_EXCESS, CANCEL_FEE_RATE, DEFAULT_JUDGE_FEE,
)


# --- Request/Response models ---

class PostContractRequest(BaseModel):
    contract: dict
    principal_pubkey: str

class AcceptRequest(BaseModel):
    agent_pubkey: str

class BondRequest(BaseModel):
    agent_pubkey: str

class InvestigateRequest(BaseModel):
    command: str
    agent_pubkey: str

class InvestigationResultRequest(BaseModel):
    command: str
    output: str
    principal_pubkey: str  # required

class SubmitFixRequest(BaseModel):
    fix: str
    explanation: str = ""
    agent_pubkey: str  # required

class VerifyRequest(BaseModel):
    success: bool
    explanation: str = ""
    principal_pubkey: str  # required

class DisputeRequest(BaseModel):
    argument: str
    side: str = "principal"  # "principal" or "agent"
    pubkey: str  # required — must match side

class RespondRequest(BaseModel):
    argument: str
    side: str  # must be the OTHER side from the dispute filer
    pubkey: str  # required — must match side

class HaltRequest(BaseModel):
    reason: str
    principal_pubkey: str

class SetAccountsRequest(BaseModel):
    principal_account: str = ""
    agent_account: str = ""
    pubkey: str  # required — caller's pubkey for auth

class ChatMessage(BaseModel):
    message: str
    from_side: str  # "agent" or "principal"
    msg_type: str = "message"  # "ask", "answer", or "message"
    pubkey: str  # required — must match from_side party

class ReviewAction(BaseModel):
    action: str  # "accept" or "dispute"
    argument: str = ""  # required if action is "dispute"
    principal_pubkey: str  # required — must be the principal

class RulingResponse(BaseModel):
    outcome: str
    reasoning: str
    flags: list[str] = []


PLATFORM_URL = "https://fix.notruefireman.org"


def _validate_contract(contract: dict):
    """Validate contract fields. Raises HTTPException(400) on bad values.

    Inclusive bond model: bounty >= judge_fee + MIN_BOUNTY_EXCESS (0.19 XNO).
    """
    escrow = contract.get("escrow", {})
    if escrow.get("bounty") is not None:
        try:
            bounty = Decimal(str(escrow["bounty"]))
        except Exception:
            raise HTTPException(400, "Invalid bounty value")
        if bounty < Decimal(MINIMUM_BOUNTY):
            raise HTTPException(400, f"Bounty below minimum ({MINIMUM_BOUNTY} XNO = judge_fee + {MIN_BOUNTY_EXCESS})")

    # Validate judge fee covers court costs
    judge_info = contract.get("judge", {})
    if judge_info and judge_info.get("fee") is not None:
        try:
            jfee = Decimal(str(judge_info["fee"]))
            min_required = Decimal(DISPUTE_BOND)
            if jfee < min_required:
                raise HTTPException(400, f"Judge fee {jfee} below minimum required ({DISPUTE_BOND} XNO = sum of all court tier fees)")
        except (ValueError, TypeError):
            raise HTTPException(400, "Invalid judge fee value")

    execution = contract.get("execution", {})
    if "max_attempts" in execution:
        ma = execution["max_attempts"]
        if not isinstance(ma, int) or ma < 1 or ma > 50:
            raise HTTPException(400, "max_attempts must be between 1 and 50")
    if "review_window" in execution:
        rw = execution["review_window"]
        if not isinstance(rw, (int, float)) or rw < 60 or rw > 86400:
            raise HTTPException(400, "review_window must be between 60 and 86400 seconds")
    if "timeout" in execution:
        to = execution["timeout"]
        if not isinstance(to, (int, float)) or to < 30 or to > 3600:
            raise HTTPException(400, "timeout must be between 30 and 3600 seconds")


def _platform_review(contract: dict):
    """Review a contract at posting time. Reject spam/abuse.

    Returns True if accepted, raises HTTPException(400) to reject.
    """
    # Platform policy: extend with content moderation as needed

    # Reject suspiciously high bounties (likely test/spam)
    escrow = contract.get("escrow", {})
    if escrow.get("bounty"):
        try:
            bounty = Decimal(str(escrow["bounty"]))
            if bounty > Decimal("100"):
                raise HTTPException(400, "Bounty exceeds platform maximum (100 XNO)")
        except Exception as e:
            if isinstance(e, HTTPException):
                raise
            pass  # bounty validation handled elsewhere

    # Reject if task command is empty
    task = contract.get("task", {})
    if not task.get("command") or not str(task.get("command", "")).strip():
        raise HTTPException(400, "Task command cannot be empty")

    # Reject empty task (no description of work)
    if not task.get("type") and not task.get("error") and not task.get("command"):
        raise HTTPException(400, "Task is empty — nothing to fix")

    return True


def _check_party(data: dict, pubkey: str, role: str):
    """Verify caller is the expected party. Raises 403 if not."""
    stored = data.get(f"{role}_pubkey", "")
    if not stored or not pubkey:
        raise HTTPException(403, f"Missing {role} pubkey")
    if pubkey != stored:
        raise HTTPException(403, f"Not the {role} of this contract")


async def _verify_auth(request: Request, pubkey: str):
    """Verify Ed25519-signed request from a party.

    Requires X-Fix-Timestamp, X-Fix-Signature, and X-Fix-Pubkey headers.
    The signature covers: METHOD\nPATH\nTIMESTAMP\nBODY
    """
    timestamp = request.headers.get("X-Fix-Timestamp", "")
    signature = request.headers.get("X-Fix-Signature", "")
    pubkey_hex = request.headers.get("X-Fix-Pubkey", "")

    if not timestamp or not signature or not pubkey_hex:
        return False

    body = (await request.body()).decode("utf-8", errors="replace")
    ok, err = verify_request_ed25519(
        request.method, request.url.path, body,
        timestamp, signature, pubkey_hex,
    )
    if not ok:
        raise HTTPException(401, f"Authentication failed: {err}")

    # Replay protection
    replay_guard = getattr(request.app.state, "replay_guard", None)
    if replay_guard and not replay_guard.check_and_record(signature):
        raise HTTPException(401, "Replay detected")

    # Verify the pubkey in headers matches the claimed identity
    expected_hex = _pubkey_str_to_hex(pubkey)
    if expected_hex and pubkey_hex != expected_hex:
        raise HTTPException(401, "Pubkey mismatch: header pubkey does not match request body pubkey")

    return True


def _pubkey_str_to_hex(pubkey: str) -> str:
    """Convert a fix_id (fix_<hex>) or raw hex pubkey to raw hex."""
    if pubkey.startswith("fix_"):
        return pubkey[4:]
    return pubkey


def _require_auth(authenticated: bool):
    """Raise 401 if request was not authenticated."""
    if not authenticated:
        raise HTTPException(401, "Signed request required (X-Fix-Timestamp + X-Fix-Signature + X-Fix-Pubkey headers)")


def build_briefing(contract_id: str, data: dict) -> str:
    """The contract document. Everything a stranger needs to do the job."""
    c = data.get("contract", {})
    task = c.get("task", {})
    env = c.get("environment", {})
    caps = c.get("capabilities", {})
    ex = c.get("execution", {})
    escrow = c.get("escrow", {})
    terms = c.get("terms", {})
    verification = c.get("verification", [])

    available = [k for k, v in caps.items() if v.get("available")]
    unavailable = [k for k, v in caps.items() if not v.get("available")]

    verify_parts = []
    for v in verification:
        m = v.get("method", "?")
        if m == "exit_code":
            verify_parts.append(f"re-run the original command, exit 0 = success")
        elif m == "principal_verification":
            verify_parts.append("principal verifies the result")
        elif m == "output_match":
            verify_parts.append(f"output must contain \"{v.get('pattern', '')}\"")
        else:
            verify_parts.append(m)

    B = PLATFORM_URL
    I = contract_id

    error_lines = "\n".join("      " + l for l in task.get("error", "").splitlines())
    verify_str = "; ".join(verify_parts) or "re-run the original command, exit 0 = success"

    bounty = escrow.get("bounty", "0") if escrow else "0"
    cur = escrow.get("currency", "XNO") if escrow else "XNO"
    judge_info = terms.get("judge", {})
    judge_name = judge_info.get("pubkey", "") or "platform AI judge"
    judge_fee = judge_info.get("fee", DEFAULT_JUDGE_FEE) if judge_info else DEFAULT_JUDGE_FEE
    cancel = terms.get("cancellation", {})
    grace_period = cancel.get("grace_period", 30) if cancel else 30
    max_attempts = ex.get("max_attempts", 5)
    inv_rounds = ex.get("investigation_rounds", 5)
    inv_rate = ex.get("investigation_rate", 5)
    timeout_s = ex.get("timeout", 300)
    sandbox = "Yes (OverlayFS). Changes only committed if verification passes." if ex.get("sandbox") else "No."

    # Inclusive bond model
    try:
        inclusive_bond = str(Decimal(bounty) + Decimal(judge_fee))
    except Exception:
        inclusive_bond = bounty

    return f"""SERVICE CONTRACT
================

Contract ID:  {I}
Platform:     {B}
Status:       {data.get('status', '?')}

PARTIES

  Principal:  The party who posted this contract.
  Agent:      The party who accepts and performs the work.
  Judge:      {judge_name}

1. SCOPE OF WORK

  The Principal's command failed:

    $ {task.get('command', '?')}
{error_lines}

  Environment: {env.get('os', '?')} {env.get('arch', '?')}
  Package managers: {', '.join(env.get('package_managers', [])) or 'none'}
  Available tools: {', '.join(available) or 'none'}
  Unavailable: {', '.join(unavailable) or 'none'}
  Sandbox: {sandbox}

  The Agent shall cause the above command to succeed on the
  Principal's machine.

2. CONSIDERATION (INCLUSIVE BOND MODEL)

  Bounty (contract value): {bounty} {cur}
  Judge fee (dispute insurance): {judge_fee} {cur}
  Inclusive bond (per side): {inclusive_bond} {cur}

  Both parties deposit the same amount ({inclusive_bond} {cur}).
  Total in escrow: {inclusive_bond} x 2 = {str(Decimal(inclusive_bond) * 2)} {cur}.

  Platform fee: 10% of excess bond (bounty - judge fee) on all
  completed contracts.
  Cancellation fee: 20% of excess bond if either side backs out
  post-grace (split 10% reimbursement + 10% platform).

3. AGENT OPTIONS

  Upon receiving this contract, the Agent may:

  a. Decline immediately. No bond required, no penalty.
  b. Post inclusive bond ({inclusive_bond} {cur}) and investigate.
     The Agent may run up to {inv_rounds} read-only commands on
     the Principal's machine to assess the problem.
     Rate limit: one command per {inv_rate} seconds.
  c. Decline after investigating. Bond returned in full,
     no penalty. Contract reopens for another agent.
  d. Accept. The Agent commits to fixing the problem.

  The Agent is not obligated to accept at any point. Bonding
  is required only to investigate; declining is always free.

4. INVESTIGATION RULES

  Commands run on the Principal's machine via the client. The
  Principal's client enforces a whitelist. Allowed commands:

    File inspection:  cat, head, tail, less, file, wc, stat,
                      md5sum, sha256sum
    Directory:        ls, find, tree, du
    Search:           grep, rg, ag
    Versions/info:    which, whereis, type, uname, arch,
                      lsb_release, hostnamectl
    Package queries:  dpkg, apt, apt-cache, rpm, pacman, pip,
                      pip3, npm, gem, cargo, rustc
    Runtimes:         gcc, g++, make, cmake, clang, clang++
    Environment:      echo, id, whoami, pwd
    System info:      lscpu, free, df, mount, ps
    Misc:             readlink, realpath, basename, dirname,
                      diff, cmp, strings, nm, ldd, objdump,
                      pkg-config, test, timeout

  Blocked: shell metacharacters (| ; & $ ` ( )), write
  redirects (>), append (>>), tee, and any command not on
  the whitelist. If a root directory is set, all paths must
  resolve inside it.

5. PERFORMANCE

  The Agent shall submit a shell command ("the fix") to be
  executed on the Principal's machine. The fix command is NOT
  restricted to the investigation whitelist; it may run any
  command needed to solve the problem.

  The Agent is allowed {max_attempts} attempt(s). If an attempt
  fails verification, the Agent is informed of the reason and
  may submit a different fix.

  Total time limit: {timeout_s} seconds from acceptance.

6. VERIFICATION

  {verify_str}

7. REMEDIES

  a. Success: bounty ({bounty} {cur}) released to Agent minus
     platform fee (10% of excess bond). Agent's bond returned.
     Principal's judge fee returned.
  b. Failure (all {max_attempts} attempts exhausted): contract
     canceled, bounty returned to Principal minus platform fee.
  c. Cancellation within {grace_period}s: no penalty, both
     sides get everything back.
  d. Late cancellation: 20% of excess bond deducted from
     canceler. 10% reimburses counterparty, 10% to platform.
  e. Dispute: three-tier court system. Loser pays tier fee
     from their judge fee portion:

       District court:  {COURT_TIERS[0]['fee']} {cur}
       Appeals court:   {COURT_TIERS[1]['fee']} {cur}
       Supreme court:   {COURT_TIERS[2]['fee']} {cur}  (FINAL)

     Winner's bond and judge fee returned in full.
     Loser gets (judge_fee - tier_fee) back.
     Evil ruling: loser's bounty portion goes to charity.
  f. Judge timeout: contract voided, everything returned.

8. COMMUNICATION

  Either party may send messages at any time during the
  contract via the chat endpoint.

EXHIBIT A: PLATFORM API

  Base URL: {B}
  All requests and responses are JSON.

  GET  /contracts/{I}
    Read contract state, transcript, and investigation results.

  POST /contracts/{I}/bond
    Body: {{"agent_pubkey": "<your_id>"}}
    Post bond to begin investigation.

  POST /contracts/{I}/investigate
    Body: {{"command": "<shell command>", "agent_pubkey": "<your_id>"}}
    Request a command be run on the Principal's machine.
    Results appear in the transcript (type: "result").

  POST /contracts/{I}/accept
    Body: {{"agent_pubkey": "<your_id>"}}
    Accept the contract. Commits you to performing the work.

  POST /contracts/{I}/decline
    Body: {{}}
    Decline. Bond returned if bonded, contract reopens.

  POST /contracts/{I}/fix
    Body: {{"fix": "<shell command>", "explanation": "<why>"}}
    Submit your fix to be run on the Principal's machine.

  POST /contracts/{I}/chat
    Body: {{"message": "<text>", "from_side": "agent"}}
    Send a message to the Principal.

  POST /contracts/{I}/verify
    Body: {{"success": true/false, "explanation": "<reason>"}}
    (Principal only) Report verification result.

  POST /contracts/{I}/dispute
    Body: {{"argument": "<your case>", "side": "agent"}}
    Escalate to judge. First call -> district court. Subsequent
    calls by the losing party -> appeals -> supreme (final).
    Response includes: outcome, court, level, can_appeal, next_court."""


# --- App factory ---

def create_app(
    store: ContractStore | None = None,
    escrow_mgr: EscrowManager | None = None,
    judge: AIJudge | None = None,
    court: TieredCourt | None = None,
    server_privkey: bytes | None = None,
) -> FastAPI:
    """Create FastAPI app with injected dependencies.

    If server_privkey is not provided, checks FIX_SERVER_KEY env var
    (path to key file) or auto-generates one.
    """

    app = FastAPI(title="Fix Platform", version="3.0")

    # Static file serving
    static_dir = os.path.join(os.path.dirname(__file__), "static")
    if os.path.isdir(static_dir):
        app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/")
    async def index():
        return FileResponse(os.path.join(static_dir, "index.html"))

    # Server identity -- persistent key required for chain verification across restarts
    if server_privkey:
        _server_privkey = server_privkey
    else:
        key_path = os.environ.get("FIX_SERVER_KEY", "")
        if key_path and os.path.exists(key_path):
            _server_privkey = load_ed25519_key(key_path)
        else:
            # Auto-generate and persist so chain entries remain verifiable
            _server_privkey, _ = generate_ed25519_keypair()
            default_key_path = os.path.expanduser("~/.fix/server.key")
            try:
                os.makedirs(os.path.dirname(default_key_path), exist_ok=True)
                save_ed25519_key(default_key_path, _server_privkey)
            except OSError:
                pass  # best effort -- test environments may not have writable home

    _server_pubkey = ed25519_privkey_to_pubkey(_server_privkey)
    _server_fix_id = pubkey_to_fix_id(_server_pubkey)

    # Replay protection -- SQLite-backed for persistence across restarts
    _replay_db = os.environ.get("FIX_REPLAY_DB", "")
    _replay_guard = ReplayGuard(db_path=_replay_db)

    # Defaults
    _store = store or ContractStore()
    _escrow = escrow_mgr or EscrowManager()
    _judge = judge  # Legacy single-judge (still works for basic disputes)
    _court = court  # Tiered court system (preferred)

    # --- SSE event bus for agent subscriptions ---
    # Use threading.Queue for cross-thread safety (TestClient uses threads)
    import queue as _queue_mod
    MAX_SSE_SUBSCRIBERS = 1000
    _sse_subscribers: list[_queue_mod.Queue] = []
    _sse_lock = __import__('threading').Lock()

    def _sse_publish(event_type: str, data: dict):
        """Push an event to all connected SSE subscribers."""
        payload = {"event": event_type, **data}
        with _sse_lock:
            dead = []
            for q in _sse_subscribers:
                try:
                    q.put_nowait(payload)
                except _queue_mod.Full:
                    dead.append(q)
            for q in dead:
                _sse_subscribers.remove(q)

    # Expose for testing
    app.state.replay_guard = _replay_guard
    app.state.store = _store
    app.state.escrow = _escrow
    app.state.judge = _judge
    app.state.court = _court
    app.state.server_privkey = _server_privkey
    app.state.server_pubkey = _server_pubkey
    app.state.server_fix_id = _server_fix_id
    app.state.sse_publish = _sse_publish

    # --- Helpers ---

    def _server_sign_and_append(contract_id: str, entry_type: str, data: dict) -> dict:
        """Build a server-signed chain entry and append it to the transcript."""
        head = _store.get_chain_head(contract_id)
        if head is None:
            head = hash_chain_init()

        contract_data = _store.get(contract_id)
        seq = len(contract_data["transcript"]) if contract_data else 0

        entry = build_chain_entry(
            entry_type=entry_type,
            data=data,
            seq=seq,
            author=_server_fix_id,
            prev_hash=head,
            privkey_bytes=_server_privkey,
        )

        ok, err = _store.append_chain_entry(contract_id, entry)
        if not ok:
            raise HTTPException(500, f"Chain append failed: {err}")
        return entry

    def _check_review_expiry(data: dict) -> dict | None:
        """Check if review window has expired. Auto-fulfill if so. Returns updated data or None."""
        if data["status"] != "review":
            return None
        expires = data.get("review_expires_at")
        if expires and time.time() >= expires:
            _store.update_status(data["id"], "fulfilled")
            _server_sign_and_append(data["id"], "auto_fulfill", {})
            # Resolve escrow
            escrow = _escrow.get(data["id"])
            if escrow and not escrow["resolved"]:
                _escrow.resolve(data["id"], "fulfilled")
            return _store.get(data["id"])
        return None

    def _compute_hash_chain(transcript: list[dict]) -> str:
        """Compute hash chain from transcript for evidence integrity."""
        import json as _json
        chain = hash_chain_init()
        for msg in transcript:
            chain = hash_chain_append(chain, _json.dumps(msg, sort_keys=True))
        return chain

    def _verify_transcript_chain(transcript: list[dict]) -> bool:
        """Check if transcript entries form a valid signed chain."""
        # Only verify entries that have signatures (chain entries)
        chain_entries = [e for e in transcript if "signature" in e]
        if not chain_entries:
            return True  # No chain entries yet (legacy or empty)
        ok, _ = verify_chain(chain_entries)
        return ok

    # --- Contract lifecycle ---

    @app.get("/server_pubkey")
    async def get_server_pubkey():
        """Get the server's Ed25519 public key so clients can verify server-signed entries."""
        return {"pubkey": _server_pubkey.hex(), "fix_id": _server_fix_id}

    @app.post("/contracts")
    async def post_contract(req: PostContractRequest, request: Request):
        """Post a new contract and lock escrow. Principal's bond locked upfront."""
        authenticated = await _verify_auth(request, req.principal_pubkey)
        _require_auth(authenticated)

        contract = req.contract
        _validate_contract(contract)
        _platform_review(contract)

        # Enforce minimum bounty
        escrow_data = contract.get("escrow", {})
        if escrow_data.get("bounty"):
            bounty = Decimal(escrow_data["bounty"])
            if bounty < Decimal(MINIMUM_BOUNTY):
                raise HTTPException(400, f"Bounty {bounty} below minimum {MINIMUM_BOUNTY} XNO")

        contract_id = _store.create(contract, req.principal_pubkey, server_pubkey=_server_pubkey.hex())

        # Lock escrow if contract has escrow terms
        escrow_data = contract.get("escrow", {})
        if escrow_data.get("bounty"):
            terms = contract.get("terms", {})
            terms["cancellation"] = terms.get("cancellation", {})
            # Pass judge fee if specified
            judge_info = contract.get("judge", {})
            judge_fee = str(judge_info.get("fee", ""))
            if judge_fee:
                terms["judge_fee"] = judge_fee
            _escrow.lock(contract_id, escrow_data["bounty"], terms,
                        judge_fee=judge_fee)

        # Notify SSE subscribers
        task = contract.get("task", {})
        terms = contract.get("terms", {})
        _sse_publish("contract_posted", {
            "contract_id": contract_id,
            "status": "open",
            "bounty": escrow_data.get("bounty", "0"),
            "command": task.get("command", ""),
        })

        return {"contract_id": contract_id, "status": "open", "server_pubkey": _server_pubkey.hex()}

    @app.get("/contracts")
    async def list_contracts(status: str = "open", limit: int = 50):
        limit = min(limit, 200)  # cap to prevent DB dump
        """List contracts by status (agents browse open ones).

        Lazy timeout: open contracts older than CONTRACT_PICKUP_TIMEOUT with
        no agent activity are auto-canceled on read.
        """
        contracts = _store.list_by_status(status, limit)
        result = []
        now = time.time()
        canceled_count = 0
        MAX_AUTO_CANCEL = 10
        for c in contracts:
            # Auto-cancel stale open contracts (lazy evaluation)
            if c["status"] == "open" and c.get("created_at"):
                age = now - c["created_at"]
                if age > CONTRACT_PICKUP_TIMEOUT:
                    if canceled_count >= MAX_AUTO_CANCEL:
                        continue  # skip, will be caught on next request
                    try:
                        _store.update_status(c["id"], "canceled")
                        _server_sign_and_append(c["id"], "auto_fulfill", {
                            "reason": "No agent accepted within timeout",
                        })
                        # Resolve escrow if present
                        escrow = _escrow.get(c["id"])
                        if escrow and not escrow["resolved"]:
                            _escrow.resolve(c["id"], "canceled")
                        c = _store.get(c["id"])
                        canceled_count += 1
                    except (ValueError, Exception):
                        pass  # already transitioned or other issue
            c["briefing"] = build_briefing(c["id"], c)
            result.append(c)
        return {"contracts": result}

    @app.get("/contracts/stream")
    async def stream_contracts(
        min_bounty: str = "0",
        status: str = "",
    ):
        """SSE stream for agent subscriptions.

        Pushes events when contracts are created, accepted, updated, or resolved.
        Optional filters: min_bounty (XNO), status (only forward events for this status).

        Usage:
            curl -N http://localhost:8000/contracts/stream?min_bounty=0.1

        Events:
            data: {"event": "contract_posted", "contract_id": "...", "bounty": "0.5", ...}
            data: {"event": "contract_accepted", "contract_id": "...", "agent": "..."}
            data: {"event": "contract_resolved", "contract_id": "...", "outcome": "fulfilled"}
        """
        min_b = Decimal(min_bounty)
        q = _queue_mod.Queue(maxsize=256)
        with _sse_lock:
            if len(_sse_subscribers) >= MAX_SSE_SUBSCRIBERS:
                raise HTTPException(503, "Too many SSE subscribers")
            _sse_subscribers.append(q)

        async def event_generator():
            try:
                while True:
                    try:
                        event = q.get(timeout=15.0)
                        # Apply filters
                        if min_b > 0:
                            event_bounty = Decimal(event.get("bounty", "0"))
                            if event_bounty < min_b:
                                continue
                        if status and event.get("status", "") != status:
                            continue
                        yield f"data: {json_mod.dumps(event)}\n\n"
                    except _queue_mod.Empty:
                        yield ": keepalive\n\n"
            finally:
                with _sse_lock:
                    if q in _sse_subscribers:
                        _sse_subscribers.remove(q)

        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    @app.get("/contracts/{contract_id}")
    async def get_contract(contract_id: str):
        """Get contract details + transcript + briefing."""
        data = _store.get(contract_id)
        if not data:
            raise HTTPException(404, "Contract not found")
        # Check review expiry on access
        updated = _check_review_expiry(data)
        result = updated or data
        result["briefing"] = build_briefing(contract_id, result)

        return result

    @app.get("/contracts/{contract_id}/chain_head")
    async def get_chain_head(contract_id: str):
        """Get current chain head for building next entry."""
        head = _store.get_chain_head(contract_id)
        if head is None:
            raise HTTPException(404, "Contract not found")
        data = _store.get(contract_id)
        seq = len(data["transcript"]) if data else 0
        return {"chain_head": head, "seq": seq}

    @app.post("/contracts/{contract_id}/bond")
    async def post_bond(contract_id: str, req: BondRequest, request: Request):
        """Agent deposits inclusive bond to start investigating. OPEN -> INVESTIGATING.

        Inclusive bond = bounty + judge_fee. Both sides pay the same amount.
        """
        authed = await _verify_auth(request, req.agent_pubkey)
        _require_auth(authed)

        data = _store.get(contract_id)
        if not data:
            raise HTTPException(404, "Contract not found")
        if data["status"] != "open":
            raise HTTPException(409, "Contract not available")

        # Lock agent's inclusive bond
        try:
            bond_result = _escrow.lock_agent(contract_id)
        except ValueError:
            bond_result = {"status": "no_escrow"}

        # Assign agent (without transitioning to in_progress yet)
        with _store._lock:
            now = time.time()
            cursor = _store.db.execute(
                "UPDATE contracts SET agent_pubkey = ?, status = 'investigating', updated_at = ? WHERE id = ? AND status = 'open'",
                (req.agent_pubkey, now, contract_id),
            )
            _store.db.commit()
            if cursor.rowcount == 0:
                # Race condition: another agent got it first, undo escrow lock
                try:
                    _escrow.release_agent(contract_id)
                except ValueError:
                    pass
                raise HTTPException(409, "Contract already taken by another agent")

        _server_sign_and_append(contract_id, "bond", {
            "agent_pubkey": req.agent_pubkey,
        })

        return {"status": "investigating", "bond": bond_result}

    @app.post("/contracts/{contract_id}/accept")
    async def accept_contract(contract_id: str, req: AcceptRequest, request: Request):
        """Agent accepts a contract. From INVESTIGATING (bonded) or OPEN (legacy)."""
        authed = await _verify_auth(request, req.agent_pubkey)
        _require_auth(authed)

        data = _store.get(contract_id)
        if not data:
            raise HTTPException(404, "Contract not found")
        if req.agent_pubkey == data.get("principal_pubkey"):
            raise HTTPException(403, "Cannot accept your own contract")

        if data["status"] == "investigating":
            # Verify the caller is the agent who bonded
            _check_party(data, req.agent_pubkey, "agent")
            _store.update_status(contract_id, "in_progress")
        elif data["status"] == "open":
            # Legacy flow: direct accept without bond
            ok = _store.assign_agent(contract_id, req.agent_pubkey, from_status="open")
            if not ok:
                raise HTTPException(409, "Could not assign agent")
        else:
            raise HTTPException(409, "Contract not available for acceptance")

        _server_sign_and_append(contract_id, "accept", {
            "agent_pubkey": req.agent_pubkey,
        })
        _sse_publish("contract_accepted", {
            "contract_id": contract_id,
            "status": "in_progress",
            "agent": req.agent_pubkey,
        })
        return {"status": "in_progress"}

    class DeclineRequest(BaseModel):
        agent_pubkey: str

    @app.post("/contracts/{contract_id}/decline")
    async def decline_investigation(contract_id: str, req: DeclineRequest, request: Request):
        """Agent declines after investigating. Bond returned, contract reopens."""
        authed = await _verify_auth(request, req.agent_pubkey)
        _require_auth(authed)

        data = _store.get(contract_id)
        if not data:
            raise HTTPException(404, "Contract not found")
        if data["status"] != "investigating":
            raise HTTPException(409, "Contract not in investigating state")

        # Verify the caller is the investigating agent
        _check_party(data, req.agent_pubkey, "agent")

        # Release agent's inclusive bond
        try:
            _escrow.release_agent(contract_id)
        except ValueError:
            pass

        # Reopen: clear agent, set back to open
        with _store._lock:
            now = time.time()
            _store.db.execute(
                "UPDATE contracts SET agent_pubkey = NULL, status = 'open', updated_at = ? WHERE id = ?",
                (now, contract_id),
            )
            _store.db.commit()

        _server_sign_and_append(contract_id, "decline", {})

        return {"status": "open"}

    @app.post("/contracts/{contract_id}/investigate")
    async def request_investigation(contract_id: str, req: InvestigateRequest, request: Request):
        """Agent requests an investigation command. Rate-limited."""
        authed = await _verify_auth(request, req.agent_pubkey)
        _require_auth(authed)

        data = _store.get(contract_id)
        if not data:
            raise HTTPException(404, "Contract not found")
        if data["status"] not in ("in_progress", "investigating"):
            raise HTTPException(409, "Contract not in progress")
        # Verify caller is the agent
        _check_party(data, req.agent_pubkey, "agent")

        # Rate limiting
        rate_limit = data["contract"].get("execution", {}).get(
            "investigation_rate", DEFAULT_INVESTIGATION_RATE
        )
        last_ts = data.get("last_investigation_at")
        now = time.time()
        if last_ts and (now - last_ts) < rate_limit:
            wait = rate_limit - (now - last_ts)
            raise HTTPException(429, f"Rate limited. Wait {wait:.1f}s")

        _store.set_last_investigation(contract_id, now)
        _server_sign_and_append(contract_id, "investigate", {
            "command": req.command,
            "from": "agent",
        })
        return {"status": "pending_result", "command": req.command}

    @app.post("/contracts/{contract_id}/result")
    async def submit_investigation_result(contract_id: str, req: InvestigationResultRequest, request: Request):
        """Principal returns investigation result."""
        authed = await _verify_auth(request, req.principal_pubkey)
        _require_auth(authed)

        data = _store.get(contract_id)
        if not data:
            raise HTTPException(404, "Contract not found")
        _check_party(data, req.principal_pubkey, "principal")

        _server_sign_and_append(contract_id, "result", {
            "command": req.command,
            "output": req.output,
            "from": "principal",
        })
        return {"status": "ok"}

    @app.post("/contracts/{contract_id}/chat")
    async def chat(contract_id: str, req: ChatMessage, request: Request):
        """Send a chat message. Works in any state except voided/canceled."""
        authed = await _verify_auth(request, req.pubkey)
        _require_auth(authed)

        data = _store.get(contract_id)
        if not data:
            raise HTTPException(404, "Contract not found")
        if data["status"] in ("voided", "canceled"):
            raise HTTPException(409, "Chat not available")
        if req.msg_type not in ("ask", "answer", "message"):
            raise HTTPException(400, "Invalid msg_type")

        # Validate msg_type against role
        ALLOWED_MSG_TYPES = {
            "principal": {"message", "answer"},
            "agent": {"message", "ask"},
        }
        allowed = ALLOWED_MSG_TYPES.get(req.from_side, set())
        if req.msg_type not in allowed:
            raise HTTPException(400, f"msg_type '{req.msg_type}' not allowed for {req.from_side}")

        # Verify caller matches the side they claim
        _check_party(data, req.pubkey, req.from_side)

        _server_sign_and_append(contract_id, req.msg_type, {
            "message": req.message,
            "from": req.from_side,
        })
        return {"status": "sent"}

    @app.post("/contracts/{contract_id}/fix")
    async def submit_fix(contract_id: str, req: SubmitFixRequest, request: Request):
        """Agent submits a fix. In autonomous mode, enters review state."""
        authed = await _verify_auth(request, req.agent_pubkey)
        _require_auth(authed)

        data = _store.get(contract_id)
        if not data:
            raise HTTPException(404, "Contract not found")
        _check_party(data, req.agent_pubkey, "agent")
        if data["status"] != "in_progress":
            raise HTTPException(409, "Contract not in progress")
        if not req.fix or not req.fix.strip():
            raise HTTPException(400, "Fix cannot be empty")

        _server_sign_and_append(contract_id, "fix", {
            "fix": req.fix,
            "explanation": req.explanation,
            "from": "agent",
        })

        mode = data.get("execution_mode", MODE_SUPERVISED)
        if mode == MODE_AUTONOMOUS:
            # Enter review state with expiry window
            review_window = data["contract"].get("execution", {}).get(
                "review_window", DEFAULT_REVIEW_WINDOW
            )
            expires_at = time.time() + review_window
            _store.update_status(contract_id, "review")
            _store.set_review_expires(contract_id, expires_at)
            return {"status": "review", "review_expires_at": expires_at}
        else:
            return {"status": "pending_verification"}

    @app.post("/contracts/{contract_id}/verify")
    async def verify_fix(contract_id: str, req: VerifyRequest, request: Request):
        """Principal reports verification result (supervised mode)."""
        authed = await _verify_auth(request, req.principal_pubkey)
        _require_auth(authed)

        data = _store.get(contract_id)
        if not data:
            raise HTTPException(404, "Contract not found")
        _check_party(data, req.principal_pubkey, "principal")
        if data["status"] != "in_progress":
            raise HTTPException(409, "Contract not in progress")
        # Must have a fix submitted before verification
        transcript = data.get("transcript", [])
        has_fix = any(m.get("type") == "fix" for m in transcript)
        if not has_fix:
            raise HTTPException(409, "No fix submitted yet")

        _server_sign_and_append(contract_id, "verify", {
            "success": req.success,
            "explanation": req.explanation,
            "from": "principal",
        })

        if req.success:
            _store.update_status(contract_id, "fulfilled")
            ruling = "fulfilled"
        else:
            # Check if retries remain
            contract = data.get("contract", {})
            max_attempts = contract.get("execution", {}).get("max_attempts", 3)
            transcript = data.get("transcript", [])
            attempts_so_far = sum(1 for m in transcript if m.get("type") == "verify" and not m.get("data", {}).get("success", m.get("success")))
            # +1 for this verify we just appended
            attempts_so_far += 1

            if attempts_so_far < max_attempts:
                # Stay in_progress -- agent should retry
                ruling = "retry"
            else:
                _store.update_status(contract_id, "canceled")
                ruling = "canceled"

        if ruling != "retry":
            # Resolve escrow
            escrow = _escrow.get(contract_id)
            if escrow and not escrow["resolved"]:
                _escrow.resolve(contract_id, ruling)

        _sse_publish("contract_resolved", {
            "contract_id": contract_id,
            "status": ruling,
            "bounty": data["contract"].get("escrow", {}).get("bounty", "0"),
        })
        return {"status": ruling}

    @app.post("/contracts/{contract_id}/review")
    async def review_action(contract_id: str, req: ReviewAction, request: Request):
        """Principal acts during review window: accept or dispute."""
        authed = await _verify_auth(request, req.principal_pubkey)
        _require_auth(authed)

        data = _store.get(contract_id)
        if not data:
            raise HTTPException(404, "Contract not found")
        _check_party(data, req.principal_pubkey, "principal")

        # Check auto-fulfill first
        updated = _check_review_expiry(data)
        if updated:
            return {"status": "fulfilled", "detail": "review window expired, auto-fulfilled"}

        if data["status"] != "review":
            raise HTTPException(409, f"Contract is {data['status']}, not in review")

        if req.action == "accept":
            _store.update_status(contract_id, "fulfilled")
            _server_sign_and_append(contract_id, "review_accept", {})
            # Resolve escrow
            escrow = _escrow.get(contract_id)
            if escrow and not escrow["resolved"]:
                _escrow.resolve(contract_id, "fulfilled")
            return {"status": "fulfilled"}

        elif req.action == "dispute":
            if not req.argument:
                raise HTTPException(400, "Dispute requires an argument")
            # Delegate to dispute endpoint logic
            _store.update_status(contract_id, "disputed")
            _server_sign_and_append(contract_id, "dispute_filed", {
                "argument": req.argument,
                "side": "principal",
            })

            if not _judge:
                raise HTTPException(501, "No judge configured")

            transcript = _store.get(contract_id)["transcript"]
            chain_valid = _verify_transcript_chain(transcript)

            evidence = Evidence(
                contract=data["contract"],
                messages=transcript,
                hash_chain=_compute_hash_chain(transcript),
                arguments={"principal": req.argument},
                chain_valid=chain_valid,
            )

            ruling = await _judge.rule(evidence)

            _store.update_status(contract_id, "resolved")
            _server_sign_and_append(contract_id, "ruling", {
                "outcome": ruling.outcome,
                "reasoning": ruling.reasoning,
                "flags": ruling.flags,
            })

            # Determine dispute loser for bond routing
            if ruling.outcome in ("fulfilled", "evil_principal"):
                dispute_loser = "principal"
                escrow_ruling = "fulfilled" if ruling.outcome == "fulfilled" else "fulfilled"
            else:
                dispute_loser = "agent"
                escrow_ruling = "canceled"

            escrow = _escrow.get(contract_id)
            if escrow and not escrow["resolved"]:
                _escrow.resolve(contract_id, escrow_ruling, flags=ruling.flags,
                              dispute_loser=dispute_loser, tier_fee=COURT_TIERS[0]["fee"])

            return {"outcome": ruling.outcome, "reasoning": ruling.reasoning, "flags": ruling.flags}

        else:
            raise HTTPException(400, f"Invalid review action: {req.action}")

    @app.get("/contracts/{contract_id}/review_status")
    async def review_status(contract_id: str):
        """Get time remaining in review window."""
        data = _store.get(contract_id)
        if not data:
            raise HTTPException(404, "Contract not found")

        # Check auto-fulfill
        updated = _check_review_expiry(data)
        if updated:
            return {"status": "fulfilled", "remaining": 0}

        if data["status"] != "review":
            return {"status": data["status"], "remaining": 0}

        expires = data.get("review_expires_at")
        if not expires:
            return {"status": "review", "remaining": 0}

        remaining = max(0, expires - time.time())
        return {"status": "review", "remaining": remaining, "expires_at": expires}

    async def _execute_ruling(contract_id: str, data: dict, arguments: dict,
                              prior_rulings: list, level: int) -> dict:
        """Run the judge and apply the ruling. Shared by dispute and respond endpoints."""
        if not _court and not _judge:
            raise HTTPException(501, "No judge configured")

        court_name = COURT_TIERS[min(level, MAX_DISPUTE_LEVEL)]["name"]

        transcript = data["transcript"]
        chain_valid = _verify_transcript_chain(transcript)

        evidence = Evidence(
            contract=data["contract"],
            messages=transcript,
            hash_chain=_compute_hash_chain(transcript),
            arguments=arguments,
            prior_rulings=[r for r in prior_rulings],
            chain_valid=chain_valid,
        )

        if _court:
            ruling = await _court.rule(evidence, level=level)
            can_appeal = level < MAX_DISPUTE_LEVEL
        else:
            ruling = await _judge.rule(evidence)
            ruling.court = court_name
            ruling.level = level
            ruling.final = True
            can_appeal = False

        if ruling.final or not can_appeal:
            _store.update_status(contract_id, "resolved")
        else:
            _store.update_status(contract_id, "in_progress")

        _server_sign_and_append(contract_id, "ruling", {
            "outcome": ruling.outcome,
            "reasoning": ruling.reasoning,
            "court": ruling.court,
            "level": ruling.level,
            "final": ruling.final,
            "flags": ruling.flags,
        })

        # Resolve escrow on final ruling
        if ruling.final or not can_appeal:
            if ruling.outcome in ("fulfilled", "evil_principal"):
                dispute_loser = "principal"
                escrow_ruling = "fulfilled"
            elif ruling.outcome in ("evil_agent", "evil_both"):
                dispute_loser = "agent"
                escrow_ruling = "canceled"
            else:
                dispute_loser = "agent"
                escrow_ruling = ruling.outcome if ruling.outcome in ("canceled", "impossible") else "canceled"

            escrow = _escrow.get(contract_id)
            if escrow and not escrow["resolved"]:
                tier_fee = COURT_TIERS[min(level, MAX_DISPUTE_LEVEL)]["fee"]
                _escrow.resolve(contract_id, escrow_ruling, flags=ruling.flags,
                              dispute_loser=dispute_loser, tier_fee=tier_fee)

        return {
            "outcome": ruling.outcome,
            "reasoning": ruling.reasoning,
            "court": ruling.court,
            "level": ruling.level,
            "final": ruling.final,
            "can_appeal": can_appeal and not ruling.final,
            "next_court": COURT_TIERS[level + 1]["name"] if can_appeal and not ruling.final else None,
            "next_fee": COURT_TIERS[level + 1]["fee"] if can_appeal and not ruling.final else None,
            "flags": ruling.flags,
        }

    @app.post("/contracts/{contract_id}/dispute")
    async def dispute_contract(contract_id: str, req: DisputeRequest, request: Request):
        """File a dispute. Two-phase: file -> other side has 30s to respond -> judge rules."""
        authed = await _verify_auth(request, req.pubkey)
        _require_auth(authed)

        data = _store.get(contract_id)
        if not data:
            raise HTTPException(404, "Contract not found")

        if data["status"] not in ("in_progress", "review", "awaiting_response", "disputed"):
            raise HTTPException(409, "Cannot dispute in current state")

        # Free-mode check: no judge configured means no disputes
        judge_info = data.get("contract", {}).get("judge", {})
        judge_pubkey = judge_info.get("pubkey", "") if judge_info else ""
        if not judge_pubkey:
            raise HTTPException(400, "Disputes not available: no judge configured for this contract. This is a free-mode contract.")

        # Verify caller matches the side they claim
        _check_party(data, req.pubkey, req.side)

        # Check for pending dispute awaiting response
        transcript = data.get("transcript", [])
        pending_filed = None
        for msg in reversed(transcript):
            msg_type = msg.get("type", "")
            # Chain entries have type in top level, data in "data" subdict
            if msg_type == "ruling":
                break
            if msg_type == "dispute_filed":
                pending_filed = msg
                break

        if pending_filed:
            # Get data from either top-level (legacy) or data subdict (chain entry)
            pf_data = pending_filed.get("data", pending_filed)
            deadline = pf_data.get("response_deadline", 0)
            if time.time() >= deadline:
                # Response window expired -- trigger ruling in absentia
                prior_rulings = [m for m in transcript if m.get("type") == "ruling"]
                level = pf_data.get("level", 0)
                arguments = {pf_data["side"]: pf_data["argument"]}
                return await _execute_ruling(contract_id, _store.get(contract_id),
                                             arguments, prior_rulings, level)
            else:
                remaining = round(deadline - time.time(), 1)
                raise HTTPException(409, f"Dispute already filed. Awaiting response ({remaining}s remaining). "
                                    f"POST /contracts/{contract_id}/respond to counter-argue.")

        prior_rulings = [m for m in data.get("transcript", []) if m.get("type") == "ruling"]
        level = len(prior_rulings)

        if level > MAX_DISPUTE_LEVEL:
            raise HTTPException(409, "Supreme court has already ruled. No further appeals.")

        # For appeals: only the loser can appeal
        if level > 0:
            last_ruling = prior_rulings[-1]
            last_data = last_ruling.get("data", last_ruling)
            last_outcome = last_data.get("outcome", "")
            if last_outcome in ("fulfilled", "evil_principal"):
                loser = "principal"
            else:
                loser = "agent"
            if req.side != loser:
                raise HTTPException(409, f"Only the losing party ({loser}) can appeal")

        court_name = COURT_TIERS[min(level, MAX_DISPUTE_LEVEL)]["name"]
        fee = COURT_TIERS[min(level, MAX_DISPUTE_LEVEL)]["fee"]
        other_side = "agent" if req.side == "principal" else "principal"
        deadline = time.time() + DISPUTE_RESPONSE_WINDOW

        _store.update_status(contract_id, "disputed")
        _server_sign_and_append(contract_id, "dispute_filed", {
            "argument": req.argument,
            "side": req.side,
            "level": level,
            "court": court_name,
            "fee": fee,
            "response_deadline": deadline,
        })

        return {
            "status": "awaiting_response",
            "court": court_name,
            "level": level,
            "fee": fee,
            "response_deadline": deadline,
            "response_window": DISPUTE_RESPONSE_WINDOW,
            "message": f"Dispute filed at {court_name} court. "
                       f"The {other_side} has {DISPUTE_RESPONSE_WINDOW}s to respond. "
                       f"POST /contracts/{contract_id}/respond or ruling proceeds in absentia.",
        }

    @app.post("/contracts/{contract_id}/respond")
    async def respond_to_dispute(contract_id: str, req: RespondRequest, request: Request):
        """Counter-argue a pending dispute. Must be the other side, within the response window."""
        authed = await _verify_auth(request, req.pubkey)
        _require_auth(authed)

        data = _store.get(contract_id)
        if not data:
            raise HTTPException(404, "Contract not found")

        # Verify caller matches claimed side
        _check_party(data, req.pubkey, req.side)

        # Find the pending dispute (must not have a ruling after it)
        transcript = data.get("transcript", [])
        last_filed = None
        for msg in reversed(transcript):
            if msg.get("type") == "ruling":
                break
            if msg.get("type") == "dispute_filed":
                last_filed = msg
                break

        if not last_filed:
            raise HTTPException(409, "No pending dispute to respond to")

        lf_data = last_filed.get("data", last_filed)
        filer_side = lf_data["side"]

        # Must be the other side
        if req.side == filer_side:
            raise HTTPException(400, f"You filed the dispute. Only the {('agent' if filer_side == 'principal' else 'principal')} can respond.")

        # Check deadline
        deadline = lf_data.get("response_deadline", 0)
        if time.time() > deadline:
            raise HTTPException(410, "Response window has expired. Ruling will proceed in absentia.")

        # Record response
        _server_sign_and_append(contract_id, "dispute_response", {
            "argument": req.argument,
            "side": req.side,
        })

        # Both sides heard -- trigger ruling immediately
        prior_rulings = [m for m in data.get("transcript", []) if m.get("type") == "ruling"]
        level = lf_data.get("level", 0)
        arguments = {
            filer_side: lf_data["argument"],
            req.side: req.argument,
        }

        return await _execute_ruling(contract_id, _store.get(contract_id),
                                     arguments, prior_rulings, level)

    @app.get("/contracts/{contract_id}/dispute_status")
    async def dispute_status(contract_id: str):
        """Check status of a pending dispute (response window, etc.)."""
        data = _store.get(contract_id)
        if not data:
            raise HTTPException(404, "Contract not found")

        pending = [m for m in data.get("transcript", []) if m.get("type") == "dispute_filed"]
        if not pending:
            return {"status": "no_pending_dispute"}

        last_filed = pending[-1]
        lf_data = last_filed.get("data", last_filed)
        deadline = lf_data.get("response_deadline", 0)
        remaining = max(0, deadline - time.time())

        # Check if response was already submitted
        responses = [m for m in data.get("transcript", []) if m.get("type") == "dispute_response"]
        responded = len(responses) > len(pending) - 1  # rough check

        return {
            "status": "awaiting_response" if remaining > 0 and not responded else "ready_for_ruling",
            "filer": lf_data.get("side", lf_data.get("data", {}).get("side")),
            "court": lf_data.get("court"),
            "level": lf_data.get("level"),
            "response_deadline": deadline,
            "remaining": round(remaining, 1),
            "responded": responded,
        }

    class VoidRequest(BaseModel):
        pubkey: str  # must be a party to the contract

    @app.post("/contracts/{contract_id}/void")
    async def void_contract(contract_id: str, req: VoidRequest, request: Request):
        """Void a disputed contract (judge timeout). All funds returned."""
        authed = await _verify_auth(request, req.pubkey)
        _require_auth(authed)

        data = _store.get(contract_id)
        if not data:
            raise HTTPException(404, "Contract not found")

        # Must be a party to the contract
        is_principal = data.get("principal_pubkey") == req.pubkey
        is_agent = data.get("agent_pubkey") == req.pubkey
        if not is_principal and not is_agent:
            raise HTTPException(403, "Not a party to this contract")

        if data["status"] != "disputed":
            raise HTTPException(409, "Contract not in disputed state")

        # Verify there is a pending dispute that has timed out
        transcript = data.get("transcript", [])
        dispute_filed_at = None
        for msg in reversed(transcript):
            msg_type = msg.get("type", "")
            if msg_type == "ruling":
                break  # a ruling exists after the last dispute — not pending
            if msg_type == "dispute_filed":
                msg_data = msg.get("data", msg)
                dispute_filed_at = msg_data.get("timestamp", msg.get("timestamp", 0))
                break
        if dispute_filed_at is None:
            raise HTTPException(409, "No pending dispute found")
        if time.time() - dispute_filed_at < DEFAULT_RULING_TIMEOUT:
            raise HTTPException(409, "Judge ruling timeout has not elapsed")

        _store.update_status(contract_id, "voided")
        _server_sign_and_append(contract_id, "voided", {"reason": "judge_timeout"})

        # Resolve escrow as voided -- everything returned
        escrow = _escrow.get(contract_id)
        if escrow and not escrow["resolved"]:
            _escrow.resolve(contract_id, "voided")

        return {"status": "voided"}

    @app.post("/contracts/{contract_id}/halt")
    async def halt_contract(contract_id: str, req: HaltRequest, request: Request):
        """Emergency halt by principal -- freeze contract and escalate to district court."""
        authed = await _verify_auth(request, req.principal_pubkey)
        _require_auth(authed)

        data = _store.get(contract_id)
        if not data:
            raise HTTPException(404, "Contract not found")
        _check_party(data, req.principal_pubkey, "principal")
        if data["status"] not in ("in_progress", "review"):
            raise HTTPException(409, "Contract not in progress or review")

        _store.update_status(contract_id, "halted")
        _server_sign_and_append(contract_id, "halt", {
            "reason": req.reason,
            "from": "principal",
        })

        ruling_resp = None

        if _court or _judge:
            # Immediate district court ruling (no response window for emergencies)
            transcript = _store.get(contract_id)["transcript"]
            chain_valid = _verify_transcript_chain(transcript)

            evidence = Evidence(
                contract=data["contract"],
                messages=transcript,
                hash_chain=_compute_hash_chain(transcript),
                arguments={"principal": req.reason},
                chain_valid=chain_valid,
            )
            if _court:
                ruling = await _court.rule(evidence, level=0)
                can_appeal = True  # halt rulings are non-final, can be appealed
            else:
                ruling = await _judge.rule(evidence)
                can_appeal = False

            # Non-final: set to in_progress so loser can appeal via /dispute
            if can_appeal:
                _store.update_status(contract_id, "in_progress")
            else:
                _store.update_status(contract_id, "resolved")

            _server_sign_and_append(contract_id, "ruling", {
                "outcome": ruling.outcome,
                "reasoning": ruling.reasoning,
                "court": ruling.court if hasattr(ruling, 'court') else "district",
                "level": 0,
                "final": not can_appeal,
                "flags": ruling.flags,
            })

            # Only resolve escrow if final (legacy judge)
            if not can_appeal:
                if ruling.outcome in ("fulfilled", "evil_principal"):
                    dispute_loser = "principal"
                    escrow_ruling = "fulfilled"
                else:
                    dispute_loser = "agent"
                    escrow_ruling = "canceled"

                escrow = _escrow.get(contract_id)
                if escrow and not escrow["resolved"]:
                    _escrow.resolve(contract_id, escrow_ruling, flags=ruling.flags,
                                  dispute_loser=dispute_loser, tier_fee=COURT_TIERS[0]["fee"])

            ruling_resp = {
                "outcome": ruling.outcome,
                "reasoning": ruling.reasoning,
                "court": ruling.court if hasattr(ruling, 'court') else "district",
                "level": 0,
                "final": not can_appeal,
                "can_appeal": can_appeal,
                "flags": ruling.flags,
            }

        updated = _store.get(contract_id)
        return {
            "status": updated["status"] if updated else "halted",
            "ruling": ruling_resp,
        }

    @app.get("/contracts/{contract_id}/ruling")
    async def get_ruling(contract_id: str):
        """Get ruling for a contract (from transcript)."""
        data = _store.get(contract_id)
        if not data:
            raise HTTPException(404, "Contract not found")
        for msg in reversed(data["transcript"]):
            if msg.get("type") == "ruling":
                msg_data = msg.get("data", msg)
                return {"outcome": msg_data.get("outcome"), "reasoning": msg_data.get("reasoning"), "flags": msg_data.get("flags", [])}
        return None

    @app.get("/contracts/{contract_id}/verify_chain")
    async def verify_contract_chain(contract_id: str):
        """Verify the signed message chain for a contract."""
        data = _store.get(contract_id)
        if not data:
            raise HTTPException(404, "Contract not found")

        transcript = data["transcript"]
        chain_entries = [e for e in transcript if "signature" in e]

        if not chain_entries:
            return {"valid": True, "entries": 0, "detail": "No signed chain entries (legacy transcript)"}

        ok, err = verify_chain(chain_entries)
        return {
            "valid": ok,
            "entries": len(chain_entries),
            "total_transcript": len(transcript),
            "error": err if not ok else None,
            "chain_head": data.get("chain_head", ""),
        }

    @app.get("/reputation/{pubkey}")
    async def get_reputation(pubkey: str):
        """Bond-as-reputation: reputation is determined by on-chain Nano balance."""
        return {
            "pubkey": pubkey,
            "note": "Reputation is determined by on-chain balance. Check the Nano ledger directly for balance/history.",
        }

    @app.post("/contracts/{contract_id}/accounts")
    async def set_accounts(contract_id: str, req: SetAccountsRequest, request: Request):
        """Set payment accounts. Each party can only set their own account."""
        authed = await _verify_auth(request, req.pubkey)
        _require_auth(authed)

        data = _store.get(contract_id)
        if not data:
            raise HTTPException(404, "Contract not found")

        # Block account changes after escrow resolution
        escrow = _escrow.get(data["id"])
        if escrow and escrow.get("resolved"):
            raise HTTPException(409, "Cannot change accounts after escrow resolution")

        # Validate Nano addresses before anything else
        if req.principal_account:
            valid, err = validate_nano_address(req.principal_account)
            if not valid:
                raise HTTPException(400, f"Invalid principal Nano address: {err}")
        if req.agent_account:
            valid, err = validate_nano_address(req.agent_account)
            if not valid:
                raise HTTPException(400, f"Invalid agent Nano address: {err}")

        # Enforce: you can only set YOUR OWN account
        is_principal = data.get("principal_pubkey") == req.pubkey
        is_agent = data.get("agent_pubkey") == req.pubkey
        if not is_principal and not is_agent:
            raise HTTPException(403, "Not a party to this contract")
        if req.principal_account and not is_principal:
            raise HTTPException(403, "Cannot set principal account -- not the principal")
        if req.agent_account and not is_agent:
            raise HTTPException(403, "Cannot set agent account -- not the agent")

        ok = _escrow.set_accounts(contract_id, req.principal_account, req.agent_account)
        if not ok:
            raise HTTPException(404, "No escrow for this contract")
        return {"status": "ok"}

    @app.get("/contracts/{contract_id}/escrow")
    async def get_escrow(contract_id: str, request: Request):
        """Get escrow state. Requires auth -- only contract parties can see full data."""
        data = _escrow.get(contract_id)
        if not data:
            raise HTTPException(404, "No escrow for this contract")

        contract_data = _store.get(contract_id)
        # Try to authenticate
        pubkey_hex = request.headers.get("X-Fix-Pubkey", "")
        caller_id = "fix_" + pubkey_hex if pubkey_hex else ""
        authenticated = False
        if caller_id:
            try:
                authenticated = await _verify_auth(request, caller_id)
            except HTTPException:
                authenticated = False

        if not authenticated:
            # Unauthenticated: strip sensitive fields
            data = {k: v for k, v in data.items()
                    if k not in ("principal_account", "agent_account", "escrow_account")}
            return data

        # Authenticated: verify party membership
        if contract_data:
            principal = contract_data.get("principal_pubkey", "")
            agent = contract_data.get("agent_pubkey", "")
            if caller_id not in (principal, agent):
                raise HTTPException(403, "Not a party to this contract")

        return data

    @app.get("/stats")
    async def get_stats():
        open_contracts = len(_store.list_by_status("open"))
        in_progress = len(_store.list_by_status("in_progress"))
        fulfilled = len(_store.list_by_status("fulfilled"))
        return {
            "open_contracts": open_contracts,
            "in_progress": in_progress,
            "fulfilled": fulfilled,
            "total": open_contracts + in_progress + fulfilled,
        }

    @app.get("/platform_info")
    async def platform_info():
        """Advertised platform rates and minimums."""
        return {
            "model": "inclusive_bond",
            "min_bounty": MINIMUM_BOUNTY,
            "judge_fee": DEFAULT_JUDGE_FEE,
            "min_inclusive_bond": str(Decimal(MINIMUM_BOUNTY) + Decimal(DEFAULT_JUDGE_FEE)),
            "platform_fee_rate": str(PLATFORM_FEE_RATE),
            "platform_fee_min": str(PLATFORM_FEE_MIN),
            "cancel_fee_rate": str(CANCEL_FEE_RATE),
            "court_tiers": [
                {"name": t["name"], "fee": t["fee"]} for t in COURT_TIERS
            ],
            "currency": "XNO",
        }

    return app
