"""HTTP API for the fix platform (FastAPI).

Endpoints for contract lifecycle: post, browse, accept, investigate,
submit fix, verify, dispute, chat, bond, review, and reputation queries.

Two execution modes:
- supervised: principal stays connected, real-time verification
- autonomous: agent works independently, fix enters review window
"""

import sys
import os
import time
# Ensure parent directory is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from decimal import Decimal
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional

from server.store import ContractStore
from server.escrow import EscrowManager
from server.reputation import ReputationManager
from server.judge import AIJudge, Evidence, JudgeRuling
from protocol import (
    DEFAULT_REVIEW_WINDOW, DEFAULT_INVESTIGATION_RATE, DEFAULT_RULING_TIMEOUT,
    MODE_SUPERVISED, MODE_AUTONOMOUS,
)


# --- Request/Response models ---

class PostContractRequest(BaseModel):
    contract: dict
    principal_pubkey: str = ""

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

class SubmitFixRequest(BaseModel):
    fix: str
    explanation: str = ""
    agent_pubkey: str = ""

class VerifyRequest(BaseModel):
    success: bool
    explanation: str = ""

class DisputeRequest(BaseModel):
    argument: str
    side: str = "principal"  # "principal" or "agent"

class HaltRequest(BaseModel):
    reason: str
    principal_pubkey: str = ""

class SetAccountsRequest(BaseModel):
    principal_account: str = ""
    agent_account: str = ""

class ChatMessage(BaseModel):
    message: str
    from_side: str  # "agent" or "principal"
    msg_type: str = "message"  # "ask", "answer", or "message"

class ReviewAction(BaseModel):
    action: str  # "accept" or "dispute"
    argument: str = ""  # required if action is "dispute"

class RulingResponse(BaseModel):
    outcome: str
    reasoning: str
    flags: list[str] = []


PLATFORM_URL = "https://fix.notruefireman.org"


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
        elif m == "human_judgment":
            verify_parts.append("human judges the result")
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
    judge_name = terms.get("judge", {}).get("pubkey", "") or "platform AI judge"
    max_attempts = ex.get("max_attempts", 3)
    inv_rounds = ex.get("investigation_rounds", 5)
    inv_rate = ex.get("investigation_rate", 5)
    timeout_s = ex.get("timeout", 300)
    sandbox = "Yes (OverlayFS). Changes only committed if verification passes." if ex.get("sandbox") else "No."

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

2. CONSIDERATION

  Upon successful completion, the Principal shall pay the Agent
  {bounty} {cur}.

3. AGENT OPTIONS

  Upon receiving this contract, the Agent may:

  a. Decline immediately. No bond required, no penalty.
  b. Post bond and investigate. The Agent may run up to
     {inv_rounds} read-only commands on the Principal's machine
     to assess the problem before committing.
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
    Search:           grep, rg, ag, awk, sed
    Versions/info:    which, whereis, type, uname, arch,
                      lsb_release, hostnamectl
    Package queries:  dpkg, apt, apt-cache, rpm, pacman, pip,
                      pip3, npm, gem, cargo, rustc
    Runtimes:         python3, python, node, gcc, g++, make,
                      cmake, java, go, ruby, clang, clang++
    Environment:      env, printenv, echo, id, whoami, pwd
    System info:      lscpu, free, df, mount, ps
    Misc:             readlink, realpath, basename, dirname,
                      diff, cmp, strings, nm, ldd, objdump,
                      pkg-config, test, timeout

  Blocked: write redirects (>), append (>>), tee, and any
  command not on the whitelist. If a root directory is set,
  all paths must resolve inside it.

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

  a. Success: bounty released to Agent.
  b. Failure (all attempts exhausted): contract canceled,
     bounty returned to Principal.
  c. Dispute: either party may escalate to the Judge.
     Both parties have a dispute bond locked. The losing
     party's bond pays the Judge. The prevailing party's
     bond is returned.
  d. Judge timeout: contract voided, all funds returned
     to both parties.
  e. Cancellation: either party may cancel within the grace
     period at no cost. Late cancellation incurs a fee.

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
    Escalate to Judge."""


# --- App factory ---

def create_app(
    store: ContractStore | None = None,
    escrow_mgr: EscrowManager | None = None,
    reputation_mgr: ReputationManager | None = None,
    judge: AIJudge | None = None,
) -> FastAPI:
    """Create FastAPI app with injected dependencies."""

    app = FastAPI(title="Fix Platform", version="3.0")

    # Static file serving
    static_dir = os.path.join(os.path.dirname(__file__), "static")
    if os.path.isdir(static_dir):
        app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/")
    async def index():
        return FileResponse(os.path.join(static_dir, "index.html"))

    # Defaults
    _store = store or ContractStore()
    _escrow = escrow_mgr or EscrowManager()
    _reputation = reputation_mgr or ReputationManager()
    _judge = judge  # None is ok -- disputes just won't work without it

    # Expose for testing
    app.state.store = _store
    app.state.escrow = _escrow
    app.state.reputation = _reputation
    app.state.judge = _judge

    # --- Helpers ---

    def _check_review_expiry(data: dict) -> dict | None:
        """Check if review window has expired. Auto-fulfill if so. Returns updated data or None."""
        if data["status"] != "review":
            return None
        expires = data.get("review_expires_at")
        if expires and time.time() >= expires:
            _store.update_status(data["id"], "fulfilled")
            _store.append_message(data["id"], {
                "type": "auto_fulfill",
                "from": "system",
            })
            # Resolve escrow
            escrow = _escrow.get(data["id"])
            if escrow and not escrow["resolved"]:
                _escrow.resolve(data["id"], "fulfilled")
            # Reputation
            bounty = Decimal(data["contract"].get("escrow", {}).get("bounty", "0"))
            if data.get("agent_pubkey"):
                _reputation.record(data["agent_pubkey"], "agent", "fulfilled", bounty)
            if data.get("principal_pubkey"):
                _reputation.record(data["principal_pubkey"], "principal", "fulfilled", bounty)
            return _store.get(data["id"])
        return None

    # --- Contract lifecycle ---

    @app.post("/contracts")
    async def post_contract(req: PostContractRequest):
        """Post a new contract and lock escrow. Principal's bond locked upfront."""
        contract = req.contract
        contract_id = _store.create(contract, req.principal_pubkey)

        # Lock escrow if contract has escrow terms
        escrow_data = contract.get("escrow", {})
        if escrow_data.get("bounty"):
            terms = contract.get("terms", {})
            terms["cancellation"] = terms.get("cancellation", {})
            # Pass judge info
            judge_info = contract.get("judge", {})
            judge_account = judge_info.get("pubkey", "")
            judge_fee = str(judge_info.get("fee", ""))
            if judge_fee:
                terms["judge_fee"] = judge_fee
            _escrow.lock(contract_id, escrow_data["bounty"], terms,
                        judge_account=judge_account, judge_fee=judge_fee)

        return {"contract_id": contract_id, "status": "open"}

    @app.get("/contracts")
    async def list_contracts(status: str = "open", limit: int = 50):
        """List contracts by status (agents browse open ones)."""
        contracts = _store.list_by_status(status, limit)
        for c in contracts:
            c["briefing"] = build_briefing(c["id"], c)
        return {"contracts": contracts}

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

    @app.post("/contracts/{contract_id}/bond")
    async def post_bond(contract_id: str, req: BondRequest):
        """Agent posts dispute bond to start investigating. OPEN -> INVESTIGATING."""
        data = _store.get(contract_id)
        if not data:
            raise HTTPException(404, "Contract not found")
        if data["status"] != "open":
            raise HTTPException(409, f"Contract is {data['status']}, not open")

        # Lock agent bond
        try:
            bond_result = _escrow.lock_agent_bond(contract_id)
        except ValueError:
            bond_result = {"status": "no_escrow"}

        # Assign agent (without transitioning to in_progress yet)
        now = time.time()
        _store.db.execute(
            "UPDATE contracts SET agent_pubkey = ?, status = 'investigating', updated_at = ? WHERE id = ?",
            (req.agent_pubkey, now, contract_id),
        )
        _store.db.commit()

        _store.append_message(contract_id, {
            "type": "bond",
            "agent_pubkey": req.agent_pubkey,
            "from": "agent",
        })

        return {"status": "investigating", "bond": bond_result}

    @app.post("/contracts/{contract_id}/accept")
    async def accept_contract(contract_id: str, req: AcceptRequest):
        """Agent accepts a contract. From INVESTIGATING (bonded) or OPEN (legacy)."""
        data = _store.get(contract_id)
        if not data:
            raise HTTPException(404, "Contract not found")

        if data["status"] == "investigating":
            # Agent already bonded, transition to in_progress
            _store.update_status(contract_id, "in_progress")
        elif data["status"] == "open":
            # Legacy flow: direct accept without bond
            ok = _store.assign_agent(contract_id, req.agent_pubkey, from_status="open")
            if not ok:
                raise HTTPException(409, "Could not assign agent")
        else:
            raise HTTPException(409, f"Contract is {data['status']}, expected investigating or open")

        _store.append_message(contract_id, {
            "type": "accept",
            "agent_pubkey": req.agent_pubkey,
        })
        return {"status": "in_progress"}

    @app.post("/contracts/{contract_id}/decline")
    async def decline_investigation(contract_id: str):
        """Agent declines after investigating. Bond returned, contract reopens."""
        data = _store.get(contract_id)
        if not data:
            raise HTTPException(404, "Contract not found")
        if data["status"] != "investigating":
            raise HTTPException(409, f"Contract is {data['status']}, not investigating")

        # Release agent bond
        try:
            _escrow.release_agent_bond(contract_id)
        except ValueError:
            pass

        # Reopen: clear agent, set back to open
        now = time.time()
        _store.db.execute(
            "UPDATE contracts SET agent_pubkey = NULL, status = 'open', updated_at = ? WHERE id = ?",
            (now, contract_id),
        )
        _store.db.commit()

        _store.append_message(contract_id, {
            "type": "decline",
            "from": "agent",
        })

        return {"status": "open"}

    @app.post("/contracts/{contract_id}/investigate")
    async def request_investigation(contract_id: str, req: InvestigateRequest):
        """Agent requests an investigation command. Rate-limited."""
        data = _store.get(contract_id)
        if not data:
            raise HTTPException(404, "Contract not found")
        if data["status"] not in ("in_progress", "investigating"):
            raise HTTPException(409, f"Contract is {data['status']}")

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
        _store.append_message(contract_id, {
            "type": "investigate",
            "command": req.command,
            "from": "agent",
        })
        return {"status": "pending_result", "command": req.command}

    @app.post("/contracts/{contract_id}/result")
    async def submit_investigation_result(contract_id: str, req: InvestigationResultRequest):
        """Principal returns investigation result."""
        data = _store.get(contract_id)
        if not data:
            raise HTTPException(404, "Contract not found")

        _store.append_message(contract_id, {
            "type": "result",
            "command": req.command,
            "output": req.output,
            "from": "principal",
        })
        return {"status": "ok"}

    @app.post("/contracts/{contract_id}/chat")
    async def chat(contract_id: str, req: ChatMessage):
        """Send a chat message. Works in any active state (investigating/in_progress/review)."""
        data = _store.get(contract_id)
        if not data:
            raise HTTPException(404, "Contract not found")
        if data["status"] not in ("investigating", "in_progress", "review"):
            raise HTTPException(409, f"Contract is {data['status']}, chat not available")
        if req.msg_type not in ("ask", "answer", "message"):
            raise HTTPException(400, f"Invalid msg_type: {req.msg_type}")

        _store.append_message(contract_id, {
            "type": req.msg_type,
            "message": req.message,
            "from": req.from_side,
        })
        return {"status": "sent"}

    @app.post("/contracts/{contract_id}/fix")
    async def submit_fix(contract_id: str, req: SubmitFixRequest):
        """Agent submits a fix. In autonomous mode, enters review state."""
        data = _store.get(contract_id)
        if not data:
            raise HTTPException(404, "Contract not found")
        if data["status"] != "in_progress":
            raise HTTPException(409, f"Contract is {data['status']}")

        _store.append_message(contract_id, {
            "type": "fix",
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
    async def verify_fix(contract_id: str, req: VerifyRequest):
        """Principal reports verification result (supervised mode)."""
        data = _store.get(contract_id)
        if not data:
            raise HTTPException(404, "Contract not found")

        _store.append_message(contract_id, {
            "type": "verify",
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
            attempts_so_far = sum(1 for m in transcript if m.get("type") == "verify" and not m.get("success"))
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

            # Record reputation
            updated = _store.get(contract_id)
            if updated:
                bounty = Decimal(data["contract"].get("escrow", {}).get("bounty", "0"))
                if updated.get("agent_pubkey"):
                    _reputation.record(updated["agent_pubkey"], "agent", ruling, bounty)
                if updated.get("principal_pubkey"):
                    _reputation.record(updated["principal_pubkey"], "principal", ruling, bounty)

        return {"status": ruling}

    @app.post("/contracts/{contract_id}/review")
    async def review_action(contract_id: str, req: ReviewAction):
        """Principal acts during review window: accept or dispute."""
        data = _store.get(contract_id)
        if not data:
            raise HTTPException(404, "Contract not found")

        # Check auto-fulfill first
        updated = _check_review_expiry(data)
        if updated:
            return {"status": "fulfilled", "detail": "review window expired, auto-fulfilled"}

        if data["status"] != "review":
            raise HTTPException(409, f"Contract is {data['status']}, not in review")

        if req.action == "accept":
            _store.update_status(contract_id, "fulfilled")
            _store.append_message(contract_id, {
                "type": "review_accept",
                "from": "principal",
            })
            # Resolve escrow
            escrow = _escrow.get(contract_id)
            if escrow and not escrow["resolved"]:
                _escrow.resolve(contract_id, "fulfilled")
            # Reputation
            bounty = Decimal(data["contract"].get("escrow", {}).get("bounty", "0"))
            if data.get("agent_pubkey"):
                _reputation.record(data["agent_pubkey"], "agent", "fulfilled", bounty)
            if data.get("principal_pubkey"):
                _reputation.record(data["principal_pubkey"], "principal", "fulfilled", bounty)
            return {"status": "fulfilled"}

        elif req.action == "dispute":
            if not req.argument:
                raise HTTPException(400, "Dispute requires an argument")
            # Delegate to dispute endpoint logic
            _store.update_status(contract_id, "disputed")
            _store.append_message(contract_id, {
                "type": "dispute",
                "argument": req.argument,
                "side": "principal",
            })

            if not _judge:
                raise HTTPException(501, "No judge configured")

            evidence = Evidence(
                contract=data["contract"],
                messages=data["transcript"],
                hash_chain="",
                arguments={"principal": req.argument},
            )

            # Check judge timeout
            ruling_timeout = data["contract"].get("judge", {}).get(
                "ruling_timeout", DEFAULT_RULING_TIMEOUT
            )
            ruling = await _judge.rule(evidence)

            _store.update_status(contract_id, "resolved")
            _store.append_message(contract_id, {
                "type": "ruling",
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
                              dispute_loser=dispute_loser)

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

    @app.post("/contracts/{contract_id}/dispute")
    async def dispute_contract(contract_id: str, req: DisputeRequest):
        """Escalate to judge. Bond loser pays judge fee."""
        data = _store.get(contract_id)
        if not data:
            raise HTTPException(404, "Contract not found")

        _store.update_status(contract_id, "disputed")
        _store.append_message(contract_id, {
            "type": "dispute",
            "argument": req.argument,
            "side": req.side,
        })

        if not _judge:
            raise HTTPException(501, "No judge configured")

        # Build evidence
        evidence = Evidence(
            contract=data["contract"],
            messages=data["transcript"],
            hash_chain="",
            arguments={req.side: req.argument},
        )

        ruling = await _judge.rule(evidence)

        _store.update_status(contract_id, "resolved")
        _store.append_message(contract_id, {
            "type": "ruling",
            "outcome": ruling.outcome,
            "reasoning": ruling.reasoning,
            "flags": ruling.flags,
        })

        # Determine dispute loser for bond routing
        if ruling.outcome in ("fulfilled", "evil_principal"):
            dispute_loser = "principal"
            escrow_ruling = "fulfilled" if ruling.outcome == "fulfilled" else "fulfilled"
        elif ruling.outcome in ("evil_agent", "evil_both"):
            dispute_loser = "agent"
            escrow_ruling = "canceled"
        else:
            dispute_loser = "agent"
            escrow_ruling = ruling.outcome if ruling.outcome in ("canceled", "impossible") else "canceled"

        escrow = _escrow.get(contract_id)
        if escrow and not escrow["resolved"]:
            _escrow.resolve(contract_id, escrow_ruling, flags=ruling.flags,
                          dispute_loser=dispute_loser)

        # Reputation
        bounty = Decimal(data["contract"].get("escrow", {}).get("bounty", "0"))
        if data.get("agent_pubkey"):
            agent_outcome = "fulfilled" if ruling.outcome == "fulfilled" else "canceled"
            _reputation.record(data["agent_pubkey"], "agent", agent_outcome, bounty)
            if "evil_agent" in ruling.flags:
                _reputation.record(data["agent_pubkey"], "agent", "evil_flag")
        if data.get("principal_pubkey"):
            principal_outcome = "fulfilled" if ruling.outcome == "fulfilled" else "canceled"
            _reputation.record(data["principal_pubkey"], "principal", principal_outcome, bounty)
            if "evil_principal" in ruling.flags:
                _reputation.record(data["principal_pubkey"], "principal", "evil_flag")

        return {"outcome": ruling.outcome, "reasoning": ruling.reasoning, "flags": ruling.flags}

    @app.post("/contracts/{contract_id}/void")
    async def void_contract(contract_id: str):
        """Void a disputed contract (judge timeout). All funds returned."""
        data = _store.get(contract_id)
        if not data:
            raise HTTPException(404, "Contract not found")
        if data["status"] != "disputed":
            raise HTTPException(409, f"Contract is {data['status']}, not disputed")

        _store.update_status(contract_id, "voided")
        _store.append_message(contract_id, {
            "type": "voided",
            "reason": "judge_timeout",
            "from": "system",
        })

        # Resolve escrow as voided -- everything returned
        escrow = _escrow.get(contract_id)
        if escrow and not escrow["resolved"]:
            _escrow.resolve(contract_id, "voided")

        return {"status": "voided"}

    @app.post("/contracts/{contract_id}/halt")
    async def halt_contract(contract_id: str, req: HaltRequest):
        """Emergency halt by principal -- freeze escrow and escalate."""
        data = _store.get(contract_id)
        if not data:
            raise HTTPException(404, "Contract not found")
        if data["status"] not in ("in_progress", "review"):
            raise HTTPException(409, f"Contract is {data['status']}, not in_progress or review")

        _store.update_status(contract_id, "halted")
        _store.append_message(contract_id, {
            "type": "halt",
            "reason": req.reason,
            "from": "principal",
        })

        ruling_resp = None

        if _judge:
            # Immediately escalate to judge
            evidence = Evidence(
                contract=data["contract"],
                messages=data["transcript"],
                hash_chain="",
                arguments={"principal": req.reason},
            )
            ruling = await _judge.rule(evidence)

            _store.update_status(contract_id, "resolved")
            _store.append_message(contract_id, {
                "type": "ruling",
                "outcome": ruling.outcome,
                "reasoning": ruling.reasoning,
                "flags": ruling.flags,
            })

            # Resolve escrow based on ruling
            if ruling.outcome in ("fulfilled", "evil_principal"):
                dispute_loser = "principal"
                escrow_ruling = "fulfilled"
            else:
                dispute_loser = "agent"
                escrow_ruling = "canceled"

            escrow = _escrow.get(contract_id)
            if escrow and not escrow["resolved"]:
                _escrow.resolve(contract_id, escrow_ruling, flags=ruling.flags,
                              dispute_loser=dispute_loser)

            ruling_resp = {
                "outcome": ruling.outcome,
                "reasoning": ruling.reasoning,
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
                return {"outcome": msg["outcome"], "reasoning": msg["reasoning"], "flags": msg.get("flags", [])}
        return None

    @app.get("/reputation/{pubkey}")
    async def get_reputation(pubkey: str):
        """Get reputation stats for a pubkey."""
        stats = _reputation.query(pubkey)
        return stats.to_dict()

    @app.post("/contracts/{contract_id}/accounts")
    async def set_accounts(contract_id: str, req: SetAccountsRequest):
        ok = _escrow.set_accounts(contract_id, req.principal_account, req.agent_account)
        if not ok:
            raise HTTPException(404, "No escrow for this contract")
        return {"status": "ok"}

    @app.get("/contracts/{contract_id}/escrow")
    async def get_escrow(contract_id: str):
        data = _escrow.get(contract_id)
        if not data:
            raise HTTPException(404, "No escrow for this contract")
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

    return app
