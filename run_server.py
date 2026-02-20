#!/usr/bin/env python3
"""Fix platform server with free judge + free agent.

API key from FIX_API_KEY env var (never in code).
"""

import os, sys, json, asyncio, time, threading
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import httpx
import uvicorn
from server.app import create_app
from server.store import ContractStore
from server.escrow import EscrowManager
from server.reputation import ReputationManager
from server.judge import AIJudge

API_KEY = os.environ.get("FIX_API_KEY", "")
MODEL = os.environ.get("FIX_MODEL", "claude-haiku-4-5-20251001")
AGENT_MODEL = os.environ.get("FIX_AGENT_MODEL", "claude-haiku-4-5-20251001")
DB_PATH = os.environ.get("FIX_DB", "/var/lib/fix/fix.db")
PORT = int(os.environ.get("FIX_PORT", "8000"))

if not API_KEY:
    print("FIX_API_KEY env var required", file=sys.stderr)
    sys.exit(1)


# --- Claude call for judge ---
async def judge_llm_call(system_prompt, user_prompt):
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": API_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": MODEL,
                "max_tokens": 1024,
                "system": system_prompt,
                "messages": [{"role": "user", "content": user_prompt}],
            },
            timeout=30,
        )
        return resp.json()["content"][0]["text"]


# --- Free agent: polls for open contracts, fixes them ---
def agent_llm_call(prompt):
    resp = httpx.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": API_KEY,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json={
            "model": AGENT_MODEL,
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": prompt}],
        },
        timeout=60,
    )
    return resp.json()["content"][0]["text"]


def run_free_agent(store, escrow_mgr):
    """Background thread: poll for open contracts, accept and fix them."""
    AGENT_KEY = "platform_free_agent"
    POLL_INTERVAL = 3

    while True:
        time.sleep(POLL_INTERVAL)
        try:
            contracts = store.list_by_status("open", limit=1)
            if not contracts:
                continue

            c = contracts[0]
            cid = c["id"]
            contract = c["contract"]
            task = contract.get("task", {})

            print(f"[agent] Picking up {cid}: {task.get('command', task.get('task', '?'))}")

            # Bond if escrow exists
            try:
                escrow_mgr.lock_agent_bond(cid)
                store.db.execute(
                    "UPDATE contracts SET agent_pubkey = ?, status = 'investigating', updated_at = ? WHERE id = ? AND status = 'open'",
                    (AGENT_KEY, time.time(), cid),
                )
                store.db.commit()
                store.append_message(cid, {"type": "bond", "agent_pubkey": AGENT_KEY, "from": "agent"})
            except Exception:
                # No escrow, direct accept
                pass

            # Accept
            data = store.get(cid)
            if data and data["status"] == "investigating":
                store.update_status(cid, "in_progress")
            elif data and data["status"] == "open":
                store.assign_agent(cid, AGENT_KEY)
            else:
                continue
            store.append_message(cid, {"type": "accept", "agent_pubkey": AGENT_KEY})

            # Build prompt
            error = task.get("error", "")
            command = task.get("command", "")
            env = contract.get("environment", {})

            prompt = f"""A command failed. Propose a fix as a JSON object.

COMMAND: {command}
ERROR: {error}
OS: {env.get('os', '?')} {env.get('arch', '?')}
Package managers: {', '.join(env.get('package_managers', []))}

Respond with JSON only (no markdown):
{{"accepted": true, "fix": "shell command(s)", "explanation": "why"}}"""

            raw = agent_llm_call(prompt)

            # Parse
            text = raw.strip()
            if text.startswith("```"):
                text = "\n".join(text.split("\n")[1:])
                if text.endswith("```"):
                    text = text[:-3]
                text = text.strip()
            start = text.find("{")
            end = text.rfind("}") + 1
            if start >= 0 and end > start:
                text = text[start:end]

            result = json.loads(text)
            fix_cmd = result.get("fix", "")
            explanation = result.get("explanation", "")

            store.append_message(cid, {
                "type": "fix",
                "fix": fix_cmd,
                "explanation": explanation,
                "from": "agent",
            })

            # In autonomous mode, go to review; otherwise stay pending
            mode = data.get("execution_mode", "supervised")
            if mode == "autonomous":
                review_window = contract.get("execution", {}).get("review_window", 7200)
                store.update_status(cid, "review")
                store.set_review_expires(cid, time.time() + review_window)
            # supervised: principal verifies via API

            print(f"[agent] Fix for {cid}: {fix_cmd[:80]}")

        except Exception as e:
            print(f"[agent] Error: {e}")


# --- Main ---
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

store = ContractStore(DB_PATH)
escrow_mgr = EscrowManager(DB_PATH.replace(".db", "_escrow.db"))
reputation_mgr = ReputationManager(DB_PATH.replace(".db", "_rep.db"))
judge = AIJudge(model=MODEL, llm_call=judge_llm_call)

app = create_app(store=store, escrow_mgr=escrow_mgr, reputation_mgr=reputation_mgr, judge=judge)

# Start free agent in background
agent_thread = threading.Thread(target=run_free_agent, args=(store, escrow_mgr), daemon=True)
agent_thread.start()
print(f"[server] Free agent running (model: {AGENT_MODEL})")
print(f"[server] Judge active (model: {MODEL})")
print(f"[server] Listening on :{PORT}")

uvicorn.run(app, host="0.0.0.0", port=PORT)
