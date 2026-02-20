#!/usr/bin/env python3
"""Fix platform server with free judge + free agent.

API key from FIX_API_KEY env var (never in code).
"""

import os, sys, json, asyncio, time, threading
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import httpx
import uvicorn
from server.app import create_app, build_briefing
from server.store import ContractStore
from server.escrow import EscrowManager
from server.reputation import ReputationManager
from server.judge import AIJudge, TieredCourt

API_KEY = os.environ.get("FIX_API_KEY", "")
MODEL = os.environ.get("FIX_MODEL", "claude-haiku-4-5-20251001")
AGENT_MODEL = os.environ.get("FIX_AGENT_MODEL", "claude-haiku-4-5-20251001")
DB_PATH = os.environ.get("FIX_DB", "/var/lib/fix/fix.db")
PORT = int(os.environ.get("FIX_PORT", "8000"))

if not API_KEY:
    print("FIX_API_KEY env var required", file=sys.stderr)
    sys.exit(1)


# --- Claude call for judge (supports model override for tiered courts) ---
async def judge_llm_call(system_prompt, user_prompt, model=None):
    use_model = model or MODEL
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": API_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": use_model,
                "max_tokens": 1024,
                "system": system_prompt,
                "messages": [{"role": "user", "content": user_prompt}],
            },
            timeout=60,
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


def _parse_llm_json(raw):
    """Extract JSON from LLM response (strips markdown fences)."""
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
    return json.loads(text)


def run_free_agent(store, escrow_mgr):
    """Background thread: full contract lifecycle.

    1. Pick up open contracts, bond into INVESTIGATING
    2. Ask LLM what to investigate, post commands, wait for results
    3. Accept and propose fix with full context
    4. Handle retries on failure
    """
    AGENT_KEY = "platform_free_agent"
    POLL_INTERVAL = 3
    RESULT_WAIT = 30  # max seconds to wait for investigation result

    while True:
        time.sleep(POLL_INTERVAL)
        try:
            # --- Phase 1: Pick up new contracts, start investigating ---
            contracts = store.list_by_status("open", limit=1)
            if contracts:
                c = contracts[0]
                cid = c["id"]
                contract = c["contract"]
                task = contract.get("task", {})
                briefing = build_briefing(cid, c)

                print(f"[agent] Picking up {cid}: {task.get('command', task.get('task', '?'))}")

                # Bond → INVESTIGATING
                try:
                    escrow_mgr.lock_agent_bond(cid)
                except Exception:
                    pass
                store.db.execute(
                    "UPDATE contracts SET agent_pubkey = ?, status = 'investigating', updated_at = ? WHERE id = ? AND status = 'open'",
                    (AGENT_KEY, time.time(), cid),
                )
                store.db.commit()
                store.append_message(cid, {"type": "bond", "agent_pubkey": AGENT_KEY, "from": "agent"})

                # Ask LLM what to investigate
                inv_prompt = f"""You are a contract agent. Read this contract and decide what
commands to run on the principal's machine to investigate the problem.

{briefing}

You have up to {contract.get('execution', {}).get('investigation_rounds', 5)} investigation commands.
These run on the PRINCIPAL'S machine (where the error happened).
Use them to understand the problem: list files, read source code, check versions, etc.

Respond with JSON only (no markdown):
{{"commands": ["ls -la", "cat file.c", ...], "reasoning": "why these commands"}}

If the error is obvious and you don't need to investigate, respond:
{{"commands": [], "reasoning": "error is clear, no investigation needed"}}"""

                raw = agent_llm_call(inv_prompt)
                inv_result = _parse_llm_json(raw)
                inv_commands = inv_result.get("commands", [])
                reasoning = inv_result.get("reasoning", "")

                if reasoning:
                    print(f"[agent] Investigation plan for {cid}: {reasoning[:80]}")

                # Post investigation commands and wait for results
                inv_results = {}
                max_rounds = contract.get("execution", {}).get("investigation_rounds", 5)
                for cmd in inv_commands[:max_rounds]:
                    store.append_message(cid, {
                        "type": "investigate",
                        "command": cmd,
                        "from": "agent",
                    })
                    print(f"[agent] Investigating {cid}: {cmd}")

                    # Wait for principal to run it and post result
                    result_text = None
                    for _ in range(RESULT_WAIT):
                        time.sleep(1)
                        data = store.get(cid)
                        if not data:
                            break
                        transcript = data.get("transcript", [])
                        for msg in transcript:
                            if (msg.get("type") == "result"
                                    and msg.get("command") == cmd):
                                result_text = msg.get("output", "")
                                break
                        if result_text is not None:
                            break

                    if result_text is not None:
                        inv_results[cmd] = result_text
                        print(f"[agent] Result for '{cmd}': {result_text[:80]}")
                    else:
                        inv_results[cmd] = "(no response from principal)"
                        print(f"[agent] No response for '{cmd}', moving on")

                # Accept → IN_PROGRESS
                data = store.get(cid)
                if not data or data["status"] != "investigating":
                    continue
                store.update_status(cid, "in_progress")
                store.append_message(cid, {"type": "accept", "agent_pubkey": AGENT_KEY})

                # Build fix prompt with investigation context
                fix_prompt = f"""You are a contract agent. You investigated the problem and
now must propose a fix.

{briefing}

INVESTIGATION RESULTS:"""
                if inv_results:
                    for cmd, output in inv_results.items():
                        fix_prompt += f"\n\n$ {cmd}\n{output}"
                else:
                    fix_prompt += "\n(no investigation performed)"

                fix_prompt += f"""

Based on the contract and your investigation, propose a shell command
that will fix the problem. The fix runs on the principal's machine.

Respond with JSON only (no markdown):
{{"fix": "shell command(s) to fix the problem", "explanation": "why this fixes it"}}

If you cannot fix it, respond:
{{"fix": null, "explanation": "why it cannot be fixed"}}"""

                raw = agent_llm_call(fix_prompt)
                result = _parse_llm_json(raw)
                fix_cmd = result.get("fix", "")
                explanation = result.get("explanation", "")

                store.append_message(cid, {
                    "type": "fix",
                    "fix": fix_cmd,
                    "explanation": explanation,
                    "from": "agent",
                })

                mode = data.get("execution_mode", "supervised")
                if mode == "autonomous":
                    review_window = contract.get("execution", {}).get("review_window", 7200)
                    store.update_status(cid, "review")
                    store.set_review_expires(cid, time.time() + review_window)

                print(f"[agent] Fix for {cid}: {str(fix_cmd)[:80]}")
                continue

            # --- Phase 2: Handle retries for failed fixes ---
            in_progress = store.list_by_status("in_progress", limit=5)
            for c in in_progress:
                cid = c["id"]
                if c.get("agent_pubkey") != AGENT_KEY:
                    continue

                transcript = c.get("transcript", [])
                fixes = [m for m in transcript if m.get("type") == "fix"]
                failures = [m for m in transcript if m.get("type") == "verify" and not m.get("success")]

                # Need a new fix only if there are more failures than fixes
                if not failures or len(fixes) > len(failures):
                    continue

                contract = c.get("contract", {})
                briefing = build_briefing(cid, c)
                max_attempts = contract.get("execution", {}).get("max_attempts", 3)
                if len(failures) >= max_attempts:
                    continue

                # Collect investigation results from transcript
                inv_results = {}
                for msg in transcript:
                    if msg.get("type") == "result":
                        inv_results[msg.get("command", "?")] = msg.get("output", "")

                # Build retry prompt
                retry_prompt = f"""You are a contract agent. Your previous fix(es) failed.
Read the contract and try again.

{briefing}

INVESTIGATION RESULTS:"""
                if inv_results:
                    for cmd, output in inv_results.items():
                        retry_prompt += f"\n\n$ {cmd}\n{output}"
                else:
                    retry_prompt += "\n(no investigation was performed)"

                retry_prompt += "\n\nPREVIOUS ATTEMPTS (do NOT repeat these):"
                for i, f in enumerate(fixes, 1):
                    # Find matching failure
                    reason = "verification failed"
                    if i <= len(failures) and failures[i-1].get("explanation"):
                        reason = failures[i-1]["explanation"]
                    retry_prompt += f"\n  Attempt {i}: {f.get('fix', '?')} -> {reason}"

                retry_prompt += f"""

Propose a DIFFERENT fix. Learn from what failed.

Respond with JSON only (no markdown):
{{"fix": "shell command(s)", "explanation": "why this is different and better"}}"""

                print(f"[agent] Retrying {cid} (attempt {len(failures) + 1})")
                raw = agent_llm_call(retry_prompt)
                result = _parse_llm_json(raw)
                fix_cmd = result.get("fix", "")
                explanation = result.get("explanation", "")

                store.append_message(cid, {
                    "type": "fix",
                    "fix": fix_cmd,
                    "explanation": explanation,
                    "from": "agent",
                })
                print(f"[agent] Retry fix for {cid}: {str(fix_cmd)[:80]}")

        except Exception as e:
            print(f"[agent] Error: {e}")


# --- Main ---
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

store = ContractStore(DB_PATH)
escrow_mgr = EscrowManager(DB_PATH.replace(".db", "_escrow.db"))
reputation_mgr = ReputationManager(DB_PATH.replace(".db", "_rep.db"))
judge = AIJudge(model=MODEL, llm_call=judge_llm_call)
court = TieredCourt(llm_call=judge_llm_call)

app = create_app(store=store, escrow_mgr=escrow_mgr, reputation_mgr=reputation_mgr, judge=judge, court=court)

# Start free agent in background
agent_thread = threading.Thread(target=run_free_agent, args=(store, escrow_mgr), daemon=True)
agent_thread.start()
print(f"[server] Free agent running (model: {AGENT_MODEL})")
print(f"[server] Tiered court active (district/appeals/supreme)")
print(f"[server] Listening on :{PORT}")

uvicorn.run(app, host="0.0.0.0", port=PORT)
