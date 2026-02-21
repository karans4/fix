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
from server.judge import AIJudge, TieredCourt
from protocol import MINIMUM_BOUNTY, AGENT_PICKUP_DELAY
from decimal import Decimal

API_KEY = os.environ.get("FIX_API_KEY", "")
OPENROUTER_KEY = os.environ.get("OPENROUTER_API_KEY", "")
MODEL = os.environ.get("FIX_MODEL", "claude-haiku-4-5-20251001")
AGENT_MODEL = os.environ.get("FIX_AGENT_MODEL", "claude-haiku-4-5-20251001")
# Free-mode agent: rotate through free OpenRouter models (200 req/day each)
FREE_MODELS = [
    "deepseek/deepseek-r1-0528:free",
    "nvidia/nemotron-nano-9b-v2:free",
    "stepfun/step-3.5-flash:free",
    "z-ai/glm-4.5-air:free",
]
DB_PATH = os.environ.get("FIX_DB", "/var/lib/fix/fix.db")
KIMI_KEY = os.environ.get("KIMI_API_KEY", "")
KIMI_BASE = os.environ.get("KIMI_BASE_URL", "https://api.moonshot.ai/v1")
KIMI_MODEL = os.environ.get("KIMI_MODEL", "kimi-k2.5")
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


def kimi_llm_call(prompt, model=None):
    """OpenAI-compatible call to Kimi (or any OpenAI-compat endpoint)."""
    if not KIMI_KEY:
        return agent_llm_call(prompt)  # fallback to Claude
    use_model = model or KIMI_MODEL
    resp = httpx.post(
        f"{KIMI_BASE}/chat/completions",
        headers={
            "Authorization": f"Bearer {KIMI_KEY}",
            "Content-Type": "application/json",
        },
        json={
            "model": use_model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 1024,
        },
        timeout=60,
    )
    return resp.json()["choices"][0]["message"]["content"]


async def kimi_judge_call(system_prompt, user_prompt, model=None):
    """Async OpenAI-compatible call for judges. Falls back to Claude if no Kimi key."""
    if not KIMI_KEY:
        return await judge_llm_call(system_prompt, user_prompt, model=model)
    use_model = model or KIMI_MODEL
    # For supreme court, always use Claude Opus
    if model and "opus" in model:
        return await judge_llm_call(system_prompt, user_prompt, model=model)
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{KIMI_BASE}/chat/completions",
            headers={
                "Authorization": f"Bearer {KIMI_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": use_model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "max_tokens": 1024,
            },
            timeout=60,
        )
        return resp.json()["choices"][0]["message"]["content"]


# Track which free models are rate-limited (model -> timestamp when limit expires)
_free_model_blocked = {}
_free_model_idx = 0

def _pick_free_model():
    """Round-robin through free models, skipping rate-limited ones. Returns None if all exhausted."""
    global _free_model_idx
    now = time.time()
    for _ in range(len(FREE_MODELS)):
        model = FREE_MODELS[_free_model_idx % len(FREE_MODELS)]
        _free_model_idx += 1
        blocked_until = _free_model_blocked.get(model, 0)
        if now > blocked_until:
            return model
    return None  # all exhausted


def openrouter_llm_call(prompt, model=None):
    """OpenRouter call with free model rotation. Returns None if all models exhausted."""
    if not OPENROUTER_KEY:
        return None  # can't call without key
    use_model = model or _pick_free_model()
    if not use_model:
        return None  # all free models rate-limited, autodecline
    try:
        resp = httpx.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENROUTER_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": use_model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 1024,
            },
            timeout=90,
        )
        data = resp.json()
    except Exception as e:
        print(f"[agent] OpenRouter network error ({use_model}): {e}")
        _free_model_blocked[use_model] = time.time() + 300  # block 5 min
        return openrouter_llm_call(prompt)
    if resp.status_code == 429:
        _free_model_blocked[use_model] = time.time() + 3600
        print(f"[agent] Free model {use_model} rate-limited, rotating")
        return openrouter_llm_call(prompt)
    if "choices" not in data:
        err = data.get("error", {}).get("message", str(data))[:120]
        print(f"[agent] OpenRouter error ({use_model}, {resp.status_code}): {err}")
        _free_model_blocked[use_model] = time.time() + 300
        return openrouter_llm_call(prompt)
    content = data["choices"][0]["message"].get("content", "")
    if not content or not content.strip():
        print(f"[agent] OpenRouter empty response ({use_model}), rotating")
        _free_model_blocked[use_model] = time.time() + 300
        return openrouter_llm_call(prompt)
    return content


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
            contracts = store.list_by_status("open", limit=5)
            c = None
            for candidate in contracts:
                contract = candidate.get("contract", {})
                bounty = Decimal(contract.get("escrow", {}).get("bounty", "0"))
                judge_info = contract.get("judge", {})
                is_free = not judge_info.get("pubkey", "")

                # Free mode (no judge): accept zero-bounty contracts
                # Paid mode: enforce minimum bounty and complexity pricing
                if not is_free:
                    min_bounty = Decimal(MINIMUM_BOUNTY)
                    if bounty < min_bounty:
                        print(f"[agent] Rejecting {candidate['id']}: bounty {bounty} < min {min_bounty}")
                        continue

                    task = contract.get("task", {})
                    error = task.get("error", "")
                    complexity = 1
                    if len(error) > 500:
                        complexity = 2
                    if any(w in error.lower() for w in ("segfault", "segmentation", "core dump", "memory")):
                        complexity = 3
                    needed = min_bounty * complexity
                    if bounty < needed:
                        print(f"[agent] Rejecting {candidate['id']}: bounty {bounty} too low for complexity {complexity} (need {needed})")
                        continue
                
                # Check age: only pick up if waiting >= AGENT_PICKUP_DELAY
                created = candidate.get("created_at", 0)
                age = time.time() - created if created else 999
                if age < AGENT_PICKUP_DELAY:
                    continue  # let independent agents have first crack
                
                c = candidate
                break
            
            if c:
                cid = c["id"]
                contract = c["contract"]
                task = contract.get("task", {})
                briefing = build_briefing(cid, c)

                # Free-mode: no judge configured → use Claude Haiku (cheap, reliable)
                judge_info = contract.get("judge", {})
                is_free_mode = not judge_info.get("pubkey", "")
                llm_fn = agent_llm_call if is_free_mode else kimi_llm_call
                mode_label = "free" if is_free_mode else "paid"

                print(f"[agent] Picking up {cid} ({mode_label}): {task.get('command', task.get('task', '?'))}")

                # Bond → INVESTIGATING (use store API, not direct DB writes)
                try:
                    escrow_mgr.lock_agent_bond(cid)
                except Exception:
                    pass
                with store._lock:
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

                raw = llm_fn(inv_prompt)
                if raw is None:
                    print(f"[agent] LLM exhausted mid-contract {cid}, backing out")
                    store.update_status(cid, "open")  # reopen for other agents
                    continue
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

                raw = llm_fn(fix_prompt)
                if raw is None:
                    print(f"[agent] LLM exhausted during fix for {cid}, backing out")
                    store.update_status(cid, "open")
                    continue
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

                # Free-mode: use cheapest LLM
                judge_info = contract.get("judge", {})
                is_free = not judge_info.get("pubkey", "")
                retry_llm = openrouter_llm_call if is_free else kimi_llm_call

                print(f"[agent] Retrying {cid} (attempt {len(failures) + 1})")
                raw = retry_llm(retry_prompt)
                if raw is None:
                    print(f"[agent] LLM exhausted during retry for {cid}, skipping")
                    continue
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
judge = AIJudge(model=MODEL, llm_call=judge_llm_call)
court = TieredCourt(llm_call=kimi_judge_call if KIMI_KEY else judge_llm_call)

app = create_app(store=store, escrow_mgr=escrow_mgr, judge=judge, court=court)

# Start free agent in background
agent_thread = threading.Thread(target=run_free_agent, args=(store, escrow_mgr), daemon=True)
agent_thread.start()
print(f"[server] Free agent running (paid: {AGENT_MODEL}, free-mode: {len(FREE_MODELS)} models rotating)")
if KIMI_KEY:
    print(f"[server] Kimi backend active (model: {KIMI_MODEL}, supreme: claude-opus)")
print(f"[server] Tiered court active (district/appeals/supreme)")
print(f"[server] Listening on :{PORT}")

uvicorn.run(app, host="0.0.0.0", port=PORT)
