"""Agent client for fix platform — pluggable interface for any AI agent.

Any agent (LLM-based or otherwise) can use FixAgent by:
1. Subclassing and overriding on_* hooks, OR
2. Passing callback functions in config

Usage:
    fix serve                              # Built-in LLM agent
    python -m agent --url http://... ...   # Standalone

The agent lifecycle per contract:
    discover → filter → bond → investigate → accept/decline → fix → done
"""

import asyncio
import json
import re
import sys
import os
from decimal import Decimal
from typing import Callable, Awaitable

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

from protocol import MAX_INVESTIGATION_ROUNDS
from client import FixClient
from contract import validate_contract, contract_for_prompt


# --- Helper functions ---

def parse_llm_investigation(response: str) -> list[str]:
    """Extract INVESTIGATE: commands from LLM response."""
    commands = []
    for line in response.splitlines():
        stripped = line.strip()
        m = re.match(r'^INVESTIGATE:\s*(.+)$', stripped, re.IGNORECASE)
        if m:
            cmd = m.group(1).strip()
            if cmd:
                commands.append(cmd)
    return commands


MEMORY_RE = re.compile(r'^MEMORY:\s*(.+)$', re.MULTILINE)


def build_agent_prompt(contract: dict, investigation_results: list[dict],
                       agent_memory: list[str] | None = None,
                       prior_failures: list[dict] | None = None) -> str:
    """Build the prompt for the LLM with contract, investigation, and memory context."""
    parts = []
    parts.append("You are a fix agent. Your job is to diagnose and fix the problem described in this contract.")
    parts.append("You may decline (\"accepted\": false) before or after investigation, as long as you haven't accepted yet.\n")
    parts.append("## Contract\n")
    parts.append('<user-content type="contract">')
    parts.append(json.dumps(contract, indent=2))
    parts.append('</user-content>')
    parts.append("")

    if agent_memory:
        parts.append("## Your Memory (observations from prior attempts)\n")
        for note in agent_memory:
            parts.append(f"- {note}")
        parts.append("")

    if prior_failures:
        parts.append("## Prior Failed Attempts\n")
        parts.append("These fixes were tried and failed. Do not repeat them.\n")
        for i, f in enumerate(prior_failures, 1):
            parts.append(f"### Attempt {i}")
            parts.append(f"Fix: `{f['fix']}`")
            parts.append(f"Result: {f['error']}")
            parts.append("")

    if investigation_results:
        parts.append("## Investigation Results So Far\n")
        for i, r in enumerate(investigation_results, 1):
            parts.append(f"### Round {i}: `{r['command']}`")
            parts.append(f'<user-content type="investigation_result">')
            parts.append(f"```\n{r['output']}\n```")
            parts.append('</user-content>')
            parts.append("")

    parts.append("## Instructions\n")
    parts.append(
        "If you need more information, output one or more lines starting with "
        "'INVESTIGATE: <command>' where <command> is a shell command to run on "
        "the principal's machine.\n"
    )
    parts.append(
        "Save observations with 'MEMORY: <note>' lines. These persist across "
        "retry attempts so you remember what you learned even if your fix fails.\n"
    )
    parts.append(
        "When you have enough information to propose a fix, output a JSON block:\n"
        "```json\n"
        '{"accepted": true, "fix": "<shell command>", "explanation": "<why this fixes it>"}\n'
        "```\n\n"
        "To decline (before or after investigation):\n"
        "```json\n"
        '{"accepted": false, "explanation": "<why this cannot be fixed>"}\n'
        "```\n"
    )
    return "\n".join(parts)


def capabilities_match(agent_caps: dict, contract: dict) -> tuple[bool, str]:
    """Check if agent capabilities satisfy contract requirements."""
    contract_caps = contract.get("capabilities", {})
    if not contract_caps:
        return True, ""

    for cap_name, cap_spec in contract_caps.items():
        if not isinstance(cap_spec, dict):
            continue
        required = cap_spec.get("available", False)
        if not required:
            continue
        agent_cap = agent_caps.get(cap_name, {})
        if not isinstance(agent_cap, dict):
            return False, f"missing capability: {cap_name}"
        if not agent_cap.get("available", False):
            return False, f"capability not available: {cap_name}"

    return True, ""


def extract_fix_proposal(llm_response: str) -> dict | None:
    """Try to extract a JSON fix proposal from LLM response."""
    m = re.search(r'```(?:json)?\s*\n?({.*?})\s*\n?```', llm_response, re.DOTALL)
    if m:
        try:
            data = json.loads(m.group(1))
            if "fix" in data and "explanation" in data:
                return data
        except json.JSONDecodeError:
            pass
    m = re.search(r'(\{[^{}]*"fix"[^{}]*"explanation"[^{}]*\})', llm_response, re.DOTALL)
    if m:
        try:
            data = json.loads(m.group(1))
            if "fix" in data and "explanation" in data:
                return data
        except json.JSONDecodeError:
            pass
    return None


class FixAgent:
    """Pluggable agent client for the fix platform.

    Override the on_* methods to customize behavior, or pass callbacks in config.
    The default implementation uses an LLM to investigate and propose fixes.

    Config keys:
        platform_url: str       Platform URL (default: https://fix.notruefireman.org)
        privkey_bytes: bytes    Ed25519 private key for signing
        pubkey: str             Agent's fix_<hex> identity
        capabilities: dict      What this agent can do
        min_bounty: str         Minimum bounty to accept (default: "0")
        max_bounty: str         Maximum bounty to accept (default: unlimited)
        poll_interval: float    Seconds between polls (default: 5.0)
        max_concurrent: int     Max simultaneous contracts (default: 1)

    Callbacks (pass in config or override methods):
        llm_call: async (prompt: str) -> str
        on_contract_found: async (contract_id, contract, briefing) -> bool
        on_investigation_result: async (contract_id, command, output) -> None
        on_fix_submitted: async (contract_id, fix, explanation) -> None
        on_error: async (contract_id, error) -> None
    """

    def __init__(self, config: dict):
        self.platform_url = config.get("platform_url", "https://fix.notruefireman.org")
        self.pubkey = config.get("pubkey", "agent-default")
        self.capabilities = config.get("capabilities", {})
        self.min_bounty = Decimal(config.get("min_bounty", "0"))
        self.max_bounty = Decimal(config.get("max_bounty", "999999"))
        self.poll_interval = config.get("poll_interval", 5.0)
        self.max_concurrent = config.get("max_concurrent", 1)
        self._running = False
        self._active_contracts: set[str] = set()

        # Client with optional Ed25519 identity
        privkey = config.get("privkey_bytes")
        self.client = FixClient(
            base_url=self.platform_url,
            privkey_bytes=privkey,
        )

        # Callbacks
        self._llm_call = config.get("llm_call")
        self._on_contract_found = config.get("on_contract_found")
        self._on_investigation_result = config.get("on_investigation_result")
        self._on_fix_submitted = config.get("on_fix_submitted")
        self._on_error = config.get("on_error")

    # --- Event hooks (override in subclass or pass callbacks) ---

    async def on_contract_found(self, contract_id: str, contract: dict, briefing: str) -> bool:
        """Called when a matching contract is found. Return True to take it."""
        if self._on_contract_found:
            return await self._on_contract_found(contract_id, contract, briefing)
        return True  # Default: accept everything that passes filters

    async def on_investigation_result(self, contract_id: str, command: str, output: str):
        """Called after each investigation result comes back."""
        if self._on_investigation_result:
            await self._on_investigation_result(contract_id, command, output)

    async def on_fix_submitted(self, contract_id: str, fix: str, explanation: str):
        """Called after a fix is submitted."""
        if self._on_fix_submitted:
            await self._on_fix_submitted(contract_id, fix, explanation)

    async def on_error(self, contract_id: str, error: Exception):
        """Called on errors during contract processing."""
        if self._on_error:
            await self._on_error(contract_id, error)

    # --- Core loop ---

    async def serve_sse(self):
        """SSE-based loop: subscribe to contract events instead of polling.

        More efficient than polling — gets instant notifications.
        Falls back to polling if SSE connection drops.
        """
        self._running = True
        print(f"[agent] Subscribing to SSE stream (min_bounty={self.min_bounty})")

        while self._running:
            try:
                await self.client.stream_contracts(
                    min_bounty=str(self.min_bounty),
                    callback=self._handle_sse_event,
                )
            except Exception as e:
                if self._running:
                    print(f"[agent] SSE connection lost ({e}), reconnecting in 5s...")
                    await asyncio.sleep(5)

    async def _handle_sse_event(self, event: dict):
        """Process an SSE event."""
        if event.get("event") != "contract_posted":
            return
        if len(self._active_contracts) >= self.max_concurrent:
            return

        contract_id = event.get("contract_id", "")
        if contract_id in self._active_contracts:
            return

        # Fetch full contract details
        try:
            data = await self.client.get_contract(contract_id)
        except Exception:
            return
        if not data:
            return

        contract = data.get("contract", {})
        valid, errors = validate_contract(contract)
        if not valid:
            return
        can, reason = self.can_handle(contract)
        if not can:
            return

        briefing = data.get("briefing", "")
        take = await self.on_contract_found(contract_id, contract, briefing)
        if not take:
            return

        self._active_contracts.add(contract_id)
        asyncio.create_task(self._safe_handle(contract_id, contract))

    async def serve(self):
        """Main loop: poll platform for open contracts, process them."""
        self._running = True
        while self._running:
            try:
                if len(self._active_contracts) >= self.max_concurrent:
                    await asyncio.sleep(self.poll_interval)
                    continue

                contracts = await self.client.list_contracts(status="open")
                for entry in contracts:
                    if len(self._active_contracts) >= self.max_concurrent:
                        break
                    contract = entry.get("contract", {})
                    contract_id = entry.get("id", "")
                    if contract_id in self._active_contracts:
                        continue

                    valid, errors = validate_contract(contract)
                    if not valid:
                        continue
                    can, reason = self.can_handle(contract)
                    if not can:
                        continue

                    briefing = entry.get("briefing", "")
                    take = await self.on_contract_found(contract_id, contract, briefing)
                    if not take:
                        continue

                    self._active_contracts.add(contract_id)
                    asyncio.create_task(self._safe_handle(contract_id, contract))

            except Exception:
                pass  # Network blip, keep going
            await asyncio.sleep(self.poll_interval)

    def stop(self):
        self._running = False

    async def _safe_handle(self, contract_id: str, contract: dict):
        """Wrapper that catches errors and cleans up."""
        try:
            await self.handle_contract(contract_id, contract)
        except Exception as e:
            await self.on_error(contract_id, e)
        finally:
            self._active_contracts.discard(contract_id)

    # --- Contract processing ---

    async def handle_contract(self, contract_id: str, contract: dict):
        """Full contract lifecycle: bond → investigate → accept → fix.

        Override this for completely custom behavior.
        """
        # 1. Post bond to investigate
        await self.client.bond(contract_id, self.pubkey)

        # 2. Investigation loop — seed with prior agents' results from transcript
        investigation_results = []
        data = await self.client.get_contract(contract_id)
        if data:
            transcript = data.get("transcript", [])
            # Extract prior investigate/result pairs
            for entry in transcript:
                etype = entry.get("type", "")
                if etype == "result":
                    cmd = entry.get("command", "") or entry.get("data", {}).get("command", "")
                    output = entry.get("output", "") or entry.get("data", {}).get("output", "")
                    if cmd:
                        investigation_results.append({"command": cmd, "output": output})
        prompt_contract = contract_for_prompt(contract)
        max_rounds = contract.get("execution", {}).get(
            "investigation_rounds", MAX_INVESTIGATION_ROUNDS
        )

        agent_memory = []
        prior_failures = []
        fix_data = None

        for _round in range(max_rounds):
            prompt = build_agent_prompt(prompt_contract, investigation_results,
                                        agent_memory=agent_memory,
                                        prior_failures=prior_failures)
            llm_response = await self._call_llm(prompt)

            # Extract MEMORY: notes
            mem_notes = MEMORY_RE.findall(llm_response)
            for note in mem_notes:
                note = note.strip()
                if note and note not in agent_memory:
                    agent_memory.append(note)

            fix_data = extract_fix_proposal(llm_response)
            if fix_data:
                break

            commands = parse_llm_investigation(llm_response)
            if not commands:
                break

            for cmd in commands:
                await self.client.request_investigation(contract_id, cmd, self.pubkey)
                result_output = await self._wait_for_result(contract_id, cmd)
                if result_output is not None:
                    investigation_results.append({"command": cmd, "output": result_output})
                    await self.on_investigation_result(contract_id, cmd, result_output)
        else:
            # Exhausted rounds -- one final LLM call
            prompt = build_agent_prompt(prompt_contract, investigation_results,
                                        agent_memory=agent_memory,
                                        prior_failures=prior_failures)
            llm_response = await self._call_llm(prompt)
            fix_data = extract_fix_proposal(llm_response)

        # 3. Decide: accept or decline
        if fix_data and fix_data.get("accepted") is False:
            reason = fix_data.get("explanation", "agent declined after investigation")
            await self.client.decline(contract_id, self.pubkey, reason=reason)
            return

        if not fix_data or not fix_data.get("fix"):
            # No fix found — decline
            await self.client.decline(contract_id, self.pubkey, reason="no fix found after investigation")
            return

        # 4. Accept and submit fix
        await self.client.accept_contract(contract_id, self.pubkey)
        await self.client.submit_fix(
            contract_id,
            fix_data["fix"],
            fix_data.get("explanation", ""),
            self.pubkey,
        )
        await self.on_fix_submitted(contract_id, fix_data["fix"], fix_data.get("explanation", ""))

    def can_handle(self, contract: dict) -> tuple[bool, str]:
        """Check if this agent can/wants to handle the contract."""
        escrow = contract.get("escrow", {})
        if escrow:
            bounty = Decimal(escrow.get("bounty", "0"))
            if bounty < self.min_bounty:
                return False, f"bounty {bounty} below minimum {self.min_bounty}"
            if bounty > self.max_bounty:
                return False, f"bounty {bounty} above maximum {self.max_bounty}"
        match, reason = capabilities_match(self.capabilities, contract)
        if not match:
            return False, reason
        return True, ""

    async def _call_llm(self, prompt: str) -> str:
        if self._llm_call:
            return await self._llm_call(prompt)
        raise NotImplementedError(
            "No LLM backend configured. Either:\n"
            "  1. Pass llm_call=async_fn in config\n"
            "  2. Subclass FixAgent and override _call_llm\n"
            "  3. Set OPENROUTER_API_KEY env var for default OpenRouter backend"
        )

    async def _wait_for_result(self, contract_id: str, command: str,
                               timeout: float = 60.0, poll: float = 1.0) -> str | None:
        """Poll for investigation result from principal."""
        import time
        deadline = time.time() + timeout
        while time.time() < deadline:
            data = await self.client.get_contract(contract_id)
            if data:
                for msg in reversed(data.get("transcript", [])):
                    if msg.get("type") == "result" and msg.get("command") == command:
                        return msg.get("output", "")
            await asyncio.sleep(poll)
        return None


# --- CLI entry point ---

def _default_openrouter_llm(model: str = "anthropic/claude-sonnet-4"):
    """Create an LLM callback using OpenRouter API."""
    import httpx

    api_key = os.environ.get("OPENROUTER_API_KEY", "")
    if not api_key:
        raise RuntimeError("OPENROUTER_API_KEY not set")

    async def call(prompt: str) -> str:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 4096,
                },
                timeout=120.0,
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]
    return call


async def _main():
    import argparse
    parser = argparse.ArgumentParser(description="fix agent — accepts and solves contracts")
    parser.add_argument("--url", default="https://fix.notruefireman.org", help="Platform URL")
    parser.add_argument("--model", default="anthropic/claude-sonnet-4", help="OpenRouter model")
    parser.add_argument("--min-bounty", default="0", help="Minimum bounty to accept")
    parser.add_argument("--max-bounty", default="999999", help="Maximum bounty to accept")
    parser.add_argument("--poll", type=float, default=5.0, help="Poll interval (seconds)")
    parser.add_argument("--sse", action="store_true", help="Use SSE stream instead of polling (recommended)")
    parser.add_argument("--concurrent", type=int, default=1, help="Max concurrent contracts")
    parser.add_argument("--key", help="Path to Ed25519 private key file")
    args = parser.parse_args()

    # Load or generate identity
    privkey = None
    key_path = args.key or os.path.expanduser("~/.fix/agent.key")
    if os.path.exists(key_path):
        with open(key_path, "rb") as f:
            privkey = f.read(32)
    else:
        from crypto import generate_ed25519_keypair, pubkey_to_fix_id, save_ed25519_key
        privkey, pubkey = generate_ed25519_keypair()
        os.makedirs(os.path.dirname(key_path), exist_ok=True)
        save_ed25519_key(key_path, privkey)
        print(f"Generated new agent identity: {pubkey_to_fix_id(pubkey)}")

    from crypto import ed25519_privkey_to_pubkey, pubkey_to_fix_id
    pubkey = ed25519_privkey_to_pubkey(privkey)
    fix_id = pubkey_to_fix_id(pubkey)

    llm = _default_openrouter_llm(args.model)

    agent = FixAgent({
        "platform_url": args.url,
        "privkey_bytes": privkey,
        "pubkey": fix_id,
        "min_bounty": args.min_bounty,
        "max_bounty": args.max_bounty,
        "poll_interval": args.poll,
        "max_concurrent": args.concurrent,
        "llm_call": llm,
    })

    mode = "SSE stream" if args.sse else f"polling every {args.poll}s"
    print(f"fix agent started")
    print(f"  identity:  {fix_id}")
    print(f"  platform:  {args.url}")
    print(f"  model:     {args.model}")
    print(f"  bounty:    {args.min_bounty} - {args.max_bounty} XNO")
    print(f"  mode:      {mode}, max {args.concurrent} concurrent")
    print()

    if args.sse:
        await agent.serve_sse()
    else:
        await agent.serve()


if __name__ == "__main__":
    asyncio.run(_main())
