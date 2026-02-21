"""Agent mode for fix v3 — polls platform for contracts, investigates, proposes fixes.

Runs via `fix serve`. Connects to the platform via FixClient,
polls for open contracts, accepts compatible ones, runs LLM-driven
investigation loop, and proposes fixes.
"""

import asyncio
import json
import re
import sys
import os
from decimal import Decimal

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
    parts.append(json.dumps(contract, indent=2))
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
            parts.append(f"```\n{r['output']}\n```")
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


class FixAgent:
    """Agent that polls the fix platform for contracts and processes them."""

    def __init__(self, config: dict):
        """
        config keys:
        - platform_url: str (URL of the fix platform, default http://localhost:8000)
        - api_key: str (platform API key)
        - pubkey: str (agent's public key identifier)
        - capabilities: dict
        - min_bounty: str (minimum bounty to accept, default "0")
        - llm_call: async callable(prompt) -> str
        - poll_interval: float (seconds between polls, default 5.0)
        """
        self.platform_url = config.get("platform_url", "https://fix.notruefireman.org")
        self.api_key = config.get("api_key", "")
        self.pubkey = config.get("pubkey", "agent-default")
        self.capabilities = config.get("capabilities", {})
        self.min_bounty = Decimal(config.get("min_bounty", "0"))
        self._llm_call = config.get("llm_call")
        self.poll_interval = config.get("poll_interval", 5.0)
        self._running = False
        self.client = FixClient(base_url=self.platform_url)

    async def serve(self):
        """Main loop: poll platform for open contracts, process them."""
        self._running = True
        while self._running:
            try:
                contracts = await self.client.list_contracts(status="open")
                for entry in contracts:
                    contract = entry.get("contract", {})
                    contract_id = entry.get("id", "")
                    valid, errors = validate_contract(contract)
                    if not valid:
                        continue
                    can, reason = self.can_handle(contract)
                    if not can:
                        continue
                    await self.handle_contract(contract_id, contract)
            except Exception:
                pass  # Log and continue
            await asyncio.sleep(self.poll_interval)

    def stop(self):
        self._running = False

    async def handle_contract(self, contract_id: str, contract: dict):
        """Process a single contract: accept, investigate, propose fix."""
        # 1. Accept
        await self.client.accept_contract(contract_id, self.pubkey)

        # 2. Investigation loop
        investigation_results = []
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

            fix_data = self._extract_fix_proposal(llm_response)
            if fix_data:
                break

            commands = parse_llm_investigation(llm_response)
            if not commands:
                break

            for cmd in commands:
                await self.client.request_investigation(contract_id, cmd, self.pubkey)
                # Poll for result
                result_output = await self._wait_for_result(contract_id, cmd)
                if result_output is not None:
                    investigation_results.append({"command": cmd, "output": result_output})
        else:
            # Exhausted rounds -- one final LLM call
            prompt = build_agent_prompt(prompt_contract, investigation_results,
                                        agent_memory=agent_memory,
                                        prior_failures=prior_failures)
            llm_response = await self._call_llm(prompt)
            fix_data = self._extract_fix_proposal(llm_response)

        # 3. Submit fix
        if not fix_data:
            fix_data = {"fix": "", "explanation": "Unable to determine a fix within investigation rounds."}

        await self.client.submit_fix(
            contract_id,
            fix_data["fix"],
            fix_data.get("explanation", ""),
            self.pubkey,
        )

    def can_handle(self, contract: dict) -> tuple[bool, str]:
        """Check if this agent can handle the contract."""
        escrow = contract.get("escrow", {})
        if escrow:
            bounty = Decimal(escrow.get("bounty", "0"))
            if bounty < self.min_bounty:
                return False, f"bounty {bounty} below minimum {self.min_bounty}"
        match, reason = capabilities_match(self.capabilities, contract)
        if not match:
            return False, reason
        return True, ""

    async def _call_llm(self, prompt: str) -> str:
        if self._llm_call:
            return await self._llm_call(prompt)
        raise NotImplementedError("LLM backend not configured. Inject llm_call in config.")

    @staticmethod
    def _extract_fix_proposal(llm_response: str) -> dict | None:
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

    async def _wait_for_result(self, contract_id: str, command: str, timeout: float = 60.0, poll: float = 1.0) -> str | None:
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
