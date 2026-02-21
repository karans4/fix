"""Tests for agent.py — helpers and FixAgent logic."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import json
import pytest
from decimal import Decimal
from agent import parse_llm_investigation, build_agent_prompt, capabilities_match, extract_fix_proposal, FixAgent


SAMPLE_CONTRACT = {
    "version": 2, "protocol": "fix",
    "task": {"type": "fix_command", "command": "make build", "error": "gcc: fatal error: no input files"},
    "environment": {"os": "Ubuntu 24.04 (Linux)", "arch": "aarch64", "package_managers": ["apt"]},
    "capabilities": {
        "sudo": {"available": False, "scope": []},
        "network": {"available": True, "scope": ["packages"]},
        "docker": {"available": False},
        "make": {"available": True},
    },
    "verification": [{"method": "exit_code", "expected": 0}],
    "execution": {"sandbox": False, "root": None, "max_attempts": 5, "investigation_rounds": 3, "timeout": 300},
    "escrow": {"bounty": "0.05", "currency": "USDC", "chain": "base", "settle": "x402"},
    "redaction": {"enabled": False, "categories": [], "custom_patterns": []},
}


def make_config(**overrides):
    config = {
        "platform_url": "http://test:8000",
        "pubkey": "test-agent-pubkey",
        "capabilities": {"make": {"available": True}, "network": {"available": True, "scope": ["packages"]}},
        "min_bounty": "0",
    }
    config.update(overrides)
    return config


# --- parse_llm_investigation ---

class TestParseLlmInvestigation:
    def test_single_command(self):
        resp = "Let me check.\nINVESTIGATE: ls -la\nDone."
        assert parse_llm_investigation(resp) == ["ls -la"]

    def test_multiple_commands(self):
        resp = "INVESTIGATE: cat Makefile\nINVESTIGATE: gcc --version\n"
        assert parse_llm_investigation(resp) == ["cat Makefile", "gcc --version"]

    def test_case_insensitive(self):
        resp = "investigate: uname -a\nInvestigate: whoami"
        assert parse_llm_investigation(resp) == ["uname -a", "whoami"]

    def test_no_commands(self):
        resp = "I think the fix is to install gcc.\n```json\n{\"fix\": \"apt install gcc\"}\n```"
        assert parse_llm_investigation(resp) == []

    def test_empty_command_skipped(self):
        resp = "INVESTIGATE:   \nINVESTIGATE: ls"
        assert parse_llm_investigation(resp) == ["ls"]

    def test_whitespace_trimmed(self):
        resp = "INVESTIGATE:   cat /etc/os-release   "
        assert parse_llm_investigation(resp) == ["cat /etc/os-release"]


# --- build_agent_prompt ---

class TestBuildAgentPrompt:
    def test_includes_contract(self):
        prompt = build_agent_prompt(SAMPLE_CONTRACT, [])
        assert "make build" in prompt
        assert json.dumps(SAMPLE_CONTRACT, indent=2) in prompt

    def test_includes_investigation_results(self):
        results = [{"command": "ls", "output": "Makefile\nmain.c"}]
        prompt = build_agent_prompt(SAMPLE_CONTRACT, results)
        assert "Round 1" in prompt
        assert "`ls`" in prompt
        assert "Makefile" in prompt

    def test_instructions_present(self):
        prompt = build_agent_prompt(SAMPLE_CONTRACT, [])
        assert "INVESTIGATE:" in prompt
        assert '"fix"' in prompt

    def test_empty_results(self):
        prompt = build_agent_prompt(SAMPLE_CONTRACT, [])
        assert "Investigation Results" not in prompt


# --- capabilities_match ---

class TestCapabilitiesMatch:
    def test_all_match(self):
        agent_caps = {"make": {"available": True}, "network": {"available": True, "scope": ["packages"]}}
        ok, reason = capabilities_match(agent_caps, SAMPLE_CONTRACT)
        assert ok is True
        assert reason == ""

    def test_missing_capability(self):
        agent_caps = {"network": {"available": True, "scope": ["packages"]}}
        ok, reason = capabilities_match(agent_caps, SAMPLE_CONTRACT)
        assert ok is False
        assert "make" in reason

    def test_capability_not_available(self):
        agent_caps = {"make": {"available": False}, "network": {"available": True}}
        ok, reason = capabilities_match(agent_caps, SAMPLE_CONTRACT)
        assert ok is False
        assert "not available" in reason

    def test_no_contract_caps(self):
        contract = {**SAMPLE_CONTRACT, "capabilities": {}}
        ok, reason = capabilities_match({}, contract)
        assert ok is True

    def test_contract_cap_not_required(self):
        """Capabilities with available=False in contract don't need agent support."""
        contract = {**SAMPLE_CONTRACT, "capabilities": {"docker": {"available": False}}}
        ok, reason = capabilities_match({}, contract)
        assert ok is True


# --- FixAgent init ---

class TestFixAgentInit:
    def test_basic_init(self):
        agent = FixAgent(make_config())
        assert agent.platform_url == "http://test:8000"
        assert agent.pubkey == "test-agent-pubkey"
        assert agent.min_bounty == Decimal("0")
        assert agent.capabilities["make"]["available"] is True

    def test_custom_min_bounty(self):
        agent = FixAgent(make_config(min_bounty="0.10"))
        assert agent.min_bounty == Decimal("0.10")


# --- FixAgent.can_handle ---

class TestCanHandle:
    def test_accepts_compatible(self):
        agent = FixAgent(make_config())
        ok, reason = agent.can_handle(SAMPLE_CONTRACT)
        assert ok is True

    def test_rejects_low_bounty(self):
        agent = FixAgent(make_config(min_bounty="1.0"))
        ok, reason = agent.can_handle(SAMPLE_CONTRACT)
        assert ok is False
        assert "bounty" in reason

    def test_rejects_missing_capability(self):
        agent = FixAgent(make_config(capabilities={}))
        ok, reason = agent.can_handle(SAMPLE_CONTRACT)
        assert ok is False
        assert "make" in reason or "network" in reason

    def test_accepts_no_escrow(self):
        contract = {k: v for k, v in SAMPLE_CONTRACT.items() if k != "escrow"}
        agent = FixAgent(make_config(min_bounty="1.0"))
        ok, reason = agent.can_handle(contract)
        assert ok is True


# --- extract_fix_proposal ---

class TestExtractFixProposal:
    def test_json_code_block(self):
        resp = 'Here is the fix:\n```json\n{"fix": "apt install gcc", "explanation": "gcc missing"}\n```'
        result = extract_fix_proposal(resp)
        assert result is not None
        assert result["fix"] == "apt install gcc"
        assert result["explanation"] == "gcc missing"

    def test_bare_json(self):
        resp = 'The fix is {"fix": "make clean && make", "explanation": "stale objects"} done.'
        result = extract_fix_proposal(resp)
        assert result is not None
        assert result["fix"] == "make clean && make"

    def test_no_fix(self):
        resp = "I need more information.\nINVESTIGATE: ls src/"
        result = extract_fix_proposal(resp)
        assert result is None

    def test_invalid_json(self):
        resp = '```json\n{fix: not valid json}\n```'
        result = extract_fix_proposal(resp)
        assert result is None

    def test_missing_fix_key(self):
        resp = '```json\n{"command": "apt install gcc", "explanation": "install it"}\n```'
        result = extract_fix_proposal(resp)
        assert result is None
