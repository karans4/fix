"""Tests for the contract module (fix v2 protocol)."""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from contract import (
    build_contract,
    validate_contract,
    contract_for_prompt,
    detect_capabilities,
)


@pytest.fixture
def env_info():
    return {
        "os": "Linux",
        "release": "6.8.0",
        "machine": "aarch64",
        "distro": "Ubuntu 24.04 LTS",
        "shell": "/bin/bash",
        "python": "3.12.3",
        "package_managers": ["apt", "pip"],
    }


@pytest.fixture
def basic_contract(env_info):
    return build_contract(
        command="pip install numpy",
        stderr="ERROR: could not install numpy",
        env_info=env_info,
    )


# --- 1. v2 contract builds with all fields ---

class TestBuildContract:
    def test_version_and_protocol(self, basic_contract):
        assert basic_contract["version"] == 2
        assert basic_contract["protocol"] == "fix"

    def test_task_command_set(self, basic_contract):
        assert basic_contract["task"]["command"] == "pip install numpy"

    def test_task_error_scrubbed(self, env_info):
        import os
        user = os.environ.get("USER", "testuser")
        c = build_contract(
            command="make build",
            stderr=f"/home/{user}/project/src/main.c:42: error: undeclared",
            env_info=env_info,
        )
        error = c["task"]["error"]
        assert f"/home/{user}" not in error
        assert "[USER]" in error

    def test_environment_fields_present(self, basic_contract):
        env = basic_contract["environment"]
        assert "os" in env
        assert "arch" in env
        assert "package_managers" in env

    def test_verification_is_list(self, basic_contract):
        assert isinstance(basic_contract["verification"], list)

    def test_execution_fields_present(self, basic_contract):
        exe = basic_contract["execution"]
        assert "max_attempts" in exe
        assert "timeout" in exe or "strategy" in exe


# --- 2. Local mode (no escrow) ---

class TestLocalMode:
    def test_no_escrow_key(self, basic_contract):
        assert "escrow" not in basic_contract

    def test_no_terms_key(self, basic_contract):
        assert "terms" not in basic_contract


# --- 3. Market mode ---

class TestMarketMode:
    def test_escrow_present(self, env_info):
        c = build_contract(
            command="apt install foo",
            stderr="E: Unable to locate package foo",
            env_info=env_info,
            market=True,
            bounty="0.01",
        )
        assert "escrow" in c
        assert "terms" in c

    def test_escrow_structure(self, env_info):
        c = build_contract(
            command="apt install foo",
            stderr="E: Unable to locate package foo",
            env_info=env_info,
            market=True,
            bounty="0.01",
        )
        assert "bounty" in c["escrow"] or "amount" in c["escrow"]
        assert isinstance(c["terms"], dict)


# --- 4. Capability detection ---

class TestDetectCapabilities:
    def test_returns_dict(self):
        caps = detect_capabilities()
        assert isinstance(caps, dict)

    def test_expected_keys(self):
        caps = detect_capabilities()
        for key in ("sudo", "network", "docker", "make"):
            assert key in caps, f"missing capability key: {key}"

    def test_available_is_bool(self):
        caps = detect_capabilities()
        for key in ("sudo", "network", "docker", "make"):
            assert isinstance(caps[key]["available"], bool)


# --- 5. Validation catches missing fields ---

class TestValidationMissing:
    def test_empty_dict_fails(self):
        ok, errors = validate_contract({})
        assert ok is False
        assert len(errors) > 0

    def test_missing_task_command(self, basic_contract):
        del basic_contract["task"]["command"]
        ok, errors = validate_contract(basic_contract)
        assert ok is False
        assert any("command" in e.lower() for e in errors)

    def test_missing_version(self, basic_contract):
        del basic_contract["version"]
        ok, errors = validate_contract(basic_contract)
        assert ok is False
        assert any("version" in e.lower() for e in errors)

    def test_valid_contract_passes(self, basic_contract):
        ok, errors = validate_contract(basic_contract)
        assert ok is True
        assert errors == []


# --- 6. Validation catches bad values ---

class TestValidationBadValues:
    def test_wrong_version(self, basic_contract):
        basic_contract["version"] = 1
        ok, errors = validate_contract(basic_contract)
        assert ok is False
        assert any("version" in e.lower() or "2" in e for e in errors)

    def test_max_attempts_zero(self, basic_contract):
        basic_contract["execution"]["max_attempts"] = 0
        ok, errors = validate_contract(basic_contract)
        assert ok is False
        assert any("max_attempts" in e.lower() or "attempt" in e.lower() for e in errors)

    def test_max_attempts_not_int(self, basic_contract):
        basic_contract["execution"]["max_attempts"] = "three"
        ok, errors = validate_contract(basic_contract)
        assert ok is False
        assert any("max_attempts" in e.lower() or "attempt" in e.lower() for e in errors)


# --- 7. contract_for_prompt strips internal fields ---

class TestContractForPrompt:
    def test_internal_fields_removed(self, basic_contract):
        prompt_c = contract_for_prompt(basic_contract)
        # Agent metadata and redaction config are internal
        for key in ("_metadata", "_redaction", "_agent", "_internal"):
            assert key not in prompt_c

    def test_task_preserved(self, basic_contract):
        prompt_c = contract_for_prompt(basic_contract)
        assert "task" in prompt_c

    def test_environment_preserved(self, basic_contract):
        prompt_c = contract_for_prompt(basic_contract)
        assert "environment" in prompt_c

    def test_verification_preserved(self, basic_contract):
        prompt_c = contract_for_prompt(basic_contract)
        assert "verification" in prompt_c


# --- 8. Scrubbing applied to stderr ---

class TestScrubbing:
    def test_home_path_scrubbed(self, env_info):
        import os
        user = os.environ.get("USER", "testuser")
        c = build_contract(
            command="cat file.txt",
            stderr=f"FileNotFoundError: /home/{user}/foo/bar.txt",
            env_info=env_info,
        )
        assert f"/home/{user}" not in c["task"]["error"]
        assert "[USER]" in c["task"]["error"]

    def test_github_pat_scrubbed(self, env_info):
        token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        c = build_contract(
            command="git push",
            stderr=f"remote: Invalid credentials for {token}",
            env_info=env_info,
        )
        assert token not in c["task"]["error"]
        assert "[REDACTED]" in c["task"]["error"]


# --- 9. Prior failures included and scrubbed ---

class TestPriorFailures:
    def test_prior_failures_present(self, env_info):
        c = build_contract(
            command="sudo apt install foo",
            stderr="E: Unable to locate package foo",
            env_info=env_info,
            prior_failures=[
                ("sudo apt install foo", "/home/username/error: package not found"),
            ],
        )
        pf = c.get("prior_failures") or c["task"].get("prior_failures")
        assert pf is not None
        assert len(pf) >= 1

    def test_prior_failures_scrubbed(self, env_info):
        import os
        user = os.environ.get("USER", "testuser")
        c = build_contract(
            command="sudo apt install foo",
            stderr="E: Unable to locate package foo",
            env_info=env_info,
            prior_failures=[
                ("sudo apt install foo", f"/home/{user}/error: package not found"),
            ],
        )
        pf = c.get("prior_failures") or c["task"].get("prior_failures")
        serialized = str(pf)
        assert f"/home/{user}" not in serialized
        assert "[USER]" in serialized
