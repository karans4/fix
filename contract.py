"""Contract builder and validator for fix v2.

Builds, validates, and transforms contract objects used by the fix protocol.
Contracts define what needs fixing, what the agent is allowed to do, and how
to verify the result.
"""

import os
import re
import shutil
import subprocess

from protocol import DEFAULT_MAX_ATTEMPTS

from scrubber import scrub


# --- Capability detection ---

def detect_capabilities():
    """Auto-detect what tools/permissions are available on this system."""
    caps = {}

    # sudo
    has_sudo = shutil.which("sudo") is not None
    passwordless = False
    if has_sudo:
        try:
            subprocess.run(
                ["sudo", "-n", "true"],
                capture_output=True, timeout=5
            )
            passwordless = True
        except (subprocess.SubprocessError, OSError):
            pass
    caps["sudo"] = {
        "available": False,
        "scope": [],
    }

    # network — always available (used for package fetches)
    caps["network"] = {"available": True, "scope": ["packages"]}

    # docker
    caps["docker"] = {"available": shutil.which("docker") is not None}

    # make
    caps["make"] = {"available": shutil.which("make") is not None}

    return caps


# --- Verification spec parsing ---

def _parse_verify_spec(spec):
    """Turn a verify_spec into a verification list.

    None          -> [{"method": "exit_code", "expected": 0}]
    "human"       -> [{"method": "principal_verification"}]  (backward compat)
    "principal"   -> [{"method": "principal_verification"}]
    "contains 'X'" -> [{"method": "output_match", "pattern": "X"}]
    list          -> recurse each element
    dict          -> pass through as-is
    """
    if spec is None:
        return [{"method": "exit_code", "expected": 0}]

    if isinstance(spec, list):
        out = []
        for s in spec:
            out.extend(_parse_verify_spec(s))
        return out

    if isinstance(spec, dict):
        return [spec]

    if isinstance(spec, str):
        if spec in ("human", "principal"):
            return [{"method": "principal_verification"}]
        m = re.match(r"^contains\s+['\"](.+)['\"]$", spec)
        if m:
            return [{"method": "output_match", "pattern": m.group(1)}]
        # Fallback: treat as custom method name
        return [{"method": spec}]

    return [{"method": "exit_code", "expected": 0}]


# --- Contract builder ---

def build_contract(command, stderr, env_info, **kwargs):
    """Build a v2 fix contract.

    Args:
        command: The command that failed.
        stderr: Raw stderr output from the failure.
        env_info: Dict from get_env_fingerprint().
        **kwargs: Optional overrides (see module docstring).

    Returns:
        Contract dict (v2 schema).
    """
    verify_spec = kwargs.get("verify_spec")
    safe_mode = kwargs.get("safe_mode", False)
    attempt = kwargs.get("attempt", 0)
    prior_failures = kwargs.get("prior_failures")
    root = kwargs.get("root")
    bounty = kwargs.get("bounty")
    judge = kwargs.get("judge")
    market = kwargs.get("market", False)
    redaction_config = kwargs.get("redaction_config")

    # Scrub stderr — always, even local
    scrubbed_stderr, matched_cats = scrub(stderr, redaction_config)
    scrubbed_stderr = scrubbed_stderr[:1000]

    # Scrub environment fields
    os_str = env_info.get("os", "")
    release = env_info.get("release", "")
    distro = env_info.get("distro", "")
    os_display = f"{distro} ({os_str})" if distro else os_str
    os_display, _ = scrub(os_display, redaction_config)

    arch = env_info.get("machine", "")

    pkg_managers = env_info.get("package_managers", [])

    contract = {
        "version": 2,
        "protocol": "fix",
        "task": {
            "type": "fix_command",
            "command": command,
            "error": scrubbed_stderr,
        },
        "environment": {
            "os": os_display,
            "arch": arch,
            "package_managers": pkg_managers,
        },
        "capabilities": detect_capabilities(),
        "verification": _parse_verify_spec(verify_spec),
        "execution": {
            "sandbox": safe_mode,
            "root": root,
            "max_attempts": DEFAULT_MAX_ATTEMPTS,
            "investigation_rounds": 5,
            "timeout": 300,
        },
        "redaction": {
            "enabled": bool(matched_cats) or redaction_config is not None,
            "categories": sorted(matched_cats) if matched_cats else [
                "env_vars", "tokens", "paths", "ips", "emails"
            ],
            "custom_patterns": (
                redaction_config.get("custom_patterns", [])
                if redaction_config else []
            ),
        },
    }

    # Prior failures (scrubbed)
    if prior_failures:
        scrubbed_failures = []
        for f in prior_failures:
            sf, _ = scrub(str(f), redaction_config)
            scrubbed_failures.append(sf[:500])
        contract["prior_failures"] = scrubbed_failures

    # Market mode: add escrow + terms
    if market:
        bounty_str = str(bounty) if bounty else "0.19"
        contract["escrow"] = {
            "bounty": bounty_str,
            "currency": "XNO",
            "chain": "nano",
            "settle": "nano_direct",
        }
        contract["terms"] = {
            "cancellation": {
                "grace_period": 30,
            },
            "abandonment": {
                "timeout": 120,
                "ruling": "escalate",
            },
            "platform": {
                "evidence_hash_algo": "sha256",
            },
        }
        if judge:
            contract["terms"]["judge"] = judge

    return contract


# --- Validator ---

def validate_contract(contract):
    """Validate a v2 contract dict.

    Returns:
        (True, []) if valid, (False, [errors]) otherwise.
    """
    errors = []

    if not isinstance(contract, dict):
        return False, ["contract is not a dict"]

    # Version
    if contract.get("version") != 2:
        errors.append(f"version must be 2, got {contract.get('version')}")

    # Task fields
    task = contract.get("task", {})
    if not isinstance(task, dict):
        errors.append("task must be a dict")
        task = {}
    if not task.get("command"):
        errors.append("task.command is required")
    if "error" not in task:
        errors.append("task.error is required")

    # Environment
    env = contract.get("environment", {})
    if not isinstance(env, dict):
        errors.append("environment must be a dict")
        env = {}
    if not env.get("os"):
        errors.append("environment.os is required")
    if not env.get("arch"):
        errors.append("environment.arch is required")

    # Verification
    verification = contract.get("verification")
    if not isinstance(verification, list) or len(verification) == 0:
        errors.append("verification must be a non-empty list")

    # Execution
    execution = contract.get("execution", {})
    if not isinstance(execution, dict):
        errors.append("execution must be a dict")
        execution = {}
    if not isinstance(execution.get("sandbox"), bool):
        errors.append("execution.sandbox must be a bool")
    max_att = execution.get("max_attempts")
    if not isinstance(max_att, int) or max_att <= 0:
        errors.append("execution.max_attempts must be an int > 0")

    # Escrow (if present)
    escrow = contract.get("escrow")
    if escrow is not None:
        if not isinstance(escrow, dict):
            errors.append("escrow must be a dict")
        else:
            b = escrow.get("bounty", "")
            try:
                float(b)
            except (ValueError, TypeError):
                errors.append(f"escrow.bounty must be a numeric string, got '{b}'")
            if not escrow.get("currency"):
                errors.append("escrow.currency is required when escrow is present")

    return (len(errors) == 0, errors)


# --- Prompt projection ---

def contract_for_prompt(contract):
    """Strip internal fields, return a copy suitable for LLM consumption.

    Removes: redaction config internals, agent metadata.
    Keeps: task, environment, capabilities, verification, execution basics, escrow/terms.
    """
    keep_keys = {
        "version", "protocol", "task", "environment", "capabilities",
        "verification", "execution", "prior_failures", "escrow", "terms",
    }
    out = {k: v for k, v in contract.items() if k in keep_keys}

    # Strip redaction internals but note if redaction is active
    if contract.get("redaction", {}).get("enabled"):
        out["redaction"] = {"enabled": True}

    # Strip execution internals that the LLM doesn't need
    if "execution" in out:
        out["execution"] = {
            k: v for k, v in out["execution"].items()
            if k in ("sandbox", "root", "max_attempts", "investigation_rounds", "timeout")
        }

    return out
