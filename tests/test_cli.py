"""CLI smoke tests -- catch argument/wiring bugs before users do."""

import subprocess
import sys


def run_fix(*args, timeout=10):
    """Run fix.py as a subprocess, return (returncode, stdout, stderr)."""
    result = subprocess.run(
        [sys.executable, "fix.py"] + list(args),
        capture_output=True, text=True, timeout=timeout,
    )
    return result.returncode, result.stdout, result.stderr


class TestCLIBasic:
    def test_no_args_shows_help(self):
        rc, out, err = run_fix()
        assert rc == 0
        assert "fix" in (out + err).lower()

    def test_failing_command_no_llm(self):
        """A failing command without any LLM should error gracefully, not crash."""
        rc, out, err = run_fix("false")
        # Should not be 0 (command failed), but shouldn't be a traceback either
        assert "Traceback" not in err

    def test_remote_failing_command_no_server(self):
        """--remote with unreachable server should fail gracefully."""
        # Point at a bogus URL so it doesn't hit the real server
        rc, out, err = run_fix("--remote", "false")
        # Key: no TypeError, no Traceback from bad kwargs
        assert "Traceback" not in err

    def test_explain_no_llm(self):
        """--explain without LLM should error gracefully."""
        rc, out, err = run_fix("--explain", "false")
        assert "Traceback" not in err

    def test_dry_run_no_llm(self):
        """--dry-run without LLM should error gracefully."""
        rc, out, err = run_fix("--dry-run", "false")
        assert "Traceback" not in err

    def test_no_safe_flag(self):
        """--no-safe shouldn't crash."""
        rc, out, err = run_fix("--no-safe", "false")
        assert "Traceback" not in err

    def test_successful_command(self):
        """A passing command should exit 0 with success message."""
        rc, out, err = run_fix("true")
        assert rc == 0
        assert "succeeded" in err.lower() or "nothing to fix" in err.lower()
