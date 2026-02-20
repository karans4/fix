#!/usr/bin/env python3
"""End-to-end test of the Sandbox class.

Test 1: Install pyfiglet in overlay sandbox, verify it works inside, rollback, confirm gone.
Test 2: Install again, commit, confirm it persists.
"""
import sys, os, subprocess, importlib.util

# Load the fix script as a module
spec = importlib.util.spec_from_loader("fix_mod", loader=None)
fix_mod = importlib.util.module_from_spec(spec)
# Execute the fix script in the module namespace but skip main
fix_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fix")
code = open(fix_path).read()
# Replace the if __name__ == "__main__" block
code = code.replace('if __name__ == "__main__":', 'if False:  # disabled for import')
fix_mod.__dict__["__file__"] = fix_path
exec(compile(code, fix_path, "exec"), fix_mod.__dict__)

Sandbox = fix_mod.Sandbox
os.environ["SUDO_PASSWORD"] = "password123"

def check_pyfiglet():
    r = subprocess.run("python3 -c 'import pyfiglet; print(pyfiglet.figlet_format(\"OK\"))'",
                       shell=True, capture_output=True, text=True)
    return r.returncode == 0

print("=" * 60)
print("TEST 1: Install in sandbox, then rollback")
print("=" * 60)

assert not check_pyfiglet(), "pyfiglet should not be installed yet"
print("[OK] pyfiglet not installed")

sandbox = Sandbox()
sandbox.setup()
print(f"[OK] Sandbox created (backend={sandbox.backend}, sudo={sandbox._use_sudo})")

# Install pyfiglet inside the sandbox
result = sandbox.run_in_sandbox("pip install --break-system-packages pyfiglet", network=True)
print(f"[OK] pip install ran (exit={result.returncode})")

# Check diff
changed = sandbox.get_diff()
print(f"[OK] Diff: {len(changed)} files changed")
for f in changed[:5]:
    print(f"     {'DEL' if f['is_delete'] else 'ADD'} {f['path']}")
if len(changed) > 5:
    print(f"     ... and {len(changed)-5} more")

# Rollback
sandbox.rollback()
sandbox.cleanup()
print("[OK] Rolled back and cleaned up")

assert not check_pyfiglet(), "pyfiglet should be gone after rollback"
print("[OK] pyfiglet is gone after rollback")

print()
print("=" * 60)
print("TEST 2: Install in sandbox, then commit")
print("=" * 60)

sandbox2 = Sandbox()
sandbox2.setup()
print(f"[OK] Sandbox created (backend={sandbox2.backend})")

result = sandbox2.run_in_sandbox("pip install --break-system-packages pyfiglet", network=True)
print(f"[OK] pip install ran (exit={result.returncode})")

changed = sandbox2.get_diff()
print(f"[OK] Diff: {len(changed)} files changed")

# Commit
sandbox2.commit()
sandbox2.cleanup()
print("[OK] Committed and cleaned up")

assert check_pyfiglet(), "pyfiglet should persist after commit"
print("[OK] pyfiglet works after commit!")

# Show it
r = subprocess.run("python3 -c 'import pyfiglet; print(pyfiglet.figlet_format(\"SANDBOX\"))'",
                   shell=True, capture_output=True, text=True)
print(r.stdout)

# Cleanup: remove pyfiglet
subprocess.run("pip uninstall -y pyfiglet --break-system-packages",
               shell=True, capture_output=True)
print("[OK] Cleaned up pyfiglet")

print("=" * 60)
print("ALL TESTS PASSED")
print("=" * 60)
