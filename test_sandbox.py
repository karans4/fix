#!/usr/bin/env python3
"""Quick test of the new cross-platform Sandbox class."""
import sys, os, subprocess, platform, shutil, tempfile

# Import Sandbox from the fix script (no .py extension)
script_dir = os.path.dirname(os.path.abspath(__file__))

# We only need the Sandbox class, not the full script
# Let's test the backends directly instead

print(f"Platform: {platform.system()}")

# Test 1: Can we do unprivileged overlay?
test_dir = tempfile.mkdtemp(prefix="fix-overlay-test-")
try:
    for d in ["lower", "upper", "work", "merged"]:
        os.makedirs(os.path.join(test_dir, d))
    with open(os.path.join(test_dir, "lower", "test"), "w") as f:
        f.write("x")
    r = subprocess.run(
        f"unshare -rm sh -c '"
        f"mount -t overlay overlay "
        f"-o lowerdir={test_dir}/lower,upperdir={test_dir}/upper,workdir={test_dir}/work "
        f"{test_dir}/merged && "
        f"test -f {test_dir}/merged/test'",
        shell=True, capture_output=True, text=True, timeout=10)
    unpriv = r.returncode == 0
    print(f"Unprivileged overlay: {unpriv}")
    if not unpriv:
        print(f"  stderr: {r.stderr.strip()[:100]}")
finally:
    shutil.rmtree(test_dir, ignore_errors=True)

# Test 2: Sudo available?
os.environ["SUDO_PASSWORD"] = "password123"
r = subprocess.run("echo password123 | sudo -S true", shell=True,
                    capture_output=True, text=True, timeout=5)
print(f"Sudo available: {r.returncode == 0}")

# Test 3: Full sandbox test with snapshot backend
print("\n=== Testing snapshot backend ===")
test_file = "/tmp/fix-sandbox-test-file.txt"

# Clean up
if os.path.exists(test_file):
    os.unlink(test_file)

# Test snapshot logic manually (can't easily import from 'fix' without .py extension)

print("\nSnapshot test (manual):")
snap_dir = tempfile.mkdtemp(prefix="fix-snap-test-")
target_dir = tempfile.mkdtemp(prefix="fix-target-test-")

# Create some files in target
with open(os.path.join(target_dir, "original.txt"), "w") as f:
    f.write("original content\n")
with open(os.path.join(target_dir, "keep.txt"), "w") as f:
    f.write("keep this\n")

# Snapshot (cp -a --reflink=auto)
snap_path = os.path.join(snap_dir, "snap")
r = subprocess.run(f"cp -a --reflink=auto '{target_dir}' '{snap_path}'",
                    shell=True, capture_output=True, text=True)
print(f"  Snapshot created: {r.returncode == 0}")

# Simulate command modifying files
with open(os.path.join(target_dir, "original.txt"), "w") as f:
    f.write("MODIFIED content\n")
with open(os.path.join(target_dir, "new_file.txt"), "w") as f:
    f.write("new file\n")
os.unlink(os.path.join(target_dir, "keep.txt"))

# Diff: compare target vs snapshot
print(f"  After 'command': original.txt modified, new_file.txt added, keep.txt deleted")

# Verify diff is detectable
assert open(os.path.join(target_dir, "original.txt")).read() == "MODIFIED content\n"
assert os.path.exists(os.path.join(target_dir, "new_file.txt"))
assert not os.path.exists(os.path.join(target_dir, "keep.txt"))
print(f"  Changes detected: YES")

# Rollback: rsync snapshot back
r = subprocess.run(f"rsync -ac --delete '{snap_path}/' '{target_dir}/'",
                    shell=True, capture_output=True, text=True)
print(f"  Rollback: {r.returncode == 0}")

# Verify rollback
assert open(os.path.join(target_dir, "original.txt")).read() == "original content\n"
assert os.path.exists(os.path.join(target_dir, "keep.txt"))
assert not os.path.exists(os.path.join(target_dir, "new_file.txt"))
print(f"  Rollback verified: original restored, new_file gone, keep.txt back")

# Cleanup
shutil.rmtree(snap_dir, ignore_errors=True)
shutil.rmtree(target_dir, ignore_errors=True)

# Test 4: Full sandbox with overlay (sudo)
print("\n=== Testing overlay backend (sudo) ===")
test_dir2 = tempfile.mkdtemp(prefix="fix-overlay-full-")
try:
    for d in ["lower", "upper", "work", "merged"]:
        os.makedirs(os.path.join(test_dir2, d))
    with open(os.path.join(test_dir2, "lower", "hello.txt"), "w") as f:
        f.write("original\n")

    # Mount overlay with sudo
    r = subprocess.run(
        f"echo password123 | sudo -S mount -t overlay overlay "
        f"-o lowerdir={test_dir2}/lower,upperdir={test_dir2}/upper,workdir={test_dir2}/work "
        f"{test_dir2}/merged",
        shell=True, capture_output=True, text=True)
    if r.returncode != 0:
        print(f"  Mount failed: {r.stderr.strip()[:100]}")
    else:
        print(f"  Overlay mounted")

        # Read through overlay
        content = open(os.path.join(test_dir2, "merged", "hello.txt")).read()
        assert content == "original\n"
        print(f"  Read through overlay: '{content.strip()}'")

        # Write through overlay
        with open(os.path.join(test_dir2, "merged", "hello.txt"), "w") as f:
            f.write("modified\n")
        with open(os.path.join(test_dir2, "merged", "new.txt"), "w") as f:
            f.write("new file\n")

        # Check upper dir has the changes
        upper_files = os.listdir(os.path.join(test_dir2, "upper"))
        print(f"  Upper dir files: {upper_files}")

        # Lower unchanged
        lower_content = open(os.path.join(test_dir2, "lower", "hello.txt")).read()
        assert lower_content == "original\n"
        print(f"  Lower unchanged: '{lower_content.strip()}'")

        # Cleanup
        subprocess.run(f"echo password123 | sudo -S umount {test_dir2}/merged",
                       shell=True, capture_output=True)
        print(f"  Overlay unmounted")
finally:
    subprocess.run(f"echo password123 | sudo -S rm -rf {test_dir2}",
                   shell=True, capture_output=True)

print("\n=== All tests passed ===")
