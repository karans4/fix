#!/usr/bin/env python3
"""fix -- AI-powered command fixer.

Usage:
    fix it                              Fix the last failed command (99% of the time)
    fix <command>                       Run command; if it fails, diagnose and fix

Options:
    fix --safe <command>                Sandboxed: overlay + rollback on failure (default on Linux)
    fix --no-safe <command>             Force direct execution (skip sandbox)
    fix --explain <command>             Explain the error without fixing
    fix --dry-run <command>             Show fix without executing
    fix --verify=human <command>        Human judges the result
    fix --verify="contains 'X'" <cmd>   Stdout must contain X
    fix --verify="CMD" <command>        Run CMD as verification
    fix --local <command>               Force Ollama backend
    fix -m MODEL <command>              Use a specific model
    fix --root DIR <command>            Jail agent investigation to DIR
    fix --msg "hint" <command>          Pass context to the agent
    fix --confirm <command>             Ask before applying (default: just do it)
    fix --remote <command>              Post contract to platform, wait for remote agent
    fix serve                           Run as an agent: poll platform for contracts

Config:
    ~/.fix/config.py                    Global config (Python)
    .fix.py                             Project config (overrides global)

    Config vars: model, ollama_model, ollama_url, safe_mode, verify, root,
                 openai_api_url, openai_model, backend, hidden_paths,
                 bounty, judge

Shell:
    eval "$(fix shell)"                 Add to .bashrc/.zshrc/config.fish (enables fix !!)

Project:
    fix init                            Create a .fix.py config for this project
"""

import subprocess, sys, os, json, time, platform, shutil, re

# Add script directory to path so sibling modules (scrubber, contract) are importable
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

try:
    from scrubber import scrub as scrub_output
    from contract import build_contract as build_contract_v2, contract_for_prompt, detect_capabilities
    _HAS_V2 = True
except ImportError:
    _HAS_V2 = False

try:
    from client import FixClient
    from agent import FixAgent
    from protocol import ContractState, FeedbackType, Ruling
    _HAS_REMOTE = True
except ImportError:
    _HAS_REMOTE = False

# --- Config ---
CONFIG_DIR = os.path.expanduser("~/.fix")
MAX_FIX_ATTEMPTS = 3
MAX_INVESTIGATE_ROUNDS = 5
INVESTIGATE_TIMEOUT = 5
HUMAN_VERIFY_TIMEOUT = 60

# Claude API defaults
CLAUDE_API_URL = "https://api.anthropic.com/v1/messages"
CLAUDE_MODEL = "claude-haiku-4-5-20251001"

# Ollama defaults
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "qwen2.5-coder:1.5b"

# --- Investigation ---
# Regex to detect investigation requests in LLM output
INVESTIGATE_RE = re.compile(r'^INVESTIGATE:\s*(.+)$', re.MULTILINE)

# Whitelist of allowed command prefixes for investigation
INVESTIGATE_WHITELIST = {
    # File inspection
    "cat", "head", "tail", "less", "file", "wc", "stat", "md5sum", "sha256sum",
    # Directory listing
    "ls", "find", "tree", "du",
    # Search
    "grep", "rg", "ag", "awk", "sed",
    # Versions/info
    "which", "whereis", "type", "command", "uname", "arch", "lsb_release", "hostnamectl",
    # Package queries
    "dpkg", "apt", "apt-cache", "apt-file", "apt-list", "rpm", "pacman",
    "pip", "pip3", "npm", "gem", "cargo", "rustc",
    # Runtime versions
    "python3", "python", "node", "gcc", "g++", "make", "cmake", "java", "go", "ruby",
    "clang", "clang++", "ld", "as", "nasm",
    # Environment
    "env", "printenv", "echo", "id", "whoami", "pwd", "hostname",
    # System info
    "lsmod", "lscpu", "free", "df", "mount", "ip", "ss", "ps",
    # Logs (read-only)
    "journalctl", "dmesg",
    # Misc
    "readlink", "realpath", "basename", "dirname", "diff", "cmp",
    "strings", "nm", "ldd", "objdump", "pkg-config", "test", "timeout",
}

# Patterns that indicate write operations (but not stderr redirects like 2>&1)
_RE_WRITE_REDIRECT = re.compile(r'(?<!\d)>(?!&)')  # > not preceded by digit, not followed by &
_RE_APPEND_REDIRECT = re.compile(r'(?<!\d)>>')
DANGEROUS_STRINGS = {"tee ", "tee\t", "| tee"}


def _extract_paths(cmd):
    """Extract file/directory path arguments from a shell command."""
    import shlex
    try:
        parts = shlex.split(cmd)
    except ValueError:
        parts = cmd.split()
    paths = []
    for p in parts[1:]:
        if p.startswith("-"):
            continue
        # Looks like a path if it contains / or starts with .
        if "/" in p or p.startswith("."):
            paths.append(p)
    return paths


def validate_investigate_command(cmd, root=None):
    """Check if a command is safe for investigation (read-only whitelist + root jail)."""
    cmd = cmd.strip()
    if not cmd:
        return False, "empty command"

    # Block write redirections (but allow 2>&1, 2>/dev/null, etc.)
    if _RE_WRITE_REDIRECT.search(cmd) or _RE_APPEND_REDIRECT.search(cmd):
        return False, "blocked: contains redirect (write operation)"
    for pat in DANGEROUS_STRINGS:
        if pat in cmd:
            return False, f"blocked: contains '{pat}' (write operation)"

    # Split on pipes and check every command in the pipeline
    import shlex
    # Split on pipe, semicolon, &&, || to get all sub-commands
    subcmds = re.split(r'\s*(?:\|(?!\|)|\|\||&&|;)\s*', cmd)
    for subcmd in subcmds:
        subcmd = subcmd.strip()
        if not subcmd:
            continue
        first_word = subcmd.split()[0]
        # Strip path prefix: /usr/bin/cat -> cat
        first_word = os.path.basename(first_word)
        if first_word not in INVESTIGATE_WHITELIST:
            return False, f"'{first_word}' not in investigation whitelist"
        # Commands that run other commands — check their argument too
        if first_word in ("timeout", "time", "nice", "ionice", "strace"):
            parts = subcmd.split()
            # Skip flags and the timeout value to find the actual command
            i = 1
            while i < len(parts) and (parts[i].startswith("-") or (first_word == "timeout" and i == 1)):
                i += 1
            if i < len(parts):
                actual = os.path.basename(parts[i])
                if actual not in INVESTIGATE_WHITELIST:
                    return False, f"'{actual}' (via {first_word}) not in investigation whitelist"

    # Root jail: check that all path arguments resolve inside root
    if root:
        root_abs = os.path.realpath(root)
        for p in _extract_paths(cmd):
            # Resolve relative to root (since cwd will be root)
            if os.path.isabs(p):
                resolved = os.path.realpath(p)
            else:
                resolved = os.path.realpath(os.path.join(root_abs, p))
            if not resolved.startswith(root_abs + "/") and resolved != root_abs:
                return False, f"path '{p}' is outside root ({root_abs})"

    return True, ""


def run_investigate_command(cmd, root=None, safe_mode=False, sandbox=None):
    """Run a read-only investigation command. Returns output string."""
    ok, reason = validate_investigate_command(cmd, root=root)
    if not ok:
        return f"[BLOCKED] {reason}"

    try:
        if safe_mode and sandbox:
            result = sandbox.run_in_sandbox(cmd, network=False)
            out = (result.stdout + result.stderr)[:2000]
            if _HAS_V2:
                out, _ = scrub_output(out)
        else:
            result = subprocess.run(
                cmd, shell=True, executable="/bin/bash",
                capture_output=True, text=True,
                timeout=INVESTIGATE_TIMEOUT,
                cwd=root,
            )
            out = (result.stdout + result.stderr)[:2000]
            if _HAS_V2:
                out, _ = scrub_output(out)
        return out if out.strip() else "(no output)"
    except subprocess.TimeoutExpired:
        return "[TIMEOUT] command exceeded 5s limit"
    except Exception as e:
        return f"[ERROR] {e}"


# --- Colors ---
C_RESET = "\033[0m"
C_RED = "\033[31m"
C_GREEN = "\033[32m"
C_YELLOW = "\033[33m"
C_BLUE = "\033[34m"
C_CYAN = "\033[36m"
C_DIM = "\033[2m"
C_BOLD = "\033[1m"
C_ITALIC = "\033[3m"

if not sys.stderr.isatty():
    C_RESET = C_RED = C_GREEN = C_YELLOW = C_BLUE = C_CYAN = C_DIM = C_BOLD = C_ITALIC = ""


def status(icon, msg):
    print(f"  {icon}  {msg}", file=sys.stderr)


# --- Config (Python) ---

DEFAULTS = {
    "backend": "auto",
    "model": CLAUDE_MODEL,
    "safe_mode": "auto",  # "auto" = True on Linux, False elsewhere
    "ollama_model": OLLAMA_MODEL,
    "ollama_url": OLLAMA_URL,
    "hidden_paths": ["~/.ssh", "~/.gnupg", "~/.aws", "~/.fix",
                     "~/.config/gh", "~/.netrc", "~/.azure", "~/.kube",
                     "~/.docker", "~/.gitconfig", "~/.bash_history",
                     "~/.python_history"],
    "openai_api_url": "",
    "openai_model": "",
    "root": None,       # restrict agent investigation to this directory
    "verify": None,     # default verification command for this project
    "agent": None,      # custom agent function: f(contract) -> response dict
    "bounty": None,     # optional escrow bounty: "0.01 USDC", "100 sats", etc.
    "judge": None,      # optional dispute judge: f(contract, outcome) -> verdict dict
}


def _exec_config(path):
    """Execute a Python config file and return its namespace as a dict."""
    ns = {"__builtins__": __builtins__}
    try:
        with open(path) as f:
            exec(f.read(), ns)
    except FileNotFoundError:
        return {}
    except Exception as e:
        print(f"  {C_RED}\u2717{C_RESET}  Error in {path}: {e}", file=sys.stderr)
        return {}
    # Extract user-defined names (skip dunders and modules)
    return {k: v for k, v in ns.items() if not k.startswith("_")}


def _find_project_config():
    """Walk up from CWD to find .fix.py (stops at git root or /)."""
    d = os.getcwd()
    while True:
        candidate = os.path.join(d, ".fix.py")
        if os.path.isfile(candidate):
            return candidate
        # Stop at git root or filesystem root
        if os.path.isdir(os.path.join(d, ".git")):
            break
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    return None


def load_config():
    """Load config: defaults <- ~/.fix/config.py <- .fix.py (project-local).

    Config files are Python. Set variables, define functions.
    A `def agent(contract)` becomes the custom backend.
    A `verify = "pytest"` sets the default verification command.
    """
    cfg = dict(DEFAULTS)

    # Global config
    global_path = os.path.join(CONFIG_DIR, "config.py")
    global_cfg = _exec_config(global_path)
    cfg.update(global_cfg)

    # Project-local config (overrides global)
    project_path = _find_project_config()
    if project_path:
        project_cfg = _exec_config(project_path)
        cfg.update(project_cfg)
        cfg["_project_config"] = project_path

    return cfg


def generate_config():
    """Generate a .fix.py in CWD with sensible defaults for the project type."""
    lines = ['# .fix.py -- project config for fix (https://github.com/karans4/fix)', '']

    # Detect project type
    cwd = os.getcwd()
    if os.path.exists(os.path.join(cwd, "pyproject.toml")) or os.path.exists(os.path.join(cwd, "setup.py")):
        lines.append('# Python project detected')
        if os.path.isdir(os.path.join(cwd, "tests")):
            lines.append('verify = "python3 -m pytest tests/"')
        else:
            lines.append('# verify = "python3 -m pytest"')
    elif os.path.exists(os.path.join(cwd, "package.json")):
        lines.append('# Node.js project detected')
        lines.append('verify = "npm test"')
    elif os.path.exists(os.path.join(cwd, "Cargo.toml")):
        lines.append('# Rust project detected')
        lines.append('verify = "cargo test"')
    elif os.path.exists(os.path.join(cwd, "go.mod")):
        lines.append('# Go project detected')
        lines.append('verify = "go test ./..."')
    elif os.path.exists(os.path.join(cwd, "Makefile")):
        lines.append('# Makefile detected')
        lines.append('verify = "make test"')
    else:
        lines.append('# verify = "make test"  # default verification command')

    lines += [
        '',
        '# --- Defaults (uncomment to override) ---',
        '',
        'safe_mode = "auto"          # "auto" = True on Linux, False elsewhere',
        'backend = "auto"          # "auto", "local" (ollama), "claude", "openai"',
        f'model = "{CLAUDE_MODEL}"',
        f'ollama_model = "{OLLAMA_MODEL}"',
        f'ollama_url = "{OLLAMA_URL}"',
        '# openai_api_url = ""    # any OpenAI-compatible endpoint',
        '# openai_model = ""',
        '# root = None            # restrict agent investigation to this directory',
        '',
        '# --- Sandbox visibility ---',
        '',
        'hidden_paths = [',
        '    "~/.ssh", "~/.gnupg", "~/.aws", "~/.fix",',
        '    "~/.config/gh", "~/.netrc", "~/.azure", "~/.kube",',
        '    "~/.docker", "~/.gitconfig", "~/.bash_history",',
        '    "~/.python_history",',
        ']',
        '',
        '# --- Scrubbing (v2) ---',
        '# Categories: "env_vars", "tokens", "paths", "ips", "emails"',
        '',
        'redaction_categories = ["env_vars", "tokens", "paths", "ips", "emails"]',
        '# redaction_custom_patterns = [',
        '#     (r"myproject-\\d+", "[PROJECT_ID]"),',
        '# ]',
        '',
        '# --- Remote mode (v2) ---',
        '',
        '# bounty = "0.01"        # USDC on Base, paid on fulfilled contract',
        '# remote = False         # enable Nostr relay + escrow',
        '# platform_url = "https://fix.notruefireman.org"',
        '',
        '# --- Custom agent ---',
        '# Receives contract dict, returns fix dict.',
        '#',
        '# def agent(contract):',
        '#     import httpx',
        '#     return httpx.post("https://my-service/fix", json=contract).json()',
        '',
    ]

    with open(".fix.py", "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"Created .fix.py ({os.path.basename(os.getcwd())})")
    return


# fc -ln -2 works for bash/ksh/dash (POSIX). head -1 grabs the one before "fix it" itself.
_POSIX_HOOK = """\
fix() {
  if [ "$1" = "it" ] || [ "$1" = "!!" ]; then
    FIX_LAST_COMMAND="$(fc -ln -2 | head -1 | sed 's/^[[:space:]]*//')" command fix "$@"
  else
    command fix "$@"
  fi
}"""

SHELL_HOOKS = {
    "bash": _POSIX_HOOK,
    "ksh":  _POSIX_HOOK,
    "dash": _POSIX_HOOK,
    "sh":   _POSIX_HOOK,
    "zsh": """\
fix() {
  if [[ "$1" == "it" || "$1" == "!!" ]]; then
    FIX_LAST_COMMAND="${history[$((HISTCMD-1))]}" command fix "$@"
  else
    command fix "$@"
  fi
}""",
    "fish": """\
function fix --wraps=fix --description 'AI command fixer'
    if test (count $argv) -gt 0; and test "$argv[1]" = "it" -o "$argv[1]" = "!!"
        set -lx FIX_LAST_COMMAND (builtin history search --max 1 --prefix "")
        command fix $argv
    else
        command fix $argv
    end
end""",
}

# Shell name -> (rc file path, eval line to append)
_RC_FILES = {
    "bash": ("~/.bashrc",                      'eval "$(fix shell)"'),
    "zsh":  ("~/.zshrc",                        'eval "$(fix shell)"'),
    "ksh":  ("~/.kshrc",                        'eval "$(fix shell)"'),
    "dash": ("~/.profile",                      'eval "$(fix shell)"'),
    "sh":   ("~/.profile",                      'eval "$(fix shell)"'),
    "fish": ("~/.config/fish/config.fish",       'fix shell fish | source'),
}


def _detect_shell():
    """Detect the actual running shell, not just $SHELL (login shell).

    1. Check parent process name via /proc/$PPID/comm (Linux)
    2. Fall back to ps(1)
    3. Fall back to $SHELL env var
    Returns the short name: bash, zsh, fish, ksh, dash, etc.
    """
    ppid = os.getppid()

    # Try /proc (Linux, fast)
    try:
        with open(f"/proc/{ppid}/comm") as f:
            name = f.read().strip()
        if name:
            return name
    except (OSError, IOError):
        pass

    # Try ps (macOS, BSDs)
    try:
        result = subprocess.run(["ps", "-p", str(ppid), "-o", "comm="],
                                capture_output=True, text=True, timeout=2)
        if result.returncode == 0:
            name = os.path.basename(result.stdout.strip()).lstrip("-")
            if name:
                return name
    except Exception:
        pass

    # Fall back to $SHELL
    return os.path.basename(os.environ.get("SHELL", "bash"))


def _rc_path(name):
    """Return the rc file path for a shell."""
    path, _ = _RC_FILES.get(name, _RC_FILES["bash"])
    return os.path.expanduser(path)


def _rc_eval_line(name):
    """Return the eval line to add to the rc file."""
    _, line = _RC_FILES.get(name, _RC_FILES["bash"])
    return line


def shell_hook():
    """Print shell integration code for eval."""
    # Allow explicit: fix shell bash / fix shell zsh / fix shell fish
    if len(sys.argv) > 2 and sys.argv[2] != "--install":
        name = sys.argv[2]
    else:
        name = _detect_shell()

    if name in SHELL_HOOKS:
        print(SHELL_HOOKS[name])
    else:
        # Unknown shell — explain what's needed
        print(f"# fix: no built-in hook for '{name}'.", file=sys.stderr)
        print(f"# Set FIX_LAST_COMMAND to the previous command before calling fix.", file=sys.stderr)
        print(f"# Example (POSIX-like shells):", file=sys.stderr)
        print(f"#   FIX_LAST_COMMAND=\"your_cmd\" fix it", file=sys.stderr)
        print(f"#", file=sys.stderr)
        print(f"# If '{name}' supports fc(1), the bash hook will likely work:", file=sys.stderr)
        print(f"#   eval \"$(fix shell bash)\"", file=sys.stderr)
        sys.exit(1)


def shell_install():
    """Auto-append shell hook to the user's rc file. Returns True if installed."""
    name = _detect_shell()

    if name not in SHELL_HOOKS:
        print(f"  {C_DIM}Unknown shell: {name}{C_RESET}", file=sys.stderr)
        print(f"  {C_DIM}If it supports fc(1), try: eval \"$(fix shell bash)\"{C_RESET}", file=sys.stderr)
        print(f"  {C_DIM}Otherwise, set FIX_LAST_COMMAND before calling fix it.{C_RESET}", file=sys.stderr)
        return False

    rc = _rc_path(name)
    eval_line = _rc_eval_line(name)

    # Check if already installed
    if os.path.exists(rc):
        with open(rc) as f:
            contents = f.read()
        if 'fix shell' in contents:
            return True  # already there

    try:
        response = input(f"  Add shell hook to {rc}? [Y/n] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    if response and response != "y":
        return False

    os.makedirs(os.path.dirname(rc) or ".", exist_ok=True)
    with open(rc, "a") as f:
        f.write(f"\n# fix shell integration (https://github.com/karans4/fix)\n{eval_line}\n")
    print(f"  Added to {rc}. Restart your shell or: source {rc}")
    return True


# --- Environment Fingerprinting ---

def get_env_fingerprint():
    info = {
        "os": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "distro": "",
        "shell": os.environ.get("SHELL", ""),
        "python": platform.python_version(),
    }
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    info["distro"] = line.split("=", 1)[1].strip().strip('"')
                    break
    except FileNotFoundError:
        pass

    pms = [pm for pm in ("apt", "dnf", "pacman", "brew", "pip", "npm", "cargo")
           if shutil.which(pm)]
    info["package_managers"] = pms
    return info


# --- Verification ---

def _input_with_countdown(prompt_tpl, timeout, default="y"):
    """Prompt with a live countdown. Returns the answer or default on timeout.

    prompt_tpl should contain {} for the remaining seconds, e.g.:
        "  ?  Did this fix your problem? [Y/n] ({}s) "
    """
    import select
    for remaining in range(timeout, 0, -1):
        sys.stderr.write(f"\r{prompt_tpl.format(remaining)}")
        sys.stderr.flush()
        ready, _, _ = select.select([sys.stdin], [], [], 1.0)
        if ready:
            answer = sys.stdin.readline().rstrip("\n")
            return answer if answer else default
    sys.stderr.write(f"\r{prompt_tpl.format(0)} auto: {default}     \n")
    sys.stderr.flush()
    return default


class Verifier:
    """Verification predicate: did the fix work?"""

    def __init__(self, spec, original_cmd):
        self.spec = spec
        self.original_cmd = original_cmd

    def verify(self, fix_result):
        """Returns (success: bool, explanation: str)"""
        if self.spec is None:
            # Default: re-run original, exit 0 = success
            return self._verify_rerun()
        if self.spec == "human":
            return self._verify_human(fix_result)
        if self.spec.startswith("contains "):
            return self._verify_contains(fix_result)
        if self.spec.startswith("not contains "):
            return self._verify_not_contains(fix_result)
        # Treat as custom verification command
        return self._verify_command(self.spec)

    def _verify_rerun(self):
        proc = subprocess.run(self.original_cmd, shell=True, capture_output=True, text=True)
        if proc.returncode == 0:
            return True, "Command succeeded (exit 0)"
        return False, f"Command failed (exit {proc.returncode}): {proc.stderr[:200]}"

    def _verify_human(self, fix_result):
        # Re-run original to show current output (skip for task mode / no-op commands)
        if self.original_cmd and self.original_cmd != "true":
            print(f"\n{C_BLUE}--- Fix Result ---{C_RESET}", file=sys.stderr)
            proc = subprocess.run(self.original_cmd, shell=True, capture_output=True, text=True)
            if proc.stdout:
                sys.stdout.write(proc.stdout)
            if proc.stderr:
                sys.stderr.write(proc.stderr)
            print(f"{C_BLUE}--- End Result ---{C_RESET}\n", file=sys.stderr)
        try:
            answer = _input_with_countdown(
                f"  ?  Contract fulfilled? [Y/n] ({{}}s) ",
                HUMAN_VERIFY_TIMEOUT,
                default="y",
            )
            if answer.strip().lower() == "n":
                # Ask why (short window, move on if nothing typed)
                import select
                sys.stderr.write(f"  ?  Why? (enter to skip) ")
                sys.stderr.flush()
                ready, _, _ = select.select([sys.stdin], [], [], 15)
                if ready:
                    reason = sys.stdin.readline().rstrip("\n").strip()
                else:
                    reason = ""
                    sys.stderr.write("\n")
                return False, f"Human rejected: {reason}" if reason else "Human rejected the result"
            return True, "Human approved the result" + (" (auto)" if answer == "y" and not sys.stdin.isatty() else "")
        except (EOFError, KeyboardInterrupt):
            return False, "No human input"

    def _verify_contains(self, fix_result):
        # Extract expected string from spec: contains 'X' or contains "X"
        match = re.match(r"contains\s+['\"](.+?)['\"]", self.spec)
        if not match:
            return False, f"Bad verify spec: {self.spec}"
        expected = match.group(1)
        proc = subprocess.run(self.original_cmd, shell=True, capture_output=True, text=True)
        if expected in proc.stdout:
            return True, f"stdout contains '{expected}'"
        return False, f"stdout does not contain '{expected}'"

    def _verify_not_contains(self, fix_result):
        match = re.match(r"not contains\s+['\"](.+?)['\"]", self.spec)
        if not match:
            return False, f"Bad verify spec: {self.spec}"
        forbidden = match.group(1)
        proc = subprocess.run(self.original_cmd, shell=True, capture_output=True, text=True)
        if forbidden in proc.stderr or forbidden in proc.stdout:
            return False, f"Output contains '{forbidden}'"
        return True, f"Output does not contain '{forbidden}'"

    def _verify_command(self, cmd):
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if proc.returncode == 0:
            return True, f"Verification command passed"
        return False, f"Verification command failed (exit {proc.returncode})"


class SandboxVerifier(Verifier):
    """Runs verification inside the sandbox."""

    def __init__(self, spec, original_cmd, sandbox):
        super().__init__(spec, original_cmd)
        self.sandbox = sandbox

    def _verify_rerun(self):
        result = self.sandbox.run_in_sandbox(self.original_cmd, network=True)
        if result.returncode == 0:
            return True, "Command succeeded in sandbox (exit 0)"
        return False, f"Command failed in sandbox (exit {result.returncode})"

    def _verify_command(self, cmd):
        result = self.sandbox.run_in_sandbox(cmd, network=True)
        if result.returncode == 0:
            return True, "Verification passed in sandbox"
        return False, f"Verification failed in sandbox (exit {result.returncode})"


# --- LLM Backends ---

def call_claude(prompt, api_key, model=None, api_url=None):
    import httpx
    resp = httpx.post(
        api_url or CLAUDE_API_URL,
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json={
            "model": model or CLAUDE_MODEL,
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": prompt}],
        },
        timeout=30,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"Claude API error {resp.status_code}: {resp.text[:200]}")
    return resp.json()["content"][0]["text"]


def call_openai(prompt, api_key, model, api_url):
    """Call any OpenAI-compatible API (OpenAI, Together, Groq, etc.)."""
    import httpx
    resp = httpx.post(
        api_url.rstrip("/") + "/chat/completions",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": prompt}],
        },
        timeout=30,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"OpenAI-compatible API error {resp.status_code}: {resp.text[:200]}")
    return resp.json()["choices"][0]["message"]["content"]


def call_ollama(prompt, model=None, url=None):
    import httpx
    resp = httpx.post(
        url or OLLAMA_URL,
        json={"model": model or OLLAMA_MODEL, "prompt": prompt, "stream": False},
        timeout=60,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"Ollama error {resp.status_code}: {resp.text[:200]}")
    return resp.json()["response"]


def ollama_available(url=None):
    try:
        import httpx
        base = (url or OLLAMA_URL).split("/api/")[0]
        resp = httpx.get(base + "/api/tags", timeout=2)
        return resp.status_code == 200
    except Exception:
        return False


def get_api_key(key_type="anthropic"):
    """Look up API key: env var > key file > config."""
    env_vars = {
        "anthropic": "ANTHROPIC_API_KEY",
        "openai": "OPENAI_API_KEY",
        "custom": "FIX_API_KEY",
    }
    key = os.environ.get(env_vars.get(key_type, ""), "")
    if not key:
        keyfile = os.path.join(CONFIG_DIR, f"{key_type}_key" if key_type != "anthropic" else "api_key")
        if os.path.exists(keyfile):
            with open(keyfile) as f:
                key = f.read().strip()
    return key


def resolve_backend(cfg, force_local=False):
    """Determine which backend to use.

    Priority: custom agent fn > explicit flag > env var > config > auto-detect
    Returns: (backend_name, call_fn_kwargs)
    """
    # Custom agent function from config (def agent(contract) in .fix.py)
    agent_fn = cfg.get("agent")
    if callable(agent_fn) and not force_local:
        return "custom", {"fn": agent_fn}

    if force_local:
        if ollama_available(cfg.get("ollama_url")):
            return "ollama", {"model": cfg.get("ollama_model"), "url": cfg.get("ollama_url")}
        raise RuntimeError("Ollama not running (--local requested)")

    # Check for custom OpenAI-compatible endpoint
    custom_url = os.environ.get("FIX_API_URL") or cfg.get("openai_api_url")
    custom_key = os.environ.get("FIX_API_KEY") or get_api_key("custom")
    custom_model = os.environ.get("FIX_MODEL") or cfg.get("openai_model")
    if custom_url and custom_key and custom_model:
        return "openai-compat", {"api_key": custom_key, "model": custom_model, "api_url": custom_url}

    # OpenAI
    openai_key = get_api_key("openai")
    if openai_key:
        return "openai", {"api_key": openai_key, "model": "gpt-4o-mini",
                          "api_url": "https://api.openai.com/v1"}

    # Claude (default cloud)
    claude_key = get_api_key("anthropic")
    if claude_key:
        return "claude", {"api_key": claude_key, "model": cfg.get("model", CLAUDE_MODEL),
                          "api_url": cfg.get("claude_api_url", CLAUDE_API_URL)}

    # Ollama fallback
    if ollama_available(cfg.get("ollama_url")):
        return "ollama", {"model": cfg.get("ollama_model"), "url": cfg.get("ollama_url")}

    raise RuntimeError("No LLM backend available. Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or start Ollama.")


# --- Contract ---

if _HAS_V2:
    def build_contract(command, stderr_text, env_info,
                       verify_spec=None, safe_mode=False, backend_name="",
                       attempt=0, prior_failures=None, root=None,
                       bounty=None, judge=None):
        """Build contract — delegates to contract module (v2)."""
        contract = build_contract_v2(
            command, stderr_text, env_info,
            verify_spec=verify_spec, safe_mode=safe_mode,
            backend_name=backend_name, attempt=attempt,
            prior_failures=prior_failures, root=root,
            bounty=bounty, judge=judge,
        )
        return contract
else:
    def build_contract(command, stderr_text, env_info,
                       verify_spec=None, safe_mode=False, backend_name="",
                       attempt=0, prior_failures=None, root=None,
                       bounty=None, judge=None):
        """Build a contract object that both parties see and agree to."""
        # Verification terms
        if verify_spec is None:
            verification = {
                "method": "exit_code",
                "target": command,
                "criterion": "exit 0"
            }
        elif verify_spec == "human":
            verification = {
                "method": "human_judgment",
                "target": command,
                "criterion": "human approves the output"
            }
        elif verify_spec.startswith("contains "):
            match = re.match(r"contains\s+['\"](.+?)['\"]", verify_spec)
            verification = {
                "method": "output_match",
                "target": command,
                "criterion": f"stdout contains '{match.group(1)}'" if match else verify_spec
            }
        elif verify_spec.startswith("not contains "):
            match = re.match(r"not contains\s+['\"](.+?)['\"]", verify_spec)
            verification = {
                "method": "output_exclusion",
                "target": command,
                "criterion": f"output must not contain '{match.group(1)}'" if match else verify_spec
            }
        else:
            verification = {
                "method": "custom_command",
                "target": verify_spec,
                "criterion": "verification command exits 0"
            }

        contract = {
            "version": 1,
            "task": {
                "type": "fix_command",
                "command": command,
                "error": stderr_text[-1000:],
            },
            "environment": {
                "os": f"{env_info.get('distro', '')} ({env_info['os']} {env_info['release']})",
                "arch": env_info["machine"],
                "shell": env_info["shell"],
                "package_managers": env_info.get("package_managers", []),
            },
            "verification": verification,
            "terms": {
                "sandbox": safe_mode,
                "network": "package_installs_only" if safe_mode else "unrestricted",
                "max_attempts": MAX_FIX_ATTEMPTS,
                "current_attempt": attempt + 1,
                "rollback_on_failure": safe_mode,
                "root": os.path.realpath(root) if root else None,
            },
            "agent": {
                "backend": backend_name,
            },
        }

        if bounty:
            contract["escrow"] = {
                "bounty": bounty,
                "judge": "provided" if judge else "none",
                "terms": "Agent receives bounty on fulfilled contract. "
                         "On breach, bounty is retained by principal. "
                         + ("Disputes are resolved by a third-party judge." if judge else
                            "No dispute resolution — verification is final."),
            }

        if prior_failures:
            contract["prior_failures"] = [
                {"fix": fix, "result": err[:300]}
                for fix, err in prior_failures
            ]

        return contract


def _get_signing_key():
    """Load or generate a 256-bit HMAC key at ~/.fix/key."""
    import hashlib, hmac
    keyfile = os.path.join(CONFIG_DIR, "key")
    if os.path.exists(keyfile):
        with open(keyfile, "rb") as f:
            return f.read()
    os.makedirs(CONFIG_DIR, exist_ok=True)
    key = os.urandom(32)
    with open(keyfile, "wb") as f:
        f.write(key)
    os.chmod(keyfile, 0o600)
    return key


def sign_contract(contract):
    """Hash and HMAC-sign a contract. Returns (sha256_hex, signature_hex).

    The hash is over the canonical JSON (sorted keys, no whitespace).
    The signature is HMAC-SHA256 with the local key at ~/.fix/key.
    """
    import hashlib, hmac
    canonical = json.dumps(contract, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    key = _get_signing_key()
    sig = hmac.new(key, canonical.encode(), hashlib.sha256).hexdigest()
    return digest, sig


def display_contract(contract, status_fn):
    """Print the full contract to the user's terminal."""
    W = 60  # inner width
    is_v2 = contract.get("version", 1) >= 2

    # Sign
    digest, sig = sign_contract(contract)

    # Header
    f = sys.stderr
    print(file=f)
    print(f"  {C_CYAN}\u250c{'─' * W}\u2510{C_RESET}", file=f)
    _is_task = contract.get("task", {}).get("type") == "task"
    title = f"FIX TASK v{contract.get('version', 1)}" if _is_task else f"FIX CONTRACT v{contract.get('version', 1)}"
    pad = W - len(title)
    print(f"  {C_CYAN}\u2502{C_RESET}{C_BOLD}  {title}{' ' * (pad - 2)}{C_CYAN}\u2502{C_RESET}", file=f)
    print(f"  {C_CYAN}\u251c{'─' * W}\u2524{C_RESET}", file=f)

    def row(label, value, color=C_RESET):
        # Truncate long values to fit
        label_w = 14
        val_w = W - label_w - 4
        val_str = str(value)
        if len(val_str) > val_w:
            val_str = val_str[:val_w - 1] + "\u2026"
        print(f"  {C_CYAN}\u2502{C_RESET}  {C_DIM}{label:>{label_w}}{C_RESET}  {color}{val_str}{C_RESET}"
              f"{' ' * max(0, W - label_w - len(val_str) - 4)}{C_CYAN}\u2502{C_RESET}", file=f)

    def separator():
        print(f"  {C_CYAN}\u251c{'─' * W}\u2524{C_RESET}", file=f)

    # Task
    is_task = contract["task"].get("type") == "task"
    if is_task:
        row("task", contract["task"]["task"], C_BOLD)
    else:
        row("command", contract["task"]["command"], C_BOLD)
        error = contract["task"].get("error", "")
        if error:
            err_lines = [l.strip() for l in error.strip().splitlines() if l.strip()]
            err_display = err_lines[-1] if err_lines else error[:80]
            row("error", err_display, C_RED)

    separator()

    # Environment
    env = contract.get("environment", {})
    row("os", env.get("os", "unknown"))
    row("arch", env.get("arch", "unknown"))
    if env.get("package_managers"):
        row("pkg managers", ", ".join(env["package_managers"]))

    # Capabilities (v2 only)
    if is_v2 and contract.get("capabilities"):
        caps = contract["capabilities"]
        avail = [k for k, v in caps.items() if v.get("available")]
        unavail = [k for k, v in caps.items() if not v.get("available")]
        if avail:
            row("available", ", ".join(avail), C_GREEN)
        if unavail:
            row("unavailable", ", ".join(unavail), C_DIM)

    separator()

    # Verification
    if is_v2:
        for v in contract.get("verification", []):
            method = v.get("method", "exit_code")
            detail = v.get("pattern", v.get("expected", ""))
            row("verify", f"{method}" + (f" ({detail})" if detail else ""))
    else:
        v = contract.get("verification", {})
        row("verify", f"{v.get('method', '?')}: {v.get('criterion', '?')}")

    # Execution / Terms
    if is_v2:
        exe = contract.get("execution", {})
        row("sandbox", "yes" if exe.get("sandbox") else "no")
        row("max attempts", exe.get("max_attempts", 3))
        row("timeout", f"{exe.get('timeout', 300)}s")
        if exe.get("root"):
            row("root jail", exe["root"])
    else:
        t = contract.get("terms", {})
        row("sandbox", "yes" if t.get("sandbox") else "no")
        row("network", t.get("network", "unrestricted"))
        row("attempt", f"{t.get('current_attempt', '?')} of {t.get('max_attempts', '?')}")
        if t.get("root"):
            row("root jail", t["root"])

    # Redaction (v2)
    if is_v2 and contract.get("redaction", {}).get("enabled"):
        cats = contract["redaction"].get("categories", [])
        row("redaction", ", ".join(cats), C_YELLOW)

    # Escrow
    if contract.get("escrow"):
        separator()
        e = contract["escrow"]
        bounty_str = e.get("bounty", "?")
        if is_v2:
            bounty_str += f" {e.get('currency', 'USDC')} on {e.get('chain', 'base')}"
        row("bounty", bounty_str, C_GREEN)
        if is_v2 and contract.get("terms"):
            ct = contract["terms"]
            if ct.get("dispute"):
                row("dispute", ct["dispute"].get("method", "none"))
            if ct.get("cancellation"):
                row("cancel fee", ct["cancellation"].get("agent_fee", "?"))

    # Prior failures
    if contract.get("prior_failures"):
        separator()
        n = len(contract["prior_failures"])
        row("prior fails", f"{n} failed attempt{'s' if n != 1 else ''}", C_YELLOW)

    # Signature block
    separator()
    row("sha256", digest[:32] + "\u2026", C_DIM)
    row("sig", sig[:32] + "\u2026", C_DIM)
    row("issued", time.strftime("%Y-%m-%d %H:%M:%S %Z"), C_DIM)

    # Footer
    print(f"  {C_CYAN}\u2514{'─' * W}\u2518{C_RESET}", file=f)


def build_prompt(command, stderr_text, env_info, contract, prior_failures=None, message=None):
    # Strip internal fields the agent doesn't need to see
    prompt_contract = contract_for_prompt(contract) if _HAS_V2 else {k: v for k, v in contract.items() if k != "agent"}
    contract_json = json.dumps(prompt_contract, indent=2)
    is_v2 = contract.get("version", 1) >= 2

    # Extract verification/execution info for prompt text (handles both v1 and v2)
    if is_v2:
        vlist = contract.get("verification", [])
        v0 = vlist[0] if vlist else {}
        verify_method = v0.get("method", "exit_code")
        verify_criterion = v0.get("pattern", v0.get("expected", "exit 0"))
        verify_target = command
        exe = contract.get("execution", {})
        sandbox = exe.get("sandbox", False)
        network = "package_installs_only" if sandbox else "unrestricted"
        max_attempts = exe.get("max_attempts", 3)
        root = exe.get("root")
        rollback = sandbox
    else:
        v = contract["verification"]
        verify_method = v["method"]
        verify_criterion = v["criterion"]
        verify_target = v["target"]
        t = contract["terms"]
        sandbox = t["sandbox"]
        network = t["network"]
        max_attempts = t["max_attempts"]
        root = t.get("root")
        rollback = t.get("rollback_on_failure", sandbox)

    # Task-only mode: --msg without a real failing command
    task_mode = message and (command == "true" or (not stderr_text.strip()))

    if task_mode:
        preamble = f"""The following is a task contract from the `fix` system. You may accept
or deny it. If you accept, propose commands to accomplish the task. If you
deny, explain why.

=== TASK ===
{message}

=== SYSTEM ===
{contract_json}"""
    else:
        preamble = f"""The following is a fix contract from the `fix` system. A command has
failed on the system described below. You may accept or deny this contract.
If you accept, you must deliver a fix that satisfies the verification terms.
The fix will be tested mechanically — there is no negotiation after acceptance.

=== FAILED COMMAND ===
{command}

=== ERROR ===
{stderr_text[:500] if stderr_text else '(no stderr)'}

=== CONTRACT ===
{contract_json}"""

    prompt = f"""{preamble}

=== OBLIGATIONS ===

1. ACCEPTANCE: Set "accepted": true to accept, or false to decline.
   If declining, explain why in "explanation".

2. DELIVERABLE: Provide shell command(s) in the "fix" field that {"accomplish the task" if task_mode else "resolve the root cause"}. Chain with && where possible.{'' if task_mode else ' Fix causes, not symptoms.'}

3. VERIFICATION: After applying, the result is verified:
   - Method: {verify_method}
   - Criterion: {verify_criterion}
   - Target: {verify_target}
   If verification fails, the attempt is marked as failed. {'All filesystem changes are rolled back.' if rollback else 'Changes persist.'}

4. CONSTRAINTS:
   - {'SANDBOXED: Runs in overlay filesystem. Committed only if verification passes.' if sandbox else 'DIRECT: Runs directly on the system.'}
   - Network: {network}
   - Max attempts: {max_attempts}
   - Keep it minimal.
   - Only use capabilities marked available in the contract.{chr(10) + '   - sudo is NOT available. Do not use sudo.' if not contract.get('capabilities', {}).get('sudo', {}).get('available') else ''}

=== INVESTIGATION ===

There are two phases:

1. INVESTIGATION (optional, read-only): Gather information before acting.
   Output lines starting with INVESTIGATE: to run read-only commands.
   Example:
       INVESTIGATE: python3 --version
       INVESTIGATE: cat foo.c
       INVESTIGATE: dpkg -l | grep libfoo
   Only read-only commands are allowed here (cat, ls, grep, which, dpkg, etc.).
   No writes, no redirections. Results are appended and you are re-prompted.
{"   Commands jailed to root: " + root + ". Use relative paths." if root else ""}

2. ACTION: When ready, respond with your JSON object. The "fix" field contains
   the shell commands that will be executed. These CAN write files, install
   packages, and make any changes needed. {'They run in a sandbox — changes' + chr(10) + '   are only committed if verification passes.' if sandbox else 'They run directly on the system.'}

Do not attempt writes during investigation — save all actions for the "fix" field.
Skip investigation if the {"task" if task_mode else "fix"} is obvious.

=== RESPONSE FORMAT ===

When ready, respond with a JSON object (no markdown fences, no commentary outside it):

{{"accepted": true, "fix": "shell command(s)", "explanation": "one line why"{', "retry": true' if not task_mode else ''}}}
{'"retry" indicates whether the original command should be re-run after the fix.' if not task_mode else ''}"""

    if message and not task_mode:
        prompt += f"\n\n=== NOTE ===\n{message}"

    if prior_failures:
        prompt += "\n\n=== PRIOR ATTEMPTS (FAILED) ===\n"
        prompt += "These fixes were tried and failed verification. Do not repeat them.\n"
        for i, (fix, err) in enumerate(prior_failures, 1):
            prompt += f"\nAttempt {i}:\n  Fix: {fix}\n  Result: {err[:300]}\n"

    return prompt


def build_explain_prompt(command, stderr_text, env_info):
    return f"""A command failed. Explain what went wrong in 2-3 sentences.
Be specific and actionable. Don't suggest a fix, just explain the error.

COMMAND: {command}

ERROR:
{stderr_text[-2000:]}

SYSTEM: {env_info.get('distro', '')} ({env_info['os']}) {env_info['machine']}"""


def parse_llm_response(raw):
    text = raw.strip()
    if text.startswith("```"):
        text = "\n".join(text.split("\n")[1:])
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()
    if not text.startswith("{"):
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            text = text[start:end]
    return json.loads(text)


def _call_backend(prompt, backend_name, backend_kwargs, contract=None):
    """Single-shot call to a backend. Returns raw text."""
    if backend_name == "custom":
        fn = backend_kwargs["fn"]
        result = fn(contract or {})
        if isinstance(result, dict):
            return json.dumps(result)
        return result
    elif backend_name == "claude":
        return call_claude(prompt, **backend_kwargs)
    elif backend_name in ("openai", "openai-compat"):
        return call_openai(prompt, **backend_kwargs)
    elif backend_name == "ollama":
        return call_ollama(prompt, **backend_kwargs)
    raise RuntimeError(f"Unknown backend: {backend_name}")


def call_llm(prompt, backend_name, backend_kwargs, contract=None):
    """Call LLM with investigation loop. Any backend can investigate.

    If the response contains INVESTIGATE: <command> lines, we run each
    command, append the results to the prompt, and re-call. Up to
    MAX_INVESTIGATE_ROUNDS total rounds.
    """
    current_prompt = prompt
    root = contract.get("terms", {}).get("root") if contract else None

    for round_n in range(MAX_INVESTIGATE_ROUNDS + 1):
        raw = _call_backend(current_prompt, backend_name, backend_kwargs, contract)

        # Check for investigation requests
        commands = INVESTIGATE_RE.findall(raw)
        if not commands or round_n >= MAX_INVESTIGATE_ROUNDS:
            return raw

        # Run each investigation command, build results
        results = []
        for cmd in commands:
            cmd = cmd.strip()
            status(f"\U0001f50d", f"{C_DIM}{cmd}{C_RESET}")
            output = run_investigate_command(cmd, root=root)
            if output.strip():
                for line in output.strip().splitlines()[:10]:
                    print(f"  {C_DIM}    {line}{C_RESET}", file=sys.stderr)
                if len(output.strip().splitlines()) > 10:
                    print(f"  {C_DIM}    ... ({len(output.strip().splitlines()) - 10} more lines){C_RESET}", file=sys.stderr)
            results.append(f"$ {cmd}\n{output}")

        # Re-prompt with investigation results appended
        investigation_block = "\n\n".join(results)
        current_prompt = (
            f"{current_prompt}\n\n"
            f"=== INVESTIGATION RESULTS ===\n"
            f"{investigation_block}\n\n"
            f"Continue investigating or respond with your JSON fix object."
        )

    return raw


# --- Shell History (fix !!) ---

def get_last_failed_command():
    """Get the last command from shell history.

    Reads bash/zsh history file. Falls back to HISTFILE env var.
    """
    histfile = os.environ.get("HISTFILE")
    if not histfile:
        shell = os.environ.get("SHELL", "")
        if "zsh" in shell:
            histfile = os.path.expanduser("~/.zsh_history")
        else:
            histfile = os.path.expanduser("~/.bash_history")

    if not os.path.exists(histfile):
        return None

    try:
        with open(histfile, "rb") as f:
            # Read last few KB (history can be huge)
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - 8192))
            data = f.read().decode("utf-8", errors="replace")

        lines = data.strip().splitlines()
        # Filter out 'fix' commands and empty lines
        for line in reversed(lines):
            line = line.strip()
            # zsh history format: ": timestamp:0;command"
            if line.startswith(":") and ";" in line:
                line = line.split(";", 1)[1]
            if line and not line.startswith("fix ") and line != "fix" and line != "claude":
                return line
    except Exception:
        pass
    return None


# --- Sandbox ---

ALLOWED_PATHS = {
    "python-pkg": ["/usr/lib/python*", "/usr/local/lib/python*", "/usr/share/python*",
                   "/var/lib/dpkg", "/var/cache/apt", "/var/lib/apt", "/etc/apt"],
    "system-pkg": ["/usr/bin/*", "/usr/lib/*", "/usr/share/*", "/var/lib/dpkg*",
                   "/var/cache/apt*", "/var/cache/debconf*", "/var/lib/apt*",
                   "/var/log/dpkg*", "/var/log/apt*", "/var/lib/update-notifier*",
                   "/etc/apt*", "/etc/ld.so.*"],
    "compiler": ["/usr/include/*", "/usr/lib/gcc/*", "/usr/bin/gcc*", "/usr/bin/cc*", "/tmp/*"],
}
DEFAULT_ALLOWED = [p for paths in ALLOWED_PATHS.values() for p in paths]


class Sandbox:
    """Overlay-only sandbox (Linux only).
    Uses OverlayFS — kernel COW, tries unprivileged first, sudo fallback.
    """

    DEFAULT_HIDDEN = [".ssh", ".gnupg", ".fix", ".config/gh", ".netrc", ".aws",
                      ".azure", ".kube", ".docker", ".gitconfig", ".bash_history",
                      ".python_history"]

    # Dirs to overlay (writes here get captured)
    TARGETS_LINUX = ["/usr", "/var", "/etc", "/home"]

    def __init__(self, allowed_paths=None, hidden_paths=None, visible_paths=None, user_home=None):
        self.workdir = None
        self.allowed_paths = allowed_paths or DEFAULT_ALLOWED
        self.user_home = user_home or self._detect_home()
        if hidden_paths:
            self.hidden_paths = [self._resolve_path(p) for p in hidden_paths]
        else:
            self.hidden_paths = [os.path.join(self.user_home, p) for p in self.DEFAULT_HIDDEN]
        self.visible_paths = [self._resolve_path(p) for p in (visible_paths or [])]
        self.backend = None  # set by setup(): "overlay"
        # overlay backend state
        self.overlay_dirs = []
        self._empty_dir = None
        self._use_sudo = False

    @staticmethod
    def _is_linux():
        return platform.system() == "Linux"

    def _detect_home(self):
        sudo_user = os.environ.get("SUDO_USER")
        if sudo_user:
            try:
                import pwd
                return pwd.getpwnam(sudo_user).pw_dir
            except (KeyError, ImportError):
                pass
        return os.path.expanduser("~")

    def _resolve_path(self, p):
        if p.startswith("~/"):
            return os.path.join(self.user_home, p[2:])
        return os.path.expanduser(p)

    def _resolve_hidden_paths(self):
        if self.visible_paths:
            hide = []
            for entry in os.listdir(self.user_home):
                full = os.path.join(self.user_home, entry)
                if not any(full == v or full.startswith(v + "/") for v in self.visible_paths):
                    hide.append(full)
            return hide
        return [p for p in self.hidden_paths if os.path.exists(p)]

    def _run(self, cmd, **kwargs):
        """Run a shell command, using sudo if needed."""
        if self._use_sudo:
            password = os.environ.get("SUDO_PASSWORD", "")
            if password:
                cmd = f"echo '{password}' | sudo -S {cmd}"
            else:
                cmd = f"sudo {cmd}"
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, **kwargs)

    # --- Backend detection ---

    def _try_overlay_unprivileged(self):
        """Try overlayfs in a user namespace (no root needed)."""
        import tempfile
        test_dir = tempfile.mkdtemp(prefix="fix-overlay-test-")
        try:
            for d in ["lower", "upper", "work", "merged"]:
                os.makedirs(os.path.join(test_dir, d))
            # Write a test file in lower
            with open(os.path.join(test_dir, "lower", "test"), "w") as f:
                f.write("x")
            r = subprocess.run(
                f"unshare -rm sh -c '"
                f"mount -t overlay overlay "
                f"-o lowerdir={test_dir}/lower,upperdir={test_dir}/upper,workdir={test_dir}/work "
                f"{test_dir}/merged && "
                f"test -f {test_dir}/merged/test'",
                shell=True, capture_output=True, text=True, timeout=10)
            return r.returncode == 0
        except Exception:
            return False
        finally:
            shutil.rmtree(test_dir, ignore_errors=True)

    def _try_overlay_sudo(self):
        """Test if sudo overlayfs works."""
        self._use_sudo = True
        r = self._run("mount -t overlay 2>&1 || true")
        self._use_sudo = False
        # If sudo works at all, we can use it
        password = os.environ.get("SUDO_PASSWORD", "")
        if password:
            r = subprocess.run(f"echo '{password}' | sudo -S true",
                               shell=True, capture_output=True, text=True, timeout=5)
        else:
            r = subprocess.run("sudo -n true", shell=True, capture_output=True, text=True, timeout=5)
        return r.returncode == 0

    # --- Setup ---

    def setup(self):
        """Detect best backend and initialize. Requires Linux with overlayfs."""
        if not self._is_linux():
            raise RuntimeError("--safe requires Linux with overlayfs support")
        if self._try_overlay_unprivileged():
            self.backend = "overlay"
            self._use_sudo = False
            self._setup_overlay()
            return
        if self._try_overlay_sudo():
            self.backend = "overlay"
            self._use_sudo = True
            self._setup_overlay()
            return
        raise RuntimeError("--safe requires Linux with overlayfs support "
                           "(neither unprivileged nor sudo overlay available)")

    def _targets(self):
        """Get target dirs, filtered to those that exist."""
        targets = list(self.TARGETS_LINUX)
        home_covered = any(self.user_home.startswith(t) for t in targets)
        if not home_covered:
            targets.append(self.user_home)
        return [t for t in targets if os.path.isdir(t)]

    def _setup_overlay(self):
        """Prepare overlay directories. Actual mount happens in run_in_sandbox
        (unprivileged overlayfs can only mount inside a user namespace)."""
        if self._use_sudo:
            r = self._run("mktemp -d /run/fix-sandbox-XXXXXXXX")
            if r.returncode != 0:
                raise RuntimeError(f"Failed to create sandbox dir: {r.stderr}")
            self.workdir = r.stdout.strip()
        else:
            import tempfile
            self.workdir = tempfile.mkdtemp(prefix="fix-sandbox-")

        self._empty_dir = os.path.join(self.workdir, "_empty")
        os.makedirs(self._empty_dir, exist_ok=True)

        for target in self._targets():
            name = target.strip("/").replace("/", "_")
            upper = os.path.join(self.workdir, f"{name}_upper")
            work = os.path.join(self.workdir, f"{name}_work")
            merged = os.path.join(self.workdir, f"{name}_merged")
            for d in (upper, work, merged):
                os.makedirs(d, exist_ok=True)
            self.overlay_dirs.append((target, upper, work, merged))

        # With sudo, mount overlays now (outside namespace)
        if self._use_sudo:
            for target, upper, work, merged in self.overlay_dirs:
                r = self._run(f"mount -t overlay overlay "
                              f"-o lowerdir={target},upperdir={upper},workdir={work} {merged}")
                if r.returncode != 0:
                    raise RuntimeError(f"Failed to mount overlay for {target}: {r.stderr}")

    # --- Run command ---

    def run_in_sandbox(self, command, network=False):
        return self._run_overlay(command, network)

    def _run_overlay(self, command, network=False):
        """Run command in mount namespace with overlay bind-mounts."""
        mount_cmds = []

        if self._use_sudo:
            # Overlays pre-mounted in setup(), just bind-mount merged dirs
            for target, upper, work, merged in self.overlay_dirs:
                mount_cmds.append(f"mount --bind {merged} {target}")
        else:
            # Unprivileged: mount overlays inside the user namespace
            for target, upper, work, merged in self.overlay_dirs:
                mount_cmds.append(
                    f"mount -t overlay overlay "
                    f"-o lowerdir={target},upperdir={upper},workdir={work} {merged}")
                mount_cmds.append(f"mount --bind {merged} {target}")

        # Privacy: hide sensitive paths
        if self.visible_paths:
            home_merged = None
            for target, upper, work, merged in self.overlay_dirs:
                if self.user_home.startswith(target):
                    home_merged = merged
                    break
            mount_cmds.append(f"mount -t tmpfs tmpfs {self.user_home}")
            for vpath in self.visible_paths:
                if os.path.exists(vpath):
                    rel = os.path.relpath(vpath, self.user_home)
                    mountpoint = os.path.join(self.user_home, rel)
                    if home_merged:
                        target_for_home = [t for t, u, w, m in self.overlay_dirs if m == home_merged][0]
                        source = os.path.join(home_merged, os.path.relpath(vpath, target_for_home))
                    else:
                        source = vpath
                    if os.path.isdir(vpath):
                        mount_cmds.append(f"mkdir -p {mountpoint}")
                    else:
                        mount_cmds.append(f"mkdir -p {os.path.dirname(mountpoint)} && touch {mountpoint}")
                    mount_cmds.append(f"mount --bind {source} {mountpoint}")
        else:
            for hidden in self._resolve_hidden_paths():
                if os.path.isdir(hidden):
                    mount_cmds.append(f"mount --bind {self._empty_dir} {hidden}")
                elif os.path.exists(hidden):
                    mount_cmds.append(f"mount --bind /dev/null {hidden}")

        safe_cmd = command.replace("'", "'\\''")
        script = " && ".join(mount_cmds + [safe_cmd])
        ns_flags = "--mount" + ("" if network else " --net")

        if self._use_sudo:
            full_cmd = f"unshare {ns_flags} -- bash -c '{script}'"
            password = os.environ.get("SUDO_PASSWORD", "")
            if password:
                full_cmd = f"echo '{password}' | sudo -S {full_cmd}"
            else:
                full_cmd = f"sudo {full_cmd}"
        else:
            # -r = fake root (needed for mount), -m = new mount namespace
            full_cmd = f"unshare -rm {ns_flags} -- bash -c '{script}'"

        return subprocess.run(full_cmd, shell=True,
                              stdin=sys.stdin, stdout=sys.stdout, stderr=sys.stderr,
                              timeout=300)

    # --- Diff ---

    def get_diff(self):
        return self._diff_overlay()

    def _diff_overlay(self):
        """Diff by walking overlay upper dirs."""
        changed = []
        for target, upper, work, merged in self.overlay_dirs:
            r = self._run(f"find {upper} -type f -printf '%s %p\\n'")
            if r.returncode != 0 or not r.stdout.strip():
                continue
            for line in r.stdout.strip().split("\n"):
                parts = line.split(" ", 1)
                if len(parts) != 2:
                    continue
                size, overlay_path = int(parts[0]), parts[1]
                rel = os.path.relpath(overlay_path, upper)
                real_path = os.path.join(target, rel)
                changed.append({
                    "path": real_path, "overlay_path": overlay_path,
                    "size": size, "is_delete": os.path.basename(overlay_path).startswith(".wh."),
                })
        return changed

    # --- Allowlist ---

    def check_allowlist(self, changed_files):
        import fnmatch
        allowed, violations = [], []
        for entry in changed_files:
            path = entry["path"]
            is_ok = False
            for pattern in self.allowed_paths:
                if fnmatch.fnmatch(path, pattern):
                    is_ok = True
                    break
                if path.startswith(pattern.rstrip("*")):
                    is_ok = True
                    break
            (allowed if is_ok else violations).append(entry)
        return allowed, violations

    # --- Commit / Rollback ---

    def commit(self):
        self._commit_overlay()

    def _commit_overlay(self):
        for target, upper, work, merged in self.overlay_dirs:
            check = self._run(f"find {upper} -mindepth 1 -maxdepth 1 | head -1")
            if check.stdout.strip():
                # --no-group avoids chgrp errors in unprivileged mode
                flags = "-a" if self._use_sudo else "-rlptD"
                r = self._run(f"rsync {flags} {upper}/ {target}/")
                if r.returncode != 0:
                    raise RuntimeError(f"Failed to merge {upper} -> {target}: {r.stderr}")

    def rollback(self):
        pass  # Overlay changes discarded on cleanup

    # --- Cleanup ---

    def cleanup(self):
        if not self.workdir:
            return
        if self.backend == "overlay":
            for target, upper, work, merged in self.overlay_dirs:
                self._run(f"umount {merged} 2>/dev/null")
        if self._use_sudo:
            self._run(f"rm -rf {self.workdir}")
        else:
            shutil.rmtree(self.workdir, ignore_errors=True)
        self.workdir = None


def format_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


def run_sandboxed_fix(fix_cmd, original_cmd, verify_spec, cfg, status_fn):
    """Transactional fix: snapshot -> fix -> verify -> commit/rollback."""
    hidden = None
    visible = None
    if os.environ.get("FIX_HIDDEN_PATHS"):
        hidden = Sandbox.DEFAULT_HIDDEN + json.loads(os.environ["FIX_HIDDEN_PATHS"])
    if os.environ.get("FIX_VISIBLE_PATHS"):
        visible = json.loads(os.environ["FIX_VISIBLE_PATHS"])

    sandbox = Sandbox(hidden_paths=hidden, visible_paths=visible)
    try:
        status_fn(f"{C_BLUE}#{C_RESET}", "Creating filesystem snapshot...")
        sandbox.setup()
        backend_label = {"overlay": "overlayfs (kernel COW)"}
        status_fn(f"{C_DIM}#{C_RESET}",
                  f"Backend: {backend_label.get(sandbox.backend, sandbox.backend)}"
                  f"{' [sudo]' if sandbox._use_sudo else ''}"
                  f" ({platform.system()})")

        hidden_list = sandbox._resolve_hidden_paths()
        if hidden_list:
            mode = "whitelist" if sandbox.visible_paths else "blacklist"
            status_fn(f"{C_DIM}#{C_RESET}", f"Visibility ({mode}): hiding {len(hidden_list)} path(s)")

        needs_net = any(pkg_cmd in fix_cmd for pkg_cmd in
                        ["apt ", "apt-get ", "pip ", "pip3 ", "npm ", "cargo ",
                         "dnf ", "pacman ", "wget ", "curl ", "git clone"])
        status_fn(f"{C_YELLOW}*{C_RESET}",
                  f"[sandbox] Running fix (net: {'yes' if needs_net else 'no'}): {fix_cmd[:60]}")
        fix_result = sandbox.run_in_sandbox(fix_cmd, network=needs_net)
        if fix_result.returncode != 0:
            err = getattr(fix_result, 'stderr', '') or ''
            status_fn(f"{C_RED}!{C_RESET}", f"[sandbox] Fix failed (exit {fix_result.returncode})" +
                       (f": {err[:100]}" if err else ""))
            sandbox.rollback()
            return False, err, ""

        # Diff audit
        changed = sandbox.get_diff()
        if changed:
            status_fn(f"{C_BLUE}#{C_RESET}", f"Diff audit: {len(changed)} file(s) modified")
            for entry in changed[:20]:
                icon = "-" if entry["is_delete"] else "+"
                status_fn(f"{C_DIM} {C_RESET}", f"  {icon} {entry['path']} ({format_size(entry['size'])})")

        # Allowlist check
        allowed, violations = sandbox.check_allowlist(changed)
        if violations:
            status_fn(f"{C_RED}!{C_RESET}", f"SECURITY: {len(violations)} file(s) outside allowlist!")
            for v in violations[:10]:
                status_fn(f"{C_RED}!{C_RESET}", f"  BLOCKED: {v['path']}")
            sandbox.rollback()
            return False, "", "ALLOWLIST_VIOLATION"

        # Verification runs inside sandbox
        verifier = SandboxVerifier(verify_spec, original_cmd, sandbox)
        success, explanation = verifier.verify(fix_result)
        status_fn(f"{C_GREEN if success else C_RED}{'+'  if success else '!'}{C_RESET}", explanation)

        if success:
            status_fn(f"{C_GREEN}+{C_RESET}", "Committing changes...")
            sandbox.commit()
            return True, "", ""
        else:
            status_fn(f"{C_RED}!{C_RESET}", "Rolling back (system unchanged).")
            sandbox.rollback()
            return False, "", explanation

    except Exception as e:
        status_fn(f"{C_RED}!{C_RESET}", f"Sandbox error: {e}")
        sandbox.rollback()
        return False, "", str(e)
    finally:
        sandbox.cleanup()


# --- Main Loop ---

def _probe_sandbox():
    """Quick check: can we use the overlay sandbox? Returns True/False."""
    try:
        s = Sandbox()
        s.setup()
        s.cleanup()
        return True
    except Exception:
        return False


def run_fix(command, cfg, verify_spec=None, explain_only=False, dry_run=False,
            force_local=False, safe_mode=False, confirm=False, message=None,
            remote=False):

    # If safe_mode was auto-enabled, verify sandbox actually works.
    # If user explicitly asked for --safe, let it fail loudly.
    if safe_mode and not any(a == "--safe" for a in sys.argv):
        if not _probe_sandbox():
            status(f"{C_DIM}#{C_RESET}",
                   f"{C_DIM}sandbox unavailable (overlay not supported), running direct{C_RESET}")
            safe_mode = False

    # Use project config verify as default if no --verify flag given
    if verify_spec is None and cfg.get("verify"):
        verify_spec = cfg["verify"]

    # Task mode: skip running the dummy "true" command
    is_task = message and command == "true"

    # Task mode defaults to human verification — what else would it be?
    if is_task and verify_spec is None:
        verify_spec = "human"

    print(file=sys.stderr)
    if is_task:
        # No command to run, go straight to dispatch
        class _FakeProc:
            returncode = 0
            stdout = ""
            stderr = ""
        proc = _FakeProc()
    else:
        status(f"{C_BLUE}\u25b8{C_RESET}", f"{C_BOLD}{command}{C_RESET}")
        proc = subprocess.run(command, shell=True, capture_output=True, text=True)

    if proc.stdout:
        sys.stdout.write(proc.stdout)
    task_mode_early = is_task or (message and proc.returncode == 0)

    if task_mode_early:
        # Task mode: skip the command output noise, go straight to dispatch
        pass
    elif proc.returncode == 0:
        if proc.stderr:
            sys.stderr.write(proc.stderr)
        status(f"{C_GREEN}\u2714{C_RESET}", f"Command succeeded (exit 0). Nothing to fix.")
        if verify_spec and verify_spec != "human":
            status(f"{C_DIM}\u25b8{C_RESET}", f"Tip: fix --verify='{verify_spec}' <cmd>  to verify against a different criterion")
        else:
            status(f"{C_DIM}\u25b8{C_RESET}", f"Tip: fix --verify='contains \"expected\"' <cmd>  or  fix --verify='pytest' <cmd>")
        return 0
    else:
        sys.stderr.write(proc.stderr)
        status(f"{C_RED}\u2717{C_RESET}", f"Exited {proc.returncode}")

    if not proc.stderr.strip() and not message:
        status(f"{C_DIM}?{C_RESET}", "No stderr to analyze.")
        return proc.returncode

    if _HAS_V2:
        scrubbed_stderr, _ = scrub_output(proc.stderr)
    else:
        scrubbed_stderr = proc.stderr

    env_info = get_env_fingerprint()

    # --- Remote mode: post to platform, wait for agent ---
    # Check this BEFORE resolve_backend so remote works without a local LLM.
    if remote and _HAS_REMOTE:
        import asyncio as _asyncio
        status(f"{C_YELLOW}\u25cb{C_RESET}", f"Dispatching to platform (remote mode)...")

        contract = build_contract(
            command, scrubbed_stderr, env_info,
            verify_spec=verify_spec, safe_mode=safe_mode,
            backend_name="remote", attempt=0,
            root=cfg.get("root"),
            bounty=cfg.get("bounty", "0.01"),
            judge=cfg.get("judge"),
        )

        if is_task:
            contract["task"] = {"type": "task", "task": message}

        display_contract(contract, status)

        async def _run_remote():
            platform_url = cfg.get("platform_url", "https://fix.notruefireman.org")
            fix_client = FixClient(base_url=platform_url)

            contract_id = await fix_client.post_contract(contract)
            status(f"{C_GREEN}\u2714{C_RESET}", f"Contract posted ({contract_id})")
            status(f"{C_DIM}\u25b8{C_RESET}", "Waiting for agent...")

            tried_fixes = set()  # track fix commands we already attempted

            # Poll for contract updates
            for _ in range(600):  # 5 min max
                await _asyncio.sleep(0.5)
                data = await fix_client.get_contract(contract_id)
                if not data:
                    continue

                transcript = data.get("transcript", [])
                contract_status = data.get("status", "open")

                # Check for investigation requests we need to answer
                for msg in transcript:
                    if msg.get("type") == "investigate" and msg.get("from") == "agent":
                        cmd = msg["command"]
                        already_replied = any(
                            m.get("type") == "result" and m.get("command") == cmd
                            for m in transcript
                        )
                        if not already_replied:
                            status(f"\U0001f50d", f"{C_DIM}{cmd}{C_RESET}")
                            output = run_investigate_command(cmd, root=cfg.get("root"))
                            if output.strip():
                                for line in output.strip().splitlines()[:10]:
                                    print(f"  {C_DIM}    {line}{C_RESET}", file=sys.stderr)
                            await fix_client.submit_investigation_result(contract_id, cmd, output)

                # Check for fix proposals we haven't tried yet
                for msg in transcript:
                    if msg.get("type") == "fix" and msg.get("from") == "agent":
                        fix_cmd = msg.get("fix", "")
                        if fix_cmd in tried_fixes:
                            continue
                        tried_fixes.add(fix_cmd)

                        explanation = msg.get("explanation", "")
                        attempt_num = len(tried_fixes)

                        status(f"{C_GREEN}\u25c6{C_RESET}",
                               f"Fix (attempt {attempt_num}): {C_BOLD}{fix_cmd}{C_RESET}")
                        if explanation:
                            status(f" ", f"{C_DIM}{C_ITALIC}{explanation}{C_RESET}")

                        # Agent declined or returned empty fix
                        if not fix_cmd or fix_cmd.lower() in ("none", "null", "n/a"):
                            status(f"{C_RED}\u2717{C_RESET}", "Agent could not produce a fix")
                            await fix_client.verify(contract_id, False,
                                                    f"agent declined (attempt {attempt_num})")
                            status(f"{C_DIM}\u25b8{C_RESET}", "Waiting for agent to retry...")
                            continue

                        if dry_run:
                            return proc.returncode

                        if confirm and sys.stdin.isatty():
                            answer = input(f"  ?  Apply this fix? [Y/n] ")
                            if answer.strip().lower() == "n":
                                return proc.returncode

                        rc = apply_fix(fix_cmd, command, verify_spec, safe_mode, cfg, contract)
                        success = (rc == 0)
                        await fix_client.verify(contract_id, success,
                                                "fulfilled" if success else f"fix failed verification (attempt {attempt_num})")

                        if success:
                            return rc

                        # Failed -- report and keep polling for next fix from agent
                        status(f"{C_RED}\u2717{C_RESET}",
                               f"Fix failed verification (attempt {attempt_num})")
                        status(f"{C_DIM}\u25b8{C_RESET}", "Waiting for agent to retry...")

                if contract_status in ("fulfilled", "canceled", "resolved"):
                    break

            if tried_fixes and not any(data.get("status") == "fulfilled" for _ in [1]):
                status(f"{C_RED}!{C_RESET}",
                       f"Agent exhausted after {len(tried_fixes)} attempt(s)")
            else:
                status(f"{C_RED}!{C_RESET}", "Timeout waiting for agent")
            return 1

        return _asyncio.run(_run_remote())
    elif remote and not _HAS_REMOTE:
        status(f"{C_RED}!{C_RESET}", "Remote mode requires: pip install httpx")
        return 1

    # Resolve backend (only needed for local mode)
    try:
        backend_name, backend_kwargs = resolve_backend(cfg, force_local)
    except RuntimeError as e:
        status(f"{C_RED}!{C_RESET}", str(e))
        return proc.returncode

    # --explain: just explain the error
    if explain_only:
        prompt = build_explain_prompt(command, proc.stderr, env_info)
        try:
            raw = call_llm(prompt, backend_name, backend_kwargs)
        except RuntimeError as e:
            status(f"{C_RED}!{C_RESET}", str(e))
            return proc.returncode
        print(f"\n{raw.strip()}\n")
        return proc.returncode

    status(f"{C_YELLOW}\u25cb{C_RESET}", f"Dispatching to agent...")

    # Multi-attempt: try up to MAX_FIX_ATTEMPTS, feeding failures back
    prior_failures = []

    for attempt in range(MAX_FIX_ATTEMPTS):
        # Build contract -- the shared agreement between user and agent
        contract = build_contract(
            command, scrubbed_stderr, env_info,
            verify_spec=verify_spec, safe_mode=safe_mode,
            backend_name=backend_name, attempt=attempt,
            prior_failures=prior_failures or None,
            root=cfg.get("root"),
            bounty=cfg.get("bounty"),
            judge=cfg.get("judge"),
        )

        # Task mode: rewrite the contract to show the message as the task
        task_mode = message and (command == "true" or not scrubbed_stderr.strip())
        if task_mode:
            contract["task"] = {
                "type": "task",
                "task": message,
            }

        display_contract(contract, status)

        prompt = build_prompt(command, scrubbed_stderr, env_info, contract,
                              prior_failures or None, message=message)

        # Parse LLM response (retry on bad JSON)
        result = None
        for json_retry in range(3):
            try:
                raw = call_llm(prompt, backend_name, backend_kwargs, contract=contract)
                result = parse_llm_response(raw)
                break
            except json.JSONDecodeError:
                if json_retry < 2:
                    status(f"{C_DIM}~{C_RESET}", "Bad response, retrying...")
                    continue
                status(f"{C_RED}!{C_RESET}", f"Could not parse fix from {backend_name}.")
                return proc.returncode
            except RuntimeError as e:
                status(f"{C_RED}!{C_RESET}", str(e))
                return proc.returncode

        # Agent's response to the contract
        accepted = result.get("accepted")
        decline_reason = result.get("explanation", "no reason given")

        if accepted is False:
            print(file=sys.stderr)
            status(f"{C_RED}\u2718{C_RESET}", f"Agent {C_RED}DECLINED{C_RESET}: {C_ITALIC}{decline_reason}{C_RESET}")
            return proc.returncode
        elif accepted is True:
            status(f"{C_GREEN}\u2714{C_RESET}", f"Agent {C_GREEN}accepted{C_RESET}")
        else:
            status(f"{C_DIM}\u2714{C_RESET}", f"{C_DIM}Agent accepted (implicit){C_RESET}")

        fix_cmd = result["fix"]
        if isinstance(fix_cmd, list):
            fix_cmd = " && ".join(fix_cmd)
        explanation = result.get("explanation", "")

        # Record agent's response in the contract
        if "agent" not in contract:
            contract["agent"] = {}
        contract["agent"]["accepted"] = True
        contract["agent"]["fix"] = fix_cmd
        contract["agent"]["explanation"] = explanation

        attempt_label = f" (attempt {attempt + 1}/{MAX_FIX_ATTEMPTS})" if attempt > 0 else ""
        print(file=sys.stderr)
        status(f"{C_GREEN}\u25c6{C_RESET}", f"Fix{attempt_label}: {C_BOLD}{fix_cmd}{C_RESET}")
        if explanation:
            status(f" ", f"{C_DIM}{C_ITALIC}{explanation}{C_RESET}")

        # --dry-run: show fix and contract, stop
        if dry_run:
            print(file=sys.stderr)
            return proc.returncode

        if confirm and sys.stdin.isatty():
            print(file=sys.stderr)
            answer = input(f"  ?  Apply this fix? [Y/n] ")
            if answer.strip().lower() == "n":
                return proc.returncode

        # Apply fix
        rc = apply_fix(fix_cmd, command, verify_spec, safe_mode, cfg, contract)

        if rc == 0:
            return 0

        # Fix didn't work -- if we have more attempts, feed failure context back
        if attempt < MAX_FIX_ATTEMPTS - 1:
            status(f"{C_YELLOW}\u21bb{C_RESET}", f"Attempt {attempt + 1} failed. Retrying with context...")
            verify_proc = subprocess.run(command, shell=True, capture_output=True, text=True)
            prior_failures.append((fix_cmd, verify_proc.stderr[:500] if verify_proc.stderr else "exit non-zero"))
            continue

    return 1


def apply_fix(fix_cmd, original_cmd, verify_spec, safe_mode, cfg, contract=None):
    """Apply a fix and verify it. Returns exit code."""

    if safe_mode:
        status(f"{C_BLUE}\u25b8{C_RESET}", "Executing in sandbox...")
        success, fix_out, verify_out = run_sandboxed_fix(
            fix_cmd, original_cmd, verify_spec, cfg, status)
        print(file=sys.stderr)
        explanation = verify_out or ("Changes committed" if success else "System unchanged")
    else:
        # Direct execution
        needs_sudo = bool(re.search(r'\bsudo\b', fix_cmd))

        # Block sudo if not allowed by contract capabilities
        if needs_sudo and contract:
            caps = contract.get("capabilities", {})
            sudo_cap = caps.get("sudo", {})
            if not sudo_cap.get("available", False):
                status(f"{C_RED}\u2717{C_RESET}", "sudo is not available — stripping")
                fix_cmd = re.sub(r'\bsudo\s+', '', fix_cmd)
                needs_sudo = False

        if needs_sudo:
            SUDO_TIMEOUT = 15
            if sys.stdin.isatty():
                answer = _input_with_countdown(
                    f"  {C_YELLOW}\u26a0{C_RESET}  sudo required — approve? [Y/n] ({{}}s) ",
                    SUDO_TIMEOUT, default="y",
                )
                if answer.strip().lower() == "n":
                    status(f"{C_RED}\u2717{C_RESET}", "sudo denied by user")
                    return 1

            # Authenticate sudo first (caches credential), then run the real command
            SUDO_AUTH_TIMEOUT = 30
            status(f"{C_BLUE}\u25b8{C_RESET}", f"Authenticating sudo ({SUDO_AUTH_TIMEOUT}s)...")
            try:
                auth = subprocess.run(
                    ["sudo", "-v"], timeout=SUDO_AUTH_TIMEOUT,
                    stdin=sys.stdin, stdout=sys.stdout, stderr=sys.stderr,
                )
                if auth.returncode != 0:
                    status(f"{C_RED}\u2717{C_RESET}", "sudo authentication failed")
                    return 1
            except subprocess.TimeoutExpired:
                status(f"{C_RED}\u2717{C_RESET}", f"No password entered ({SUDO_AUTH_TIMEOUT}s) — aborted")
                return 1

            # Credential cached — run the actual command with no timeout
            status(f"{C_BLUE}\u25b8{C_RESET}", f"Running: {fix_cmd}")
            fix_proc = subprocess.run(
                fix_cmd, shell=True, executable="/bin/bash",
                stdin=sys.stdin, stdout=sys.stdout, stderr=sys.stderr,
            )
            class _R:
                def __init__(self, rc): self.returncode, self.stdout, self.stderr = rc, "", ""
            fix_proc = _R(fix_proc.returncode)
        else:
            status(f"{C_BLUE}\u25b8{C_RESET}", f"Running: {fix_cmd}")
            fix_proc = subprocess.run(fix_cmd, shell=True, executable="/bin/bash",
                                      stdin=sys.stdin, stdout=sys.stdout, stderr=sys.stderr)
            class _R:
                def __init__(self, rc): self.returncode, self.stdout, self.stderr = rc, "", ""
            fix_proc = _R(fix_proc.returncode)

        if fix_proc.returncode != 0:
            err_msg = getattr(fix_proc, 'stderr', '')
            status(f"{C_RED}\u2717{C_RESET}", f"Fix command failed (exit {fix_proc.returncode})" +
                   (f": {err_msg[:100]}" if err_msg else ""))
            return fix_proc.returncode

        # Verify
        verifier = Verifier(verify_spec, original_cmd)
        success, explanation = verifier.verify(fix_proc)
        print(file=sys.stderr)

    # Dispute resolution: if verification failed and a judge is configured, appeal
    judge_flags = []
    if not success and contract and contract.get("escrow"):
        judge_fn = cfg.get("judge")
        if callable(judge_fn):
            outcome = {
                "fix": fix_cmd,
                "success": False,
                "explanation": explanation,
            }
            status(f"{C_YELLOW}\u2696{C_RESET}", "Verification failed. Appealing to judge...")
            try:
                verdict = judge_fn(contract, outcome)
                if isinstance(verdict, dict):
                    ruling = verdict.get("ruling", "canceled")
                    reason = verdict.get("reason", "no reason given")
                    flagged = verdict.get("flag")  # "evil_agent" or "evil_principal"
                    if ruling == "fulfilled":
                        status(f"{C_GREEN}\u2696{C_RESET}",
                               f"Judge {C_GREEN}overruled{C_RESET}: {C_ITALIC}{reason}{C_RESET}")
                        success = True
                        explanation = f"Judge: {reason}"
                    elif ruling == "impossible":
                        status(f"{C_YELLOW}\u2696{C_RESET}",
                               f"Judge ruled {C_YELLOW}impossible{C_RESET}: {C_ITALIC}{reason}{C_RESET}")
                        explanation = f"Judge: impossible — {reason}"
                    else:
                        status(f"{C_RED}\u2696{C_RESET}",
                               f"Judge {C_RED}upheld{C_RESET}: {C_ITALIC}{reason}{C_RESET}")
                    if flagged:
                        if isinstance(flagged, list):
                            flags = flagged
                        else:
                            flags = [flagged]
                        judge_flags = flags
                        for f in flags:
                            target = f.replace("evil_", "")
                            status(f"{C_RED}\u2620{C_RESET}",
                                   f"{C_RED}FLAGGED{C_RESET}: {target} marked as malicious — "
                                   f"{verdict.get('flag_reason', reason)}")
            except Exception as e:
                status(f"{C_RED}!{C_RESET}", f"Judge error: {e}")

    if success:
        status(f"{C_GREEN}\u2714{C_RESET}", f"{C_GREEN}Contract fulfilled.{C_RESET} {explanation}")
        if contract and contract.get("escrow"):
            bounty = contract["escrow"]["bounty"]
            if "evil_principal" in judge_flags:
                status(f"{C_RED}${C_RESET}",
                       f"Escrow: {bounty} donated to charity (principal flagged)")
            else:
                status(f"{C_GREEN}${C_RESET}",
                       f"Escrow: {bounty} released to agent")
    else:
        msg = f"{C_YELLOW}Contract canceled.{C_RESET} {explanation}"
        if safe_mode:
            msg += " System unchanged."
        status(f"{C_YELLOW}\u2718{C_RESET}", msg)
        if contract and contract.get("escrow"):
            cancel_fee = contract.get("terms", {}).get("cancellation", {}).get("agent_fee", "0.002")
            bounty = contract["escrow"]["bounty"]
            both_evil = "evil_agent" in judge_flags and "evil_principal" in judge_flags
            agent_evil = "evil_agent" in judge_flags
            principal_evil = "evil_principal" in judge_flags
            if both_evil:
                status(f"{C_RED}${C_RESET}",
                       f"Escrow: {bounty} + fees donated to charity (both parties flagged)")
            elif agent_evil:
                status(f"{C_RED}${C_RESET}",
                       f"Escrow: {bounty} returned to principal (agent flagged, forfeits cancellation fee)")
            elif principal_evil:
                status(f"{C_RED}${C_RESET}",
                       f"Escrow: {bounty} donated to charity (principal flagged)")
            else:
                status(f"{C_DIM}${C_RESET}",
                       f"Escrow: {bounty} returned to principal (agent pays {cancel_fee} cancellation fee)")

    return 0 if success else 1


# --- CLI ---

def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__.strip())
        return

    cfg = load_config()

    # Subcommands
    if sys.argv[1] == "init":
        generate_config()
        return
    if sys.argv[1] == "shell":
        if len(sys.argv) > 2 and sys.argv[2] == "--install":
            shell_install()
        else:
            shell_hook()
        return
    if sys.argv[1] == "serve":
        if not _HAS_REMOTE:
            print(f"  {C_RED}!{C_RESET}  Remote mode requires: pip install httpx fastapi", file=sys.stderr)
            sys.exit(1)
        import asyncio as _asyncio
        platform_url = cfg.get("platform_url", "https://fix.notruefireman.org")
        agent_config = {
            "platform_url": platform_url,
            "api_key": cfg.get("api_key", ""),
            "pubkey": cfg.get("pubkey", "agent-default"),
            "min_bounty": str(cfg.get("min_bounty", "0")),
            "capabilities": detect_capabilities() if _HAS_V2 else {},
        }
        fix_agent = FixAgent(agent_config)
        status(f"{C_GREEN}\u25b8{C_RESET}", f"Starting fix agent (serve mode)...")
        status(f"{C_DIM}\u25b8{C_RESET}", f"Platform: {platform_url}")
        try:
            _asyncio.run(fix_agent.serve())
        except KeyboardInterrupt:
            status(f"{C_DIM}\u25b8{C_RESET}", "Agent stopped.")
        return

    # Parse flags
    args = sys.argv[1:]

    # Resolve safe_mode: "auto" means True on Linux, False elsewhere
    _cfg_safe = cfg.get("safe_mode", "auto")
    if _cfg_safe == "auto":
        _cfg_safe = platform.system() == "Linux"

    flags = {
        "confirm": False,
        "force_local": False,
        "safe_mode": _cfg_safe,
        "explain_only": False,
        "dry_run": False,
        "verify_spec": None,
        "message": None,
        "remote": cfg.get("remote", False),
    }
    hidden_extra = []
    visible_only = []
    filtered_args = []

    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-c", "--confirm"):
            flags["confirm"] = True
        elif a in ("--local", "--ollama"):
            flags["force_local"] = True
        elif a == "--safe":
            flags["safe_mode"] = True
        elif a == "--no-safe":
            flags["safe_mode"] = False
        elif a == "--remote":
            flags["remote"] = True
        elif a == "--explain":
            flags["explain_only"] = True
        elif a == "--dry-run":
            flags["dry_run"] = True
        elif a.startswith("--verify="):
            flags["verify_spec"] = a[len("--verify="):]
        elif a == "--verify" and i + 1 < len(args):
            i += 1
            flags["verify_spec"] = args[i]
        elif a.startswith("--model="):
            cfg["model"] = cfg["ollama_model"] = a.split("=", 1)[1]
        elif a in ("-m", "--model") and i + 1 < len(args):
            i += 1
            cfg["model"] = cfg["ollama_model"] = args[i]
        elif a.startswith("--root="):
            cfg["root"] = a.split("=", 1)[1]
        elif a == "--root" and i + 1 < len(args):
            i += 1
            cfg["root"] = args[i]
        elif a.startswith("--msg="):
            flags["message"] = a.split("=", 1)[1]
        elif a == "--msg" and i + 1 < len(args):
            i += 1
            flags["message"] = args[i]
        elif a.startswith("--hide="):
            hidden_extra.append(a.split("=", 1)[1])
        elif a == "--hide" and i + 1 < len(args):
            i += 1
            hidden_extra.append(args[i])
        elif a.startswith("--visible="):
            visible_only.append(a.split("=", 1)[1])
        elif a == "--visible" and i + 1 < len(args):
            i += 1
            visible_only.append(args[i])
        else:
            filtered_args.append(a)
        i += 1

    if hidden_extra:
        os.environ["FIX_HIDDEN_PATHS"] = json.dumps(hidden_extra)
    if visible_only:
        os.environ["FIX_VISIBLE_PATHS"] = json.dumps(visible_only)

    # Handle fix it / fix !!
    if filtered_args in (["it"], ["!!"]):
        last_cmd = os.environ.get("FIX_LAST_COMMAND") or get_last_failed_command()
        if not last_cmd:
            status(f"{C_RED}!{C_RESET}", "Could not find last command in shell history.")
            print(f"\n  {C_DIM}fix needs a shell hook to capture the last command.{C_RESET}", file=sys.stderr)
            if sys.stdin.isatty():
                if shell_install():
                    print(f"\n  {C_DIM}Run your command again, then try fix it.{C_RESET}", file=sys.stderr)
            else:
                name = _detect_shell()
                print(f"  {C_DIM}Run: fix shell --install{C_RESET}", file=sys.stderr)
            sys.exit(1)
        status(f"{C_DIM}\u25b8{C_RESET}", f"Last command: {C_BOLD}{last_cmd}{C_RESET}")
        command = last_cmd
    elif not filtered_args and not flags.get("message"):
        print(__doc__.strip())
        return
    elif not filtered_args and flags.get("message"):
        # --msg with no command: use 'true' as a no-op so the agent runs
        command = "true"
        sys.exit(run_fix(command, cfg, **flags))
        return
    else:
        command = " ".join(filtered_args)

    sys.exit(run_fix(command, cfg, **flags))


if __name__ == "__main__":
    main()
