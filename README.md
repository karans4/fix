# fix

AI-powered command fixer. Run a command, if it fails, an LLM diagnoses the error and generates a fix.

## Install

```sh
# From source
git clone https://github.com/karans4/fix && cd fix
pip install -e .

# Or just copy the script
cp fix ~/.local/bin/fix
chmod +x ~/.local/bin/fix
pip install httpx
```

## Setup

Set an API key (any one of these):

```sh
# Claude (default, cheapest)
export ANTHROPIC_API_KEY=sk-ant-...
# or save it
mkdir -p ~/.fix && echo "sk-ant-..." > ~/.fix/api_key

# OpenAI
export OPENAI_API_KEY=sk-...

# Any OpenAI-compatible endpoint (Together, Groq, etc.)
export FIX_API_URL=https://api.together.xyz/v1
export FIX_API_KEY=...
export FIX_MODEL=meta-llama/Llama-3-70b-chat-hf

# Or use Ollama (free, local, no API key)
ollama pull qwen2.5-coder:1.5b
ollama serve
```

## Usage

```sh
# Basic: run command, fix if it fails
fix "gcc foo.c"
fix "python3 -c 'import flask'"

# Re-run last failed command
fix !!

# Just explain the error
fix --explain "python3 bad.py"

# Show the fix without running it
fix --dry-run "python3 bad.py"

# Force local Ollama backend
fix --local "gcc missing.c"

# Auto-apply without confirmation
fix -y "npm install"
```

## Verification

By default, `fix` re-runs the original command after applying the fix. Exit 0 = success. You can customize verification:

```sh
# Default: re-run command, exit 0 = success
fix "gcc foo.c"

# Human judges the result
fix --verify=human "python3 render.py"

# Stdout must contain a string
fix --verify="contains 'Hello'" "python3 foo.py"

# Output must NOT contain a string
fix --verify="not contains 'error'" "python3 foo.py"

# Custom verification command
fix --verify="python3 -m pytest tests/" "pip install flask"
```

## Safe mode (sandbox)

Runs fixes in an OverlayFS sandbox. Changes are only committed if verification passes.

```sh
fix --safe "python3 -c 'import flask'"
```

Security layers:
1. **Overlay** -- filesystem snapshot, changes isolated until commit
2. **Network isolation** -- fix can't phone home (except package installs)
3. **Visibility control** -- sensitive paths hidden from the agent
4. **Diff audit** -- every changed file shown before commit
5. **Allowlist** -- only expected paths may be modified

```sh
# Hide additional paths from the agent
fix --safe --hide ~/.env --hide ~/secrets "python3 app.py"

# Whitelist mode: agent can ONLY see these paths
fix --safe --visible ~/myproject "python3 build.py"
```

## Config

Optional config at `~/.fix/config.toml`:

```toml
backend = "claude"
model = "claude-haiku-4-5-20251001"
budget_cents = 50
safe_mode = false
ollama_model = "qwen2.5-coder:1.5b"

[hidden_paths]
paths = ["~/.ssh", "~/.gnupg", "~/.aws"]
```

## Cache

Fixes are cached in SQLite (`~/.fix/fixes.db`) with environment fingerprinting. Same error on same system = instant cache hit.

```sh
fix --cache    # show cached fixes
fix --stats    # show spending stats
fix --clear    # clear cache

# Export/import fixes
fix export > fixes.json
fix import fixes.json
```

## How it works

1. Run command, capture stderr
2. Hash error + environment fingerprint
3. Check SQLite cache (exact env match, then fuzzy)
4. On cache miss, ask LLM for a fix
5. Apply fix, verify, cache if successful
6. Multi-attempt: if first fix fails, retry with failure context (up to 3 tries)

Backend priority: explicit flag > env var > config > auto-detect (Claude > OpenAI > Ollama)

## License

MIT
