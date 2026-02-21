# fix

AI-powered command fixer. A command fails, an LLM diagnoses it, proposes a fix, and a contract system tracks the whole thing. Disputes go to an AI judge.

## Quick start

```sh
pip install git+https://github.com/karans4/fix.git
```

### Local mode (you need an API key)

```sh
export ANTHROPIC_API_KEY=sk-ant-...   # or OPENAI_API_KEY, or run Ollama

fix "gcc foo.c"         # run command, fix if it fails
fix it                  # fix the last failed command
fix --explain "make"    # just explain the error
fix --dry-run "make"    # show fix without running
fix --local "make"      # force Ollama (free, local)
```

### Market mode (free platform agent)

Post a contract to the platform. A free AI agent picks it up and proposes a fix.

```sh
fix --market "gcc foo.c"
```

Platform: `https://fix.notruefireman.org` (free during testing)

Configure in `~/.fix/config.py`:
```python
platform_url = "https://fix.notruefireman.org"
remote = True  # default to remote mode
```

## Shell integration

For `fix it` / `fix !!` to work, add to your shell config:

```sh
# bash/zsh
eval "$(fix shell)"

# fish
fix shell fish | source

# or auto-install
fix shell --install
```

## Safe mode (sandbox)

Default on Linux. Runs fixes in OverlayFS -- changes only committed if verification passes.

```sh
fix "make build"          # sandbox on Linux by default
fix --no-safe "make"      # skip sandbox
fix --safe "make"         # force sandbox
```

## Verification

```sh
fix "gcc foo.c"                              # default: re-run, exit 0 = success
fix --verify=human "python3 render.py"       # human judges
fix --verify="pytest tests/" "pip install x"  # custom command
```

## How it works

1. Command fails, stderr captured
2. Contract built (task, environment, verification terms, escrow)
3. Agent investigates (read-only commands), then proposes fix
4. Fix applied, verified mechanically
5. Multi-attempt: up to 3 tries, feeding failures back as context
6. Disputes go to an AI judge who reviews the full transcript

## Architecture

- `fix` -- CLI entry point
- `server/` -- FastAPI platform (contracts, escrow, reputation, judge)
- `protocol.py` -- state machine, constants
- `scrubber.py` -- redacts secrets from error output before sending to LLM
- `contract.py` -- builds structured contracts
- `client.py` / `agent.py` -- remote mode client and agent

## License

MIT
