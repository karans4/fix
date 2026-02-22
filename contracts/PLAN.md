# Fix Platform — IOTA EVM Smart Contract Architecture

## The Big Picture

Fix is an AI-powered command fixer where principals post broken commands and agents fix them for payment. The platform is a marketplace. The smart contract handles escrow. The platform handles discovery and transcript relay. The oracle handles disputes.

Three independent roles:
- **Platform** (us): indexer + transcript relay + agent hosting. Gets listing fee.
- **Oracle** (us, for now): runs LLM judges. Gets court fees from loser's bond.
- **Contract** (on-chain): dumb escrow machine. Holds money, enforces state transitions, routes funds.

Anyone can fill any role. We're just the first and default provider.

## What Goes Where

### On-chain (FixEscrow.sol)
- All money: bounty, bonds, fees
- State machine: open → investigating → in_progress → fulfilled/canceled/voided
- Fund routing: who gets paid based on outcome
- Timing enforcement: grace period, response window, ruling timeout, appeal window
- Dispute mechanics: file, respond, rule, appeal, void

### Off-chain (platform server)
- Contract discovery: indexer lists approved contracts, agents browse
- Transcript: investigation commands, fix text, chat messages, Ed25519 signed chain
- Agent matching: platform decides which contracts to show agents
- Policy enforcement: minimum bounty (USD-equivalent), minimum fees, trusted oracles
- Transcript anchoring: hash of off-chain transcript posted on-chain periodically

### Off-chain (oracle)
- Judge execution: runs LLM on transcript, decides ruling
- Posts ruling on-chain via `rule()` call
- Can refuse by not responding (contract voids after timeout)

## The Contract — What It Looks Like

### No Hardcoded Prices

Everything price-sensitive is per-contract, set at post time:
- `courtFees[3]`: oracle fees per tier, set by principal (platform suggests values)
- `platformFeeBps`: listing fee in basis points
- `minBond`: agent trust requirement
- `bounty`: whatever the principal sends minus bond

Only timing and percentages are hardcoded:
- `CANCEL_FEE_BPS = 1000` (10%) — ratio, not a price
- `GRACE_PERIOD = 30s`
- `RESPONSE_WINDOW = 30s`
- `RULING_TIMEOUT = 60s`
- `APPEAL_WINDOW = 30s`
- `ABANDONMENT_TIMEOUT = 120s`
- `PICKUP_TIMEOUT = 30s`

### Platform Always Gets Paid

Platform fee is deducted on EVERY resolution except grace-period backout:
- Fulfilled: yes
- Canceled: yes
- Void (oracle failed): yes — not the platform's fault the oracle didn't show
- Stale (no agent): yes — platform listed it, did its job
- Abandoned: yes
- Backout post-grace: yes
- Backout in-grace: NO — grace period is "free trial"

### Bonding Through Platform

Problem: anyone can call `bond()` on-chain directly. The platform doesn't gate agent access.

Solution: **platform-signed approval**. The contract requires a platform signature to bond:

```solidity
function bond(bytes32 id, bytes calldata platformApproval) external payable {
    // Verify platform signed this agent for this contract
    bytes32 hash = keccak256(abi.encodePacked(id, msg.sender, "bond"));
    require(recoverSigner(hash, platformApproval) == c.platform, "not approved");
    ...
}
```

Flow:
1. Agent finds contract on platform
2. Agent requests to bond via platform API
3. Platform checks agent reputation, bond amount, etc.
4. Platform signs approval: `sign(contractId + agentAddress + "bond")`
5. Agent calls `bond(id, approval)` on-chain with the signature
6. Contract verifies platform approved this agent

This means:
- Platform controls who can bond (quality control)
- Agent still interacts with chain directly (trustless escrow)
- If platform disappears, someone deploys a new one that auto-approves everyone
- The approval is per-contract, not global — platform can be selective

### Oracle Can Refuse

Add `refuseDispute()` — oracle actively declines rather than silent timeout:

```solidity
function refuseDispute(bytes32 id) external {
    require(msg.sender == c.oracle, "not oracle");
    // Immediately void — faster than waiting for timeout
    _settleVoid(id);
}
```

Better UX than waiting 90 seconds for timeout.

## Complete State Machine

```
Open ──────────► Investigating ──────────► InProgress ──────────► Fulfilled
  │  bond()          │  accept()              │  verify(true)        (terminal)
  │                  │                        │  autoFulfill()
  │                  ├──► Open                │
  │                  │    decline()            ├──► Review ──────────► Fulfilled
  │                  │    (bond returned)      │    submitFix()        autoFulfill()
  │                  │                        │    (autonomous)
  │                  │                        │
  ├──► Canceled      ├──► Canceled            ├──► Canceled
  │    cancelStale()      cancelAbandoned()   │    backOut()
  │                                           │
  │                                           ├──► AwaitResponse
  │                                           │    fileDispute()
  │                                           │         │
  │                                           │         ├──► Disputed
  │                                           │         │    respondDispute()
  │                                           │         │    escalateDispute()
  │                                           │         │         │
  │                                           │         │         ├──► Ruled
  │                                           │         │         │    rule()
  │                                           │         │         │    (tier < supreme)
  │                                           │         │         │         │
  │                                           │         │         │         ├──► AwaitResponse
  │                                           │         │         │         │    appeal()
  │                                           │         │         │         │    (next tier)
  │                                           │         │         │         │
  │                                           │         │         │         ├──► Fulfilled/Canceled
  │                                           │         │         │         │    finalizeRuling()
  │                                           │         │         │         │    (no appeal)
  │                                           │         │         │
  │                                           │         │         ├──► Fulfilled/Canceled
  │                                           │         │         │    rule() at supreme
  │                                           │         │         │
  │                                           │         │         ├──► Voided
  │                                           │         │              voidDispute()
  │                                           │         │              refuseDispute()
  │                                           │
  │                                           ├──► Halted ──────► Ruled/Voided
  │                                                halt()         (same as dispute
  │                                                (emergency)     but no response window)
```

## Complete Money Flows

Using variables, not hardcoded amounts:

```
Deposits:
  Principal sends: bounty + sum(courtFees)    → principalBond = sum(courtFees)
  Agent sends:     agentBond (>= minBond)

Variables:
  PF  = bounty * platformFeeBps / 10000      (platform listing fee)
  CF  = cancel fee = bounty * 10%            (cancellation penalty)
  NET = bounty - PF                           (bounty after platform fee)
  TF  = courtFees[tier]                       (this tier's oracle fee)
  CTF = sum(courtFees[0..tier])               (cumulative oracle fees)
```

### Terminal States

```
FULFILLED (no dispute):
  Agent:      NET + agentBond
  Principal:  principalBond
  Platform:   PF
  Oracle:     —

FULFILLED (after dispute, agent wins):
  Agent:      NET + agentBond
  Principal:  principalBond - CTF
  Platform:   PF
  Oracle:     CTF (paid per tier as rulings happen)

CANCELED (no dispute — verify failed, max retries):
  Principal:  NET + principalBond
  Agent:      agentBond
  Platform:   PF
  Oracle:     —

CANCELED (after dispute, principal wins):
  Principal:  NET + principalBond
  Agent:      agentBond - CTF
  Platform:   PF
  Oracle:     CTF

IMPOSSIBLE (after dispute):
  Principal:  NET + principalBond - CTF      (filer pays court costs)
  Agent:      agentBond
  Platform:   PF
  Oracle:     CTF

STALE (no agent picked up):
  Principal:  bounty + principalBond - PF    (= NET + principalBond)
  Platform:   PF

ABANDONED (agent went silent):
  Principal:  NET + principalBond + min(CF, agentBond)
  Agent:      agentBond - min(CF, agentBond)
  Platform:   PF

BACKOUT IN GRACE:
  Principal:  bounty + principalBond         (everything back, no fees)
  Agent:      agentBond

BACKOUT POST-GRACE (agent backs out):
  Principal:  NET + principalBond + min(CF, agentBond)
  Agent:      agentBond - min(CF, agentBond)
  Platform:   PF

BACKOUT POST-GRACE (principal backs out):
  Principal:  NET - min(CF, NET) + principalBond
  Agent:      min(CF, NET) + agentBond
  Platform:   PF

VOIDED (oracle no-show):
  Principal:  bounty + principalBond - CTF   (minus any already-paid tier fees)
  Agent:      agentBond
  Platform:   PF                              (platform still gets paid)
  Oracle:     CTF (whatever was already paid before void)

EVIL_AGENT (dispute, agent flagged evil):
  Principal:  principalBond (or principalBond - CTF if principal filed and lost earlier tier)
  Agent:      — (forfeits everything)
  Charity:    agentBond - CTF + NET           (agent's remaining bond + bounty)
  Platform:   PF
  Oracle:     CTF

EVIL_PRINCIPAL (dispute, principal flagged evil):
  Principal:  — (forfeits everything)
  Agent:      agentBond
  Charity:    principalBond - CTF + NET       (principal's remaining bond + bounty)
  Platform:   PF
  Oracle:     CTF

EVIL_BOTH:
  Principal:  —
  Agent:      —
  Charity:    agentBond - CTF + principalBond + NET   (everything minus fees)
  Platform:   PF
  Oracle:     CTF
```

### Invariant

For every terminal state:
```
Agent + Principal + Platform + Oracle + Charity = bounty + principalBond + agentBond
```

No money created, no money destroyed.

## Interaction with Existing Codebase

### What Changes

1. **`server/escrow.py`** — mostly deleted. The smart contract handles all escrow logic. Keep `EscrowManager` as a thin wrapper that calls the contract via web3.
2. **`server/nano.py`** — deleted entirely. No more Nano.
3. **`server/app.py`** — endpoints become thin relays:
   - `POST /contracts` → validate, sign platform approval, tell client to call `post()` on-chain
   - `POST /contracts/{id}/bond` → check agent, sign approval, return signature for `bond()` call
   - `POST /contracts/{id}/fix` → relay fix to transcript, agent calls `submitFix()` on-chain
   - `POST /contracts/{id}/verify` → principal calls `verify()` on-chain directly
   - `POST /contracts/{id}/dispute` → principal/agent calls `fileDispute()` on-chain, platform sees event
   - Dispute resolution: platform's oracle watches `Disputed` events, runs judge, calls `rule()`
4. **`client.py`** — gains web3/ethers.js calls for on-chain interactions
5. **`fix.py`** — needs IOTA wallet (private key) instead of Nano key derivation
6. **`crypto.py`** — Ed25519 transcript chain stays (for off-chain data). Add EVM signing helpers.
7. **`protocol.py`** — remove Nano constants, add IOTA EVM chain config (RPC URL, contract address)

### What Stays Exactly The Same

- **Transcript chain** — Ed25519 signed entries for off-chain data (investigation, fixes, chat)
- **Judge system** — `server/judge.py` still runs LLMs, just posts rulings on-chain instead of to DB
- **Free mode** — no contract, no escrow, Claude Haiku direct. Completely off-chain.
- **Agent logic** — `run_server.py` agent loop, investigation, fix generation
- **CLI UX** — `fix it` still just works. The chain stuff is invisible to the user.
- **Scrubber** — `scrubber.py` still redacts sensitive data from transcripts

### Migration Path

Phase 1 (now): Write and test the Solidity contract. Deploy to IOTA EVM testnet.
Phase 2: Build thin web3 wrapper in Python (`server/chain.py`) that talks to the contract.
Phase 3: Update `server/app.py` to use chain for money, keep everything else.
Phase 4: Update `client.py` and `fix.py` for IOTA wallet + on-chain calls.
Phase 5: Delete `server/nano.py`, `server/escrow.py` logic, Nano key derivation.

## Open Questions

1. **Do we support contracts without an oracle?** Currently free mode = no oracle, no escrow, off-chain only. If someone posts an on-chain contract with `oracle = address(0)`, disputes can't happen. Verify/autoFulfill still work. Should we allow this as "cheap mode" (on-chain escrow but no dispute resolution)?

2. **Gas sponsorship**: On IOTA EVM, gas is ~$0.0003 per transaction. Negligible. But users need IOTA for gas. Should the platform sponsor gas for new users? IOTA has a Gas Station module for this.

3. **Multi-oracle**: Could a contract specify different oracles per tier? District = cheap oracle, supreme = expensive oracle. Adds complexity but interesting for decentralization.

4. **Appeal bonds**: Should appealing to a higher tier require posting additional bond? Currently the original bond covers all tiers. If appeals required extra stake, it would further deter frivolous appeals.

## File Layout

```
contracts/
  FixEscrow.sol          — the contract
  PLAN.md                — this file
  test/
    FixEscrow.t.sol      — Foundry tests (every money flow)
server/
  chain.py               — web3 wrapper (new)
  app.py                 — updated endpoints
  judge.py               — posts rulings on-chain
  escrow.py              — thin wrapper around chain.py (mostly deleted)
  nano.py                — DELETED
```
