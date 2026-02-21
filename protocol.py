"""Shared constants and interfaces for fix v2 protocol.

All modules import from here to avoid circular dependencies.
"""

import os
from decimal import Decimal
from enum import Enum

# --- Protocol Constants ---

PROTOCOL_VERSION = 2

DEFAULT_BOUNTY = "0.05"
DEFAULT_CURRENCY = "XNO"
DEFAULT_CHAIN = "nano"
DEFAULT_CANCEL_FEE = "0.005"
MINIMUM_BOUNTY = "0.05"
GRACE_PERIOD_SECONDS = 30
ABANDONMENT_TIMEOUT = 120
MAX_INVESTIGATION_ROUNDS = 5
DEFAULT_MAX_ATTEMPTS = 5
XNO_RAW_PER_UNIT = 10**30

# Execution modes
MODE_SUPERVISED = "supervised"
MODE_AUTONOMOUS = "autonomous"

# Review window (autonomous mode): seconds before auto-fulfill
DEFAULT_REVIEW_WINDOW = 7200  # 2 hours

# Judge defaults
DEFAULT_JUDGE_FEE = "0.17"  # XNO -- each side stakes this as dispute bond
DEFAULT_RULING_TIMEOUT = 60  # seconds judge has to rule
DEFAULT_MIN_BOND = "0"  # XNO -- minimum bond to accept a contract (0 = judge fee only)

# Tiered court system: escalating models and fees
COURT_TIERS = [
    {"name": "district",  "model": "glm-4-plus",               "fee": "0.02"},
    {"name": "appeals",   "model": "anthropic/claude-sonnet-4", "fee": "0.05"},
    {"name": "supreme",   "model": "anthropic/claude-opus-4",   "fee": "0.10"},
]
MAX_DISPUTE_LEVEL = len(COURT_TIERS) - 1  # supreme is final
# Bond = sum of all tier fees (covers worst-case full appeal)
DISPUTE_BOND = str(sum(Decimal(t["fee"]) for t in COURT_TIERS))  # "0.21"

# Platform fee: percentage of bounty from BOTH sides on every resolution
# Covers platform costs (agent LLM, hosting). Non-refundable.
PLATFORM_FEE_RATE = Decimal("0.10")  # 10% of bounty per side
PLATFORM_FEE_MIN = Decimal("0.002")  # XNO minimum per side

# Response window: seconds the other side has to counter-argue in a dispute
DISPUTE_RESPONSE_WINDOW = 30  # seconds

# Agent auto-pickup: seconds a contract sits before platform agent grabs it
AGENT_PICKUP_DELAY = 15

CONTRACT_PICKUP_TIMEOUT = 30  # seconds before unclaimed contract is auto-canceled

# Platform treasury — set via FIX_PLATFORM_ADDRESS env var, or empty (fees stay in escrow)
PLATFORM_ADDRESS = os.environ.get("FIX_PLATFORM_ADDRESS", "")

# Charity address: evil_both funds go here (Green Mountain State Wolfdog Refuge)
CHARITY_ADDRESS = "nano_1q3hsjq6tmj1tne66rymctadqbi8ijtak7x1fr5dkmesnkdrqxnoojttcgok"

# Sanity check: validate charity address at import time (inline to avoid circular import)
def _validate_charity():
    import hashlib
    _alphabet = '13456789abcdefghijkmnopqrstuwxyz'
    addr = CHARITY_ADDRESS
    if not addr.startswith('nano_') and not addr.startswith('xrb_'):
        raise RuntimeError(f"CHARITY_ADDRESS has invalid prefix")
    payload = addr[5:] if addr.startswith('nano_') else addr[4:]
    if len(payload) != 60:
        raise RuntimeError(f"CHARITY_ADDRESS has invalid length")
    for c in payload:
        if c not in _alphabet:
            raise RuntimeError(f"CHARITY_ADDRESS has invalid character '{c}'")
    key_part, ck_part = payload[:52], payload[52:]
    val = 0
    for c in key_part:
        val = (val << 5) | _alphabet.index(c)
    val &= (1 << 256) - 1
    pubkey = val.to_bytes(32, 'big')
    ck_val = 0
    for c in ck_part:
        ck_val = (ck_val << 5) | _alphabet.index(c)
    decoded_ck = ck_val.to_bytes(5, 'big')
    expected_ck = hashlib.blake2b(pubkey, digest_size=5).digest()[::-1]
    if decoded_ck != expected_ck:
        raise RuntimeError(f"CHARITY_ADDRESS has invalid checksum")

_validate_charity()
del _validate_charity

# Investigation rate limiting
DEFAULT_INVESTIGATION_RATE = 5  # seconds between commands


# --- State Machine ---

class ContractState(Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"  # agent bonded, inspecting before accept
    IN_PROGRESS = "in_progress"
    REVIEW = "review"  # autonomous mode: fix submitted, awaiting accept/dispute/timeout
    FULFILLED = "fulfilled"
    CANCELED = "canceled"
    BACKED_OUT = "backed_out"
    DISPUTED = "disputed"
    HALTED = "halted"
    RESOLVED = "resolved"
    VOIDED = "voided"  # judge timeout, all funds returned


# Valid state transitions: current_state -> set of valid next states
STATE_TRANSITIONS = {
    ContractState.OPEN: {ContractState.INVESTIGATING, ContractState.IN_PROGRESS, ContractState.CANCELED},
    ContractState.INVESTIGATING: {ContractState.IN_PROGRESS, ContractState.OPEN},  # accept or decline
    ContractState.IN_PROGRESS: {
        ContractState.FULFILLED,
        ContractState.CANCELED,
        ContractState.BACKED_OUT,
        ContractState.DISPUTED,
        ContractState.HALTED,
        ContractState.REVIEW,
    },
    ContractState.REVIEW: {ContractState.FULFILLED, ContractState.DISPUTED, ContractState.CANCELED, ContractState.HALTED},
    ContractState.BACKED_OUT: {ContractState.OPEN},  # reopen
    ContractState.DISPUTED: {ContractState.RESOLVED, ContractState.VOIDED, ContractState.IN_PROGRESS},
    ContractState.HALTED: {ContractState.RESOLVED, ContractState.IN_PROGRESS},
    ContractState.FULFILLED: set(),
    ContractState.CANCELED: set(),
    ContractState.RESOLVED: set(),
    ContractState.VOIDED: set(),
}


# --- Feedback Message Types ---

class FeedbackType(Enum):
    ACCEPT = "accept"
    DECLINE = "decline"
    INVESTIGATE = "investigate"
    RESULT = "result"
    VERDICT = "verdict"
    BACK_OUT = "back_out"
    HALT = "halt"  # emergency kill by principal
    ASK = "ask"  # agent asks principal a question
    ANSWER = "answer"  # principal answers agent
    MESSAGE = "message"  # general chat (either direction)


# --- Verdict Rulings ---

class Ruling(Enum):
    FULFILLED = "fulfilled"
    CANCELED = "canceled"
    IMPOSSIBLE = "impossible"
    EVIL_AGENT = "evil_agent"
    EVIL_PRINCIPAL = "evil_principal"
    EVIL_BOTH = "evil_both"


# --- Evil Flags ---

EVIL_FLAGS = {"evil_agent", "evil_principal", "evil_both"}


# --- Investigation Command Whitelist ---
# (re-exported from main fix CLI for agent use)

INVESTIGATE_WHITELIST = {
    "cat", "head", "tail", "less", "file", "wc", "stat", "md5sum", "sha256sum",
    "ls", "find", "tree", "du",
    "grep", "rg", "ag", "awk", "sed",
    "which", "whereis", "type", "command", "uname", "arch", "lsb_release", "hostnamectl",
    "dpkg", "apt", "apt-cache", "apt-file", "apt-list", "rpm", "pacman",
    "pip", "pip3", "npm", "gem", "cargo", "rustc",
    "python3", "python", "node", "gcc", "g++", "make", "cmake", "java", "go", "ruby",
    "clang", "clang++", "ld", "as", "nasm",
    "env", "printenv", "echo", "id", "whoami", "pwd", "hostname",
    "lsmod", "lscpu", "free", "df", "mount", "ip", "ss", "ps",
    "journalctl", "dmesg",
    "readlink", "realpath", "basename", "dirname", "diff", "cmp",
    "strings", "nm", "ldd", "objdump", "pkg-config", "test", "timeout",
}


# --- Chain Entry Types ---

# All valid chain entry types
CHAIN_ENTRY_TYPES = {
    "post", "bond", "accept", "decline", "investigate", "result",
    "fix", "verify", "dispute_filed", "dispute_response",
    "chat", "ask", "answer", "message",
    "halt", "review_accept",
    # Server-only types
    "ruling", "auto_fulfill", "voided",
}

# Only the server can sign these types
SERVER_ENTRY_TYPES = {"ruling", "auto_fulfill", "voided"}
