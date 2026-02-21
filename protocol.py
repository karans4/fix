"""Shared constants and interfaces for fix v2 protocol.

All modules import from here to avoid circular dependencies.
"""

from decimal import Decimal
from enum import Enum

# --- Protocol Constants ---

PROTOCOL_VERSION = 2

DEFAULT_BOUNTY = "0.1"
DEFAULT_CURRENCY = "XNO"
DEFAULT_CHAIN = "nano"
DEFAULT_CANCEL_FEE = "0.01"
MINIMUM_BOUNTY = "0.1"
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
DEFAULT_JUDGE_FEE = "0.21"  # XNO -- each side stakes this as dispute bond
DEFAULT_RULING_TIMEOUT = 60  # seconds judge has to rule

# Tiered court system: escalating models and fees
COURT_TIERS = [
    {"name": "district",  "model": "claude-haiku-4-5-20251001", "fee": "0.02"},
    {"name": "appeals",   "model": "claude-haiku-4-5-20251001", "fee": "0.04"},
    {"name": "supreme",   "model": "claude-opus-4-6",           "fee": "0.15"},
]
MAX_DISPUTE_LEVEL = len(COURT_TIERS) - 1  # supreme is final
# Bond = sum of all tier fees (covers worst-case full appeal)
DISPUTE_BOND = str(sum(Decimal(t["fee"]) for t in COURT_TIERS))  # "0.21"

# Platform fee: percentage of bounty from BOTH sides on every resolution
# Covers platform costs (agent LLM, hosting). Non-refundable.
PLATFORM_FEE_RATE = Decimal("0.10")  # 10% of bounty per side
PLATFORM_FEE_MIN = Decimal("0.005")  # XNO minimum per side

# Response window: seconds the other side has to counter-argue in a dispute
DISPUTE_RESPONSE_WINDOW = 30  # seconds

# Agent auto-pickup: seconds a contract sits before platform agent grabs it
AGENT_PICKUP_DELAY = 15

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
    ContractState.REVIEW: {ContractState.FULFILLED, ContractState.DISPUTED, ContractState.CANCELED},
    ContractState.BACKED_OUT: {ContractState.OPEN},  # reopen
    ContractState.DISPUTED: {ContractState.RESOLVED, ContractState.VOIDED},
    ContractState.HALTED: {ContractState.RESOLVED},
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
