"""Shared crypto utilities for fix v2 protocol.

Provides:
- Ed25519 identity (keypair generation, signing, verification)
- Signed message chain (tamper-evident transcript entries)
- SHA-256 hash chains for dispute evidence integrity
- HMAC-SHA256 signing (legacy, used by escrow)

Dependencies: hashlib, hmac, json, os, cryptography
"""

import hashlib
import hmac as hmac_mod
import json
import os
import time as _time

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization


# ---------------------------------------------------------------------------
# SHA-256 hash chain -- for evidence integrity in disputes
# ---------------------------------------------------------------------------

def sha256_hash(data: bytes) -> str:
    """SHA-256 hex digest of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def hash_chain_init() -> str:
    """Return the genesis link: SHA-256 of the empty string."""
    return sha256_hash(b"")


def hash_chain_append(chain: str, message: str) -> str:
    """Extend chain by one link: SHA256(chain || message)."""
    combined = (chain + message).encode("utf-8")
    return sha256_hash(combined)


def hash_chain_verify(chain: str, messages: list[str]) -> bool:
    """Rebuild the hash chain from scratch and compare to *chain*."""
    current = hash_chain_init()
    for msg in messages:
        current = hash_chain_append(current, msg)
    return current == chain


# ---------------------------------------------------------------------------
# HMAC-SHA256 signing (legacy -- used by escrow internals)
# ---------------------------------------------------------------------------

def hmac_sign(key: bytes, data: bytes) -> str:
    """HMAC-SHA256 of *data* under *key*, returned as hex."""
    return hmac_mod.new(key, data, hashlib.sha256).hexdigest()


def hmac_verify(key: bytes, data: bytes, signature: str) -> bool:
    """Constant-time comparison of HMAC-SHA256 signature."""
    expected = hmac_sign(key, data)
    return hmac_mod.compare_digest(expected, signature)


# ---------------------------------------------------------------------------
# Ed25519 identity
# ---------------------------------------------------------------------------

def generate_ed25519_keypair() -> tuple[bytes, bytes]:
    """Generate a new Ed25519 keypair. Returns (privkey_bytes, pubkey_bytes).
    Both are 32 bytes raw."""
    privkey = Ed25519PrivateKey.generate()
    priv_bytes = privkey.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    pub_bytes = privkey.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return priv_bytes, pub_bytes


def load_ed25519_key(path: str) -> bytes:
    """Load a 32-byte raw Ed25519 private key from file."""
    with open(path, "rb") as f:
        data = f.read()
    if len(data) != 32:
        raise ValueError(f"Expected 32-byte Ed25519 key, got {len(data)} bytes")
    return data


def save_ed25519_key(path: str, key: bytes) -> None:
    """Save a 32-byte raw Ed25519 private key to file (mode 0600)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, key)
    finally:
        os.close(fd)


def ed25519_privkey_to_pubkey(privkey_bytes: bytes) -> bytes:
    """Derive the 32-byte public key from a 32-byte private key."""
    privkey = Ed25519PrivateKey.from_private_bytes(privkey_bytes)
    return privkey.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def ed25519_sign(privkey_bytes: bytes, data: bytes) -> str:
    """Sign data with Ed25519 private key. Returns 128-char hex signature."""
    privkey = Ed25519PrivateKey.from_private_bytes(privkey_bytes)
    sig = privkey.sign(data)
    return sig.hex()


def ed25519_verify(pubkey_bytes: bytes, data: bytes, sig_hex: str) -> bool:
    """Verify Ed25519 signature. Returns True if valid."""
    from cryptography.exceptions import InvalidSignature
    try:
        pubkey = Ed25519PublicKey.from_public_bytes(pubkey_bytes)
        pubkey.verify(bytes.fromhex(sig_hex), data)
        return True
    except (InvalidSignature, ValueError):
        return False


# ---------------------------------------------------------------------------
# fix identity: pubkey <-> fix_id
# ---------------------------------------------------------------------------

def pubkey_to_fix_id(pubkey_bytes: bytes) -> str:
    """Convert 32-byte Ed25519 pubkey to fix identity string: 'fix_<64hex>'."""
    return "fix_" + pubkey_bytes.hex()


def fix_id_to_pubkey(fix_id: str) -> bytes:
    """Convert 'fix_<64hex>' identity string to 32-byte pubkey."""
    if not fix_id.startswith("fix_"):
        raise ValueError(f"Invalid fix identity: {fix_id}")
    hex_part = fix_id[4:]
    if len(hex_part) != 64:
        raise ValueError(f"Invalid fix identity length: {fix_id}")
    return bytes.fromhex(hex_part)


# ---------------------------------------------------------------------------
# Canonical JSON -- deterministic serialization for signing
# ---------------------------------------------------------------------------

def canonical_json(obj: dict) -> bytes:
    """Canonical JSON: sorted keys, no extra whitespace, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------------------
# Signed chain entries
# ---------------------------------------------------------------------------

def build_chain_entry(
    entry_type: str,
    data: dict,
    seq: int,
    author: str,
    prev_hash: str,
    privkey_bytes: bytes,
    timestamp: float | None = None,
) -> dict:
    """Build and sign a chain entry.

    Returns the full entry dict including signature.
    """
    entry = {
        "type": entry_type,
        "data": data,
        "seq": seq,
        "author": author,
        "prev_hash": prev_hash,
        "timestamp": int(_time.time()) if timestamp is None else int(timestamp),
    }
    # Sign the canonical JSON of the entry (without signature field)
    payload = canonical_json(entry)
    entry["signature"] = ed25519_sign(privkey_bytes, payload)
    return entry


def chain_entry_hash(entry: dict) -> str:
    """SHA-256 hash of the canonical JSON of a full entry (including signature)."""
    return sha256_hash(canonical_json(entry))


def verify_chain_entry(entry: dict) -> tuple[bool, str]:
    """Verify a single chain entry's signature.

    Returns (ok, error_message).
    """
    try:
        author = entry.get("author", "")
        pubkey_bytes = fix_id_to_pubkey(author)
    except (ValueError, KeyError) as e:
        return False, f"Invalid author: {e}"

    sig = entry.get("signature", "")
    if not sig:
        return False, "Missing signature"

    # Reconstruct the signing payload (everything except signature)
    payload_dict = {
        "type": entry["type"],
        "data": entry["data"],
        "seq": entry["seq"],
        "author": entry["author"],
        "prev_hash": entry["prev_hash"],
        "timestamp": entry["timestamp"],
    }
    payload = canonical_json(payload_dict)

    if not ed25519_verify(pubkey_bytes, payload, sig):
        return False, "Invalid signature"

    return True, ""


def verify_chain(entries: list[dict]) -> tuple[bool, str]:
    """Verify an entire chain: signatures + prev_hash linkage + seq ordering.

    Returns (ok, error_message).
    """
    if not entries:
        return True, ""

    expected_prev = hash_chain_init()
    for i, entry in enumerate(entries):
        # Check seq
        if entry.get("seq") != i:
            return False, f"Entry {i}: expected seq={i}, got seq={entry.get('seq')}"

        # Check prev_hash
        if entry.get("prev_hash") != expected_prev:
            return False, f"Entry {i}: prev_hash mismatch"

        # Verify signature
        ok, err = verify_chain_entry(entry)
        if not ok:
            return False, f"Entry {i}: {err}"

        # Advance chain
        expected_prev = chain_entry_hash(entry)

    return True, ""


# ---------------------------------------------------------------------------
# Ed25519 request signing -- for GET endpoints and non-chain auth
# ---------------------------------------------------------------------------

REQUEST_MAX_AGE = 300  # 5 minutes


class ReplayGuard:
    """Track seen signatures to prevent replay attacks. TTL matches REQUEST_MAX_AGE."""

    def __init__(self, ttl: int = REQUEST_MAX_AGE):
        self._seen: dict[str, float] = {}  # sig_hex -> expiry_timestamp
        self._ttl = ttl
        self._check_count = 0

    def check_and_record(self, sig_hex: str) -> bool:
        """Return False if sig was already seen, True if new (and record it)."""
        self._check_count += 1
        if self._check_count % 100 == 0:
            self._prune()

        now = _time.time()
        if sig_hex in self._seen:
            if now < self._seen[sig_hex]:
                return False  # still valid, replay detected
            # expired entry, treat as new
        self._seen[sig_hex] = now + self._ttl
        return True

    def _prune(self):
        now = _time.time()
        self._seen = {k: v for k, v in self._seen.items() if v > now}


def sign_request_ed25519(
    privkey_bytes: bytes,
    pubkey_hex: str,
    method: str,
    path: str,
    body: str = "",
    timestamp: float | None = None,
) -> dict:
    """Sign an API request with Ed25519. Returns headers to include.

    Signs: METHOD\nPATH\nTIMESTAMP\nBODY
    """
    ts = str(int(_time.time() if timestamp is None else timestamp))
    payload = f"{method}\n{path}\n{ts}\n{body}".encode("utf-8")
    sig = ed25519_sign(privkey_bytes, payload)
    return {
        "X-Fix-Timestamp": ts,
        "X-Fix-Signature": sig,
        "X-Fix-Pubkey": pubkey_hex,
    }


def verify_request_ed25519(
    method: str,
    path: str,
    body: str,
    timestamp: str,
    signature: str,
    pubkey_hex: str,
) -> tuple[bool, str]:
    """Verify an Ed25519-signed API request.

    Returns (ok, error_message).
    """
    # Check timestamp freshness
    try:
        ts = int(timestamp)
    except (ValueError, TypeError):
        return False, "invalid timestamp"

    now = _time.time()
    age = now - ts
    if age < -30:  # allow 30s clock skew for future timestamps
        return False, f"request timestamp is in the future (skew={int(-age)}s)"
    if age > REQUEST_MAX_AGE:
        return False, f"request expired (age={int(age)}s, max={REQUEST_MAX_AGE}s)"

    # Decode pubkey
    try:
        pubkey_bytes = bytes.fromhex(pubkey_hex)
        if len(pubkey_bytes) != 32:
            return False, "invalid pubkey length"
    except ValueError:
        return False, "invalid pubkey hex"

    # Verify signature
    payload = f"{method}\n{path}\n{timestamp}\n{body}".encode("utf-8")
    if not ed25519_verify(pubkey_bytes, payload, signature):
        return False, "invalid signature"

    return True, ""
