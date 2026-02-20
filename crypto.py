"""Shared crypto utilities for fix v2 protocol.

Provides:
- SHA-256 hash chains for dispute evidence integrity
- HMAC-SHA256 signing

Dependencies: hashlib, hmac, json, os
"""

import hashlib
import hmac as hmac_mod
import json
import os


# ---------------------------------------------------------------------------
# SHA-256 hash chain — for evidence integrity in disputes
# ---------------------------------------------------------------------------

def sha256_hash(data: bytes) -> str:
    """SHA-256 hex digest of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def hash_chain_init() -> str:
    """Return the genesis link: SHA-256 of the empty string."""
    return sha256_hash(b"")


def hash_chain_append(chain: str, message: str) -> str:
    """Extend chain by one link: SHA256(chain || message).

    Both chain (hex) and message (utf-8) are concatenated as raw strings
    before hashing so the chain is order-dependent and tamper-evident.
    """
    combined = (chain + message).encode("utf-8")
    return sha256_hash(combined)


def hash_chain_verify(chain: str, messages: list[str]) -> bool:
    """Rebuild the hash chain from scratch and compare to *chain*.

    Returns True iff replaying every message in order produces the same
    final hash.
    """
    current = hash_chain_init()
    for msg in messages:
        current = hash_chain_append(current, msg)
    return current == chain


# ---------------------------------------------------------------------------
# HMAC-SHA256 signing
# ---------------------------------------------------------------------------

def hmac_sign(key: bytes, data: bytes) -> str:
    """HMAC-SHA256 of *data* under *key*, returned as hex."""
    return hmac_mod.new(key, data, hashlib.sha256).hexdigest()


def hmac_verify(key: bytes, data: bytes, signature: str) -> bool:
    """Constant-time comparison of HMAC-SHA256 signature."""
    expected = hmac_sign(key, data)
    return hmac_mod.compare_digest(expected, signature)
