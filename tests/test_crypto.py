"""Tests for fix v3 crypto utilities (hash chains + HMAC)."""

import hashlib
import hmac as hmac_mod
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest

from crypto import (
    sha256_hash,
    hash_chain_init,
    hash_chain_append,
    hash_chain_verify,
    hmac_sign,
    hmac_verify,
)


# ---- SHA-256 hash chain ----

class TestSHA256:
    def test_known_empty_hash(self):
        """SHA-256 of empty bytes matches the well-known constant."""
        expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert sha256_hash(b"") == expected

    def test_known_hello_hash(self):
        expected = hashlib.sha256(b"hello").hexdigest()
        assert sha256_hash(b"hello") == expected


class TestHashChain:
    def test_init_is_empty_hash(self):
        assert hash_chain_init() == sha256_hash(b"")

    def test_append_deterministic(self):
        chain = hash_chain_init()
        a = hash_chain_append(chain, "msg1")
        b = hash_chain_append(chain, "msg1")
        assert a == b

    def test_append_changes_chain(self):
        chain = hash_chain_init()
        new_chain = hash_chain_append(chain, "hello")
        assert new_chain != chain

    def test_order_matters(self):
        chain = hash_chain_init()
        path_a = hash_chain_append(hash_chain_append(chain, "a"), "b")
        path_b = hash_chain_append(hash_chain_append(chain, "b"), "a")
        assert path_a != path_b

    def test_verify_valid_chain(self):
        messages = ["open contract", "accept", "submit result", "fulfill"]
        chain = hash_chain_init()
        for m in messages:
            chain = hash_chain_append(chain, m)
        assert hash_chain_verify(chain, messages) is True

    def test_verify_empty_chain(self):
        """An empty message list should verify against the init hash."""
        assert hash_chain_verify(hash_chain_init(), []) is True

    def test_verify_detects_tampered_message(self):
        messages = ["open contract", "accept", "fulfill"]
        chain = hash_chain_init()
        for m in messages:
            chain = hash_chain_append(chain, m)
        tampered = ["open contract", "accept", "TAMPERED"]
        assert hash_chain_verify(chain, tampered) is False

    def test_verify_detects_missing_message(self):
        messages = ["a", "b", "c"]
        chain = hash_chain_init()
        for m in messages:
            chain = hash_chain_append(chain, m)
        assert hash_chain_verify(chain, ["a", "b"]) is False

    def test_verify_detects_extra_message(self):
        messages = ["a", "b"]
        chain = hash_chain_init()
        for m in messages:
            chain = hash_chain_append(chain, m)
        assert hash_chain_verify(chain, ["a", "b", "c"]) is False


# ---- HMAC ----

class TestHMAC:
    def test_sign_matches_stdlib(self):
        key = b"secret-key"
        data = b"some payload"
        expected = hmac_mod.new(key, data, hashlib.sha256).hexdigest()
        assert hmac_sign(key, data) == expected

    def test_verify_valid(self):
        key = b"key"
        data = b"data"
        sig = hmac_sign(key, data)
        assert hmac_verify(key, data, sig) is True

    def test_verify_rejects_bad_sig(self):
        key = b"key"
        data = b"data"
        assert hmac_verify(key, data, "0" * 64) is False

    def test_different_keys_differ(self):
        data = b"same data"
        sig1 = hmac_sign(b"key1", data)
        sig2 = hmac_sign(b"key2", data)
        assert sig1 != sig2
