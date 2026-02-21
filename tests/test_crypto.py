"""Tests for fix v3 crypto utilities (hash chains + HMAC + Ed25519)."""

import hashlib
import hmac as hmac_mod
import sys
import os
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest

from crypto import (
    sha256_hash,
    hash_chain_init,
    hash_chain_append,
    hash_chain_verify,
    hmac_sign,
    hmac_verify,
    generate_ed25519_keypair,
    load_ed25519_key,
    save_ed25519_key,
    ed25519_privkey_to_pubkey,
    ed25519_sign,
    ed25519_verify,
    pubkey_to_fix_id,
    fix_id_to_pubkey,
    canonical_json,
    build_chain_entry,
    chain_entry_hash,
    verify_chain_entry,
    verify_chain,
    sign_request_ed25519,
    verify_request_ed25519,
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


# ---- Ed25519 ----

class TestEd25519:
    def test_generate_keypair_lengths(self):
        priv, pub = generate_ed25519_keypair()
        assert len(priv) == 32
        assert len(pub) == 32

    def test_keypair_deterministic_pubkey(self):
        priv, pub = generate_ed25519_keypair()
        assert ed25519_privkey_to_pubkey(priv) == pub

    def test_sign_and_verify(self):
        priv, pub = generate_ed25519_keypair()
        sig = ed25519_sign(priv, b"hello world")
        assert ed25519_verify(pub, b"hello world", sig)

    def test_verify_rejects_wrong_data(self):
        priv, pub = generate_ed25519_keypair()
        sig = ed25519_sign(priv, b"hello")
        assert not ed25519_verify(pub, b"wrong", sig)

    def test_verify_rejects_wrong_key(self):
        priv1, pub1 = generate_ed25519_keypair()
        _, pub2 = generate_ed25519_keypair()
        sig = ed25519_sign(priv1, b"data")
        assert not ed25519_verify(pub2, b"data", sig)

    def test_signature_is_128_hex_chars(self):
        priv, _ = generate_ed25519_keypair()
        sig = ed25519_sign(priv, b"test")
        assert len(sig) == 128
        int(sig, 16)  # valid hex

    def test_save_and_load_key(self):
        priv, _ = generate_ed25519_keypair()
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name
        try:
            save_ed25519_key(path, priv)
            loaded = load_ed25519_key(path)
            assert loaded == priv
            # File should be mode 0600
            mode = os.stat(path).st_mode & 0o777
            assert mode == 0o600
        finally:
            os.unlink(path)

    def test_load_bad_key_length(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"short")
            path = f.name
        try:
            with pytest.raises(ValueError, match="Expected 32-byte"):
                load_ed25519_key(path)
        finally:
            os.unlink(path)


class TestFixIdentity:
    def test_pubkey_to_fix_id_format(self):
        _, pub = generate_ed25519_keypair()
        fix_id = pubkey_to_fix_id(pub)
        assert fix_id.startswith("fix_")
        assert len(fix_id) == 68  # "fix_" + 64 hex chars

    def test_roundtrip(self):
        _, pub = generate_ed25519_keypair()
        fix_id = pubkey_to_fix_id(pub)
        recovered = fix_id_to_pubkey(fix_id)
        assert recovered == pub

    def test_invalid_prefix(self):
        with pytest.raises(ValueError, match="Invalid fix identity"):
            fix_id_to_pubkey("bad_1234")

    def test_invalid_length(self):
        with pytest.raises(ValueError, match="Invalid fix identity length"):
            fix_id_to_pubkey("fix_1234")


# ---- Chain entries ----

class TestChainEntries:
    def test_build_and_verify_entry(self):
        priv, pub = generate_ed25519_keypair()
        author = pubkey_to_fix_id(pub)
        entry = build_chain_entry("fix", {"cmd": "gcc"}, 0, author, hash_chain_init(), priv)
        assert entry["type"] == "fix"
        assert entry["seq"] == 0
        assert entry["author"] == author
        assert "signature" in entry
        ok, err = verify_chain_entry(entry)
        assert ok, err

    def test_verify_detects_tampered_data(self):
        priv, pub = generate_ed25519_keypair()
        author = pubkey_to_fix_id(pub)
        entry = build_chain_entry("fix", {"cmd": "gcc"}, 0, author, hash_chain_init(), priv)
        entry["data"]["cmd"] = "rm -rf /"  # tamper
        ok, err = verify_chain_entry(entry)
        assert not ok
        assert "Invalid signature" in err

    def test_verify_detects_tampered_type(self):
        priv, pub = generate_ed25519_keypair()
        author = pubkey_to_fix_id(pub)
        entry = build_chain_entry("fix", {"cmd": "gcc"}, 0, author, hash_chain_init(), priv)
        entry["type"] = "ruling"
        ok, err = verify_chain_entry(entry)
        assert not ok

    def test_chain_entry_hash_deterministic(self):
        priv, pub = generate_ed25519_keypair()
        author = pubkey_to_fix_id(pub)
        entry = build_chain_entry("fix", {"cmd": "gcc"}, 0, author, hash_chain_init(), priv, timestamp=1.0)
        h1 = chain_entry_hash(entry)
        h2 = chain_entry_hash(entry)
        assert h1 == h2

    def test_verify_chain_valid(self):
        priv, pub = generate_ed25519_keypair()
        author = pubkey_to_fix_id(pub)
        prev = hash_chain_init()
        entries = []
        for i in range(5):
            e = build_chain_entry("msg", {"i": i}, i, author, prev, priv)
            entries.append(e)
            prev = chain_entry_hash(e)
        ok, err = verify_chain(entries)
        assert ok, err

    def test_verify_chain_detects_reorder(self):
        priv, pub = generate_ed25519_keypair()
        author = pubkey_to_fix_id(pub)
        prev = hash_chain_init()
        entries = []
        for i in range(3):
            e = build_chain_entry("msg", {"i": i}, i, author, prev, priv)
            entries.append(e)
            prev = chain_entry_hash(e)
        # Swap entries 1 and 2
        entries[1], entries[2] = entries[2], entries[1]
        ok, err = verify_chain(entries)
        assert not ok

    def test_verify_chain_detects_gap(self):
        priv, pub = generate_ed25519_keypair()
        author = pubkey_to_fix_id(pub)
        prev = hash_chain_init()
        entries = []
        for i in range(3):
            e = build_chain_entry("msg", {"i": i}, i, author, prev, priv)
            entries.append(e)
            prev = chain_entry_hash(e)
        # Remove middle entry
        ok, err = verify_chain([entries[0], entries[2]])
        assert not ok

    def test_verify_empty_chain(self):
        ok, err = verify_chain([])
        assert ok

    def test_multi_author_chain(self):
        """Chain with entries from different authors."""
        priv1, pub1 = generate_ed25519_keypair()
        priv2, pub2 = generate_ed25519_keypair()
        a1 = pubkey_to_fix_id(pub1)
        a2 = pubkey_to_fix_id(pub2)
        prev = hash_chain_init()
        e0 = build_chain_entry("post", {}, 0, a1, prev, priv1)
        prev = chain_entry_hash(e0)
        e1 = build_chain_entry("accept", {}, 1, a2, prev, priv2)
        ok, err = verify_chain([e0, e1])
        assert ok, err


# ---- Ed25519 request signing ----

class TestRequestSigning:
    def test_sign_and_verify_request(self):
        priv, pub = generate_ed25519_keypair()
        headers = sign_request_ed25519(priv, pub.hex(), "POST", "/test", "body")
        ok, err = verify_request_ed25519(
            "POST", "/test", "body",
            headers["X-Fix-Timestamp"],
            headers["X-Fix-Signature"],
            headers["X-Fix-Pubkey"],
        )
        assert ok, err

    def test_verify_rejects_wrong_method(self):
        priv, pub = generate_ed25519_keypair()
        headers = sign_request_ed25519(priv, pub.hex(), "POST", "/test", "body")
        ok, _ = verify_request_ed25519(
            "GET", "/test", "body",
            headers["X-Fix-Timestamp"],
            headers["X-Fix-Signature"],
            headers["X-Fix-Pubkey"],
        )
        assert not ok

    def test_verify_rejects_expired(self):
        import time
        priv, pub = generate_ed25519_keypair()
        old_ts = time.time() - 600  # 10 min ago
        headers = sign_request_ed25519(priv, pub.hex(), "POST", "/test", "", timestamp=old_ts)
        ok, err = verify_request_ed25519(
            "POST", "/test", "",
            headers["X-Fix-Timestamp"],
            headers["X-Fix-Signature"],
            headers["X-Fix-Pubkey"],
        )
        assert not ok
        assert "expired" in err

    def test_verify_rejects_bad_pubkey(self):
        priv, pub = generate_ed25519_keypair()
        _, pub2 = generate_ed25519_keypair()
        headers = sign_request_ed25519(priv, pub.hex(), "POST", "/test", "")
        ok, _ = verify_request_ed25519(
            "POST", "/test", "",
            headers["X-Fix-Timestamp"],
            headers["X-Fix-Signature"],
            pub2.hex(),  # wrong pubkey
        )
        assert not ok


# ---- Canonical JSON ----

class TestCanonicalJSON:
    def test_sorted_keys(self):
        assert canonical_json({"b": 1, "a": 2}) == b'{"a":2,"b":1}'

    def test_no_spaces(self):
        result = canonical_json({"key": "value"})
        assert b" " not in result

    def test_deterministic(self):
        d = {"z": 1, "a": 2, "m": 3}
        assert canonical_json(d) == canonical_json(d)
