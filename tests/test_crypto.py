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


# ---- Ed25519 edge cases ----

class TestEd25519EdgeCases:
    def test_verify_forged_all_zeros_signature(self):
        """All-zeros signature returns False, not a crash."""
        _, pub = generate_ed25519_keypair()
        assert ed25519_verify(pub, b"data", "0" * 128) is False

    def test_verify_corrupted_signature(self):
        """Flipping one char in a valid sig invalidates it."""
        priv, pub = generate_ed25519_keypair()
        sig = ed25519_sign(priv, b"data")
        # Flip first hex char
        corrupted = ("1" if sig[0] == "0" else "0") + sig[1:]
        assert ed25519_verify(pub, b"data", corrupted) is False

    def test_sign_empty_data(self):
        """Signing empty bytes should not raise."""
        priv, _ = generate_ed25519_keypair()
        sig = ed25519_sign(priv, b"")
        assert len(sig) == 128

    def test_verify_empty_data(self):
        """Sign and verify empty bytes round-trips."""
        priv, pub = generate_ed25519_keypair()
        sig = ed25519_sign(priv, b"")
        assert ed25519_verify(pub, b"", sig) is True

    def test_load_nonexistent_file(self):
        """Loading a key from a nonexistent path raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            load_ed25519_key("nonexistent")


# ---- Fix identity edge cases ----

class TestFixIdentityEdgeCases:
    def test_fix_id_to_pubkey_invalid_hex(self):
        """Invalid hex chars in fix_id raise ValueError."""
        bad_id = "fix_" + "gg" * 32
        with pytest.raises(ValueError):
            fix_id_to_pubkey(bad_id)

    def test_pubkey_to_fix_id_wrong_length(self):
        """pubkey_to_fix_id with 16 bytes just hex-encodes without error."""
        result = pubkey_to_fix_id(b"\x00" * 16)
        assert result == "fix_" + "00" * 16


# ---- Chain entry edge cases ----

class TestChainEntryEdgeCases:
    def test_build_chain_entry_wrong_author_prefix(self):
        """Entry built with bad author prefix fails verification."""
        priv, pub = generate_ed25519_keypair()
        bad_author = "bad_" + pub.hex()
        entry = build_chain_entry("msg", {}, 0, bad_author, hash_chain_init(), priv)
        ok, err = verify_chain_entry(entry)
        assert not ok
        assert "Invalid author" in err or "author" in err.lower()

    def test_verify_chain_entry_missing_signature(self):
        """Entry dict without 'signature' key returns (False, error)."""
        priv, pub = generate_ed25519_keypair()
        author = pubkey_to_fix_id(pub)
        entry = build_chain_entry("msg", {}, 0, author, hash_chain_init(), priv)
        del entry["signature"]
        ok, err = verify_chain_entry(entry)
        assert not ok
        assert "signature" in err.lower() or "Missing" in err

    def test_verify_chain_entry_missing_fields(self):
        """Entry dict with only {"type": "x"} returns (False, error)."""
        ok, err = verify_chain_entry({"type": "x"})
        assert not ok

    def test_chain_entry_hash_includes_signature(self):
        """Same entry content but different signatures produce different hashes."""
        priv1, pub1 = generate_ed25519_keypair()
        priv2, pub2 = generate_ed25519_keypair()
        author1 = pubkey_to_fix_id(pub1)
        author2 = pubkey_to_fix_id(pub2)
        # Build two entries with identical structure but signed by different keys
        e1 = build_chain_entry("msg", {"x": 1}, 0, author1, hash_chain_init(), priv1, timestamp=1000)
        e2 = build_chain_entry("msg", {"x": 1}, 0, author2, hash_chain_init(), priv2, timestamp=1000)
        # Different authors/signatures -> different hashes
        assert chain_entry_hash(e1) != chain_entry_hash(e2)


# ---- Canonical JSON edge cases ----

class TestCanonicalJSONEdgeCases:
    def test_nested_objects_sorted(self):
        """Inner dict keys are also sorted."""
        result = canonical_json({"b": {"d": 1, "c": 2}, "a": 3})
        assert result == b'{"a":3,"b":{"c":2,"d":1}}'

    def test_unicode_handling(self):
        """Unicode values don't crash."""
        result = canonical_json({"key": "\u00e9"})
        assert b"key" in result

    def test_list_preserved(self):
        """List element order is preserved (not sorted)."""
        result = canonical_json({"a": [3, 1, 2]})
        assert result == b'{"a":[3,1,2]}'

    def test_bool_values(self):
        """Booleans encode as true/false."""
        result = canonical_json({"a": True, "b": False})
        assert result == b'{"a":true,"b":false}'

    def test_none_value(self):
        """None encodes as null."""
        result = canonical_json({"a": None})
        assert result == b'{"a":null}'


# ---- Request signing edge cases ----

class TestRequestSigningEdgeCases:
    def test_verify_empty_body(self):
        """Sign and verify with empty body."""
        priv, pub = generate_ed25519_keypair()
        headers = sign_request_ed25519(priv, pub.hex(), "GET", "/test", body="")
        ok, err = verify_request_ed25519(
            "GET", "/test", "",
            headers["X-Fix-Timestamp"],
            headers["X-Fix-Signature"],
            headers["X-Fix-Pubkey"],
        )
        assert ok, err

    def test_verify_tampered_body(self):
        """Signing with body='a' but verifying with body='b' fails."""
        priv, pub = generate_ed25519_keypair()
        headers = sign_request_ed25519(priv, pub.hex(), "POST", "/test", body="a")
        ok, _ = verify_request_ed25519(
            "POST", "/test", "b",
            headers["X-Fix-Timestamp"],
            headers["X-Fix-Signature"],
            headers["X-Fix-Pubkey"],
        )
        assert not ok

    def test_verify_malformed_timestamp(self):
        """Non-numeric timestamp returns (False, error)."""
        priv, pub = generate_ed25519_keypair()
        sig = ed25519_sign(priv, b"GET\n/test\nnot_a_number\n")
        ok, err = verify_request_ed25519(
            "GET", "/test", "",
            "not_a_number",
            sig.hex() if isinstance(sig, bytes) else sig,
            pub.hex(),
        )
        assert not ok
        assert "timestamp" in err.lower()

    def test_verify_future_timestamp(self):
        """Timestamp 600s in the future should still verify (within 30s skew check)."""
        import time
        priv, pub = generate_ed25519_keypair()
        future_ts = time.time() + 600
        headers = sign_request_ed25519(priv, pub.hex(), "GET", "/path", body="", timestamp=future_ts)
        ok, err = verify_request_ed25519(
            "GET", "/path", "",
            headers["X-Fix-Timestamp"],
            headers["X-Fix-Signature"],
            headers["X-Fix-Pubkey"],
        )
        # 600s in future exceeds the 30s skew allowance, so this should fail
        assert not ok
        assert "future" in err.lower()
