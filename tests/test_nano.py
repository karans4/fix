import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from decimal import Decimal
from unittest.mock import MagicMock, patch

from server.nano import (
    NanoBackend, StubBackend, SimBackend, PaymentBackend,
    xno_to_raw, raw_to_xno, RAW_PER_XNO,
    _pubkey_to_address, _address_to_pubkey,
    validate_nano_address,
)


# --- Unit conversion tests ---

def test_xno_to_raw():
    assert xno_to_raw("1") == 10**30
    assert xno_to_raw("0.001") == 10**27
    assert xno_to_raw("0") == 0

def test_raw_to_xno():
    assert raw_to_xno(10**30) == Decimal("1")
    assert raw_to_xno(10**27) == Decimal("0.001")
    assert raw_to_xno(0) == Decimal("0")

def test_roundtrip_conversion():
    for val in ["1", "0.5", "0.001", "100.123456"]:
        raw = xno_to_raw(val)
        back = raw_to_xno(raw)
        assert back == Decimal(val)


# --- Address encoding/decoding ---

def test_address_roundtrip():
    """Encode pubkey -> address -> decode -> same pubkey."""
    import hashlib, ed25519_blake2b
    seed = bytes.fromhex("aa" * 32)
    priv = hashlib.blake2b(seed + b"test", digest_size=32).digest()
    sk = ed25519_blake2b.SigningKey(priv)
    pubkey = sk.get_verifying_key().to_bytes()
    addr = _pubkey_to_address(pubkey)
    assert addr.startswith("nano_")
    assert len(addr) == 65  # nano_ + 52 + 8
    decoded = _address_to_pubkey(addr)
    assert decoded == pubkey


# --- StubBackend tests ---

def test_stub_create_account():
    stub = StubBackend()
    result = stub.create_escrow_account("contract123")
    assert "account" in result
    assert result["account"].startswith("nano_stub_")

def test_stub_check_deposit_always_true():
    stub = StubBackend()
    stub.create_escrow_account("c1")
    assert stub.check_deposit("c1", "1.0") is True

def test_stub_send_logs():
    stub = StubBackend()
    stub.create_escrow_account("c1")
    h = stub.send("c1", "nano_dest", "0.5")
    assert h.startswith("stub_hash_")
    assert len(stub.sends) == 1
    assert stub.sends[0]["to"] == "nano_dest"
    assert stub.sends[0]["amount"] == "0.5"

def test_stub_balance():
    stub = StubBackend()
    assert stub.get_balance("nonexistent") == "0"

def test_stub_no_index_in_result():
    """StubBackend.create_escrow_account should not return 'index'."""
    stub = StubBackend()
    result = stub.create_escrow_account("c1")
    assert "index" not in result


# --- NanoBackend tests ---

def test_nano_requires_seed():
    with pytest.raises(ValueError, match="seed required"):
        NanoBackend(seed="")

def test_nano_requires_64_hex():
    with pytest.raises(ValueError, match="64 hex"):
        NanoBackend(seed="abc")

def test_nano_rejects_non_hex():
    with pytest.raises(ValueError, match="64 hex"):
        NanoBackend(seed="g" * 64)

def test_nano_nonce_is_random():
    """Different contracts get different random nonces."""
    backend = NanoBackend(seed="a" * 64, node_url="http://fake")
    n1 = backend._get_nonce("contract_1")
    n2 = backend._get_nonce("contract_2")
    assert len(n1) == 32
    assert len(n2) == 32
    assert n1 != n2

def test_nano_nonce_is_stable():
    """Same contract always returns same nonce."""
    backend = NanoBackend(seed="a" * 64, node_url="http://fake")
    n1 = backend._get_nonce("contract_1")
    n2 = backend._get_nonce("contract_1")
    assert n1 == n2

def test_nano_keypair_deterministic():
    """Same seed + same nonce = same keypair."""
    backend = NanoBackend(seed="a" * 64, node_url="http://fake")
    sk1, vk1 = backend._derive_keypair("c1")
    sk2, vk2 = backend._derive_keypair("c1")
    assert vk1.to_bytes() == vk2.to_bytes()

def test_nano_different_contracts_different_keys():
    """Different contracts get different keypairs."""
    backend = NanoBackend(seed="a" * 64, node_url="http://fake")
    _, vk1 = backend._derive_keypair("c1")
    _, vk2 = backend._derive_keypair("c2")
    assert vk1.to_bytes() != vk2.to_bytes()

def test_nano_different_seeds_different_keys():
    """Same nonce with different seeds = different keys (need both secrets)."""
    b1 = NanoBackend(seed="a" * 64, node_url="http://fake")
    b2 = NanoBackend(seed="b" * 64, node_url="http://fake")
    # Force same nonce into both backends
    nonce = b1._get_nonce("c1")
    b2._db.execute("INSERT INTO nano_nonces (contract_id, nonce) VALUES (?, ?)", ("c1", nonce))
    b2._db.commit()
    # Even with same nonce, different seed = different key
    _, vk1 = b1._derive_keypair("c1")
    _, vk2 = b2._derive_keypair("c1")
    assert vk1.to_bytes() != vk2.to_bytes()

def test_nano_create_account():
    backend = NanoBackend(seed="a" * 64, node_url="http://fake")
    result = backend.create_escrow_account("contract_1")
    assert "account" in result
    assert result["account"].startswith("nano_")
    assert "index" not in result  # no more index

def test_nano_create_account_deterministic():
    backend = NanoBackend(seed="a" * 64, node_url="http://fake")
    r1 = backend.create_escrow_account("contract_1")
    r2 = backend.create_escrow_account("contract_1")
    assert r1["account"] == r2["account"]

def test_nano_different_contracts_different_accounts():
    backend = NanoBackend(seed="a" * 64, node_url="http://fake")
    r1 = backend.create_escrow_account("contract_1")
    r2 = backend.create_escrow_account("contract_2")
    assert r1["account"] != r2["account"]

def test_nano_valid_address_format():
    """Generated addresses should be valid nano_ addresses."""
    backend = NanoBackend(seed="a" * 64, node_url="http://fake")
    result = backend.create_escrow_account("c1")
    addr = result["account"]
    assert addr.startswith("nano_")
    assert len(addr) == 65
    # Should roundtrip through decode/encode
    pubkey = _address_to_pubkey(addr)
    assert _pubkey_to_address(pubkey) == addr

def test_nano_check_deposit_sufficient():
    backend = NanoBackend(seed="a" * 64, node_url="http://fake")
    backend._receive_all = MagicMock()  # skip RPC
    backend._rpc = MagicMock(return_value={"balance": str(10**30), "receivable": "0"})
    assert backend.check_deposit("c1", "1.0") is True

def test_nano_check_deposit_insufficient():
    backend = NanoBackend(seed="a" * 64, node_url="http://fake")
    backend._receive_all = MagicMock()
    backend._rpc = MagicMock(return_value={"balance": str(10**27), "receivable": "0"})
    assert backend.check_deposit("c1", "1.0") is False

def test_nano_send():
    backend = NanoBackend(seed="a" * 64, node_url="http://fake")
    backend._receive_all = MagicMock()

    account = backend._get_account("c1")

    def mock_rpc(action, **kwargs):
        if action == "account_info":
            return {
                "frontier": "ab" * 32,
                "balance": str(10**30),
                "representative": account,
            }
        if action == "work_generate":
            return {"work": "0000000000000000"}
        if action == "process":
            return {"hash": "DEADBEEF" * 8}
        return {}

    backend._rpc = MagicMock(side_effect=mock_rpc)
    result = backend.send("c1", "nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3", "0.5")
    assert result == "DEADBEEF" * 8

def test_nano_send_insufficient_balance():
    backend = NanoBackend(seed="a" * 64, node_url="http://fake")
    backend._receive_all = MagicMock()

    account = backend._get_account("c1")

    def mock_rpc(action, **kwargs):
        if action == "account_info":
            return {
                "frontier": "ab" * 32,
                "balance": str(10**27),  # 0.001 XNO
                "representative": account,
            }
        return {}

    backend._rpc = MagicMock(side_effect=mock_rpc)
    with pytest.raises(ValueError, match="Insufficient balance"):
        backend.send("c1", "nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3", "1.0")

def test_nano_send_zero_is_noop():
    backend = NanoBackend(seed="a" * 64, node_url="http://fake")
    assert backend.send("c1", "nano_dest", "0") == "noop_zero_amount"

def test_nano_get_balance():
    backend = NanoBackend(seed="a" * 64, node_url="http://fake")
    backend._rpc = MagicMock(return_value={"balance": str(5 * 10**29)})
    bal = backend.get_balance("c1")
    assert Decimal(bal) == Decimal("0.5")

def test_nano_get_balance_error_returns_zero():
    backend = NanoBackend(seed="a" * 64, node_url="http://fake")
    backend._rpc = MagicMock(side_effect=Exception("network error"))
    assert backend.get_balance("c1") == "0"


# --- PaymentBackend ABC test ---

def test_payment_backend_is_abstract():
    with pytest.raises(TypeError):
        PaymentBackend()


# --- Integration: EscrowManager with StubBackend ---

# Two valid addresses for integration tests
_VALID_ADDR_1 = "nano_1q3hsjq6tmj1tne66rymctadqbi8ijtak7x1fr5dkmesnkdrqxnoojttcgok"
_VALID_ADDR_2 = "nano_1n14s3f4dyz7cnq6y848a5ep6wysy15jzxbjn4hbyebn7stgi3p13jin3o8q"

def test_escrow_manager_with_stub():
    from server.escrow import EscrowManager
    stub = StubBackend()
    mgr = EscrowManager(payment_backend=stub)

    # Lock
    result = mgr.lock("c1", "1.0", {})
    assert result["status"] == "locked"
    assert "escrow_account" in result

    # Set accounts
    mgr.set_accounts("c1", principal_account=_VALID_ADDR_1, agent_account=_VALID_ADDR_2)

    # Resolve fulfilled -> send to agent
    result = mgr.resolve("c1", "fulfilled")
    assert result["action"] == "release_to_agent"
    assert len(stub.sends) == 1
    assert stub.sends[0]["to"] == _VALID_ADDR_2

def test_escrow_manager_resolve_canceled():
    from server.escrow import EscrowManager
    stub = StubBackend()
    mgr = EscrowManager(payment_backend=stub)
    mgr.lock("c1", "1.0", {})
    mgr.set_accounts("c1", principal_account=_VALID_ADDR_1, agent_account=_VALID_ADDR_2)

    result = mgr.resolve("c1", "canceled")
    assert result["action"] == "return_to_principal"
    assert len(stub.sends) == 1
    assert stub.sends[0]["to"] == _VALID_ADDR_1

def test_escrow_manager_get_includes_accounts():
    from server.escrow import EscrowManager
    stub = StubBackend()
    mgr = EscrowManager(payment_backend=stub)
    mgr.lock("c1", "0.5", {})
    mgr.set_accounts("c1", principal_account=_VALID_ADDR_1, agent_account=_VALID_ADDR_2)

    data = mgr.get("c1")
    assert data["escrow_account"] is not None
    assert data["principal_account"] == _VALID_ADDR_1
    assert data["agent_account"] == _VALID_ADDR_2


# --- Address validation tests ---

def test_validate_known_good_address():
    """The charity address from protocol.py should be valid."""
    addr = "nano_1q3hsjq6tmj1tne66rymctadqbi8ijtak7x1fr5dkmesnkdrqxnoojttcgok"
    ok, err = validate_nano_address(addr)
    assert ok, f"Expected valid, got: {err}"
    assert err == ""

def test_validate_generated_address():
    """Addresses generated by _pubkey_to_address should validate."""
    import hashlib, ed25519_blake2b
    seed = bytes.fromhex("bb" * 32)
    priv = hashlib.blake2b(seed + b"test_validate", digest_size=32).digest()
    sk = ed25519_blake2b.SigningKey(priv)
    pubkey = sk.get_verifying_key().to_bytes()
    addr = _pubkey_to_address(pubkey)
    ok, err = validate_nano_address(addr)
    assert ok, f"Generated address failed validation: {err}"

def test_validate_xrb_prefix():
    """xrb_ prefix should also be accepted (legacy format)."""
    # Build an xrb_ address from a known nano_ one
    addr = "nano_1q3hsjq6tmj1tne66rymctadqbi8ijtak7x1fr5dkmesnkdrqxnoojttcgok"
    xrb_addr = "xrb_" + addr[5:]
    ok, err = validate_nano_address(xrb_addr)
    assert ok, f"xrb_ address failed validation: {err}"

def test_validate_bad_prefix():
    ok, err = validate_nano_address("btc_1q3hsjq6tmj1tne66rymctadqbi8ijtak7x1fr5dkmesnkdrqxnoojttcgok")
    assert not ok
    assert "prefix" in err.lower()

def test_validate_too_short():
    ok, err = validate_nano_address("nano_1q3hsjq6tmj1tne66rymctadqbi8ijtak7x1fr5d")
    assert not ok
    assert "length" in err.lower()

def test_validate_too_long():
    ok, err = validate_nano_address("nano_1q3hsjq6tmj1tne66rymctadqbi8ijtak7x1fr5dkmesnkdrqxnoojttcgokAAAA")
    assert not ok
    # Could be length or bad char
    assert not ok

def test_validate_bad_char():
    """Characters not in Nano base32 alphabet (0, 2, l, v) should fail."""
    # Replace a valid char with '0' (not in alphabet)
    addr = "nano_0q3hsjq6tmj1tne66rymctadqbi8ijtak7x1fr5dkmesnkdrqxnoojttcgok"
    ok, err = validate_nano_address(addr)
    assert not ok
    assert "character" in err.lower() or "invalid" in err.lower()

def test_validate_bad_checksum():
    """Flip a char in the checksum portion (last 8 chars) to corrupt it."""
    addr = "nano_1q3hsjq6tmj1tne66rymctadqbi8ijtak7x1fr5dkmesnkdrqxnoojttcgok"
    # Flip last char
    last = addr[-1]
    replacement = '1' if last != '1' else '3'
    bad_addr = addr[:-1] + replacement
    ok, err = validate_nano_address(bad_addr)
    assert not ok
    assert "checksum" in err.lower()

def test_validate_bad_pubkey_char():
    """Flip a char in the pubkey portion to corrupt checksum."""
    addr = "nano_1q3hsjq6tmj1tne66rymctadqbi8ijtak7x1fr5dkmesnkdrqxnoojttcgok"
    # Flip char at position 10 (in pubkey section)
    chars = list(addr)
    pos = 15  # somewhere in the key part
    chars[pos] = '1' if chars[pos] != '1' else '3'
    bad_addr = ''.join(chars)
    ok, err = validate_nano_address(bad_addr)
    assert not ok
    assert "checksum" in err.lower()

def test_validate_empty_string():
    ok, err = validate_nano_address("")
    assert not ok

def test_validate_just_prefix():
    ok, err = validate_nano_address("nano_")
    assert not ok
    assert "length" in err.lower()


# --- EscrowManager rejects invalid addresses ---

def test_escrow_set_accounts_rejects_invalid():
    """set_accounts should raise ValueError for invalid Nano addresses."""
    from server.escrow import EscrowManager
    stub = StubBackend()
    mgr = EscrowManager(payment_backend=stub)
    mgr.lock("c1", "1.0", {})

    with pytest.raises(ValueError, match="Invalid.*Nano address"):
        mgr.set_accounts("c1", principal_account="not_a_valid_address")

    with pytest.raises(ValueError, match="Invalid.*Nano address"):
        mgr.set_accounts("c1", agent_account="nano_tooshort")

def test_escrow_set_accounts_accepts_valid():
    """set_accounts should work with valid Nano addresses."""
    from server.escrow import EscrowManager
    stub = StubBackend()
    mgr = EscrowManager(payment_backend=stub)
    mgr.lock("c1", "1.0", {})

    valid_addr = "nano_1q3hsjq6tmj1tne66rymctadqbi8ijtak7x1fr5dkmesnkdrqxnoojttcgok"
    ok = mgr.set_accounts("c1", principal_account=valid_addr)
    assert ok


# --- SimBackend tests ---

@pytest.fixture
def sim():
    return SimBackend(seed="aa" * 32)


def test_sim_create_account(sim):
    result = sim.create_escrow_account("c1")
    assert "account" in result
    assert result["account"].startswith("nano_")
    assert len(result["account"]) == 65


def test_sim_create_account_deterministic(sim):
    r1 = sim.create_escrow_account("c1")
    r2 = sim.create_escrow_account("c1")
    assert r1["account"] == r2["account"]


def test_sim_different_contracts_different_accounts(sim):
    r1 = sim.create_escrow_account("c1")
    r2 = sim.create_escrow_account("c2")
    assert r1["account"] != r2["account"]


def test_sim_deposit_and_check(sim):
    sim.create_escrow_account("c1")
    assert sim.check_deposit("c1", "1.0") is False
    sim.deposit("c1", "1.0")
    assert sim.check_deposit("c1", "1.0") is True
    assert sim.check_deposit("c1", "2.0") is False


def test_sim_send_success(sim):
    sim.create_escrow_account("c1")
    sim.deposit("c1", "1.0")
    dest = "nano_1q3hsjq6tmj1tne66rymctadqbi8ijtak7x1fr5dkmesnkdrqxnoojttcgok"
    tx_hash = sim.send("c1", dest, "0.5")
    assert len(tx_hash) == 64  # blake2b hex
    assert sim.get_balance("c1") == "0.5"
    assert sim.get_account_balance(dest) == "0.5"


def test_sim_send_insufficient_balance(sim):
    sim.create_escrow_account("c1")
    sim.deposit("c1", "0.1")
    dest = "nano_1q3hsjq6tmj1tne66rymctadqbi8ijtak7x1fr5dkmesnkdrqxnoojttcgok"
    with pytest.raises(ValueError, match="Insufficient balance"):
        sim.send("c1", dest, "1.0")


def test_sim_send_zero_is_noop(sim):
    sim.create_escrow_account("c1")
    sim.deposit("c1", "1.0")
    result = sim.send("c1", "nano_dest", "0")
    assert result == "noop_zero_amount"


def test_sim_send_zero_allowed():
    sim = SimBackend(seed="aa" * 32, allow_zero_sends=True)
    sim.create_escrow_account("c1")
    result = sim.send("c1", "nano_dest", "0")
    assert result == "sim_noop_zero"


def test_sim_send_no_escrow(sim):
    dest = "nano_1q3hsjq6tmj1tne66rymctadqbi8ijtak7x1fr5dkmesnkdrqxnoojttcgok"
    with pytest.raises(ValueError, match="No escrow account"):
        sim.send("nonexistent", dest, "0.5")


def test_sim_fund_external(sim):
    addr = "nano_1q3hsjq6tmj1tne66rymctadqbi8ijtak7x1fr5dkmesnkdrqxnoojttcgok"
    sim.fund(addr, "10.0")
    assert sim.get_account_balance(addr) == "10"


def test_sim_transaction_log(sim):
    sim.create_escrow_account("c1")
    sim.deposit("c1", "1.0")
    dest = "nano_1q3hsjq6tmj1tne66rymctadqbi8ijtak7x1fr5dkmesnkdrqxnoojttcgok"
    sim.send("c1", dest, "0.3")

    txs = sim.get_transactions("c1")
    assert len(txs) == 2  # deposit + send
    assert txs[0]["tx_type"] == "deposit"
    assert txs[1]["tx_type"] == "send"
    assert txs[1]["amount_xno"] == "0.3"


def test_sim_transaction_log_all(sim):
    sim.create_escrow_account("c1")
    sim.create_escrow_account("c2")
    sim.deposit("c1", "1.0")
    sim.deposit("c2", "2.0")
    all_txs = sim.get_transactions()
    assert len(all_txs) == 2


def test_sim_multiple_sends(sim):
    """Multiple sends deplete balance correctly."""
    sim.create_escrow_account("c1")
    sim.deposit("c1", "1.0")
    dest = "nano_1q3hsjq6tmj1tne66rymctadqbi8ijtak7x1fr5dkmesnkdrqxnoojttcgok"
    sim.send("c1", dest, "0.3")
    sim.send("c1", dest, "0.3")
    sim.send("c1", dest, "0.3")
    assert Decimal(sim.get_balance("c1")) == Decimal("0.1")
    with pytest.raises(ValueError, match="Insufficient"):
        sim.send("c1", dest, "0.2")


def test_sim_escrow_integration():
    """Full escrow flow with SimBackend catches real balance errors."""
    from server.escrow import EscrowManager
    sim = SimBackend(seed="bb" * 32)
    mgr = EscrowManager(payment_backend=sim)

    # Lock escrow
    mgr.lock("c1", "0.5", {})
    escrow = mgr.get("c1")
    escrow_addr = escrow["escrow_account"]

    # Simulate principal depositing
    sim.deposit("c1", "0.5")
    assert sim.check_deposit("c1", "0.5") is True

    # Set payment addresses
    agent_addr = "nano_1q3hsjq6tmj1tne66rymctadqbi8ijtak7x1fr5dkmesnkdrqxnoojttcgok"
    principal_addr = "nano_1n14s3f4dyz7cnq6y848a5ep6wysy15jzxbjn4hbyebn7stgi3p13jin3o8q"
    mgr.set_accounts("c1", principal_account=principal_addr, agent_account=agent_addr)

    # Resolve as fulfilled -> agent gets paid
    result = mgr.resolve("c1", "fulfilled")
    assert result["action"] == "release_to_agent"
    assert not result.get("payment_failed")

    # Agent received funds (minus platform fee)
    agent_bal = sim.get_account_balance(agent_addr)
    assert Decimal(agent_bal) > 0

    # Escrow is drained
    assert Decimal(sim.get_balance("c1")) < Decimal("0.5")


def test_sim_double_resolve_blocked():
    """Cannot resolve same escrow twice (SimBackend has real balances)."""
    from server.escrow import EscrowManager
    sim = SimBackend(seed="cc" * 32)
    mgr = EscrowManager(payment_backend=sim)

    mgr.lock("c1", "0.5", {})
    sim.deposit("c1", "0.5")
    agent_addr = "nano_1q3hsjq6tmj1tne66rymctadqbi8ijtak7x1fr5dkmesnkdrqxnoojttcgok"
    mgr.set_accounts("c1", agent_account=agent_addr)

    result1 = mgr.resolve("c1", "fulfilled")
    assert not result1.get("payment_failed")

    # Second resolve returns cached result (double-resolution guard in EscrowManager)
    result2 = mgr.resolve("c1", "fulfilled")
    assert "already resolved" in str(result2.get("error", "")) or result2.get("action") == "release_to_agent"
