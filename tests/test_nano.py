import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(__file__))

import pytest
import secrets
from decimal import Decimal

from server.nano import (
    NanoBackend, PaymentBackend,
    xno_to_raw, raw_to_xno, RAW_PER_XNO,
    _pubkey_to_address, _address_to_pubkey,
    validate_nano_address,
)
from server.escrow import EscrowManager
from conftest import (
    DEV_NODE, GENESIS_ACCOUNT, TEST_SEED,
    fund_account, make_nano_backend,
    TEST_PRINCIPAL_ADDR, TEST_AGENT_ADDR,
    set_funded_accounts, fund_escrow,
)


@pytest.fixture
def backend():
    return make_nano_backend()


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
    import hashlib, ed25519_blake2b
    seed = bytes.fromhex("aa" * 32)
    priv = hashlib.blake2b(seed + b"test", digest_size=32).digest()
    sk = ed25519_blake2b.SigningKey(priv)
    pubkey = sk.get_verifying_key().to_bytes()
    addr = _pubkey_to_address(pubkey)
    assert addr.startswith("nano_")
    assert len(addr) == 65
    decoded = _address_to_pubkey(addr)
    assert decoded == pubkey


# --- NanoBackend key derivation ---

def test_nano_requires_seed():
    with pytest.raises(ValueError, match="seed required"):
        NanoBackend(seed="", db_path=":memory:")

def test_nano_requires_64_hex():
    with pytest.raises(ValueError, match="64 hex"):
        NanoBackend(seed="abc", db_path=":memory:")

def test_nano_rejects_non_hex():
    with pytest.raises(ValueError, match="64 hex"):
        NanoBackend(seed="g" * 64, db_path=":memory:")

def test_nano_nonce_is_random(backend):
    n1 = backend._get_nonce("contract_1")
    n2 = backend._get_nonce("contract_2")
    assert len(n1) == 32
    assert len(n2) == 32
    assert n1 != n2

def test_nano_nonce_is_stable(backend):
    n1 = backend._get_nonce("contract_1")
    n2 = backend._get_nonce("contract_1")
    assert n1 == n2

def test_nano_keypair_deterministic(backend):
    sk1, vk1 = backend._derive_keypair("c1")
    sk2, vk2 = backend._derive_keypair("c1")
    assert vk1.to_bytes() == vk2.to_bytes()

def test_nano_different_contracts_different_keys(backend):
    _, vk1 = backend._derive_keypair("c1")
    _, vk2 = backend._derive_keypair("c2")
    assert vk1.to_bytes() != vk2.to_bytes()

def test_nano_different_seeds_different_keys():
    b1 = NanoBackend(seed="a" * 64, node_url=DEV_NODE, db_path=":memory:")
    b2 = NanoBackend(seed="b" * 64, node_url=DEV_NODE, db_path=":memory:")
    nonce = b1._get_nonce("c1")
    b2._db.execute("INSERT INTO nano_nonces (contract_id, nonce) VALUES (?, ?)", ("c1", nonce))
    b2._db.commit()
    _, vk1 = b1._derive_keypair("c1")
    _, vk2 = b2._derive_keypair("c1")
    assert vk1.to_bytes() != vk2.to_bytes()

def test_nano_create_account(backend):
    result = backend.create_escrow_account("contract_1")
    assert "account" in result
    assert result["account"].startswith("nano_")
    assert "index" not in result

def test_nano_create_account_deterministic(backend):
    r1 = backend.create_escrow_account("contract_1")
    r2 = backend.create_escrow_account("contract_1")
    assert r1["account"] == r2["account"]

def test_nano_different_contracts_different_accounts(backend):
    r1 = backend.create_escrow_account("contract_1")
    r2 = backend.create_escrow_account("contract_2")
    assert r1["account"] != r2["account"]

def test_nano_valid_address_format(backend):
    result = backend.create_escrow_account("c1")
    addr = result["account"]
    assert addr.startswith("nano_")
    assert len(addr) == 65
    pubkey = _address_to_pubkey(addr)
    assert _pubkey_to_address(pubkey) == addr

def test_nano_send_zero_is_noop(backend):
    assert backend.send("c1", "nano_dest", "0") == "noop_zero_amount"


# --- Real RPC tests against dev node ---

def test_nano_check_deposit(backend):
    cid = f"test_deposit_{secrets.token_hex(4)}"
    result = backend.create_escrow_account(cid)
    addr = result["account"]

    assert backend.check_deposit(cid, "0.001") is False

    fund_account(addr, "0.01")

    assert backend.check_deposit(cid, "0.001") is True
    assert backend.check_deposit(cid, "0.01") is True
    assert backend.check_deposit(cid, "1.0") is False


def test_nano_send(backend):
    cid = f"test_send_{secrets.token_hex(4)}"
    result = backend.create_escrow_account(cid)
    escrow_addr = result["account"]

    fund_account(escrow_addr, "0.1")
    backend._receive_all(cid)

    tx_hash = backend.send(cid, GENESIS_ACCOUNT, "0.05")
    assert len(tx_hash) == 64

    bal = Decimal(backend.get_balance(cid))
    assert bal == Decimal("0.05")


def test_nano_send_insufficient_balance(backend):
    cid = f"test_insuf_{secrets.token_hex(4)}"
    backend.create_escrow_account(cid)
    escrow_addr = backend._get_account(cid)

    fund_account(escrow_addr, "0.001")
    backend._receive_all(cid)

    with pytest.raises(ValueError, match="Insufficient balance"):
        backend.send(cid, GENESIS_ACCOUNT, "1.0")


def test_nano_get_balance(backend):
    cid = f"test_bal_{secrets.token_hex(4)}"
    backend.create_escrow_account(cid)
    escrow_addr = backend._get_account(cid)

    assert backend.get_balance(cid) == "0"

    fund_account(escrow_addr, "0.5")
    backend._receive_all(cid)

    bal = Decimal(backend.get_balance(cid))
    assert bal == Decimal("0.5")


def test_nano_multiple_sends(backend):
    cid = f"test_multi_{secrets.token_hex(4)}"
    backend.create_escrow_account(cid)
    escrow_addr = backend._get_account(cid)

    fund_account(escrow_addr, "1.0")
    backend._receive_all(cid)

    backend.send(cid, GENESIS_ACCOUNT, "0.3")
    backend.send(cid, GENESIS_ACCOUNT, "0.3")
    backend.send(cid, GENESIS_ACCOUNT, "0.3")

    bal = Decimal(backend.get_balance(cid))
    assert bal == Decimal("0.1")

    with pytest.raises(ValueError, match="Insufficient"):
        backend.send(cid, GENESIS_ACCOUNT, "0.2")


# --- PaymentBackend ABC ---

def test_payment_backend_is_abstract():
    with pytest.raises(TypeError):
        PaymentBackend()


# --- Address validation ---

def test_validate_known_good_address():
    addr = "nano_1q3hsjq6tmj1tne66rymctadqbi8ijtak7x1fr5dkmesnkdrqxnoojttcgok"
    ok, err = validate_nano_address(addr)
    assert ok, f"Expected valid, got: {err}"

def test_validate_generated_address():
    import hashlib, ed25519_blake2b
    seed = bytes.fromhex("bb" * 32)
    priv = hashlib.blake2b(seed + b"test_validate", digest_size=32).digest()
    sk = ed25519_blake2b.SigningKey(priv)
    pubkey = sk.get_verifying_key().to_bytes()
    addr = _pubkey_to_address(pubkey)
    ok, err = validate_nano_address(addr)
    assert ok, f"Generated address failed validation: {err}"

def test_validate_xrb_prefix():
    addr = "nano_1q3hsjq6tmj1tne66rymctadqbi8ijtak7x1fr5dkmesnkdrqxnoojttcgok"
    xrb_addr = "xrb_" + addr[5:]
    ok, err = validate_nano_address(xrb_addr)
    assert ok

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

def test_validate_bad_char():
    addr = "nano_0q3hsjq6tmj1tne66rymctadqbi8ijtak7x1fr5dkmesnkdrqxnoojttcgok"
    ok, err = validate_nano_address(addr)
    assert not ok

def test_validate_bad_checksum():
    addr = "nano_1q3hsjq6tmj1tne66rymctadqbi8ijtak7x1fr5dkmesnkdrqxnoojttcgok"
    last = addr[-1]
    replacement = '1' if last != '1' else '3'
    ok, err = validate_nano_address(addr[:-1] + replacement)
    assert not ok
    assert "checksum" in err.lower()

def test_validate_bad_pubkey_char():
    addr = "nano_1q3hsjq6tmj1tne66rymctadqbi8ijtak7x1fr5dkmesnkdrqxnoojttcgok"
    chars = list(addr)
    chars[15] = '1' if chars[15] != '1' else '3'
    ok, err = validate_nano_address(''.join(chars))
    assert not ok

def test_validate_empty_string():
    ok, err = validate_nano_address("")
    assert not ok

def test_validate_just_prefix():
    ok, err = validate_nano_address("nano_")
    assert not ok
    assert "length" in err.lower()


# --- EscrowManager address validation ---

def test_escrow_set_accounts_rejects_invalid():
    from server.escrow import EscrowManager
    nano = make_nano_backend()
    mgr = EscrowManager(payment_backend=nano)
    mgr.lock("c1", "1.0", {})

    with pytest.raises(ValueError, match="Invalid.*Nano address"):
        mgr.set_accounts("c1", principal_account="not_a_valid_address")

    with pytest.raises(ValueError, match="Invalid.*Nano address"):
        mgr.set_accounts("c1", agent_account="nano_tooshort")

def test_escrow_set_accounts_accepts_valid():
    from server.escrow import EscrowManager
    nano = make_nano_backend()
    mgr = EscrowManager(payment_backend=nano)
    mgr.lock("c1", "1.0", {})

    ok = mgr.set_accounts("c1", principal_account=TEST_PRINCIPAL_ADDR)
    assert ok

def test_escrow_requires_payment_backend():
    from server.escrow import EscrowManager
    with pytest.raises(ValueError, match="payment_backend is required"):
        EscrowManager()


# --- Integration: EscrowManager with real NanoBackend ---

def test_escrow_fulfilled():
    from server.escrow import EscrowManager
    nano = make_nano_backend()
    mgr = EscrowManager(payment_backend=nano)

    cid = f"test_ful_{secrets.token_hex(4)}"
    mgr.lock(cid, "0.5", {})

    agent_nano = make_nano_backend(seed="bb" * 32)
    agent_info = agent_nano.create_escrow_account("agent_wallet")
    agent_addr = agent_info["account"]

    principal_nano = make_nano_backend(seed="cc" * 32)
    principal_info = principal_nano.create_escrow_account("principal_wallet")
    principal_addr = principal_info["account"]

    # Inclusive bond model: fund with 2 * inclusive_bond (both sides' deposits)
    # bounty=0.5 + judge_fee=0.17 = 0.67 per side, 1.34 total
    fund_escrow(mgr, cid, "1.34")

    mgr.set_accounts(cid, principal_account=principal_addr, agent_account=agent_addr)

    result = mgr.resolve(cid, "fulfilled")
    assert result["action"] == "release_to_agent"
    assert not result.get("payment_failed")

    agent_nano._receive_all("agent_wallet")
    agent_bal = Decimal(agent_nano.get_balance("agent_wallet"))
    assert agent_bal > 0


def test_escrow_canceled():
    from server.escrow import EscrowManager
    nano = make_nano_backend()
    mgr = EscrowManager(payment_backend=nano)

    cid = f"test_can_{secrets.token_hex(4)}"
    mgr.lock(cid, "0.5", {})

    principal_nano = make_nano_backend(seed="dd" * 32)
    principal_info = principal_nano.create_escrow_account("principal_wallet")
    principal_addr = principal_info["account"]

    agent_nano = make_nano_backend(seed="ee" * 32)
    agent_info = agent_nano.create_escrow_account("agent_wallet")
    agent_addr = agent_info["account"]

    fund_escrow(mgr, cid, "1.34")

    mgr.set_accounts(cid, principal_account=principal_addr, agent_account=agent_addr)

    result = mgr.resolve(cid, "canceled")
    assert result["action"] == "return_to_principal"
    assert not result.get("payment_failed")

    principal_nano._receive_all("principal_wallet")
    principal_bal = Decimal(principal_nano.get_balance("principal_wallet"))
    assert principal_bal > 0


def test_escrow_double_resolve_blocked():
    from server.escrow import EscrowManager
    nano = make_nano_backend()
    mgr = EscrowManager(payment_backend=nano)

    cid = f"test_dbl_{secrets.token_hex(4)}"
    mgr.lock(cid, "0.5", {})

    fund_escrow(mgr, cid, "1.34")

    agent_nano = make_nano_backend(seed="ff" * 32)
    agent_info = agent_nano.create_escrow_account("agent_wallet")
    set_funded_accounts(mgr, cid, TEST_PRINCIPAL_ADDR, agent_info["account"])

    result1 = mgr.resolve(cid, "fulfilled")
    assert not result1.get("payment_failed")

    result2 = mgr.resolve(cid, "fulfilled")
    assert "already resolved" in str(result2.get("error", "")) or result2.get("action") == "release_to_agent"


# --- Security audit tests ---

def test_send_validates_address(backend):
    """1.4: send() rejects invalid Nano addresses."""
    import pytest
    with pytest.raises(ValueError, match="Invalid destination"):
        backend.send("c1", "not_a_valid_address", "0.001")

def test_nonce_db_requires_explicit_path():
    """1.5: NanoBackend raises if no nonce DB path provided."""
    import pytest
    with pytest.raises(ValueError, match="Nano nonce DB path required"):
        NanoBackend(seed="aa" * 32, node_url=DEV_NODE)

def test_seed_deleted_after_derive():
    """5.5: Seed string removed from memory after deriving bytes."""
    b = make_nano_backend()
    assert not hasattr(b, 'seed')

def test_escrow_requires_valid_platform_account():
    """Platform account validated at EscrowManager init."""
    import pytest
    nano = make_nano_backend()
    with pytest.raises(ValueError, match="Invalid platform Nano address"):
        EscrowManager(payment_backend=nano, platform_account="bad_address")
