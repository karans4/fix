import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from decimal import Decimal
from unittest.mock import MagicMock, patch

from server.nano import (
    NanoBackend, StubBackend, PaymentBackend,
    xno_to_raw, raw_to_xno, RAW_PER_XNO,
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


# --- NanoBackend tests (mocked RPC) ---

def test_nano_requires_seed():
    with pytest.raises(ValueError, match="seed required"):
        NanoBackend(seed="")

def test_nano_requires_64_hex():
    with pytest.raises(ValueError, match="64 hex"):
        NanoBackend(seed="abc")

def test_nano_derive_index_deterministic():
    seed = "a" * 64
    backend = NanoBackend.__new__(NanoBackend)
    backend.seed = seed
    idx1 = backend._derive_index("contract_abc")
    idx2 = backend._derive_index("contract_abc")
    idx3 = backend._derive_index("contract_xyz")
    assert idx1 == idx2  # same input -> same output
    assert idx1 != idx3  # different input -> different output
    assert 0 <= idx1 < 2**31  # within safe range

def test_nano_derive_index_different_contracts():
    backend = NanoBackend.__new__(NanoBackend)
    backend.seed = "b" * 64
    indices = set()
    for i in range(100):
        idx = backend._derive_index(f"contract_{i}")
        indices.add(idx)
    # Should have no collisions in 100 contracts
    assert len(indices) == 100

@patch("server.nano.nano.RPC")
def test_nano_create_account(mock_rpc_cls):
    backend = NanoBackend(seed="a" * 64, node_url="http://fake")
    result = backend.create_escrow_account("contract_1")
    assert "account" in result
    assert result["account"].startswith("nano_")
    assert "index" in result

@patch("server.nano.nano.RPC")
def test_nano_create_account_deterministic(mock_rpc_cls):
    backend = NanoBackend(seed="a" * 64, node_url="http://fake")
    r1 = backend.create_escrow_account("contract_1")
    r2 = backend.create_escrow_account("contract_1")
    assert r1["account"] == r2["account"]
    assert r1["index"] == r2["index"]

@patch("server.nano.nano.RPC")
def test_nano_different_contracts_different_accounts(mock_rpc_cls):
    backend = NanoBackend(seed="a" * 64, node_url="http://fake")
    r1 = backend.create_escrow_account("contract_1")
    r2 = backend.create_escrow_account("contract_2")
    assert r1["account"] != r2["account"]

@patch("server.nano.nano.RPC")
def test_nano_check_deposit_sufficient(mock_rpc_cls):
    mock_rpc = MagicMock()
    mock_rpc.get_account_balance.return_value = {"balance": str(10**30), "receivable": "0"}
    mock_rpc_cls.return_value = mock_rpc
    
    backend = NanoBackend(seed="a" * 64, node_url="http://fake")
    backend.rpc = mock_rpc
    
    # Mock wallet receive_all
    with patch("server.nano.nano.Wallet") as mock_wallet_cls:
        mock_wallet = MagicMock()
        mock_wallet_cls.return_value = mock_wallet
        assert backend.check_deposit("c1", "1.0") is True

@patch("server.nano.nano.RPC")
def test_nano_check_deposit_insufficient(mock_rpc_cls):
    mock_rpc = MagicMock()
    mock_rpc.get_account_balance.return_value = {"balance": str(10**27), "receivable": "0"}
    mock_rpc_cls.return_value = mock_rpc
    
    backend = NanoBackend(seed="a" * 64, node_url="http://fake")
    backend.rpc = mock_rpc
    
    with patch("server.nano.nano.Wallet") as mock_wallet_cls:
        mock_wallet = MagicMock()
        mock_wallet_cls.return_value = mock_wallet
        assert backend.check_deposit("c1", "1.0") is False

@patch("server.nano.nano.RPC")
def test_nano_send(mock_rpc_cls):
    mock_rpc = MagicMock()
    mock_rpc_cls.return_value = mock_rpc
    
    backend = NanoBackend(seed="a" * 64, node_url="http://fake")
    
    with patch("server.nano.nano.Wallet") as mock_wallet_cls:
        mock_wallet = MagicMock()
        mock_wallet.send.return_value = {"hash": "ABC123"}
        mock_wallet_cls.return_value = mock_wallet
        
        result = backend.send("c1", "nano_dest", "0.5")
        assert result == "ABC123"
        mock_wallet.send.assert_called_once()

@patch("server.nano.nano.RPC")
def test_nano_get_balance(mock_rpc_cls):
    mock_rpc = MagicMock()
    mock_rpc.get_account_balance.return_value = {"balance": str(5 * 10**29), "receivable": "0"}
    mock_rpc_cls.return_value = mock_rpc
    
    backend = NanoBackend(seed="a" * 64, node_url="http://fake")
    backend.rpc = mock_rpc
    bal = backend.get_balance("c1")
    assert Decimal(bal) == Decimal("0.5")

@patch("server.nano.nano.RPC")
def test_nano_get_balance_error_returns_zero(mock_rpc_cls):
    mock_rpc = MagicMock()
    mock_rpc.get_account_balance.side_effect = Exception("network error")
    mock_rpc_cls.return_value = mock_rpc
    
    backend = NanoBackend(seed="a" * 64, node_url="http://fake")
    backend.rpc = mock_rpc
    assert backend.get_balance("c1") == "0"


# --- PaymentBackend ABC test ---

def test_payment_backend_is_abstract():
    with pytest.raises(TypeError):
        PaymentBackend()


# --- Integration: EscrowManager with StubBackend ---

def test_escrow_manager_with_stub():
    from server.escrow import EscrowManager
    stub = StubBackend()
    mgr = EscrowManager(payment_backend=stub)
    
    # Lock
    result = mgr.lock("c1", "1.0", {})
    assert result["status"] == "locked"
    assert "escrow_account" in result
    
    # Set accounts
    mgr.set_accounts("c1", principal_account="nano_principal", agent_account="nano_agent")
    
    # Resolve fulfilled -> send to agent
    result = mgr.resolve("c1", "fulfilled")
    assert result["action"] == "release_to_agent"
    assert len(stub.sends) == 1
    assert stub.sends[0]["to"] == "nano_agent"

def test_escrow_manager_resolve_canceled():
    from server.escrow import EscrowManager
    stub = StubBackend()
    mgr = EscrowManager(payment_backend=stub)
    mgr.lock("c1", "1.0", {})
    mgr.set_accounts("c1", principal_account="nano_principal", agent_account="nano_agent")
    
    result = mgr.resolve("c1", "canceled")
    assert result["action"] == "return_to_principal"
    assert len(stub.sends) == 1
    assert stub.sends[0]["to"] == "nano_principal"

def test_escrow_manager_get_includes_accounts():
    from server.escrow import EscrowManager
    stub = StubBackend()
    mgr = EscrowManager(payment_backend=stub)
    mgr.lock("c1", "0.5", {})
    mgr.set_accounts("c1", principal_account="nano_p", agent_account="nano_a")
    
    data = mgr.get("c1")
    assert data["escrow_account"] is not None
    assert data["principal_account"] == "nano_p"
    assert data["agent_account"] == "nano_a"
