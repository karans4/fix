"""Tests for client.py against a mock transport."""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
import asyncio
from client import FixClient, Transport, HTTPTransport


class MockTransport(Transport):
    def __init__(self):
        self.calls = []

    async def post(self, path, data):
        self.calls.append(("POST", path, data))
        if path == "/contracts":
            return {"contract_id": "test123", "status": "open"}
        if "/accept" in path:
            return {"status": "in_progress"}
        if "/fix" in path:
            return {"status": "pending_verification"}
        if "/verify" in path:
            return {"status": "fulfilled"}
        if "/dispute" in path:
            return {"outcome": "fulfilled", "reasoning": "test", "flags": []}
        return {}

    async def get(self, path, params=None):
        self.calls.append(("GET", path, params))
        if path == "/contracts":
            return {"contracts": []}
        if "/reputation/" in path:
            return {"as_agent": {}, "as_principal": {}}
        if "/ruling" in path:
            return {"outcome": "fulfilled", "reasoning": "test", "flags": []}
        return {"id": "test123", "status": "open", "contract": {}, "transcript": []}


@pytest.fixture
def mock_transport():
    return MockTransport()


@pytest.fixture
def fix_client(mock_transport):
    return FixClient(transport=mock_transport)


# --- Transport ABC ---

def test_transport_is_abstract():
    """Transport ABC cannot be instantiated directly."""
    with pytest.raises(TypeError):
        Transport()


def test_transport_can_be_subclassed():
    """MockTransport properly implements the Transport interface."""
    t = MockTransport()
    assert isinstance(t, Transport)


# --- FixClient.post_contract ---

@pytest.mark.asyncio
async def test_post_contract(fix_client, mock_transport):
    cid = await fix_client.post_contract({"task": "test"}, principal_pubkey="pk1")
    assert cid == "test123"
    assert mock_transport.calls[-1] == (
        "POST", "/contracts",
        {"contract": {"task": "test"}, "principal_pubkey": "pk1"},
    )


# --- FixClient.list_contracts ---

@pytest.mark.asyncio
async def test_list_contracts(fix_client, mock_transport):
    result = await fix_client.list_contracts(status="open", limit=10)
    assert result == []
    assert mock_transport.calls[-1] == (
        "GET", "/contracts", {"status": "open", "limit": 10},
    )


# --- FixClient.get_contract ---

@pytest.mark.asyncio
async def test_get_contract(fix_client, mock_transport):
    result = await fix_client.get_contract("test123")
    assert result["id"] == "test123"
    assert result["status"] == "open"
    assert mock_transport.calls[-1] == ("GET", "/contracts/test123", None)


# --- FixClient.accept_contract ---

@pytest.mark.asyncio
async def test_accept_contract(fix_client, mock_transport):
    result = await fix_client.accept_contract("c1", "agent_abc")
    assert result["status"] == "in_progress"
    assert mock_transport.calls[-1] == (
        "POST", "/contracts/c1/accept", {"agent_pubkey": "agent_abc"},
    )


# --- FixClient.submit_fix ---

@pytest.mark.asyncio
async def test_submit_fix(fix_client, mock_transport):
    result = await fix_client.submit_fix("c1", "apt install gcc", explanation="missing dep")
    assert result["status"] == "pending_verification"
    assert mock_transport.calls[-1] == (
        "POST", "/contracts/c1/fix",
        {"fix": "apt install gcc", "explanation": "missing dep", "agent_pubkey": ""},
    )


# --- FixClient.verify ---

@pytest.mark.asyncio
async def test_verify(fix_client, mock_transport):
    result = await fix_client.verify("c1", success=True, explanation="works")
    assert result["status"] == "fulfilled"
    assert mock_transport.calls[-1] == (
        "POST", "/contracts/c1/verify",
        {"success": True, "explanation": "works", "principal_pubkey": ""},
    )


# --- FixClient.dispute ---

@pytest.mark.asyncio
async def test_dispute(fix_client, mock_transport):
    result = await fix_client.dispute("c1", argument="agent cheated", side="principal")
    assert result["outcome"] == "fulfilled"
    assert mock_transport.calls[-1] == (
        "POST", "/contracts/c1/dispute",
        {"argument": "agent cheated", "side": "principal"},
    )


# --- FixClient.get_reputation ---

@pytest.mark.asyncio
async def test_get_reputation(fix_client, mock_transport):
    result = await fix_client.get_reputation("pk_abc")
    assert "as_agent" in result
    assert "as_principal" in result
    assert mock_transport.calls[-1] == ("GET", "/reputation/pk_abc", None)


# --- FixClient.get_ruling ---

@pytest.mark.asyncio
async def test_get_ruling(fix_client, mock_transport):
    result = await fix_client.get_ruling("c1")
    assert result["outcome"] == "fulfilled"
    assert mock_transport.calls[-1] == ("GET", "/contracts/c1/ruling", None)


# --- FixClient.request_investigation ---

@pytest.mark.asyncio
async def test_request_investigation(fix_client, mock_transport):
    result = await fix_client.request_investigation("c1", "ls -la", agent_pubkey="agent_1")
    assert mock_transport.calls[-1] == (
        "POST", "/contracts/c1/investigate",
        {"command": "ls -la", "agent_pubkey": "agent_1"},
    )


# --- FixClient.submit_investigation_result ---

@pytest.mark.asyncio
async def test_submit_investigation_result(fix_client, mock_transport):
    result = await fix_client.submit_investigation_result("c1", "ls", "file.txt")
    assert mock_transport.calls[-1] == (
        "POST", "/contracts/c1/result",
        {"command": "ls", "output": "file.txt"},
    )


# --- HTTPTransport ---

def test_http_transport_init():
    t = HTTPTransport(base_url="http://example.com:9000", api_key="secret")
    assert t.base_url == "http://example.com:9000"
    assert t.api_key == "secret"


def test_http_transport_default():
    t = HTTPTransport()
    assert t.base_url == "http://localhost:8000"
    assert t.api_key == ""


def test_http_transport_strips_trailing_slash():
    t = HTTPTransport(base_url="http://example.com/")
    assert t.base_url == "http://example.com"


def test_http_transport_headers():
    t = HTTPTransport(api_key="mykey")
    headers = t._headers()
    assert headers["Authorization"] == "Bearer mykey"
    assert headers["Content-Type"] == "application/json"


def test_http_transport_headers_no_key():
    t = HTTPTransport()
    headers = t._headers()
    assert "Authorization" not in headers
