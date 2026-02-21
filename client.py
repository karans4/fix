"""Platform API client for fix protocol.

Thin HTTP client with a pluggable transport interface.
Default transport: HTTP to our centralized platform.
"""

import json
from abc import ABC, abstractmethod

import httpx


class Transport(ABC):
    """Override this to use Nostr, gRPC, pigeons, whatever."""

    @abstractmethod
    async def post(self, path: str, data: dict) -> dict:
        ...

    @abstractmethod
    async def get(self, path: str, params: dict | None = None) -> dict:
        ...


class HTTPTransport(Transport):
    """Default. Talks to our centralized platform over HTTP."""

    def __init__(self, base_url: str = "http://localhost:8000", api_key: str = ""):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    async def post(self, path: str, data: dict) -> dict:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.base_url}{path}",
                json=data,
                headers=self._headers(),
                timeout=30.0,
            )
            resp.raise_for_status()
            return resp.json()

    async def get(self, path: str, params: dict | None = None) -> dict:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{self.base_url}{path}",
                params=params,
                headers=self._headers(),
                timeout=30.0,
            )
            resp.raise_for_status()
            return resp.json()


class FixClient:
    """High-level client for the fix platform."""

    def __init__(self, transport: Transport | None = None, base_url: str = "http://localhost:8000"):
        self.transport = transport or HTTPTransport(base_url)

    async def post_contract(self, contract: dict, principal_pubkey: str = "") -> str:
        """Post a contract. Returns contract_id."""
        resp = await self.transport.post("/contracts", {
            "contract": contract,
            "principal_pubkey": principal_pubkey,
        })
        return resp["contract_id"]

    async def list_contracts(self, status: str = "open", limit: int = 50) -> list[dict]:
        """List contracts by status."""
        resp = await self.transport.get("/contracts", {"status": status, "limit": limit})
        return resp["contracts"]

    async def get_contract(self, contract_id: str) -> dict:
        """Get contract details."""
        return await self.transport.get(f"/contracts/{contract_id}")

    async def accept_contract(self, contract_id: str, agent_pubkey: str) -> dict:
        """Agent accepts a contract."""
        return await self.transport.post(f"/contracts/{contract_id}/accept", {
            "agent_pubkey": agent_pubkey,
        })

    async def request_investigation(self, contract_id: str, command: str, agent_pubkey: str = "") -> dict:
        """Agent requests investigation."""
        return await self.transport.post(f"/contracts/{contract_id}/investigate", {
            "command": command,
            "agent_pubkey": agent_pubkey,
        })

    async def submit_investigation_result(self, contract_id: str, command: str, output: str) -> dict:
        """Principal submits investigation result."""
        return await self.transport.post(f"/contracts/{contract_id}/result", {
            "command": command,
            "output": output,
        })

    async def submit_fix(self, contract_id: str, fix: str, explanation: str = "", agent_pubkey: str = "") -> dict:
        """Agent submits a fix."""
        return await self.transport.post(f"/contracts/{contract_id}/fix", {
            "fix": fix,
            "explanation": explanation,
            "agent_pubkey": agent_pubkey,
        })

    async def verify(self, contract_id: str, success: bool, explanation: str = "") -> dict:
        """Principal reports verification result."""
        return await self.transport.post(f"/contracts/{contract_id}/verify", {
            "success": success,
            "explanation": explanation,
        })

    async def dispute(self, contract_id: str, argument: str, side: str = "principal") -> dict:
        """File a dispute. Returns awaiting_response status with deadline.
        Other side has 30s to respond before judge rules in absentia."""
        return await self.transport.post(f"/contracts/{contract_id}/dispute", {
            "argument": argument,
            "side": side,
        })

    async def respond(self, contract_id: str, argument: str, side: str) -> dict:
        """Respond to a pending dispute. Triggers judge ruling with both arguments."""
        return await self.transport.post(f"/contracts/{contract_id}/respond", {
            "argument": argument,
            "side": side,
        })

    async def dispute_status(self, contract_id: str) -> dict:
        """Check status of a pending dispute."""
        return await self.transport.get(f"/contracts/{contract_id}/dispute_status")

    async def chat(self, contract_id: str, message: str, from_side: str = "principal",
                   msg_type: str = "message") -> dict:
        """Send a chat message."""
        return await self.transport.post(f"/contracts/{contract_id}/chat", {
            "message": message,
            "from_side": from_side,
            "msg_type": msg_type,
        })

    async def halt(self, contract_id: str, reason: str, principal_pubkey: str = "") -> dict:
        """Emergency halt -- freeze contract and escalate to judge."""
        return await self.transport.post(f"/contracts/{contract_id}/halt", {
            "reason": reason,
            "principal_pubkey": principal_pubkey,
        })

    async def get_ruling(self, contract_id: str) -> dict | None:
        """Get ruling for a contract."""
        return await self.transport.get(f"/contracts/{contract_id}/ruling")

    async def get_reputation(self, pubkey: str) -> dict:
        """Get reputation stats."""
        return await self.transport.get(f"/reputation/{pubkey}")
