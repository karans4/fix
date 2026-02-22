"""Platform API client for fix protocol.

Thin HTTP client with a pluggable transport interface.
Default transport: HTTP with Ed25519 authentication.

Clients sign their own chain entries for non-repudiation.
Server validates and appends. Server only signs server-initiated actions.
"""

import json
from abc import ABC, abstractmethod

import httpx

from crypto import (
    sign_request_ed25519, ed25519_privkey_to_pubkey, pubkey_to_fix_id,
    build_chain_entry, verify_chain,
)


class Transport(ABC):
    """Override this to use Nostr, gRPC, pigeons, whatever."""

    @abstractmethod
    async def post(self, path: str, data: dict) -> dict:
        ...

    @abstractmethod
    async def get(self, path: str, params: dict | None = None) -> dict:
        ...


class HTTPTransport(Transport):
    """Default. Talks to our centralized platform over HTTP with Ed25519 auth."""

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        api_key: str = "",
        privkey_bytes: bytes | None = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.privkey_bytes = privkey_bytes
        if privkey_bytes:
            self.pubkey_hex = ed25519_privkey_to_pubkey(privkey_bytes).hex()
        else:
            self.pubkey_hex = ""

    def _headers(self, method: str = "GET", path: str = "", body: str = "") -> dict:
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        if self.privkey_bytes:
            auth = sign_request_ed25519(
                self.privkey_bytes, self.pubkey_hex, method, path, body
            )
            h.update(auth)
        return h

    async def post(self, path: str, data: dict) -> dict:
        body = json.dumps(data)
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.base_url}{path}",
                content=body,
                headers=self._headers("POST", path, body),
                timeout=30.0,
            )
            if resp.status_code == 409:
                return {"status": 409, **resp.json()}
            resp.raise_for_status()
            return resp.json()

    async def get(self, path: str, params: dict | None = None) -> dict:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{self.base_url}{path}",
                params=params,
                headers=self._headers("GET", path),
                timeout=30.0,
            )
            resp.raise_for_status()
            return resp.json()


class FixClient:
    """High-level client for the fix platform."""

    def __init__(self, transport: Transport | None = None, base_url: str = "http://localhost:8000",
                 privkey_bytes: bytes | None = None):
        self.privkey_bytes = privkey_bytes
        if privkey_bytes:
            pubkey = ed25519_privkey_to_pubkey(privkey_bytes)
            self.fix_id = pubkey_to_fix_id(pubkey)
        else:
            self.fix_id = ""
        if transport:
            self.transport = transport
        else:
            self.transport = HTTPTransport(base_url, privkey_bytes=privkey_bytes)

    async def _signed_action(self, contract_id: str, path: str, entry_type: str,
                              entry_data: dict, extra_fields: dict | None = None,
                              max_retries: int = 3) -> dict:
        """Build a client-signed chain entry, send it with the request, retry on 409.

        Args:
            contract_id: Contract to act on
            path: API path (e.g. /contracts/{id}/bond)
            entry_type: Chain entry type (e.g. "bond", "fix", "verify")
            entry_data: Data payload for the chain entry
            extra_fields: Additional request body fields (e.g. agent_pubkey for business logic)
            max_retries: Max attempts on chain conflict (409)
        """
        if not self.privkey_bytes:
            # No privkey: send without chain_entry (server will sign — legacy mode)
            payload = {**(extra_fields or {})}
            return await self.transport.post(path, payload)

        for attempt in range(max_retries):
            head_info = await self.get_chain_head(contract_id)
            entry = build_chain_entry(
                entry_type=entry_type,
                data=entry_data,
                seq=head_info["seq"],
                author=self.fix_id,
                prev_hash=head_info["chain_head"],
                privkey_bytes=self.privkey_bytes,
            )
            payload = {**(extra_fields or {}), "chain_entry": entry}
            resp = await self.transport.post(path, payload)
            if resp.get("status") == 409:
                continue
            return resp
        raise RuntimeError(f"Chain conflict after {max_retries} retries on {path}")

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

    async def get_chain_head(self, contract_id: str) -> dict:
        """Get current chain head and seq for building next entry."""
        return await self.transport.get(f"/contracts/{contract_id}/chain_head")

    async def get_server_pubkey(self) -> dict:
        """Get the server's Ed25519 public key."""
        return await self.transport.get("/server_pubkey")

    async def accept_contract(self, contract_id: str, agent_pubkey: str) -> dict:
        """Agent accepts a contract."""
        return await self._signed_action(
            contract_id, f"/contracts/{contract_id}/accept",
            "accept", {"agent_pubkey": agent_pubkey},
            extra_fields={"agent_pubkey": agent_pubkey},
        )

    async def bond(self, contract_id: str, agent_pubkey: str) -> dict:
        """Agent posts bond to investigate. Verifies chain integrity first."""
        # Verify chain before committing funds
        data = await self.get_contract(contract_id)
        chain_entries = [e for e in data.get("transcript", []) if e.get("signature")]
        if chain_entries:
            ok, err = verify_chain(chain_entries)
            if not ok:
                raise RuntimeError(f"Chain verification failed before bond: {err}")

        return await self._signed_action(
            contract_id, f"/contracts/{contract_id}/bond",
            "bond", {"agent_pubkey": agent_pubkey},
            extra_fields={"agent_pubkey": agent_pubkey},
        )

    async def decline(self, contract_id: str, agent_pubkey: str, reason: str = "") -> dict:
        """Agent declines after investigating."""
        return await self._signed_action(
            contract_id, f"/contracts/{contract_id}/decline",
            "decline", {"reason": reason},
            extra_fields={"agent_pubkey": agent_pubkey, "reason": reason},
        )

    async def request_investigation(self, contract_id: str, command: str, agent_pubkey: str = "") -> dict:
        """Agent requests investigation."""
        return await self._signed_action(
            contract_id, f"/contracts/{contract_id}/investigate",
            "investigate", {"command": command, "from": "agent"},
            extra_fields={"command": command, "agent_pubkey": agent_pubkey},
        )

    async def submit_investigation_result(self, contract_id: str, command: str, output: str,
                                          principal_pubkey: str = "") -> dict:
        """Principal submits investigation result."""
        return await self._signed_action(
            contract_id, f"/contracts/{contract_id}/result",
            "result", {"command": command, "output": output, "from": "principal"},
            extra_fields={"command": command, "output": output, "principal_pubkey": principal_pubkey},
        )

    async def submit_fix(self, contract_id: str, fix: str, explanation: str = "", agent_pubkey: str = "") -> dict:
        """Agent submits a fix."""
        return await self._signed_action(
            contract_id, f"/contracts/{contract_id}/fix",
            "fix", {"fix": fix, "explanation": explanation, "from": "agent"},
            extra_fields={"fix": fix, "explanation": explanation, "agent_pubkey": agent_pubkey},
        )

    async def verify(self, contract_id: str, success: bool, explanation: str = "",
                     principal_pubkey: str = "") -> dict:
        """Principal reports verification result."""
        return await self._signed_action(
            contract_id, f"/contracts/{contract_id}/verify",
            "verify", {"success": success, "explanation": explanation, "from": "principal"},
            extra_fields={"success": success, "explanation": explanation, "principal_pubkey": principal_pubkey},
        )

    async def dispute(self, contract_id: str, argument: str, side: str = "principal",
                      pubkey: str = "") -> dict:
        """File a dispute."""
        return await self._signed_action(
            contract_id, f"/contracts/{contract_id}/dispute",
            "dispute_filed", {"argument": argument, "side": side},
            extra_fields={"argument": argument, "side": side, "pubkey": pubkey},
        )

    async def respond(self, contract_id: str, argument: str, side: str,
                      pubkey: str = "") -> dict:
        """Respond to a pending dispute."""
        return await self._signed_action(
            contract_id, f"/contracts/{contract_id}/respond",
            "dispute_response", {"argument": argument, "side": side},
            extra_fields={"argument": argument, "side": side, "pubkey": pubkey},
        )

    async def dispute_status(self, contract_id: str) -> dict:
        """Check status of a pending dispute."""
        return await self.transport.get(f"/contracts/{contract_id}/dispute_status")

    async def chat(self, contract_id: str, message: str, from_side: str = "principal",
                   msg_type: str = "message", pubkey: str = "") -> dict:
        """Send a chat message."""
        return await self._signed_action(
            contract_id, f"/contracts/{contract_id}/chat",
            msg_type, {"message": message, "from": from_side},
            extra_fields={"message": message, "from_side": from_side, "msg_type": msg_type, "pubkey": pubkey},
        )

    async def halt(self, contract_id: str, reason: str, principal_pubkey: str = "") -> dict:
        """Emergency halt -- freeze contract and escalate to judge."""
        return await self._signed_action(
            contract_id, f"/contracts/{contract_id}/halt",
            "halt", {"reason": reason, "from": "principal"},
            extra_fields={"reason": reason, "principal_pubkey": principal_pubkey},
        )

    async def void(self, contract_id: str, pubkey: str = "") -> dict:
        """Void a disputed contract."""
        return await self.transport.post(f"/contracts/{contract_id}/void", {
            "pubkey": pubkey,
        })

    async def review(self, contract_id: str, action: str, argument: str = "",
                     principal_pubkey: str = "") -> dict:
        """Principal acts during review window: accept or dispute."""
        entry_type = "review_accept" if action == "accept" else "dispute_filed"
        entry_data = {} if action == "accept" else {"argument": argument, "side": "principal"}
        return await self._signed_action(
            contract_id, f"/contracts/{contract_id}/review",
            entry_type, entry_data,
            extra_fields={"action": action, "argument": argument, "principal_pubkey": principal_pubkey},
        )

    async def verify_chain(self, contract_id: str) -> dict:
        """Verify the signed message chain for a contract."""
        return await self.transport.get(f"/contracts/{contract_id}/verify_chain")

    async def get_ruling(self, contract_id: str) -> dict | None:
        """Get ruling for a contract."""
        return await self.transport.get(f"/contracts/{contract_id}/ruling")

    async def get_reputation(self, pubkey: str) -> dict:
        """Get reputation stats."""
        return await self.transport.get(f"/reputation/{pubkey}")

    async def stream_contracts(self, min_bounty: str = "0",
                               callback=None):
        """Subscribe to SSE contract events.

        Args:
            min_bounty: Only receive events for contracts >= this bounty
            callback: async callable(event_dict) called for each event

        Usage:
            async def on_event(event):
                if event["event"] == "contract_posted":
                    print(f"New contract: {event['contract_id']}")

            await client.stream_contracts(min_bounty="0.1", callback=on_event)
        """
        import httpx

        base = self.transport.base_url if hasattr(self.transport, 'base_url') else "http://localhost:8000"
        url = f"{base}/contracts/stream?min_bounty={min_bounty}"

        async with httpx.AsyncClient() as client:
            async with client.stream("GET", url, timeout=None) as resp:
                async for line in resp.aiter_lines():
                    if line.startswith("data: "):
                        import json
                        event = json.loads(line[6:])
                        if callback:
                            await callback(event)
