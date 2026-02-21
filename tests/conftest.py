import sys
import os
import json
import time

# Ensure fix/ root is on the path for all tests
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from crypto import (
    generate_ed25519_keypair, ed25519_privkey_to_pubkey, pubkey_to_fix_id,
    sign_request_ed25519,
)


# Monotonic counter to ensure unique timestamps across rapid test calls.
# Each call gets a unique second offset so Ed25519 signatures differ.
_nonce_counter = 0

# Pre-generated test keypairs for deterministic tests
_PRINCIPAL_PRIV, _PRINCIPAL_PUB = generate_ed25519_keypair()
_AGENT_PRIV, _AGENT_PUB = generate_ed25519_keypair()
_SERVER_PRIV, _SERVER_PUB = generate_ed25519_keypair()

PRINCIPAL_PUBKEY = pubkey_to_fix_id(_PRINCIPAL_PUB)
AGENT_PUBKEY = pubkey_to_fix_id(_AGENT_PUB)
SERVER_PUBKEY = pubkey_to_fix_id(_SERVER_PUB)

PRINCIPAL_PRIV = _PRINCIPAL_PRIV
AGENT_PRIV = _AGENT_PRIV
SERVER_PRIV = _SERVER_PRIV

PRINCIPAL_PUB_HEX = _PRINCIPAL_PUB.hex()
AGENT_PUB_HEX = _AGENT_PUB.hex()
SERVER_PUB_HEX = _SERVER_PUB.hex()


def signed_post(client, path, data, pubkey, privkey_bytes):
    """Make an Ed25519-signed POST request for tests.

    Uses a nonce embedded in the body to ensure unique signatures even when
    the same endpoint+body is called multiple times in the same second
    (prevents replay guard false positives in tests).
    """
    global _nonce_counter
    _nonce_counter += 1
    data_with_nonce = {**data, "_nonce": _nonce_counter}
    body = json.dumps(data_with_nonce)
    pub_hex = pubkey[4:] if pubkey.startswith("fix_") else pubkey
    auth_headers = sign_request_ed25519(privkey_bytes, pub_hex, "POST", path, body)
    return client.post(path, content=body, headers={
        "Content-Type": "application/json",
        **auth_headers,
    })


def signed_headers(pubkey, privkey_bytes, method, path, body=""):
    """Generate Ed25519 auth headers for a request."""
    pub_hex = pubkey[4:] if pubkey.startswith("fix_") else pubkey
    return sign_request_ed25519(privkey_bytes, pub_hex, method, path, body)
