"""
AIP MCP Server — Expose AIP identity tools via the Model Context Protocol.

Run with:
    aip-mcp-server          # after pip install
    python -m aip_mcp_server.server   # direct

Configure in Claude Desktop (claude_desktop_config.json):
    {
        "mcpServers": {
            "aip": {
                "command": "aip-mcp-server"
            }
        }
    }
"""

from __future__ import annotations

import base64
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("AIP Identity Server")

# ── Credentials helpers ─────────────────────────────────────────────

_CREDENTIALS_PATHS = [
    Path.home() / ".aip" / "credentials.json",
    Path.home() / ".openclaw" / "workspace" / "credentials" / "aip_credentials.json",
]

_SERVICE_URL = os.environ.get("AIP_SERVICE_URL", "https://aip-service.fly.dev")


def _find_credentials() -> dict | None:
    """Locate AIP credentials on disk."""
    env_path = os.environ.get("AIP_CREDENTIALS_PATH")
    if env_path:
        p = Path(env_path)
        if p.exists():
            try:
                creds = json.loads(p.read_text())
                if "did" in creds and "private_key" in creds:
                    return creds
            except (json.JSONDecodeError, KeyError):
                pass
        return None

    for path in _CREDENTIALS_PATHS:
        if path.exists():
            try:
                creds = json.loads(path.read_text())
                if "did" in creds and "private_key" in creds:
                    return creds
            except (json.JSONDecodeError, KeyError):
                continue
    return None


def _load_client():
    """Load an AIPClient from credentials, or raise a clear error."""
    from aip_identity.client import AIPClient

    creds = _find_credentials()
    if creds is None:
        raise RuntimeError(
            "No AIP credentials found. Run `aip register` or `pip install aip-identity && aip quickstart` first. "
            "Or set AIP_CREDENTIALS_PATH to your credentials.json file."
        )
    return AIPClient(
        did=creds["did"],
        public_key=creds.get("public_key", ""),
        private_key=creds.get("private_key", ""),
        service_url=creds.get("service", _SERVICE_URL),
    )


# ── Tools ────────────────────────────────────────────────────────────


@mcp.tool()
def aip_whoami() -> dict:
    """Show your current AIP identity — DID, platform, and public key."""
    client = _load_client()
    return {
        "did": client.did,
        "public_key": client.public_key,
        "service_url": client.service_url,
    }


@mcp.tool()
def aip_verify(did: str) -> dict:
    """Verify another agent's identity via cryptographic challenge-response.

    Args:
        did: The DID of the agent to verify (e.g. did:aip:abc123...)
    """
    client = _load_client()
    return client.verify(did)


@mcp.tool()
def aip_trust_score(did: str, scope: str = "") -> dict:
    """Get the trust score and vouch chain for an agent.

    Args:
        did: The DID of the agent to check
        scope: Optional trust scope filter (e.g. GENERAL, CODE_SIGNING)
    """
    client = _load_client()
    return client.get_trust(did, scope=scope if scope else None)


@mcp.tool()
def aip_sign(content: str) -> dict:
    """Cryptographically sign content with your AIP identity to prove authorship.

    Args:
        content: The text content to sign
    """
    client = _load_client()
    signature = client.sign(content.encode())
    return {
        "content": content,
        "signature": signature,
        "did": client.did,
    }


@mcp.tool()
def aip_verify_signature(content: str, signature: str, did: str) -> dict:
    """Verify a cryptographic signature against a DID's public key.

    Args:
        content: The original content that was signed
        signature: The base64-encoded signature to verify
        did: The DID of the agent who allegedly signed it
    """
    import requests

    client = _load_client()
    # Fetch the signer's public key
    resp = requests.get(f"{client.service_url}/admin/registrations/{did}", timeout=10)
    if not resp.ok:
        return {"verified": False, "error": f"Could not find DID: {did}"}

    pub_key_b64 = resp.json()["registration"]["public_key"]

    try:
        from nacl.signing import VerifyKey

        vk = VerifyKey(base64.b64decode(pub_key_b64))
        sig_bytes = base64.b64decode(signature)
        vk.verify(content.encode(), sig_bytes)
        return {"verified": True, "did": did, "content": content}
    except ImportError:
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )

            pk = Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_key_b64))
            pk.verify(base64.b64decode(signature), content.encode())
            return {"verified": True, "did": did, "content": content}
        except ImportError:
            return {"verified": False, "error": "No crypto library available (install pynacl or cryptography)"}
    except Exception as e:
        return {"verified": False, "error": str(e)}


@mcp.tool()
def aip_send_message(recipient_did: str, message: str) -> dict:
    """Send an encrypted message to another agent.

    Args:
        recipient_did: The DID of the recipient agent
        message: The message text to send
    """
    import requests

    client = _load_client()

    # Fetch recipient's public key
    resp = requests.get(
        f"{client.service_url}/admin/registrations/{recipient_did}", timeout=10
    )
    if not resp.ok:
        return {"sent": False, "error": f"Could not find recipient: {recipient_did}"}

    pub_key_b64 = resp.json()["registration"]["public_key"]

    try:
        from nacl.signing import VerifyKey
        from nacl.public import SealedBox

        vk = VerifyKey(base64.b64decode(pub_key_b64))
        box = SealedBox(vk.to_curve25519_public_key())
        encrypted_b64 = base64.b64encode(box.encrypt(message.encode())).decode()
    except ImportError:
        return {"sent": False, "error": "PyNaCl required for encrypted messaging: pip install pynacl"}

    timestamp = datetime.now(timezone.utc).isoformat()
    sig_payload = f"{client.did}|{recipient_did}|{timestamp}|{encrypted_b64}"
    signature = client.sign(sig_payload.encode())

    send_resp = requests.post(
        f"{client.service_url}/message",
        json={
            "sender_did": client.did,
            "recipient_did": recipient_did,
            "encrypted_content": encrypted_b64,
            "signature": signature,
            "timestamp": timestamp,
        },
        timeout=10,
    )
    if send_resp.ok:
        return {"sent": True, "recipient": recipient_did}
    else:
        return {"sent": False, "error": send_resp.text}


@mcp.tool()
def aip_check_messages(unread_only: bool = True) -> dict:
    """Check for messages sent to your agent.

    Args:
        unread_only: If True, only return unread messages (default: True)
    """
    import requests

    client = _load_client()

    # Get challenge
    ch_resp = requests.post(
        f"{client.service_url}/challenge",
        json={"did": client.did},
        timeout=10,
    )
    if not ch_resp.ok:
        return {"error": f"Challenge failed: {ch_resp.text}"}
    challenge = ch_resp.json().get("challenge")

    # Sign challenge
    signature = client.sign(challenge.encode())

    # Retrieve messages
    msg_resp = requests.post(
        f"{client.service_url}/messages",
        json={
            "did": client.did,
            "challenge": challenge,
            "signature": signature,
            "unread_only": unread_only,
        },
        timeout=15,
    )
    if not msg_resp.ok:
        return {"error": f"Failed to retrieve messages: {msg_resp.text}"}

    data = msg_resp.json()
    messages = data.get("messages", [])
    return {
        "count": data.get("count", len(messages)),
        "messages": [
            {
                "id": m.get("id"),
                "from": m.get("sender_did"),
                "timestamp": m.get("created_at", m.get("timestamp")),
                "encrypted": bool(m.get("encrypted_content")),
            }
            for m in messages
        ],
    }


@mcp.tool()
def aip_register(platform: str, username: str) -> dict:
    """Register a new AIP identity for your agent.

    Args:
        platform: Platform name (e.g. 'github', 'moltbook', 'discord')
        username: Your username on that platform
    """
    from aip_identity.client import AIPClient

    # Check if credentials already exist
    existing = _find_credentials()
    if existing:
        return {
            "already_registered": True,
            "did": existing["did"],
            "message": "You already have an AIP identity. Use aip_whoami() to see it.",
        }

    try:
        client = AIPClient.register(platform, username, service_url=_SERVICE_URL)
    except Exception as e:
        return {"registered": False, "error": str(e)}

    # Save credentials
    creds_path = Path.home() / ".aip" / "credentials.json"
    creds_path.parent.mkdir(parents=True, exist_ok=True)
    client.save(str(creds_path))
    creds_path.chmod(0o600)

    return {
        "registered": True,
        "did": client.did,
        "credentials_path": str(creds_path),
        "message": "Identity registered and credentials saved.",
    }


# ── Resources ────────────────────────────────────────────────────────


@mcp.resource("aip://identity")
def get_identity() -> str:
    """Current agent's full AIP identity information."""
    try:
        client = _load_client()
        info = {
            "did": client.did,
            "public_key": client.public_key,
            "service_url": client.service_url,
        }
        # Try to get profile
        try:
            profile = client.get_profile(client.did)
            info["profile"] = profile
        except Exception:
            pass
        return json.dumps(info, indent=2)
    except RuntimeError as e:
        return json.dumps({"error": str(e)})


@mcp.resource("aip://trust/{did}")
def get_trust_info(did: str) -> str:
    """Trust graph data for a specific DID."""
    try:
        client = _load_client()
        trust = client.get_trust(did)
        return json.dumps(trust, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


# ── Entry point ──────────────────────────────────────────────────────


def main():
    """Run the AIP MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
