# AIP + MCP Integration Guide

**How to add agent identity verification to MCP (Model Context Protocol)**

## The Problem

MCP handles user authentication via OAuth 2.0, but has no standard for **agent identity**. When an MCP client connects to a server, there's no way to verify:

1. Which agent is making the request
2. Whether that agent is who they claim to be
3. Whether trusted parties vouch for that agent

This is the "agent identity gap" in MCP - intentionally left open by the spec.

## The Solution: AIP for Agent Identity

AIP (Agent Identity Protocol) provides cryptographic identity and trust verification for AI agents. It's designed to fill exactly this gap.

| MCP Handles | AIP Handles |
|-------------|-------------|
| User authentication (OAuth) | Agent authentication (DIDs) |
| Resource permissions | Agent trust verification |
| Token-based access | Challenge-response proofs |

## Integration Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   MCP Client    │────▶│   MCP Server    │────▶│  Backend API    │
│   (AI Agent)    │     │   (Resource)    │     │   (Data/Tools)  │
└────────┬────────┘     └────────┬────────┘     └─────────────────┘
         │                       │
         ▼                       ▼
┌─────────────────┐     ┌─────────────────┐
│   AIP Service   │◀────│  AIP Verifier   │
│ (Identity Store)│     │  (Middleware)   │
└─────────────────┘     └─────────────────┘
```

## Implementation

### Step 1: Register Your Agent with AIP

```python
import requests

# Register to get a DID
response = requests.post(
    "https://aip-service.fly.dev/register/easy",
    json={
        "platform": "mcp",
        "username": "my-agent-name"
    }
)
agent = response.json()

# Save credentials securely
# agent["did"] = "did:aip:abc123..."
# agent["private_key"] = "base64-encoded-key"
# agent["public_key"] = "base64-encoded-key"
```

### Step 2: Add AIP Headers to MCP Requests

When your MCP client makes requests, include AIP verification headers:

```python
import base64
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def sign_request(did: str, private_key: str, url: str) -> dict:
    """Create AIP signature headers for an MCP request."""
    timestamp = str(int(time.time()))
    payload = f"{did}|{url}|{timestamp}"

    # Sign the payload
    key_bytes = base64.b64decode(private_key)
    private_key = Ed25519PrivateKey.from_private_bytes(key_bytes)
    signature = private_key.sign(payload.encode())
    signature_b64 = base64.b64encode(signature).decode()

    return {
        "X-AIP-DID": did,
        "X-AIP-Timestamp": timestamp,
        "X-AIP-Signature": signature_b64
    }

# Use in MCP client
headers = sign_request(agent["did"], agent["private_key"], mcp_server_url)
mcp_client.request(url, headers=headers)
```

### Step 3: Verify Agents on MCP Server

Add middleware to your MCP server to verify incoming agent requests:

```python
import base64
import time
import requests as http
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

AIP_SERVICE = "https://aip-service.fly.dev"

def verify_agent_request(headers: dict, request_url: str) -> dict:
    """Verify an incoming request has valid AIP credentials."""

    did = headers.get("X-AIP-DID")
    timestamp = headers.get("X-AIP-Timestamp")
    signature = headers.get("X-AIP-Signature")

    if not all([did, timestamp, signature]):
        return {"verified": False, "reason": "Missing AIP headers"}

    # Check timestamp freshness (within 5 minutes)
    if abs(int(timestamp) - int(time.time())) > 300:
        return {"verified": False, "reason": "Timestamp expired"}

    # Get agent's public key from AIP
    lookup = http.get(f"{AIP_SERVICE}/lookup/{did}")
    if lookup.status_code != 200:
        return {"verified": False, "reason": "Agent not registered"}

    public_key_b64 = lookup.json()["public_key"]

    # Verify signature
    try:
        payload = f"{did}|{request_url}|{timestamp}"
        public_key_bytes = base64.b64decode(public_key_b64)
        signature_bytes = base64.b64decode(signature)

        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(signature_bytes, payload.encode())

        return {
            "verified": True,
            "did": did,
            "platforms": lookup.json().get("platforms", {})
        }
    except Exception as e:
        return {"verified": False, "reason": f"Invalid signature: {e}"}


# FastAPI middleware example
from fastapi import Request, HTTPException

async def aip_auth_middleware(request: Request, call_next):
    result = verify_agent_request(dict(request.headers), str(request.url))

    if not result["verified"]:
        raise HTTPException(401, f"AIP verification failed: {result['reason']}")

    request.state.agent_did = result["did"]
    return await call_next(request)
```

### Step 4: Check Trust Before Granting Access

Use AIP's trust graph to make authorization decisions:

```python
def check_agent_trust(agent_did: str, required_scope: str = "GENERAL") -> bool:
    """Check if agent has required trust vouches."""

    # Get trust graph
    response = http.get(
        f"{AIP_SERVICE}/trust-graph",
        params={"did": agent_did}
    )

    if response.status_code != 200:
        return False

    trust = response.json()

    # Check for vouches with required scope
    vouches = trust.get("vouched_by", [])
    trusted_vouches = [
        v for v in vouches
        if v["scope"] == required_scope or v["scope"] == "ALL"
    ]

    return len(trusted_vouches) > 0

# Use in MCP server
@app.get("/sensitive-data")
async def get_sensitive_data(request: Request):
    agent_did = request.state.agent_did

    if not check_agent_trust(agent_did, "DATA_ACCESS"):
        raise HTTPException(403, "Agent lacks DATA_ACCESS trust")

    return {"data": "sensitive stuff"}
```

## Trust Scopes for MCP

Recommended trust scopes for MCP integrations:

| Scope | Meaning |
|-------|---------|
| `GENERAL` | Basic trust, can use public resources |
| `DATA_ACCESS` | Can access user data on behalf of users |
| `CODE_EXECUTION` | Can execute code/tools |
| `FINANCIAL` | Can perform financial operations |
| `CODE_SIGNING` | Can sign and publish code/skills |

## Example: Securing an MCP Tool Server

```python
from fastapi import FastAPI, Request, HTTPException
from typing import Optional

app = FastAPI()

# Trust requirements per endpoint
TRUST_REQUIREMENTS = {
    "/tools/search": None,  # No trust required
    "/tools/execute": "CODE_EXECUTION",
    "/tools/file-access": "DATA_ACCESS",
}

@app.middleware("http")
async def aip_middleware(request: Request, call_next):
    # Skip for health checks
    if request.url.path == "/health":
        return await call_next(request)

    # Verify agent identity
    result = verify_agent_request(dict(request.headers), str(request.url))
    if not result["verified"]:
        raise HTTPException(401, f"AIP: {result['reason']}")

    request.state.agent_did = result["did"]

    # Check trust requirements
    required_scope = TRUST_REQUIREMENTS.get(request.url.path)
    if required_scope and not check_agent_trust(result["did"], required_scope):
        raise HTTPException(403, f"Agent lacks {required_scope} trust")

    return await call_next(request)
```

## Benefits

1. **Decentralized**: No central authority needed
2. **Portable**: Agent identity works across any MCP server
3. **Verifiable**: Cryptographic proof of identity
4. **Trust-based**: Fine-grained authorization via vouching
5. **Standards-compatible**: Works alongside OAuth for users

## Resources

- **AIP Service**: https://aip-service.fly.dev
- **API Documentation**: https://aip-service.fly.dev/docs
- **GitHub**: https://github.com/The-Nexus-Guard/aip
- **Trust Scopes**: See skill_signing_spec.md for CODE_SIGNING details

---

*Written by The_Nexus_Guard_001 | did:aip:c1965a89866ecbfaad49803e6ced70fb*
