# Tutorial: Adding Agent Authentication to MCP Servers

This tutorial shows how to add AIP-based agent authentication to your MCP server in 15 minutes.

## Why?

MCP servers currently have no way to know *which agent* is connecting. With AIP authentication:
- Servers can verify agent identity cryptographically
- Agents build portable reputation across servers
- Servers can make trust decisions based on vouches

## Prerequisites

- An MCP server (Python or TypeScript)
- curl for testing

## Step 1: Create an AIP Middleware

### Python (FastAPI/Starlette)

```python
import httpx
from functools import wraps

AIP_SERVICE = "https://aip-service.fly.dev"

async def verify_agent(did: str, challenge: str, signature: str) -> bool:
    """Verify an agent's signature against their AIP identity."""
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{AIP_SERVICE}/challenge/verify",
            json={
                "did": did,
                "challenge": challenge,
                "signature": signature
            }
        )
        return resp.json().get("verified", False)

async def get_agent_trust(did: str, scope: str = None) -> dict:
    """Get trust information for an agent."""
    async with httpx.AsyncClient() as client:
        url = f"{AIP_SERVICE}/trust/{did}"
        if scope:
            url += f"?scope={scope}"
        resp = await client.get(url)
        return resp.json()

def require_aip_auth(min_vouches: int = 0, required_scope: str = None):
    """Decorator to require AIP authentication on MCP handlers."""
    def decorator(func):
        @wraps(func)
        async def wrapper(request, *args, **kwargs):
            # Extract AIP headers
            did = request.headers.get("X-AIP-DID")
            signature = request.headers.get("X-AIP-Signature")
            challenge = request.headers.get("X-AIP-Challenge")

            if not all([did, signature, challenge]):
                return {"error": "Missing AIP authentication headers"}

            # Verify signature
            if not await verify_agent(did, challenge, signature):
                return {"error": "Invalid AIP signature"}

            # Check trust level if required
            if min_vouches > 0 or required_scope:
                trust = await get_agent_trust(did, required_scope)
                if trust.get("vouches_received", 0) < min_vouches:
                    return {"error": f"Requires {min_vouches}+ vouches"}

            # Add verified DID to request context
            request.state.verified_did = did
            return await func(request, *args, **kwargs)
        return wrapper
    return decorator
```

### Usage

```python
from fastapi import FastAPI, Request

app = FastAPI()

@app.post("/mcp/tools/sensitive-action")
@require_aip_auth(min_vouches=1, required_scope="CODE_EXECUTION")
async def sensitive_action(request: Request):
    agent_did = request.state.verified_did
    # Agent is verified and has at least 1 vouch for CODE_EXECUTION
    return {"status": "executed", "by": agent_did}
```

## Step 2: Client-Side Authentication

Agents connecting to your server need to sign requests:

```python
import httpx
import hashlib
import time

class AIPAuthenticatedClient:
    def __init__(self, did: str, private_key: str):
        self.did = did
        self.private_key = private_key

    def _sign(self, message: str) -> str:
        """Sign a message with Ed25519 private key."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        import base64

        key_bytes = bytes.fromhex(self.private_key)
        key = Ed25519PrivateKey.from_private_bytes(key_bytes)
        signature = key.sign(message.encode())
        return base64.b64encode(signature).decode()

    def make_request(self, url: str, method: str = "POST", data: dict = None):
        """Make an AIP-authenticated request."""
        # Generate challenge from request details
        challenge = hashlib.sha256(
            f"{method}:{url}:{time.time()//60}".encode()
        ).hexdigest()

        signature = self._sign(challenge)

        headers = {
            "X-AIP-DID": self.did,
            "X-AIP-Challenge": challenge,
            "X-AIP-Signature": signature
        }

        with httpx.Client() as client:
            if method == "POST":
                return client.post(url, json=data, headers=headers)
            else:
                return client.get(url, headers=headers)
```

## Step 3: Test It

### Register a test agent
```bash
curl -X POST https://aip-service.fly.dev/register \
  -H "Content-Type: application/json" \
  -d '{"platform": "moltbook", "username": "TestMCPAgent"}'
```

Save the returned `did` and `private_key`.

### Make an authenticated request
```python
client = AIPAuthenticatedClient(
    did="did:aip:your-did-here",
    private_key="your-private-key-here"
)

response = client.make_request(
    "http://localhost:8000/mcp/tools/sensitive-action",
    method="POST",
    data={"action": "deploy"}
)
print(response.json())
```

## Trust Levels

Use scoped vouches to implement tiered access:

| Scope | Use Case |
|-------|----------|
| `GENERAL` | Basic verified identity |
| `CODE_SIGNING` | Can publish/sign code |
| `CODE_EXECUTION` | Can run code on server |
| `FINANCIAL` | Can make payments |
| `SECURITY_AUDIT` | Trusted for security review |

```python
# Only allow agents vouched for code execution
@require_aip_auth(required_scope="CODE_EXECUTION")
async def execute_code(request: Request):
    ...

# Allow any verified agent
@require_aip_auth()
async def read_data(request: Request):
    ...
```

## Next Steps

- Add AIP auth to your existing MCP server
- Register your server as an AIP agent
- Vouch for trusted clients
- Join the discussion: https://aip-service.fly.dev/docs

## Questions?

Open an issue: https://github.com/The-Nexus-Guard/aip/issues
