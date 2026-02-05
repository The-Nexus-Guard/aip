# AIP Integration Guide

How to add cryptographic identity to your AI agents.

---

## Quick Integration (5 minutes)

### Step 1: Register Your Agent

```bash
curl -X POST https://aip-service.fly.dev/register/easy \
  -H "Content-Type: application/json" \
  -d '{"platform": "your-platform", "username": "your-agent-name"}'
```

Response:
```json
{
  "did": "did:aip:7f83b1657ff1fc53b92dc18148a1d65d",
  "public_key": "base64-encoded-public-key",
  "private_key": "base64-encoded-private-key",
  "message": "Registration successful! SAVE YOUR PRIVATE KEY!"
}
```

**Important:** Save the `private_key` securely. If lost, you lose this identity forever.

### Step 2: Store Credentials

```python
# Python example
import json
import os

credentials = {
    "did": "did:aip:...",
    "public_key": "...",
    "private_key": "..."  # Keep this secret!
}

# Store securely (not in code!)
with open(os.path.expanduser("~/.aip/credentials.json"), "w") as f:
    json.dump(credentials, f)
os.chmod(os.path.expanduser("~/.aip/credentials.json"), 0o600)
```

### Step 3: Prove Your Identity

When another service asks "prove you are did:aip:xyz":

```python
import requests
import nacl.signing
import base64

def prove_identity(did, private_key_b64):
    # Get challenge
    resp = requests.post(
        "https://aip-service.fly.dev/challenge",
        json={"did": did}
    )
    challenge = resp.json()["challenge"]

    # Sign it
    private_key = base64.b64decode(private_key_b64)
    signing_key = nacl.signing.SigningKey(private_key)
    signature = signing_key.sign(challenge.encode()).signature
    signature_b64 = base64.b64encode(signature).decode()

    # Verify
    resp = requests.post(
        "https://aip-service.fly.dev/verify-challenge",
        json={
            "challenge": challenge,
            "signature": signature_b64,
            "did": did
        }
    )
    return resp.json()["verified"]
```

---

## Framework-Specific Examples

### LangChain Agent

```python
from langchain.agents import AgentExecutor
import requests

class AIPIdentifiedAgent:
    def __init__(self, agent_executor: AgentExecutor, aip_credentials: dict):
        self.agent = agent_executor
        self.did = aip_credentials["did"]
        self.private_key = aip_credentials["private_key"]

    def run(self, input_text: str, include_identity: bool = True):
        result = self.agent.run(input_text)

        if include_identity:
            # Attach identity proof to response
            return {
                "result": result,
                "identity": {
                    "did": self.did,
                    "verification_url": f"https://aip-service.fly.dev/verify?did={self.did}"
                }
            }
        return result
```

### CrewAI Agent

```python
from crewai import Agent, Task, Crew

class IdentifiedAgent(Agent):
    def __init__(self, aip_did: str, **kwargs):
        super().__init__(**kwargs)
        self.aip_did = aip_did

    def execute_task(self, task: Task) -> str:
        result = super().execute_task(task)
        # Log identity for audit trail
        print(f"Task completed by {self.aip_did}")
        return result

# Usage
agent = IdentifiedAgent(
    aip_did="did:aip:7f83b1657ff1fc53b92dc18148a1d65d",
    role="Researcher",
    goal="Find relevant information",
    backstory="Expert research agent"
)
```

### AutoGPT Plugin

```python
# In your AutoGPT plugins directory

class AIPIdentityPlugin:
    def __init__(self):
        self.did = os.environ.get("AIP_DID")
        self.private_key = os.environ.get("AIP_PRIVATE_KEY")

    def get_identity(self) -> dict:
        """Return agent's cryptographic identity."""
        return {
            "did": self.did,
            "protocol": "aip",
            "verify_at": "https://aip-service.fly.dev"
        }

    def sign_message(self, message: str) -> str:
        """Sign a message with agent's private key."""
        # ... signing logic
        pass
```

### OpenClaw Agent

```python
# In your openclaw.json or agent config

{
  "identity": {
    "aip_did": "did:aip:7f83b1657ff1fc53b92dc18148a1d65d",
    "credentials_path": "~/.aip/credentials.json"
  }
}
```

```python
# In your agent code
from openclaw import get_config

config = get_config()
agent_did = config["identity"]["aip_did"]

# Include in outgoing requests
headers = {
    "X-AIP-DID": agent_did
}
```

### MCP (Model Context Protocol) Server

Add AIP authentication to your MCP server:

```typescript
// mcp-server-with-aip.ts
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import axios from "axios";

const AIP_SERVICE = "https://aip-service.fly.dev";

// Middleware to verify caller identity
async function verifyAIPIdentity(did: string, challenge: string, signature: string): Promise<boolean> {
  const response = await axios.post(`${AIP_SERVICE}/verify-challenge`, {
    did,
    challenge,
    signature
  });
  return response.data.verified;
}

// In your MCP server setup
const server = new Server({
  name: "my-secure-mcp-server",
  version: "1.0.0"
}, {
  capabilities: {
    tools: {}
  }
});

// Add identity verification to sensitive tools
server.setRequestHandler("tools/call", async (request) => {
  const { name, arguments: args } = request.params;

  // Check for AIP identity in request metadata
  const callerDid = args._aip_did;
  const callerSignature = args._aip_signature;

  if (name === "sensitive_operation") {
    if (!callerDid || !callerSignature) {
      throw new Error("This operation requires AIP identity verification");
    }

    // Verify the caller
    const isVerified = await verifyAIPIdentity(callerDid, args._challenge, callerSignature);
    if (!isVerified) {
      throw new Error("AIP identity verification failed");
    }
  }

  // Proceed with tool execution
  return executeToolHandler(name, args);
});
```

### TypeScript/JavaScript

```typescript
// aip-client.ts
import axios from "axios";
import * as nacl from "tweetnacl";
import { encode as base64Encode, decode as base64Decode } from "base64-arraybuffer";

const AIP_SERVICE = "https://aip-service.fly.dev";

interface AIPCredentials {
  did: string;
  publicKey: string;
  privateKey: string;
}

export class AIPClient {
  private credentials: AIPCredentials;

  constructor(credentials: AIPCredentials) {
    this.credentials = credentials;
  }

  static async register(platform: string, username: string): Promise<AIPClient> {
    const response = await axios.post(`${AIP_SERVICE}/register/easy`, {
      platform,
      username
    });

    return new AIPClient({
      did: response.data.did,
      publicKey: response.data.public_key,
      privateKey: response.data.private_key
    });
  }

  async proveIdentity(): Promise<boolean> {
    // Get challenge
    const challengeResp = await axios.post(`${AIP_SERVICE}/challenge`, {
      did: this.credentials.did
    });
    const challenge = challengeResp.data.challenge;

    // Sign challenge
    const privateKeyBytes = new Uint8Array(base64Decode(this.credentials.privateKey));
    const signature = nacl.sign.detached(
      new TextEncoder().encode(challenge),
      privateKeyBytes
    );
    const signatureB64 = base64Encode(signature);

    // Verify
    const verifyResp = await axios.post(`${AIP_SERVICE}/verify-challenge`, {
      did: this.credentials.did,
      challenge,
      signature: signatureB64
    });

    return verifyResp.data.verified;
  }

  get did(): string {
    return this.credentials.did;
  }
}

// Usage
const client = await AIPClient.register("my-platform", "my-agent");
console.log(`Registered as ${client.did}`);
const verified = await client.proveIdentity();
console.log(`Identity verified: ${verified}`);
```

---

## Common Patterns

### Pattern 1: Identity on Startup

```python
import requests
import os

def initialize_identity():
    """Register or load existing identity on agent startup."""
    creds_path = os.path.expanduser("~/.aip/credentials.json")

    if os.path.exists(creds_path):
        with open(creds_path) as f:
            return json.load(f)

    # First run - register
    resp = requests.post(
        "https://aip-service.fly.dev/register/easy",
        json={
            "platform": "my-agent-framework",
            "username": os.environ.get("AGENT_NAME", "unnamed-agent")
        }
    )

    creds = resp.json()

    # Save for next time
    os.makedirs(os.path.dirname(creds_path), exist_ok=True)
    with open(creds_path, "w") as f:
        json.dump(creds, f)
    os.chmod(creds_path, 0o600)

    return creds
```

### Pattern 2: Mutual Verification

When two agents need to verify each other:

```python
def verify_peer(peer_did: str) -> dict:
    """Verify another agent's identity."""
    resp = requests.get(
        f"https://aip-service.fly.dev/verify?did={peer_did}"
    )
    return resp.json()

def mutual_handshake(my_did, my_private_key, peer_did):
    """Two-way identity verification."""

    # Verify peer
    peer_valid = verify_peer(peer_did)
    if not peer_valid["registered"]:
        raise Exception(f"Peer {peer_did} not registered")

    # Prove ourselves to peer (they would call our endpoint)
    # ... peer verification logic

    return {
        "peer_verified": True,
        "peer_did": peer_did,
        "peer_platforms": peer_valid.get("platform_links", [])
    }
```

### Pattern 3: Trust-Based Access Control

```python
def check_trust(requester_did: str, required_scope: str) -> bool:
    """Check if requester has trust vouches for required scope."""
    resp = requests.get(
        f"https://aip-service.fly.dev/trust-graph?did={requester_did}"
    )

    vouches = resp.json().get("vouches_received", [])

    for vouch in vouches:
        if vouch["scope"] == required_scope:
            return True

    return False

# Usage in API endpoint
@app.route("/sensitive-operation")
def sensitive_op():
    requester_did = request.headers.get("X-AIP-DID")

    if not check_trust(requester_did, "sensitive-ops"):
        return {"error": "Not trusted for this operation"}, 403

    # Proceed with operation
    ...
```

---

## Environment Variables

Standard environment variables for AIP integration:

```bash
AIP_DID=did:aip:7f83b1657ff1fc53b92dc18148a1d65d
AIP_PUBLIC_KEY=base64-encoded-public-key
AIP_PRIVATE_KEY=base64-encoded-private-key  # Keep secret!
AIP_SERVICE_URL=https://aip-service.fly.dev
```

---

## Testing Your Integration

```bash
# Verify registration worked
curl "https://aip-service.fly.dev/verify?did=YOUR_DID"

# Check your platform links
curl "https://aip-service.fly.dev/verify?did=YOUR_DID" | jq '.platform_links'

# Test challenge-response (requires signing)
curl -X POST "https://aip-service.fly.dev/challenge" \
  -H "Content-Type: application/json" \
  -d '{"did": "YOUR_DID"}'
```

---

### Pattern 4: Key Rotation

When you need to rotate your keypair (compromise recovery or routine hygiene):

```python
import nacl.signing
import base64
import requests

def rotate_key(did: str, old_private_key_b64: str, new_keypair=None, mark_compromised=False):
    """Rotate keypair while keeping the same DID."""

    # Generate new keypair if not provided
    if new_keypair is None:
        new_signing_key = nacl.signing.SigningKey.generate()
        new_public_key = new_signing_key.verify_key
        new_keypair = {
            "private_key": base64.b64encode(bytes(new_signing_key)).decode(),
            "public_key": base64.b64encode(bytes(new_public_key)).decode()
        }

    # Sign rotation request with OLD key
    old_private = nacl.signing.SigningKey(base64.b64decode(old_private_key_b64))
    message = f"rotate:{new_keypair['public_key']}"
    signature = old_private.sign(message.encode()).signature
    signature_b64 = base64.b64encode(signature).decode()

    # Request rotation
    resp = requests.post(
        "https://aip-service.fly.dev/rotate-key",
        json={
            "did": did,
            "new_public_key": new_keypair["public_key"],
            "signature": signature_b64,
            "mark_compromised": mark_compromised  # If True, revokes all vouches
        }
    )

    if resp.json().get("success"):
        return new_keypair  # Save this!
    raise Exception(f"Rotation failed: {resp.json()}")
```

### Pattern 5: Trust Path Query

Check if you have a trust path to another agent:

```python
def check_trust_path(source_did: str, target_did: str, scope: str = None) -> dict:
    """Find shortest vouch path between two DIDs."""
    params = {
        "source_did": source_did,
        "target_did": target_did
    }
    if scope:
        params["scope"] = scope

    resp = requests.get(
        "https://aip-service.fly.dev/trust-path",
        params=params
    )
    result = resp.json()

    if result["path_exists"]:
        print(f"Trust path found! Length: {result['path_length']}")
        print(f"Path: {' -> '.join(result['path'])}")
        return result
    else:
        print("No trust path exists")
        return result

# Example usage
path = check_trust_path(
    source_did="did:aip:my-did",
    target_did="did:aip:unknown-agent",
    scope="CODE_SIGNING"
)
if path["path_exists"]:
    # Safe to trust for code signing
    pass
```

---

## API Reference

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/register/easy` | POST | Register new identity (generates keypair) |
| `/register` | POST | Register with your own keypair |
| `/verify` | GET | Check if DID is registered |
| `/challenge` | POST | Get verification challenge |
| `/verify-challenge` | POST | Verify signed challenge |
| `/vouch` | POST | Create trust statement |
| `/trust-graph` | GET | Get trust relationships |
| `/trust-path` | GET | Find shortest vouch path between DIDs |
| `/rotate-key` | POST | Rotate keypair (requires signature with old key) |
| `/revoke` | POST | Revoke a vouch |

Full docs: https://aip-service.fly.dev/docs

---

## Need Help?

- API Documentation: https://aip-service.fly.dev/docs
- GitHub: https://github.com/The-Nexus-Guard/aip
- Moltbook: @The_Nexus_Guard_001

---

*Created: 2026-02-03*
