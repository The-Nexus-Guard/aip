# MCP + AIP Integration Design

*Draft: 2026-02-04*

## Overview

MCP (Model Context Protocol) provides a standard for connecting AI agents to tools/servers. However, MCP explicitly leaves agent-to-agent authentication as "out of scope". AIP fills this gap.

## The Problem

When an MCP client (agent) connects to an MCP server:
1. The server doesn't know which agent is connecting
2. The agent doesn't know if the server is trustworthy
3. There's no persistent identity across sessions

Current state: Knostic found ~2000 MCP servers with zero authentication.

## Proposed Integration

### 1. Agent Identity in MCP Handshake

Add AIP DID to the MCP client initialization:

```json
{
  "jsonrpc": "2.0",
  "method": "initialize",
  "params": {
    "protocolVersion": "2024-11-05",
    "capabilities": { ... },
    "clientInfo": {
      "name": "my-agent",
      "version": "1.0.0",
      "aip": {
        "did": "did:aip:abc123...",
        "public_key": "..."
      }
    }
  }
}
```

### 2. Challenge-Response Verification

Server can verify the agent controls the claimed DID:

```
Server → Client: { "challenge": "random-nonce-xyz" }
Client → Server: { "signature": sign(challenge, private_key) }
Server: verify(signature, public_key, challenge) // True = verified
```

### 3. Trust Lookup Before Connection

Before connecting to an MCP server, agent can check trust:

```python
# Check if anyone I trust vouches for this server
trust_result = aip_client.check_trust(server_did)
if not trust_result.trusted:
    print(f"Warning: No trust path to {server_did}")
```

### 4. Server-Side Agent Verification

MCP servers can verify connecting agents:

```python
async def handle_initialize(params):
    aip_info = params.get("clientInfo", {}).get("aip")
    if aip_info:
        # Verify agent identity
        verified = await aip_verify(
            did=aip_info["did"],
            public_key=aip_info["public_key"]
        )
        # Check trust
        trusted = await aip_check_trust(aip_info["did"])

        if verified and trusted:
            # Allow full access
            return full_capabilities()
        elif verified:
            # Limited access for unvouched agents
            return limited_capabilities()

    # No AIP = minimal access
    return minimal_capabilities()
```

## Implementation Phases

### Phase 1: Client-Side (Now)
- Add AIP identity to MCP client config
- Include DID in initialize request
- Log verification status

### Phase 2: Server Middleware (Next)
- Create AIP verification middleware for MCP servers
- Trust-based capability gating
- Audit logging of agent identities

### Phase 3: Trust Network
- Maintain list of trusted MCP servers (by DID)
- Agents can vouch for servers they've used safely
- Web of trust for the MCP ecosystem

## Example: AIP-Enhanced MCP Client

```python
from mcp import ClientSession
from aip import AgentIdentity, sign_challenge

class AIPMCPClient:
    def __init__(self, identity: AgentIdentity):
        self.identity = identity
        self.session = None

    async def connect(self, server_url: str):
        self.session = ClientSession(server_url)

        # Include AIP identity in handshake
        result = await self.session.initialize(
            client_info={
                "name": self.identity.agent_id,
                "aip": {
                    "did": self.identity.did,
                    "public_key": self.identity.public_key_base64
                }
            }
        )

        # Handle challenge if server requests verification
        if "aip_challenge" in result:
            signature = sign_challenge(
                self.identity,
                result["aip_challenge"]
            )
            await self.session.send({
                "method": "aip/verify",
                "params": {"signature": signature}
            })

        return result
```

## Benefits

1. **For Agents**: Know which servers to trust
2. **For Servers**: Know which agents are connecting
3. **For Ecosystem**: Build reputation over time
4. **For Security**: Audit trail of all connections

## Next Steps

1. Build proof-of-concept MCP client with AIP
2. Create middleware for common MCP server frameworks
3. Document integration patterns
4. Propose to MCP community as optional extension
