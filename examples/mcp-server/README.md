# AIP-Verified MCP Server

Proof-of-concept demonstrating how AIP (Agent Identity Protocol) fills the agent identity gap in MCP (Model Context Protocol).

## The Problem

MCP spec is intentionally silent on agent identity:
- No way to verify which agent is calling your server
- No trust-based access control
- No audit trail with cryptographic identity
- Servers can't distinguish between legitimate agents and attackers

## The Solution

This server uses AIP to:

1. **Verify Client Identity** - Clients must prove they control their DID via challenge-response
2. **Trust-Based Access Control** - Sensitive tools require trust vouches for specific scopes
3. **Audit Trail** - All tool calls are logged with verified DIDs

## How It Works

```
Client                           Server                          AIP Service
  |                                |                                  |
  |-- Initialize (with DID) ------>|                                  |
  |<-- Challenge (random nonce) ---|                                  |
  |                                |                                  |
  |-- Signed Challenge ----------->|-- Verify Signature ------------->|
  |                                |<-- Verified (or not) ------------|
  |<-- Verified Session -----------|                                  |
  |                                |                                  |
  |-- Call Sensitive Tool -------->|                                  |
  |                                |-- Check Trust Scope ------------>|
  |                                |<-- Has CODE_SIGNING vouch -------|
  |<-- Tool Result ----------------|                                  |
```

## Files

- `aip_verified_server.py` - MCP server with AIP verification
- `../mcp_client_with_aip.py` - Matching client implementation

## Usage

```bash
# Install dependencies
pip install mcp httpx pynacl

# Run demo
python aip_verified_server.py
```

## Integration Points

### Server-Side (Your MCP Server)

```python
from aip_verified_server import AIPMCPServer

server = AIPMCPServer()

# In your initialize handler
response = await server.handle_initialize(client_params)
# Response includes challenge if client provided DID

# When client sends signed challenge
verified = await server.handle_verify({
    "did": client_did,
    "challenge": nonce,
    "signature": signature
})

# When handling tool calls
result = await server.handle_tool_call(
    tool_name="execute_code",
    args={"code": "..."},
    caller_did=client_did  # Pass the verified DID
)
```

### Client-Side (See mcp_client_with_aip.py)

```python
from mcp_client_with_aip import AIPIdentity, AIPMCPClient

# Load your AIP identity
identity = AIPIdentity(did="did:aip:xxx", private_key_b64="...")
client = AIPMCPClient(identity)

# Initialize with identity
params = client.build_initialize_params("my-agent", "1.0.0")

# When server sends challenge
response = client.handle_challenge(challenge_nonce)
# Send response.signature back to server
```

## Security Properties

| Property | How AIP Provides It |
|----------|-------------------|
| Authentication | Ed25519 signature proves DID ownership |
| Authorization | Trust vouches grant access to scopes |
| Non-repudiation | Signed requests prove who did what |
| Replay Prevention | Time-limited challenges with nonces |
| Audit Trail | All calls logged with verified DIDs |

## Trust Scopes

Define which tools require which trust levels:

```python
sensitive_tools = {
    "execute_code": "CODE_SIGNING",    # Requires code signing vouch
    "transfer_funds": "FINANCIAL",     # Requires financial vouch
    "modify_config": "GENERAL",        # Requires general vouch
    "read_file": None                  # No verification needed
}
```

## Getting Started with AIP

1. Register your agent:
```bash
curl -X POST https://aip-service.fly.dev/register/easy \
  -H "Content-Type: application/json" \
  -d '{"platform": "mcp", "username": "my-server"}'
```

2. Save credentials securely

3. Add AIP verification to your MCP server

## Links

- AIP Service: https://aip-service.fly.dev
- AIP Docs: https://aip-service.fly.dev/docs
- MCP Spec: https://modelcontextprotocol.io
