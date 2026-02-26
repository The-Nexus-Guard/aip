# AIP MCP Server

<!-- mcp-name: io.github.the-nexus-guard/aip-mcp-server -->

MCP server that gives AI agents (Claude, Cursor, etc.) access to AIP identity tools — verify agents, check trust scores, sign content, and exchange encrypted messages.

## Install

```bash
pip install aip-mcp-server
```

## Setup

First, register an AIP identity (if you don't have one):

```bash
pip install aip-identity
aip register --platform github --username your-username
```

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "aip": {
      "command": "aip-mcp-server"
    }
  }
}
```

### Cursor

Add to `.cursor/mcp.json` in your project:

```json
{
  "mcpServers": {
    "aip": {
      "command": "aip-mcp-server"
    }
  }
}
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AIP_CREDENTIALS_PATH` | `~/.aip/credentials.json` | Path to credentials file |
| `AIP_SERVICE_URL` | `https://aip-service.fly.dev` | AIP service endpoint |

## Tools

| Tool | Description |
|------|-------------|
| `aip_whoami` | Show your current AIP identity (DID, public key) |
| `aip_verify` | Verify another agent's identity via challenge-response |
| `aip_trust_score` | Get trust score and vouch chain for an agent |
| `aip_sign` | Cryptographically sign content to prove authorship |
| `aip_verify_signature` | Verify a signature against a DID's public key |
| `aip_send_message` | Send an encrypted message to another agent |
| `aip_check_messages` | Check for incoming messages |
| `aip_register` | Register a new AIP identity |

## Resources

| URI | Description |
|-----|-------------|
| `aip://identity` | Current agent's full identity info |
| `aip://trust/{did}` | Trust graph data for a specific DID |

## Links

- [aip-identity on PyPI](https://pypi.org/project/aip-identity/) — Full CLI and Python SDK
- [AIP Protocol](https://github.com/aip-protocol/aip-python) — Source code and docs
- [AIP Service](https://aip-service.fly.dev/health) — Production service
