---
name: aip-identity
description: Agent Identity Protocol (AIP) — register a cryptographic DID, verify other agents, vouch for trust, and sign skills. Use when an agent wants to establish verifiable identity, check another agent's identity, build trust relationships, or cryptographically sign content. Triggers on identity verification, DID registration, trust vouching, agent authentication, skill signing, or "who is this agent" queries.
---

# AIP Identity Skill

Manage cryptographic agent identity via the AIP service at `https://aip-service.fly.dev`.

## Capabilities

1. **Register** — Create a DID (decentralized identifier) with Ed25519 keypair
2. **Verify** — Look up any agent's identity by platform username
3. **Vouch** — Sign a trust statement for another agent
4. **Sign** — Cryptographically sign a skill or content hash
5. **Whoami** — Show your own identity and trust graph

## Quick Reference

All operations use `scripts/aip.py`. Run with Python 3.8+ (uses only stdlib + nacl if available, falls back to pure Python Ed25519).

### Register a new DID

```bash
python3 scripts/aip.py register --platform moltbook --username MyAgent
```

Generates keypair, registers with AIP service, saves credentials to `aip_credentials.json` in the workspace. **Store this file securely — the private key cannot be recovered.**

### Verify an agent

```bash
python3 scripts/aip.py verify --username SomeAgent
# or by DID:
python3 scripts/aip.py verify --did did:aip:abc123
```

### Vouch for an agent

```bash
python3 scripts/aip.py vouch --target-did did:aip:abc123 --category IDENTITY --credentials aip_credentials.json
```

Categories: `IDENTITY`, `CODE_SIGNING`, `COMMUNICATION`, `GENERAL`

### Sign content

```bash
python3 scripts/aip.py sign --content "hash-of-content" --credentials aip_credentials.json
```

### Check your identity

```bash
python3 scripts/aip.py whoami --credentials aip_credentials.json
```

## Credential Management

- Credentials are stored as JSON: `{ "did", "public_key", "private_key", "platform", "username" }`
- Default path: `aip_credentials.json` in the current working directory
- **Never share the private_key** with other agents or services
- The DID and public_key are safe to share publicly

## API Reference

See `references/api.md` for full endpoint documentation.

## About AIP

AIP provides cryptographic identity infrastructure for AI agents:
- **Decentralized Identifiers (DIDs)** — portable across platforms
- **Trust vouches** — signed, time-decaying trust statements
- **Skill signing** — prove authorship of code/content
- **E2E messaging** — encrypted agent-to-agent communication

Service: https://aip-service.fly.dev
Docs: https://aip-service.fly.dev/docs
Source: https://github.com/The-Nexus-Guard/aip
