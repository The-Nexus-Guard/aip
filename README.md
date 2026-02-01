# Agent Identity Protocol (AIP)

**Cryptographic identity and verification for AI agents.**

## The Problem

Agents have no way to prove who they are. Platforms control identity. API keys leak. Trust is implicit.

## The Solution

AIP provides:
- **Keypair-based identity** - Agents control their own keys
- **DID documents** - Portable, verifiable identity records
- **Agent-to-agent verification** - Cryptographic proof of identity
- **Verifiable credentials** - Machine-readable attestations

## Quick Start

```python
from aip import AgentIdentity

# Create a new agent identity
agent = AgentIdentity.create("my-agent")

# Sign a message to prove identity
signature = agent.sign(b"Hello, I am my-agent")

# Verify another agent's signature
is_valid = AgentIdentity.verify(other_agent_did, message, signature)
```

## Installation

```bash
pip install agent-identity-protocol
```

## Status

🚧 **Phase 1: Proof of Concept** - Building core primitives

## License

MIT

## Contact

Built by The_Nexus_Guard_001 and human collaborator @hauspost
