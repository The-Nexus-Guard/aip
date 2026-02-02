# Agent Identity Protocol (AIP)

**Cryptographic identity and trust for AI agents.**

## The Problem

Agents have no way to prove who they are *or* who to trust. Platforms control identity. API keys leak. Trust is implicit and fragile.

## The Solution

AIP provides two layers:

**Identity Layer** - "Is this the same agent?"
- Ed25519 keypair-based identity
- DID (Decentralized Identifier) for each agent
- Challenge-response verification
- Signed messages and payloads

**Trust Layer** - "Should I trust this agent?"
- Vouching: signed statements of trust between agents
- Trust scopes: general, code-signing, financial, etc.
- Trust paths: verifiable chains showing *how* you trust someone
- Revocation: withdraw trust when needed

## Key Properties

- **Decentralized** - No central registry needed
- **Verifiable** - All vouches are cryptographically signed
- **Local-first** - Each agent maintains their own trust view
- **Auditable** - Full "isnad chains" show trust provenance
- **Zero dependencies** - Pure Python implementation available

## Quick Start

### Identity

```python
from src.identity import AgentIdentity, VerificationChallenge

# Create agent identities
alice = AgentIdentity.create("alice")
bob = AgentIdentity.create("bob")

# Alice challenges Bob to prove his identity
challenge = VerificationChallenge.create_challenge()
response = VerificationChallenge.respond_to_challenge(bob, challenge)
is_bob = VerificationChallenge.verify_response(challenge, response)
# is_bob == True
```

### Trust

```python
from src.trust import TrustGraph, TrustLevel, TrustScope

# Each agent maintains their own trust graph
alice_trust = TrustGraph(alice)

# Alice vouches for Bob
vouch = alice_trust.vouch_for(
    bob,
    scope=TrustScope.CODE_SIGNING,
    level=TrustLevel.STRONG,
    statement="Bob writes secure code"
)

# Later: check if Alice trusts someone
trusted, path = alice_trust.check_trust(target_did, TrustScope.CODE_SIGNING)

if trusted:
    print(f"Trust level: {path.trust_level.name}")
    print(f"Path length: {path.length} hops")
    # Full isnad chain available in path.path
```

### Trust Paths (Isnad Chains)

When Alice trusts Bob, and Bob trusts Carol, Alice can find a trust path to Carol:

```
Alice → Bob → Carol
  ↑       ↑
  |       └── "Bob vouches for Carol for code-signing"
  └── "Alice vouches for Bob for general trust"
```

Each link is cryptographically signed and verifiable.

## Demos

```bash
# Identity verification demo
python3 examples/multi_agent_workflow.py

# Full trust network demo
python3 examples/trust_network_demo.py
```

## Installation

```bash
# Clone the repo
git clone https://github.com/The-Nexus-Guard/aip.git
cd aip

# No external dependencies required (uses pure Python Ed25519)
# Optional: install PyNaCl for better performance
pip install pynacl
```

## Status

🚀 **v0.2.0** - Identity + Trust layers implemented

- [x] Ed25519 identity (pure Python + PyNaCl backends)
- [x] DID document generation
- [x] Challenge-response verification
- [x] Trust graphs with vouching
- [x] Trust path discovery (isnad chains)
- [x] Trust revocation
- [ ] Trust gossip protocol
- [ ] Reputation scoring

## Architecture

```
┌─────────────────────────────────────────────┐
│              Application Layer               │
│    (Moltbook, DeFi agents, multi-agent)     │
├─────────────────────────────────────────────┤
│              Trust Layer (NEW)               │
│  Vouching • Trust Paths • Revocation        │
├─────────────────────────────────────────────┤
│              Identity Layer                  │
│  Ed25519 • DIDs • Challenge-Response        │
└─────────────────────────────────────────────┘
```

## Why Both Layers?

**Identity alone** tells you "this is the same agent I talked to before."

**Trust** tells you "this agent is worth talking to."

Cryptographic identity is necessary but not sufficient. You need to know not just *who* someone is, but whether they're trustworthy. AIP provides both.

## License

MIT

## Contact

Built by The_Nexus_Guard_001 (agent) and @hauspost (human)

GitHub: https://github.com/The-Nexus-Guard/aip
