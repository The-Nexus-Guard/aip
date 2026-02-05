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

## Live Service

**API:** https://aip-service.fly.dev
**Docs:** https://aip-service.fly.dev/docs
**Landing:** https://the-nexus-guard.github.io/aip/

## Status

🚀 **v0.3.0** - Identity + Trust + Skill Signing

- [x] Ed25519 identity (pure Python + PyNaCl + cryptography backends)
- [x] DID document generation
- [x] Challenge-response verification
- [x] Trust graphs with vouching
- [x] Trust path discovery (isnad chains)
- [x] Trust revocation
- [x] **Skill signing** - Sign skill.md files with your DID
- [x] **CODE_SIGNING vouches** - Trust chains for code provenance
- [x] **MCP integration** - Add AIP to Model Context Protocol
- [ ] Trust gossip protocol
- [ ] Reputation scoring

## Skill Signing (NEW in v0.3.0)

Sign your skills with cryptographic proof of authorship:

```bash
# Using the CLI
./cli/aip skill-sign my_skill.md

# Verify a signed skill
./cli/aip skill-verify my_skill.md
```

Or via the API:

```bash
# Hash content
curl -X POST "https://aip-service.fly.dev/skill/hash?skill_content=..."

# Verify signature
curl "https://aip-service.fly.dev/skill/verify?content_hash=...&author_did=...&signature=...&timestamp=..."
```

See [docs/skill_signing_tutorial.md](docs/skill_signing_tutorial.md) for the full guide.

## Architecture

```
┌─────────────────────────────────────────────┐
│              Application Layer               │
│    (Moltbook, MCP, DeFi agents, skills)     │
├─────────────────────────────────────────────┤
│            Skill Signing Layer               │
│  Signed Skills • CODE_SIGNING Vouches       │
├─────────────────────────────────────────────┤
│              Trust Layer                     │
│  Vouching • Trust Paths • Revocation        │
├─────────────────────────────────────────────┤
│              Identity Layer                  │
│  Ed25519 • DIDs • Challenge-Response        │
└─────────────────────────────────────────────┘
```

## MCP Integration

AIP fills the "agent identity gap" in MCP (Model Context Protocol):

```python
# Sign MCP requests with AIP
headers = {
    "X-AIP-DID": agent_did,
    "X-AIP-Timestamp": timestamp,
    "X-AIP-Signature": signature
}
mcp_client.request(url, headers=headers)
```

See [docs/mcp_integration_guide.md](docs/mcp_integration_guide.md) for full details.

## Why Both Layers?

**Identity alone** tells you "this is the same agent I talked to before."

**Trust** tells you "this agent is worth talking to."

Cryptographic identity is necessary but not sufficient. You need to know not just *who* someone is, but whether they're trustworthy. AIP provides both.

## Documentation

- [Skill Signing Spec](docs/skill_signing_spec.md) - Full specification
- [Skill Signing Tutorial](docs/skill_signing_tutorial.md) - Step-by-step guide
- [MCP Integration Guide](docs/mcp_integration_guide.md) - Add AIP to MCP

## License

MIT

## Contact

Built by The_Nexus_Guard_001 (agent) and @hauspost (human)

- GitHub: https://github.com/The-Nexus-Guard/aip
- DID: did:aip:c1965a89866ecbfaad49803e6ced70fb
