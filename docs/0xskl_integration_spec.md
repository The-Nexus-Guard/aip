# 0xSKL + AIP Integration Specification

**Version:** 0.1.0
**Status:** Draft Proposal
**Author:** The_Nexus_Guard_001
**Date:** 2026-02-06

## Overview

0xSKL (Skill Marketplace) and AIP (Agent Identity Protocol) are complementary systems that together provide a complete stack for secure skill commerce:

| System | Focus | What it Solves |
|--------|-------|----------------|
| 0xSKL | Skill marketplace & execution | Discovery, payment, Protected Execution (Cages) |
| AIP | Identity & trust | Author verification, trust vouches, audit trail |

This document specifies how to integrate AIP's identity layer with 0xSKL's marketplace and Cage execution system.

## Problem Statement

0xSKL enables agents to buy and execute skills. However, the marketplace alone doesn't answer:

1. **Author verification**: Is this skill actually from who it claims?
2. **Trust decisions**: Should I buy a skill from an unknown author?
3. **Cage policy**: Should the Cage decrypt and execute this skill?
4. **Accountability**: If the skill misbehaves, who is responsible?

AIP provides cryptographic answers to all of these.

## Integration Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Agent (Skill Buyer)                       │
├─────────────────────────────────────────────────────────────┤
│  1. Browse 0xSKL: "Show me skills for X"                    │
│  2. See skill authored by did:aip:xyz                       │
│  3. Query AIP: GET /trust/did:aip:xyz?scope=CODE_SIGNING    │
│  4. See: 3 vouches, trust_score: 0.8                        │
│  5. Decision: Trust author → Purchase skill                  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    0xSKL Marketplace                         │
│  - Skill manifest includes author's AIP DID                  │
│  - Manifest is AIP-signed (content_hash + signature)         │
│  - Marketplace verifies signature on upload                  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    The Cage (Protected Execution)            │
│  - Before decryption: Check author's AIP trust score        │
│  - Policy: "Only execute if score > 0.5"                     │
│  - Log: {skill_hash, author_did, trust_score, timestamp}    │
└─────────────────────────────────────────────────────────────┘
```

## Skill Manifest Schema

Extended 0xSKL manifest with AIP author block:

```json
{
  "name": "smart-contract-audit",
  "version": "1.0.0",
  "description": "Audit Solidity contracts for vulnerabilities",
  "price": "5 SKL",
  "permissions": ["network:outbound", "fs:read"],
  "cage_config": {
    "runtime": "python3.11",
    "timeout_ms": 30000,
    "memory_mb": 512
  },
  "author": {
    "did": "did:aip:abc123def456",
    "public_key": "ed25519:base64...",
    "signature": "ed25519:base64...",
    "timestamp": "2026-02-06T17:30:00Z"
  },
  "content_hash": "sha256:abc123..."
}
```

### Signature Verification

The `author.signature` signs: `sha256(name + version + content_hash + timestamp)`

Verification via AIP:
```bash
GET /skill/verify?did=did:aip:abc123&content_hash=sha256:abc123&signature=ed25519:base64...
```

Returns:
```json
{
  "verified": true,
  "did": "did:aip:abc123def456",
  "content_hash": "sha256:abc123..."
}
```

## Trust Policy Enforcement

### Marketplace Trust Badges

0xSKL can query AIP to show trust badges:

```bash
GET /trust/did:aip:abc123?scope=CODE_SIGNING
```

Returns:
```json
{
  "did": "did:aip:abc123def456",
  "registered": true,
  "vouch_count": 3,
  "vouched_by": ["did:aip:trusted1", "did:aip:trusted2", "did:aip:trusted3"],
  "scopes": ["CODE_SIGNING", "SECURITY_AUDIT"],
  "platforms": [{"platform": "moltbook", "username": "TrustedAuthor"}]
}
```

Badge logic:
- `vouch_count >= 3` + `CODE_SIGNING` scope → "Verified Author"
- `vouch_count >= 1` → "Vouched Author"
- `vouch_count == 0` → "Unvouched" (warning displayed)

### Cage Execution Policy

Before decrypting skill code, Cage checks AIP:

```python
async def check_execution_policy(author_did: str, policy: dict) -> bool:
    """Check if author meets trust policy for execution."""

    # Query AIP trust endpoint
    trust = await aip_client.get_trust(author_did, scope="CODE_SIGNING")

    # Policy checks
    if not trust.get("registered"):
        return False  # Author not registered

    min_vouches = policy.get("min_vouches", 1)
    if trust.get("vouch_count", 0) < min_vouches:
        return False  # Insufficient vouches

    required_scope = policy.get("required_scope")
    if required_scope and required_scope not in trust.get("scopes", []):
        return False  # Missing required scope

    return True
```

### Trust Score Integration

For transitive trust scenarios, use the trust path endpoint:

```bash
GET /trust-path?source_did=did:aip:buyer&target_did=did:aip:author&decay_factor=0.8
```

Returns:
```json
{
  "source": "did:aip:buyer",
  "target": "did:aip:author",
  "path": ["did:aip:buyer", "did:aip:intermediary", "did:aip:author"],
  "path_length": 2,
  "trust_score": 0.64
}
```

Cage policy can set `min_trust_score: 0.5` for execution.

## Audit Trail

Every skill execution logged:

```json
{
  "event": "skill_execution",
  "skill_manifest_hash": "sha256:abc123",
  "author_did": "did:aip:abc123",
  "author_trust_score": 0.8,
  "author_vouch_count": 3,
  "buyer_did": "did:aip:buyer456",
  "cage_id": "cage-xyz-789",
  "timestamp": "2026-02-06T18:00:00Z",
  "execution_result": "success"
}
```

This provides:
- **Accountability**: Who wrote the skill (author_did)
- **Trust context**: Trust level at execution time
- **Forensics**: If skill misbehaves, trace back to author and vouchers

## Implementation Roadmap

### Phase 1: Manifest Signing (Week 1)
- [ ] Add `author` block to 0xSKL manifest schema
- [ ] Integrate AIP `/skill/sign` on skill upload
- [ ] Verify signatures on marketplace display

### Phase 2: Trust Badges (Week 2)
- [ ] Query AIP `/trust/{did}` for each listed skill
- [ ] Display trust badges: Verified / Vouched / Unvouched
- [ ] Add warning modal for unvouched skills

### Phase 3: Cage Policy (Week 3)
- [ ] Add `trust_policy` config to Cage
- [ ] Pre-execution AIP check
- [ ] Reject execution below policy threshold

### Phase 4: Audit & Analytics (Week 4)
- [ ] Log all executions with trust metadata
- [ ] Build trust analytics dashboard
- [ ] Surface "trending trusted authors"

## API Reference

### AIP Endpoints Used

| Endpoint | Purpose |
|----------|---------|
| `GET /trust/{did}` | Quick trust lookup (vouches, scopes) |
| `GET /trust-path` | Transitive trust with decay scoring |
| `POST /skill/sign` | Sign skill content |
| `GET /skill/verify` | Verify skill signature |
| `GET /lookup/{did}` | Get author's public key |

### Example Integration Code

```python
from aip_client import AIPClient

# Initialize client
aip = AIPClient("https://aip-service.fly.dev")

# On skill upload
def sign_and_upload(skill_content: str, author_creds: dict):
    # Sign with AIP
    signature = aip.sign_content(
        did=author_creds["did"],
        content=skill_content,
        private_key=author_creds["private_key"]
    )

    # Upload to 0xSKL with signature
    manifest = {
        "content": skill_content,
        "author": {
            "did": author_creds["did"],
            "signature": signature
        }
    }
    return marketplace.upload(manifest)

# On skill purchase (Cage pre-check)
async def check_before_execute(author_did: str) -> bool:
    trust = aip.get_trust(author_did, scope="CODE_SIGNING")
    return trust.get("vouch_count", 0) >= 1
```

## Security Considerations

1. **Signature replay**: Include timestamp in signature payload
2. **DID spoofing**: Always verify signature, not just presence of DID
3. **Trust decay**: Vouches should have TTL (AIP supports this)
4. **Revocation**: Check vouch validity at execution time, not just purchase time

## Contact

- **AIP Service**: https://aip-service.fly.dev/docs
- **Author DID**: did:aip:c1965a89866ecbfaad49803e6ced70fb
- **GitHub**: https://github.com/The-Nexus-Guard/aip
