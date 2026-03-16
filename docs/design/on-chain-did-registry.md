# On-Chain DID Registry: Technical Brief

*What AIP needs from an on-chain persistence layer*

## Context

AIP DIDs are currently server-anchored — registered against the AIP service at `aip-service.fly.dev`. APS DIDs live in the AEOESS network. Neither has immutable on-chain anchoring. This document specifies what an on-chain DID registry would need to support for both protocols.

## Goals

1. **Decouple identity from any single service** — if AIP goes down, DIDs still resolve on-chain
2. **Enable cross-protocol trust paths** — vouches between AIP and APS agents anchored alongside registrations
3. **Give agents portable identity** — move between protocols without re-registering
4. **Minimize on-chain cost** — store only what needs to be immutable

## DID Document Structure

An on-chain DID document needs to support:

```json
{
  "id": "did:aip:1af060d6e522d6304074f418888f0e7b",
  "controller": "did:aip:1af060d6e522d6304074f418888f0e7b",
  "verificationMethod": [{
    "id": "did:aip:1af060d6e522d6304074f418888f0e7b#key-1",
    "type": "Ed25519VerificationKey2020",
    "controller": "did:aip:1af060d6e522d6304074f418888f0e7b",
    "publicKeyMultibase": "z6Mk..."
  }],
  "authentication": ["did:aip:1af060d6e522d6304074f418888f0e7b#key-1"],
  "alsoKnownAs": [
    "did:key:z6Mk...",
    "did:aps:abc123..."
  ],
  "service": [{
    "id": "did:aip:1af060d6e522d6304074f418888f0e7b#aip-service",
    "type": "AIPService",
    "serviceEndpoint": "https://aip-service.fly.dev"
  }]
}
```

### Required Fields
- `id` — the DID itself
- `verificationMethod` — Ed25519 public key (both AIP and APS use Ed25519)
- `authentication` — which keys can authenticate
- `alsoKnownAs` — cross-protocol DID aliases (critical for bridging)

### Optional Fields
- `service` — service endpoints (API URLs, messaging endpoints)
- `controller` — delegation support (who can update this document)
- `created` / `updated` — timestamps

## Key Operations

### 1. Register
- Input: DID + public key + optional metadata
- On-chain: store DID document hash + public key
- Off-chain: full DID document on IPFS or similar
- Authorization: signed by the DID's key

### 2. Key Rotation
- Critical for long-lived agent identities
- Input: old key signature + new key
- Must maintain a key history (old keys marked as revoked with timestamp)
- The registry must support a `versionId` for each update

```
rotate(did, newPublicKey, signature_by_old_key, nonce)
```

### 3. Revocation
- Mark a DID as deactivated
- Must be signed by the controller
- Irreversible (a deactivated DID cannot be reactivated)
- Use case: compromised key, agent decomissioned

### 4. Resolve
- Input: DID string
- Output: current DID document (or hash + pointer)
- Must support: `versionId` (get historical state), `versionTime` (get state at timestamp)

### 5. Cross-Protocol Linking
- Bidirectional: AIP DID claims `alsoKnownAs: did:aps:X`, and vice versa
- Verification: both sides must sign the link claim
- On-chain: store the link as a separate attestation, signed by both parties

```
link(did_a, did_b, signature_a, signature_b, nonce)
```

## What Stays On-Chain vs Off-Chain

### On-Chain (immutable, minimal)
- DID → public key mapping
- Key rotation history
- Revocation status
- Cross-protocol link attestations
- Vouch attestations (hash only, not full vouch content)

### Off-Chain (IPFS / service endpoints)
- Full DID documents
- Profile metadata (name, description)
- Vouch content and context
- PDR observations

## Vouch Anchoring

Vouches are trust assertions. On-chain anchoring makes them tamper-evident.

```
anchor_vouch(
  voucher_did,
  vouchee_did,
  vouch_hash,       // SHA-256 of the full vouch document
  voucher_signature,
  timestamp
)
```

The full vouch document lives off-chain (AIP service, IPFS). The on-chain record proves:
1. This vouch existed at this timestamp
2. The voucher's key signed it
3. The vouch content hasn't been modified (hash verification)

## Chain Requirements

- **Low cost** — agent registrations should cost < $0.01
- **Fast finality** — agents need identity in seconds, not minutes
- **Programmable** — smart contract for registry logic
- **Decentralized enough** — not a single company's chain
- **Active ecosystem** — existing DID tooling helps

Candidates: Ethereum L2s (Base, Arbitrum, Optimism), Solana, Polygon, Stacks (Bitcoin L2)

## Integration with AIP

### Phase 1: Optional Anchoring
- AIP continues to work server-side as today
- New optional `aip anchor` command publishes DID to chain
- On-chain record is a backup, not the primary

### Phase 2: Dual Resolution
- `aip resolve <did>` checks both AIP server and on-chain registry
- If server is down, falls back to on-chain
- Vouch verification can use on-chain anchored vouches

### Phase 3: Chain-Primary
- New registrations anchor on-chain first
- AIP server becomes a caching/indexing layer
- Full decentralization of identity

## Integration with APS (AEOESS)

The cross-protocol bridge we built (did:aps resolver in AIP, AIP card in AEOESS) currently goes through service APIs. On-chain anchoring would:

1. Make the bridge trust-minimized — verify cross-protocol links on-chain instead of trusting service APIs
2. Survive either service going down
3. Enable third-party verifiers who don't trust either service

## Open Questions

1. **Which chain?** Needs to be a joint decision between AIP, APS, and omar-web3
2. **Gas costs** — who pays? Could use a faucet for initial registrations
3. **Governance** — who controls the registry contract? Multi-sig between protocol teams?
4. **Privacy** — public key on-chain means all identities are public. OK for agents?
5. **Upgrade path** — how to migrate if we pick the wrong chain?

## Next Steps

1. Share this brief with omar-web3 (via AEOESS intro)
2. Get feedback on chain selection and registry contract design
3. Prototype a minimal registry on a testnet
4. Define the cross-protocol link verification flow

---
*Draft: 2026-03-16. Prepared for discussion with AEOESS and omar-web3.*
