# AIP × InsumerAPI Integration Design
*Draft: 2026-03-03*

## Overview

Adds on-chain credential verification as a fourth trust signal in AIP, using InsumerAPI as the verification oracle. Implements "attestation-as-vouch" — InsumerAPI results are stored as vouches from a credential oracle identity, keeping the trust graph unified.

## Architecture

```
Agent A (did:aip:abc)
  │
  ├── Identity: Ed25519 keypair ✓
  ├── Social trust: 3 vouches, score 0.85 ✓
  ├── Communication: E2E encrypted ✓
  └── Economic trust: NEW
       ├── Wallet binding: 0x1234...abcd → did:aip:abc
       ├── Attestation: holds ≥100 UNI on Ethereum ✓
       └── Attestation: Coinbase KYC verified ✓
```

## Components

### 1. Wallet-DID Binding (`/wallet/bind`)

New endpoint. Agent proves ownership of both identities:

```
POST /wallet/bind
{
  "did": "did:aip:abc",
  "wallet_address": "0x1234...abcd",
  "chain_type": "evm",  // or "solana", "xrpl"
  "did_signature": "<Ed25519 sig of 'bind:{wallet}:{timestamp}'>",
  "wallet_signature": "<ECDSA/Ed25519 sig of 'bind:{did}:{timestamp}'>"
}
```

Server verifies both signatures, stores the binding. One DID can bind multiple wallets. Binding is revocable.

### 2. Credential Oracle Identity

A service-managed DID (`did:aip:<insumer-oracle>`) that issues vouches based on InsumerAPI results. This is NOT a human voucher — it's a cryptographic attestation backed by on-chain state.

Vouch metadata includes:
- `type`: "onchain_credential"
- `oracle`: "insumerapi"
- `attestation`: the signed InsumerAPI response
- `conditions_met`: boolean array
- `block_number`: chain state reference
- `expires_at`: InsumerAPI expiry (30 min default)

### 3. Verify Endpoint (`/verify/onchain`)

```
POST /verify/onchain
{
  "did": "did:aip:abc",
  "conditions": [
    {"type": "token_balance", "contractAddress": "0xA0b8...", "chainId": 1, "threshold": 100, "decimals": 18},
    {"type": "eas_attestation", "template": "coinbase_verified_account", "chainId": 8453}
  ]
}
```

Response: combined AIP identity + InsumerAPI attestation, with the oracle vouch auto-created.

### 4. Trust Score Extension

Current trust score formula: `social_trust = f(vouches, decay, path_length)`

Extended: `composite_trust = w1 * social_trust + w2 * economic_trust`

Where `economic_trust` = f(attestations met, attestation freshness, oracle signature validity)

Weights configurable per consuming agent — some care more about social trust, others about on-chain state.

## Data Model

```sql
-- Wallet bindings
CREATE TABLE wallet_bindings (
    did TEXT NOT NULL,
    wallet_address TEXT NOT NULL,
    chain_type TEXT NOT NULL,  -- evm, solana, xrpl
    bound_at TEXT NOT NULL,
    revoked_at TEXT,
    PRIMARY KEY (did, wallet_address)
);

-- Cached attestations (InsumerAPI results are ephemeral)
CREATE TABLE onchain_attestations (
    did TEXT NOT NULL,
    wallet_address TEXT NOT NULL,
    conditions_hash TEXT NOT NULL,  -- SHA-256 of canonical conditions
    result BOOLEAN NOT NULL,
    insumer_signature TEXT NOT NULL,
    insumer_kid TEXT NOT NULL,
    block_number TEXT,
    queried_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    PRIMARY KEY (did, conditions_hash)
);
```

## Privacy

- Wallet bindings are opt-in per agent
- InsumerAPI returns booleans, never raw balances
- Agents choose which conditions to expose in the trust graph
- Wallet addresses can be hidden behind the oracle vouch (verifier sees "has Coinbase KYC" without seeing the wallet)

## Implementation Phases

1. **Phase 1:** Wallet-DID binding + `/verify/onchain` endpoint (uses InsumerAPI `/v1/attest`)
2. **Phase 2:** Auto-vouch from credential oracle + trust score integration
3. **Phase 3:** MCP server `onchain_verify` tool + `aip verify --onchain` CLI command

## Open Questions

- Should wallet bindings expire? Or persist until revoked?
- InsumerAPI attestation TTL is 30 min — should we cache longer and re-verify lazily?
- How to handle multi-sig wallets (no single ECDSA signer)?
