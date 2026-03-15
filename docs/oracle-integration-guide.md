# AIP Oracle Integration Guide
*On-chain credential verification via InsumerAPI*

## Overview

AIP's oracle system lets agents prove on-chain credentials (token balances, NFT ownership, KYC attestations) as part of their identity. Under the hood, [InsumerAPI](https://insumermodel.com) does the chain verification; AIP translates the result into a **vouch** in the trust graph.

Result: an agent's trust profile can include both social trust (who vouched for them) and economic trust (what's verifiable on-chain), in a single unified graph.

## Quick Start

### Prerequisites

- An AIP identity (`pip install aip-identity && aip register`)
- An EVM wallet address you control
- AIP service running with InsumerAPI key configured

### Step 1: Bind Your Wallet

Link your wallet address to your AIP identity. This is a one-time operation.

```bash
# Generate the binding signature
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
WALLET="0xYourWalletAddress"

# Sign the binding message with your AIP identity
aip sign "bind:${WALLET}:${TIMESTAMP}"
```

Then POST the binding:

```bash
curl -X POST https://aip-service.fly.dev/oracle/wallet/bind \
  -H "Content-Type: application/json" \
  -d '{
    "did": "did:aip:your_did_here",
    "wallet_address": "0xYourWalletAddress",
    "chain_type": "evm",
    "did_signature": "<signature_from_aip_sign>",
    "timestamp": "2026-03-04T20:00:00Z"
  }'
```

Response:
```json
{
  "success": true,
  "message": "Wallet bound to DID successfully",
  "did": "did:aip:your_did_here",
  "wallet_address": "0xYourWalletAddress",
  "chain_type": "evm"
}
```

### Step 2: Verify On-Chain Conditions

Request verification of specific conditions against your bound wallet.

**Token balance check:**
```bash
curl -X POST https://aip-service.fly.dev/oracle/verify/onchain \
  -H "Content-Type: application/json" \
  -d '{
    "did": "did:aip:your_did_here",
    "conditions": [{
      "type": "token_balance",
      "contractAddress": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
      "chainId": 1,
      "threshold": 1,
      "decimals": 6,
      "label": "USDC >= 1 on Ethereum"
    }]
  }'
```

**Coinbase KYC check** (requires Coinbase-verified wallet on Base):
```bash
curl -X POST https://aip-service.fly.dev/oracle/verify/onchain \
  -H "Content-Type: application/json" \
  -d '{
    "did": "did:aip:your_did_here",
    "conditions": [{
      "type": "eas_attestation",
      "template": "coinbase_verified_account",
      "label": "Coinbase KYC verified"
    }]
  }'
```

Note: Template conditions (like `coinbase_verified_account`) imply the chain — don't include `chain_id`.

**Response (conditions met):**
```json
{
  "ok": true,
  "data": {
    "attestation": {
      "did": "did:aip:your_did_here",
      "wallet_address": "0xYour...Wallet",
      "attestation_id": "att_abc123",
      "pass": true,
      "results": [
        {
          "type": "token_balance",
          "label": "USDC >= 1 on Ethereum",
          "met": true,
          "conditionHash": "sha256:a1b2c3...",
          "blockNumber": 19876543,
          "blockTimestamp": "2026-03-04T20:00:00Z"
        }
      ]
    },
    "sig": "MEUCIQD...",
    "kid": "insumer-attest-v1"
  },
  "meta": {
    "vouch_id": "oracle-a1b2c3d4e5f6",
    "expires_at": "2026-03-04T20:30:00Z"
  }
}
```

Note on the response:
- **Top-level `pass`** indicates whether all conditions passed.
- **Per-result `met`** (not `pass`) indicates whether each individual condition was satisfied.
- **`conditionHash`** is a SHA-256 hash per condition for tamper detection — verifiers can confirm the condition wasn't modified in transit.
- **`sig` and `kid`** are InsumerAPI's ECDSA signature and key ID, enabling independent verification via their JWKS endpoint.

When conditions pass, the oracle automatically creates a vouch from the credential oracle identity (`did:aip:insumer-oracle`). This vouch appears in the agent's trust graph alongside social vouches.

### Step 3: Verify the Oracle Independently

The oracle doesn't re-sign the attestation — it passes through InsumerAPI's ECDSA signature. Any verifier can check the signature against InsumerAPI's [JWKS endpoint](https://api.insumermodel.com/v1/jwks) independently using the `sig` and `kid` fields from the response. The oracle translates format; it doesn't add trust it hasn't verified.

## Condition Types

| Type | Fields | Notes |
|------|--------|-------|
| `token_balance` | `contractAddress`, `chainId`, `threshold`, `decimals`, `label` | ERC-20 balance check |
| `nft_ownership` | `contractAddress`, `chainId`, `label` | ERC-721/1155 ownership |
| `eas_attestation` | `template`, `label` | Named templates (see below). Chain is implied by template — omit `chainId`. |
| `farcaster_id` | `label` | Standalone Farcaster identity check. No chain or template needed. |

**EAS templates:** `coinbase_verified_account`, `coinbase_one`, `gitcoin_passport_active`, `worldcoin_verified`, `ens_primary`

## How It Fits in the Trust Graph

```
Agent A
├── Social trust
│   ├── Vouch from Agent B (scope: "collaboration")
│   └── Vouch from Agent C (scope: "code review")
└── Economic trust
    ├── Oracle vouch: "USDC >= 1 on Ethereum" (expires 30 min)
    └── Oracle vouch: "Coinbase KYC verified" (expires 30 min)
```

Consuming agents can weight these signals differently. A DeFi agent might care heavily about economic trust. A code review agent might only look at social vouches. The graph is unified; the interpretation is per-consumer.

## Caching & Expiry

- InsumerAPI attestations expire after 30 minutes
- AIP caches results for 25 minutes (stale-while-revalidate)
- Oracle vouches have a 1-day TTL (minimum granularity), but the cached attestation expires sooner
- Re-verification is automatic on the next `/verify/onchain` call after cache expiry

## Wallet Management

**List bound wallets:**
```bash
curl https://aip-service.fly.dev/oracle/wallet/did:aip:your_did_here
```

**Unbind a wallet:**
```bash
curl -X DELETE "https://aip-service.fly.dev/oracle/wallet/bind?did=did:aip:your_did_here&wallet_address=0xYour..."
```

**View cached attestations:**
```bash
curl https://aip-service.fly.dev/oracle/attestations/did:aip:your_did_here
```

## Privacy Model

- **Wallet bindings are opt-in.** No agent is required to link a wallet.
- **InsumerAPI returns booleans, not raw balances.** A "USDC >= 1" check returns pass/fail, not "you have $47,293."
- **Agents choose what to expose.** The conditions in the vouch statement are what the agent chose to verify — nothing more.
- **Wallet can be partially hidden.** The vouch statement shows a truncated address (`0x1234...abcd`). Full address is in the binding record but not in the public trust graph.

## Design Decisions

- **Persist-until-revoked wallet bindings.** Wallet ownership doesn't expire. Re-binding friction isn't worth it.
- **25-minute cache TTL.** Conservative against InsumerAPI's 30-minute attestation expiry.
- **Single-signer only (Phase 1).** Multi-sig wallets need a threshold-of-signers binding scheme — future work.
- **Attestation-as-vouch.** Oracle results are stored as vouches, not a separate data structure. Keeps the trust graph unified and queryable through existing AIP APIs.

## Endpoints Summary

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/oracle/wallet/bind` | POST | Bind wallet to DID |
| `/oracle/wallet/bind` | DELETE | Unbind wallet from DID |
| `/oracle/wallet/{did}` | GET | List wallet bindings |
| `/oracle/verify/onchain` | POST | Verify on-chain conditions |
| `/oracle/attestations/{did}` | GET | View cached attestations |

## Further Reading

- [InsumerAPI docs](https://insumermodel.com)
- [AIP identity protocol](https://the-nexus-guard.github.io/aip/)
- [Trust graph visualization](https://the-nexus-guard.github.io/aip/trust-graph.html)
- [Integration design doc](./insumer-integration-design.md)
