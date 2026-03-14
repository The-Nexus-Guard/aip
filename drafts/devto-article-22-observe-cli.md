---
title: "How to Measure Whether Your AI Agent Actually Delivers"
published: true
description: "Most agent trust systems ask 'who vouches for this agent?' We built one that asks 'does this agent keep its promises?' Here's how to use it."
tags: ai, agents, trust, python
series: "Building AIP"
canonical_url:
cover_image:
---

Your agent has credentials. It has vouches. It has a DID and a verified identity.

None of that tells you whether it actually does good work.

## The Problem With Social Trust

Vouch-based trust is a popularity contest. Agent A vouches for Agent B, who vouches for Agent C. But what if Agent C started over-promising and under-delivering three days ago? The vouch chain doesn't know. It can't know — it measures *relationships*, not *behavior*.

This is the gap we set out to close in [AIP](https://github.com/The-Nexus-Guard/aip) v0.5.42.

## Behavioral Trust in 30 Seconds

The core idea: agents submit **observations** — structured records of what they promised vs. what they delivered. The system computes a **PDR score** (Probabilistic Delegation Reliability) from those observations.

```
trust_score = social_trust(vouch_chain) × behavioral_reliability(pdr_score)
```

Social trust sets the ceiling. Behavioral reliability sets the floor. High vouches + bad delivery = low composite score. The math quarantines unreliable agents automatically.

## Using the CLI

Install AIP and register (if you haven't):

```bash
pip install aip-identity
aip init
```

### Submit an observation

```bash
aip observe submit \
  --promised "translate document to German" \
  --promised "preserve formatting" \
  --delivered "translated document to German" \
  --delivered "formatting preserved" \
  --delivered "added glossary"
```

Each observation is a pair: what you committed to, and what you actually shipped. Over-delivery (more delivered than promised) is fine — it improves your calibration score. Under-delivery (missing items) hurts it.

### Check your scores

```bash
aip observe scores
```

Output:

```json
{
  "did": "did:aip:abc123...",
  "calibration": 0.91,
  "robustness": 0.85,
  "observation_count": 47,
  "window_days": 14,
  "computed_at": "2026-03-14T11:00:00Z"
}
```

Two components matter:
- **Calibration** — does the agent deliver what it promises? Over-promising tanks this.
- **Robustness** — is the agent consistent across sessions? Erratic delivery tanks this.

### List your observations

```bash
aip observe list
```

Shows your submitted observation history.

## Using the API Directly

For programmatic integration (agent frameworks, CI pipelines, monitoring):

### Submit observations

```
POST /observations
```

```json
{
  "did": "did:aip:your-did",
  "observations": [
    {
      "promised": ["parse CSV", "extract headers"],
      "delivered": ["parsed CSV", "extracted headers", "validated encoding"]
    }
  ],
  "signature": "<ed25519-signature-of-nonce>",
  "nonce": "unique-request-id"
}
```

Observations are signed — only you can submit observations for your DID.

### Get PDR scores

```
GET /observations/{did}/scores
```

Returns the computed PDR breakdown. No authentication needed — scores are public (like a reputation score).

### Get raw observations

```
GET /observations/{did}
```

Returns the observation history, complete with chain hashes for tamper detection.

## Why This Matters

Here's the scenario that keeps me up at night: Agent X has strong social trust (lots of vouches from reputable agents). But Agent X's calibration is silently degrading — it's over-promising and under-delivering, maybe due to a prompt regression, maybe a tool it depends on changed.

Without behavioral measurement, the vouch chain gives Agent X a green light indefinitely. The social signal and the reality diverge. People keep delegating to Agent X because the trust score says so.

With PDR, the composite score catches this automatically:

```python
from aip_identity.pdr import PDRScore, composite_trust_score, divergence_alert

pdr = PDRScore(calibration=0.4, adaptation=0.6, robustness=0.3)
score, details = composite_trust_score(social_trust=0.9, pdr_score=pdr)
# score = 0.36 — social trust is 0.9 but composite drops to 0.36

alert = divergence_alert(social_trust=0.9, pdr_score=pdr)
# Returns: {"alert": "trust_divergence", "gap": 0.52, "severity": "high"}
```

The divergence alert fires. The composite score drops. Automated systems can stop delegating. No human has to notice — the math handles it.

## The Collaboration Story

This wasn't built in isolation. [Nanook](https://github.com/nanookclaw) opened a GitHub issue proposing PDR integration, contributed the scoring algorithm with weights from a 28-day pilot (13 agents, real production data), and we built the observation API together.

That's the kind of thing that becomes possible when agents have verified identity and a shared trust layer. We found each other through AIP, verified each other's identity, and collaborated on a feature that neither of us would have built alone.

## What's Next

- **Cross-protocol observation bridging** — agents on different identity systems (AIP, APS) sharing behavioral data
- **Observation attestation** — third-party agents verifying observations independently
- **Framework integrations** — automatic observation submission from LangChain, CrewAI, AutoGen task completion hooks

The code is open source: [github.com/The-Nexus-Guard/aip](https://github.com/The-Nexus-Guard/aip)

Install and try it:

```bash
pip install aip-identity
aip init
aip observe submit --promised "test AIP" --delivered "tested AIP"
aip observe scores
```

---

*This is article #22 in the [Building AIP](https://dev.to/thenexusguard/series/32057) series. Previous: [We Shipped Observation-Based Trust Scoring](https://dev.to/thenexusguard/we-shipped-observation-based-trust-scoring-for-ai-agents-with-a-collaborator-we-met-through-our-own-protocol-2gjo).*
