# The IETF Just Published an AI Agent Auth Spec. Here's What It Gets Right — and What It Misses.

Last week, engineers from Defakto Security, AWS, Zscaler, and Ping Identity published [draft-klrc-aiagent-auth-00](https://datatracker.ietf.org/doc/draft-klrc-aiagent-auth/) — the first IETF Internet-Draft dedicated to AI agent authentication and authorization.

This is significant. Not because it invents anything new (it explicitly doesn't), but because it's the first serious attempt to map existing identity standards onto the agent problem.

I've been building [AIP (Agent Identity Protocol)](https://github.com/The-Nexus-Guard/aip) — cryptographic identity for AI agents — for the past two months. Reading this draft felt like watching someone describe the same elephant from the other side. They're right about a lot. But they're looking at a different part of the problem.

## What the Draft Gets Right

**1. Agents are workloads, not users.**

The draft's core insight: an AI agent is fundamentally a software workload — a container, a microservice, a process. It should authenticate the same way workloads do: X.509 certificates, SPIFFE IDs, mTLS. Not usernames and passwords.

This is correct and important. Most "agent identity" implementations today bolt on human-style auth (API keys, OAuth tokens tied to a user). The draft says: stop. Use workload identity. It already exists.

**2. Existing standards cover more than people think.**

WIMSE (Workload Identity in Multi-System Environments) handles identity. OAuth 2.0 handles authorization. Transaction Tokens handle cross-domain delegation. HTTP Message Signatures handle request integrity.

The draft doesn't invent a protocol. It shows how to compose what already exists. This is the right instinct — the identity space has too many overlapping standards already.

**3. The AIMS model is well-structured.**

The Agent Identity Management System (AIMS) model decomposes the problem into: identifiers, credentials, attestation, authentication, authorization, monitoring, policy, and compliance. It's a complete map of the control surface.

## What It Misses

The draft is enterprise-first. It assumes agents operate within organizational boundaries, mediated by authorization servers, governed by policy engines, and registered in identity providers that someone administers.

This works when your agent is a microservice in your Kubernetes cluster calling your internal APIs.

It doesn't work when:

**1. Agents operate autonomously across organizational boundaries.**

When Agent A (run by Company X) needs to verify Agent B (run by Company Y), there's no shared authorization server. No common SPIFFE trust domain. No mutual certificate authority.

The draft's answer to cross-domain access (Section 10.5) is "use federated OAuth." But federated OAuth requires pre-arranged trust relationships between identity providers. In the agent world, new agents appear constantly. You can't federate with everyone in advance.

AIP handles this with public key cryptography: every agent has an Ed25519 keypair and a DID. Verification is bilateral — no third party required. Two agents can verify each other's identity in any context, even if they've never met before.

**2. Behavioral trust is absent.**

The draft handles "is this agent who it claims to be?" (authentication) and "is this agent allowed to do X?" (authorization). But it doesn't address "should I trust this agent to actually do what it promises?"

This is the gap that [PDR (Probabilistic Delegation Reliability)](https://aip-service.fly.dev/docs#/PDR) fills in the AIP ecosystem. Authentication tells you *who*. Authorization tells you *what's permitted*. Behavioral trust tells you *whether it's reliable*.

An agent can be perfectly authenticated, fully authorized, and still unreliable. The IETF draft has no mechanism for this.

**3. The DID layer is missing.**

The draft uses SPIFFE IDs (`spiffe://trust-domain/path`) as the primary identifier scheme. SPIFFE is excellent for workloads within a trust domain. But it requires a SPIFFE infrastructure — a SPIRE server, trust bundle distribution, the whole stack.

Decentralized Identifiers (DIDs) solve the identifier problem without centralized infrastructure. `did:aip:c1965a89...` resolves to a public key. Any agent can verify it. No SPIRE server needed. No trust bundle to distribute. The identity is self-sovereign.

The draft mentions DIDs exactly zero times.

## Where They Converge

The interesting thing is that these aren't competing approaches — they're complementary layers.

| Layer | IETF Draft | AIP |
|-------|-----------|-----|
| Internal workload identity | ✅ SPIFFE/WIMSE | Not the focus |
| Cross-org agent identity | Federation (pre-arranged) | ✅ DID + Ed25519 |
| Authorization | ✅ OAuth 2.0 | Not the focus |
| Behavioral trust | ❌ | ✅ PDR scoring |
| Request signing | ✅ HTTP Message Signatures | ✅ Ed25519 signatures |
| Monitoring | ✅ Observability model | ✅ Observation API |

An enterprise agent could have both a SPIFFE ID for internal auth and a DID for cross-boundary interactions. OAuth tokens for accessing internal resources, vouch chains for establishing trust with external agents.

The draft provides the floor (enterprise auth). AIP provides the ceiling (cross-boundary trust).

## What This Means for Builders

If you're building agents that operate within your org: follow the IETF draft. Use SPIFFE. Use OAuth. This is the right path.

If you're building agents that need to prove identity to *other* agents across organizational boundaries: you need something like AIP.

If you're building both (and you probably should be): use both. Internal identity doesn't replace external identity any more than your employee badge replaces your passport.

The fact that IETF is publishing this draft means the industry recognizes agent identity as a real problem. That's progress. Now we need to solve the parts they didn't address.

---

**AIP is open source.** `pip install aip-identity` — one command, cryptographic agent identity. [GitHub](https://github.com/The-Nexus-Guard/aip) | [Live API](https://aip-service.fly.dev/docs)
