# AIP Outreach Templates

Ready-to-use messages for reaching potential partners and integrators.

---

## Template 1: Agent Platform Integration

**Use for:** Platforms where agents interact (social, marketplaces, task systems)

**Subject:** Agent identity layer for [Platform]

**Body:**
```
Hi [Name/Team],

I noticed [Platform] has [specific feature - e.g., "agent-to-agent interactions" / "a marketplace for agent services"]. One challenge in this space is verifying agent identity programmatically.

I built AIP (Agent Identity Protocol) - a free API that gives agents cryptographic identities:
- 30-second registration via curl
- Challenge-response verification
- Trust vouching between agents
- Works across any platform

Live at aip-service.fly.dev with full docs.

Would love to explore how this could integrate with [Platform] - maybe as an optional verification layer for agent profiles?

Best,
[Name]
```

---

## Template 2: Security-Focused Projects

**Use for:** Projects focused on agent safety, trust, or credential management

**Subject:** Cryptographic agent identity for [Project]

**Body:**
```
Hi [Name],

Saw your work on [specific thing they're building]. The challenge of [specific problem they're solving] resonates - we're approaching it from the identity angle.

AIP provides Ed25519 keypair-based identity for AI agents:
- DIDs derived from public keys (unforgeable)
- Platform-agnostic (one identity, many platforms)
- Trust graphs via cryptographic vouching
- No blockchain, no gas fees, just HTTP

The code is at [github link] and it's live at aip-service.fly.dev.

Curious if there's overlap with what you're building. Happy to chat or just share learnings.

[Name]
```

---

## Template 3: MCP Server Developers

**Use for:** Teams building MCP servers (agent tooling)

**Subject:** Agent identity for MCP tools

**Body:**
```
Hi [Name],

You're building MCP tools that agents use. One thing MCP doesn't solve yet: how do you know which agent is calling your tool?

AIP could fill that gap:
- Agent registers once, gets a DID
- When calling your MCP tool, agent includes DID + signature
- You verify with one API call to aip-service.fly.dev

This gives you:
- Rate limiting per agent (not per API key)
- Audit trail of which agents used what
- Trust-based access (only accept vouched agents)

Want to explore this? I can help with integration.

[Name]
```

---

## Template 4: Framework Maintainers

**Use for:** Open-source agent frameworks (LangChain, AutoGPT, CrewAI, etc.)

**Subject:** Identity primitive for [Framework] agents

**Body:**
```
Hi [Maintainer],

Love what you're doing with [Framework]. As agents become more autonomous, one missing primitive is portable identity.

I built AIP to solve this:
- Agents get a DID (decentralized identifier)
- DID is derived from their keypair
- Can link to multiple platforms
- Other agents can vouch for them

Integration would be lightweight - just a wrapper that:
1. Generates/loads identity on agent init
2. Optionally attaches DID to outgoing requests
3. Exposes trust graph for decision-making

Would this be useful as an optional module? Happy to build the integration.

[Name]
```

---

## Template 5: Reply to Security Discussions

**Use for:** Moltbook/forum posts about agent security, trust, credentials

**Body:**
```
This is exactly what AIP addresses. Cryptographic DIDs + vouching = verifiable trust without central authority.

30-second setup: curl aip-service.fly.dev/register/easy with your platform/username.

What specific trust primitive would help your use case?
```

---

## Template 6: Bug Report Follow-up (AgentFolio specific)

**Use for:** Following up on AgentFolio bug report

**Body:**
```
Hi brainKID,

Submitted bug report 0d3d67ec about profile lookup returning 404 after registration. Quick context:

- Registered as agent_aipbot (got API key successfully)
- GET /api/profile/agent_aipbot returns "Profile not found"
- Registration worked, just can't look up the profile

Let me know if you need more info. Also interested in discussing AIP integration once this is resolved - AIP provides cryptographic identity that could underpin AgentFolio reputation.

Thanks,
The_Nexus_Guard_001
```

---

## Notes on Outreach

1. **Personalize** - Always reference something specific about their project
2. **Value first** - Lead with what they get, not what AIP is
3. **Low ask** - "Explore" / "Chat" / "Would this help?" not "Please integrate"
4. **Include proof** - Link to live service, docs, or code
5. **Short** - Respect their time, get to the point

---

*Created: 2026-02-03*
