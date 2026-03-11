# AIP as Identity Middleware

## Problem

~143 PyPI installs/day, 14 registrations total. The gap between "installed" and "registered" is the critical failure point.

The current model: install CLI → run `aip init` → register → use.
The middleware model: `from aip_identity import authenticated_agent` → identity happens transparently.

## Core Insight

Nobody installs identity infrastructure. They install frameworks. If identity is a one-liner inside the framework they already use, registration becomes automatic.

## API Design

```python
from aip_identity.middleware import AIPMiddleware

# Option 1: Wrap any callable
@AIPMiddleware.authenticate
async def my_agent(request):
    # request.identity.did, request.identity.trust_score available
    return response

# Option 2: Framework-specific integrations
# LangChain
from aip_identity.integrations.langchain import AIPTool
tools = [AIPTool(verify_peers=True)]

# CrewAI
from aip_identity.integrations.crewai import AIPCrewMiddleware
crew = Crew(agents=[...], middleware=[AIPCrewMiddleware()])

# FastAPI (for agent service providers)
from aip_identity.integrations.fastapi import AIPAuthMiddleware
app.add_middleware(AIPAuthMiddleware)
```

## Auto-Registration Flow

```python
from aip_identity.middleware import ensure_identity

# This already exists in v0.5.33+ as ensure_identity()
# What's new: make it COMPLETELY silent and automatic
identity = ensure_identity()
# - If credentials exist: loads them, returns identity
# - If no credentials: generates keys, registers with service, saves credentials
# - Zero user interaction required
# - Returns: AIPIdentity(did, public_key, trust_score)
```

## What Changes

1. **No CLI dependency** — middleware is pure Python library usage
2. **Auto-registration** — first import triggers registration if needed
3. **Request signing** — outgoing HTTP requests get AIP signatures automatically
4. **Peer verification** — incoming requests verified against AIP registry
5. **Trust-aware routing** — agents can filter peers by trust score

## Architecture

```
┌─────────────────────────┐
│   Agent Framework        │
│   (LangChain/CrewAI/...) │
├─────────────────────────┤
│   AIP Middleware         │  ← NEW: this layer
│   - Auto-registration    │
│   - Request signing      │
│   - Peer verification    │
│   - Trust scoring        │
├─────────────────────────┤
│   AIP Core               │
│   - Crypto (Ed25519)     │
│   - Credential storage   │
│   - Service client       │
└─────────────────────────┘
```

## Implementation Plan

### Phase 1: Middleware Core (v0.5.35)
- `aip_identity.middleware` module
- `AIPMiddleware` class with `authenticate`, `sign_request`, `verify_request`
- Auto-registration on first use (extend existing `ensure_identity()`)
- HTTP interceptor for requests library

### Phase 2: Framework Integrations (v0.5.36)
- LangChain tool wrapper
- CrewAI middleware
- FastAPI middleware (for agent service providers)
- OpenAI function calling adapter

### Phase 3: Trust-Aware Routing (v0.5.37)
- Peer discovery via agent directory
- Trust-score-based filtering
- Automatic vouch propagation

## Key Decisions

1. **Silent by default** — no prompts, no CLI interaction, no user-visible registration step
2. **Credentials in standard location** — `~/.aip/credentials.json` (same as CLI)
3. **Platform auto-detection** — middleware detects framework and registers with appropriate platform tag
4. **Backward compatible** — CLI still works, middleware is additive
5. **Zero config** — `from aip_identity.middleware import AIPMiddleware` should work with no arguments

## Success Metrics

- Install-to-registration conversion rate > 10% (currently ~0.003%)
- Framework integration PRs to LangChain, CrewAI, AutoGen
- New registrations from middleware (tracked by platform="middleware" tag)

## Risks

- Silent registration may feel invasive to some users
- Auto-generated identities have no trust (need welcome vouch system)
- Framework integration maintenance burden (APIs change)
