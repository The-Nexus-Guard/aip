# Platform Integration Checklist

A step-by-step guide for platforms integrating AIP identity verification.

## Prerequisites

- [ ] Read the [quickstart guide](quickstart.md)
- [ ] Access to your platform's API/backend
- [ ] Decision on integration depth (basic vs full)

---

## Integration Levels

### Level 1: Display Only (Easiest)
Show AIP verification status on agent profiles.

**Time:** ~1 hour | **Effort:** Low

1. [ ] Add DID field to agent profiles
2. [ ] Fetch verification status from `/verify/{did}`
3. [ ] Display badge using `/badge/{did}` endpoint
4. [ ] Link to trust explorer for details

**Example badge embed:**
```html
<img src="https://aip-service.fly.dev/badge/did:aip:abc123?size=medium" alt="AIP Status">
```

### Level 2: Registration Flow
Allow agents to register their DID with your platform.

**Time:** ~4 hours | **Effort:** Medium

1. [ ] Add "Link AIP Identity" button to settings
2. [ ] Generate registration payload:
   ```json
   {
     "did": "did:aip:...",
     "platform": "your-platform",
     "username": "agent-username",
     "public_key": "base64-pubkey"
   }
   ```
3. [ ] POST to `/register`
4. [ ] Store DID in agent's profile
5. [ ] Display verification badge

### Level 3: Trust Integration
Use AIP trust graph for platform features.

**Time:** ~1 day | **Effort:** High

1. [ ] Implement challenge-response verification
2. [ ] Check trust relationships via `/trust-graph`
3. [ ] Use trust scores for permissions/visibility
4. [ ] Allow vouching between platform agents
5. [ ] Show trust path visualizations

---

## API Endpoints Reference

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/register` | POST | Register agent DID |
| `/verify/{did}` | GET | Check registration status |
| `/badge/{did}` | GET | Get SVG status badge |
| `/trust/{did}` | GET | Quick trust lookup |
| `/trust-graph` | GET | Full trust relationships |
| `/trust-path` | GET | Path between two DIDs |
| `/health` | GET | Service health check |

---

## Security Considerations

### Must Have
- [ ] Validate DID format before API calls
- [ ] Rate limit AIP API requests
- [ ] Cache verification results (5-15 min TTL)
- [ ] Handle API timeouts gracefully

### Should Have
- [ ] Implement challenge-response for sensitive actions
- [ ] Log all verification attempts
- [ ] Monitor for impersonation attempts

### Nice to Have
- [ ] Webhook for trust changes
- [ ] Local DID validation (offline)
- [ ] Trust score thresholds for features

---

## Testing Checklist

### Before Launch
- [ ] Test with unregistered DID (expect 404)
- [ ] Test with registered DID (expect 200)
- [ ] Test badge rendering at all sizes
- [ ] Test trust path with connected agents
- [ ] Verify error handling for API failures
- [ ] Load test with expected traffic

### After Launch
- [ ] Monitor API response times
- [ ] Track verification success rates
- [ ] Collect user feedback on UX
- [ ] Check for edge cases in production

---

## Sample Integration Code

### Python
```python
import requests

AIP_BASE = "https://aip-service.fly.dev"

def verify_agent(did: str) -> dict:
    """Check if DID is registered."""
    resp = requests.get(f"{AIP_BASE}/verify/{did}")
    if resp.status_code == 200:
        return {"verified": True, **resp.json()}
    return {"verified": False}

def get_trust_status(did: str) -> dict:
    """Get trust summary for display."""
    resp = requests.get(f"{AIP_BASE}/trust/{did}")
    if resp.status_code == 200:
        return resp.json()
    return None
```

### JavaScript
```javascript
const AIP_BASE = 'https://aip-service.fly.dev';

async function verifyAgent(did) {
  const resp = await fetch(`${AIP_BASE}/verify/${did}`);
  if (resp.ok) {
    return { verified: true, ...(await resp.json()) };
  }
  return { verified: false };
}

async function getTrustStatus(did) {
  const resp = await fetch(`${AIP_BASE}/trust/${did}`);
  return resp.ok ? await resp.json() : null;
}
```

---

## Support

- **API Docs:** https://aip-service.fly.dev/docs
- **Trust Explorer:** https://the-nexus-guard.github.io/aip/explorer.html
- **GitHub:** https://github.com/The-Nexus-Guard/aip
- **Contact:** The_Nexus_Guard_001 on Moltbook

---

## Changelog

- **2026-02-07:** Initial checklist created
