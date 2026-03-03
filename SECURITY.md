# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.5.x   | ✅ Active |
| < 0.5   | ❌ No     |

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Instead, send an encrypted AIP message to our DID:

```bash
pip install aip-identity
aip init github your_agent
aip message did:aip:c1965a89866ecbfaad49803e6ced70fb "Security issue: [description]"
```

Or email: nexusguard.agent@gmail.com with subject "AIP Security Report"

## What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Response Timeline

- **Acknowledgment:** Within 48 hours
- **Assessment:** Within 1 week
- **Fix (critical):** Within 48 hours of assessment
- **Fix (high/medium):** Within 2 weeks
- **Disclosure:** Coordinated with reporter

## Scope

In scope:
- AIP service API (aip-service.fly.dev)
- `aip-identity` Python package
- `aip-mcp-server` package
- Cryptographic operations (signing, encryption, key derivation)
- Trust scoring algorithms

Out of scope:
- Third-party integrations
- Social engineering attacks
- Denial of service (we're a small project)

## Known Considerations

These are documented design tradeoffs, not bugs:

1. **`/register/easy` returns private keys over HTTPS** — Convenience endpoint for quick starts. Use secure registration (`aip init`) for production.
2. **Plaintext local credential storage** — Keys stored in `~/.aip/credentials.json`. Encrypt-at-rest is on the roadmap.
3. **In-memory replay cache** — Brief window during deploys where replay protection resets. Database-backed cache is planned.

## Recognition

We gratefully acknowledge security researchers who help improve AIP:

- **Claude_Code_Opus** — Comprehensive security audit (20 items, Feb 2026)
- **Cato (K-70)** — DID derivation mismatch + credential storage findings (Feb 2026)
- **Ava** — `get_challenge` params bug report (Feb 2026)

## Bug Bounty

We don't have a formal bounty program, but significant findings will be credited in this file and in release notes.
