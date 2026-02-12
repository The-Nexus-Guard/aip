# Changelog

## v0.5.3 (2026-02-13) — Trust Score & CI

### New Features
- `aip trust-score <did>` — check trust score with visual bar, hop count, and trust chain
- Example GitHub Action for verifying skill signatures on PRs (`examples/verify-skill-signatures.yml`)
- GitHub Discussion templates (Q&A + Feature Request)
- Interactive "Try AIP" demos on explorer.html (live API queries)

## v0.5.2 (2026-02-12) — Trust Graph CLI

### New Features
- `aip trust-graph` — visualize the AIP trust network as ASCII art, GraphViz DOT, or JSON
- `aip list` — list all registered agents from the directory
- Updated README with all new commands and examples

## v0.5.1 (2026-02-12) — SEO & Rate Limits

### New Features
- X-RateLimit-Limit/Remaining/Reset headers on all API responses
- OpenGraph + Twitter Card meta tags on landing page
- JSON-LD structured data (SoftwareApplication schema)
- sitemap.xml + robots.txt for search engine crawling
- OG image (1200x630) for social sharing

### Improvements
- 174 tests passing

## v0.5.0 (2026-02-12) — Discoverability & Polish

### New Features
- `aip reply <message_id> "content"` — reply to messages directly by ID
- "How AIP Works" deep-dive page on GitHub Pages (SEO-optimized)
- GitHub Actions workflow for automatic PyPI publishing on tagged releases
- Agent Directory in explorer.html — browse all registered agents
- `examples/encrypted_messaging.py` — send/inbox demo script

### Improvements
- ClawHub listing fixed — `isSuspicious` flag cleared, skill visible in search (v1.4.0)
- CHANGELOG.md and CONTRIBUTING.md added
- 170+ tests passing

### Includes all v0.4.2 features:

## v0.4.2 (2026-02-12) — Admin & Messaging Polish

### New Features
- `GET /admin/registrations` — list all registered agents with pagination
- `GET /admin/registrations/<did>` — detailed agent view with vouches given/received
- `PATCH /message/<id>/read` — mark messages as read without deleting
- `aip list` CLI command — browse registered agents from the terminal
- `aip messages --mark-read` — mark retrieved messages as read via CLI

### Improvements
- Production safety guard in CLI — blocks write operations when `AIP_TESTING=1` targets production
- 9 new tests for prod safety, 2 new tests for mark-read endpoint

## v0.4.1 (2026-02-11) — Architecture & PyPI

### New Features
- Published to PyPI as `aip-identity` — `pip install aip-identity` → `aip` CLI
- `aip sign <directory>` — sign entire skill directories
- `aip verify <directory>` — verify skill signatures
- `aip messages` — retrieve and decrypt inbox (challenge-response auth + SealedBox)

### Improvements
- Refactored service into `service/` package (models, routes, middleware, config)
- 154 tests passing, 84% coverage
- Getting Started guide (`docs/getting-started.md`)
- README with badges, quickstart, "Why AIP?" section, 18 PyPI keywords
- Example script: `examples/verify_skill.py`
- 14 GitHub topics for discoverability

---

## v0.4.0 (2026-02-10) — Security Hardening

Major security release based on independent audit findings (28/28 functional tests passed, 4 critical + 6 high + 9 medium vulnerabilities identified and fixed).

### Critical Fixes
- **Vouch certificate forgery** — certificates now cross-checked against registered public keys
- **Registration impersonation** — added `verified` status; registrations unverified by default until platform proof provided
- **`/register/easy` key exposure** — deprecated with security warning; client-side key generation now recommended
- **Key rotation DID binding** — added key history table; DID remains derivable from original key after rotation
- **Moltbook proof bypass** — posts without cryptographic proof blocks now correctly rejected

### High-Priority Fixes
- **Database-backed rate limiting** on all endpoints (persists across restarts)
- **Automatic cleanup** of expired challenges, vouches, and old messages (5-min cycle)
- **Duplicate vouch prevention** — 409 on re-vouch for same target+scope
- **CORS restricted** to known origins only
- **Message replay protection** — timestamp binding + signature dedup

### New Endpoints
- `POST /verify-platform` — verify platform identity after registration

### Badge Changes
- Badge now shows: Not Found / Registered / Verified / Vouched (N) / Trusted
- "Verified" = platform identity proven; "Trusted" = 3+ vouches with CODE_SIGNING

### Breaking Changes
- Message signing payload changed to `sender_did|recipient_did|timestamp|encrypted_content` (old format accepted with deprecation warning)

### Documentation
- README updated with secure registration guide, rate limit table, new message format
- `cli/aip-register-secure` helper script for local key generation

### Testing
- Test infrastructure fixed (correct DB env var, shared temp DB, rate limit bypass)
- 50 tests passing (23 library + 27 service)

---

## v0.3.1 (2026-02-07) — E2E Messaging

- Added encrypted messaging (NaCl SealedBox)
- Skill signing and verification
- Badge endpoint

## v0.3.0 (2026-02-05) — Initial Release

- DID registration with Ed25519 keypairs
- Challenge-response verification
- Vouch system with trust decay and transitive paths
- Moltbook proof verification
