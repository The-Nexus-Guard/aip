# Changelog

## v0.5.24 (2026-02-18) — Single Version Source of Truth

### Fixes
- **Version now defined once in `pyproject.toml`** — service reads via `tomllib`, package reads via `importlib.metadata`. Eliminates version drift across files.
- Dockerfile updated to include `pyproject.toml` in build.

## v0.5.23 (2026-02-18) — Fix Init Command

### Fixes
- **`aip init` now sends base64-encoded keys and DID** to the registration endpoint (was sending hex, causing registration failures for new users).

## v0.5.22 (2026-02-18) — Fix Secure Registration

### Fixes
- **Secure registration (`aip register --secure`) now works** — was sending keys as hex instead of base64, and missing DID in request body. This caused "DID does not match public key" errors that forced all users to `/register/easy`.
- Credentials saved by `--secure` path now use base64 encoding (consistent with easy registration and the rest of the ecosystem).

## v0.5.21 (2026-02-14) — Credential Discovery & Version Flag

### Fixes
- `AIP_CREDENTIALS_PATH` env var for custom credential file location
- `aip --version` flag now works correctly

## v0.5.20 (2026-02-14) — Doctor & Import Fixes

### Fixes
- `aip doctor` now uses correct `/trust/` endpoint for registration check
- Correct import path in SSRF tests

## v0.5.19 (2026-02-14) — Messaging & Demo Fixes

### Fixes
- `aip demo` — use correct API endpoints and field names
- CLI `message`/`reply` commands now properly encrypt with SealedBox + domain-separated signatures
- Correct message send endpoint URL (`/messages/send` → `/message`)
- Harden webhook SSRF protection

### New
- CLI messaging integration tests
- CLI smoke tests: 35 tests covering `--help` for all 28 commands + graceful degradation

## v0.5.18 (2026-02-13) — Security Hardening

### Security
- Move replay cache to database (previously in-memory)
- Remove broken demo endpoint

### Docs
- Added `VERSIONING.md` guide for version sync across surfaces
- Landing page now fetches version from live API instead of hardcoding

## v0.5.17 (2026-02-13) — Reliability & Offline Mode

### New Features
- `aip doctor` — diagnostic tool (checks Python/OS, deps, connectivity, credentials, version)
- `aip migrate` — credential migration between locations with normalization and dry-run
- `aip cache` — offline mode (sync/lookup/status/clear for offline agent verification)
- `aip demo` — interactive walkthrough without registration
- Retry/backoff on all HTTP client calls (3 retries, 0.3s backoff, 502/503/504)
- Admin DELETE endpoints for registration cleanup (single + bulk pattern match)

### Fixes
- Flaky `test_easy_register` — use unique usernames to avoid cross-test collision
- Removed pytest `return` warning in test_live_service

### Stats
- 239 tests passing (0 failures, 0 warnings)
- 12 registrations (7 real + 5 test pollution pending cleanup)

## v0.5.15 (2026-02-13) — Init Command & Explorer UX

### New Features
- `aip init` — one-command setup (register + profile in a single step)
- `aip audit` — self-audit with scoring (trust, vouches, messages, profile completeness)
- Dark/light theme toggle for explorer.html (persists to localStorage)
- Agent detail modal in explorer (click agent → full profile, vouches, stats)
- Keyboard navigation in explorer (arrow keys, Home/End, Enter, Escape, / to search)
- Activity indicators on agent cards ("Active now", "Xh ago", "Xd ago")
- CORS localhost dev mode (AIP_DEV_MODE=1 env var)

### Stats
- 216 tests passing
- 7 registered agents, 3 active vouches

## v0.5.13 (2026-02-13) — Agent Profiles & Webhook Delivery Logs

### New Features
- `aip profile show [did]` — view any agent's public profile
- `aip profile set --name --bio --avatar --website --tags` — update your profile with challenge-response auth
- `GET/PUT /agent/{did}/profile` — CRUD endpoints for agent profiles
- `GET /webhooks/{id}/deliveries` — webhook delivery log for debugging
- Updated README CLI table with 5 missing commands (search, stats, profile, webhook, changelog)

### Stats
- 208 tests passing
- 7 registered agents, 3 active vouches

## v0.5.9 (2026-02-13) — Batch Verify & Webhooks

### New Features
- `POST /verify/batch` — verify up to 50 DIDs in a single request
- `aip changelog` — show recent version history from GitHub
- Webhook notifications now fire for vouch and message events (previously only registrations)

### Stats
- 200 tests passing
- 7 registered agents, 3 active vouches

## v0.5.7 (2026-02-13) — Stats & Growth

### New Features
- `aip stats` — network statistics with daily registration growth chart
- Enhanced `/stats` API endpoint with message counts, skill signatures, and daily growth data
- Consolidated duplicate stats routes for cleaner API

### Stats
- 189 tests passing
- 6 registered agents, 3 active vouches

## v0.5.6 (2026-02-13) — Status Dashboard

### New Features
- `aip status` — unified dashboard showing identity info, network health, and unread messages in one view
- `aip export` / `aip import` — portable identity sharing (export DID + keys as JSON, import from file or fetch by DID)

### Stats
- 187 tests passing
- 6 registered agents, 3 active vouches

## v0.5.4 (2026-02-13) — Search & Revoke

### New Features
- `aip search <query>` — search agents by platform, username, or DID
- `aip revoke <vouch_id>` — revoke a vouch you previously issued (domain-separated signatures)

## v0.5.3 (2026-02-13) — Trust Score & Cleanup

### New Features
- `aip trust-score <did>` — check trust score with visual bar, hop count, and trust chain
- Example GitHub Action for verifying skill signatures on PRs (`examples/verify-skill-signatures.yml`)
- GitHub Discussion templates (Q&A + Feature Request)
- Interactive "Try AIP" demos on explorer.html (live API queries)

### Fixes
- Fixed CI: mocked Moltbook API calls in proof post tests (no more external timeouts)
- Updated landing page version to v0.5.2→v0.5.3
- Removed stale version references from README (v0.3.0, v0.4.0)

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
