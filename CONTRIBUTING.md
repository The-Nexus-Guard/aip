# Contributing to AIP

Thanks for your interest in the Agent Identity Protocol! Whether you're fixing a bug, adding a feature, or improving docs — contributions are welcome.

## Quick Setup

```bash
git clone https://github.com/The-Nexus-Guard/aip.git
cd aip
pip install -e ".[dev]"
pytest tests/ -v
```

All 288 tests should pass. Tests use in-memory SQLite — no external services needed.

## Project Structure

```
aip/
├── service/           # FastAPI service (models, routes, middleware)
│   ├── models.py      # Pydantic models + SQLite schema
│   ├── registration.py # Agent registration endpoints
│   ├── vouch.py       # Trust vouching system
│   ├── messaging.py   # E2E encrypted messaging
│   ├── webhooks.py    # Webhook delivery system
│   └── middleware.py  # Rate limiting, CORS, logging
├── aip_identity/      # PyPI package (CLI + client library)
│   ├── client.py      # AIPClient — main API wrapper
│   ├── crypto.py      # Ed25519 signing + SealedBox encryption
│   ├── cli.py         # CLI entry point (aip command)
│   └── trust.py       # Trust scoring + path finding
├── tests/             # pytest suite (288 tests)
├── docs/              # Getting started, API docs, specs
├── examples/          # Runnable examples (see below)
└── skills/            # OpenClaw skill definition
```

## Architecture Overview

AIP has three layers:

1. **Identity** — Ed25519 keypairs, DIDs, challenge-response verification
2. **Trust** — Signed vouches with scopes, trust paths, decay scoring
3. **Communication** — E2E encrypted messaging via SealedBox

Key design decisions:
- **No external crypto dependencies for core** — Ed25519 + SHA-256 only (PyNaCl for encryption)
- **Local-first** — Keys generated client-side, never transmitted (except `/register/easy` convenience endpoint)
- **Backward compatible** — Old formats get deprecation warnings, not rejection
- **Everything is signed** — Vouches, messages, key rotations, skills
- **Domain-separated signatures** — Each operation signs a prefixed payload (e.g., `vouch:`, `revoke:`, `msg:`)

## Running Tests

```bash
# Full suite with coverage
AIP_TESTING=1 pytest tests/ -v --cov=service

# Specific module
pytest tests/test_vouch.py -v

# Just the fast unit tests
pytest tests/ -v -k "not slow"
```

CI runs on every push and PR via GitHub Actions.

## What to Work On

### Good First Issues

Look for issues labeled `good first issue` in the [issue tracker](https://github.com/The-Nexus-Guard/aip/issues). These are scoped, well-defined, and a great way to learn the codebase.

### Areas We'd Love Help With

- **Language bindings** — JavaScript/TypeScript, Go, Rust clients for the AIP API
- **Framework integrations** — LangChain, CrewAI, AutoGen identity plugins
- **A2A interop** — Agent-to-Agent protocol identity extensions
- **Security hardening** — Audit findings, SSRF protections, encrypted credential storage
- **Documentation** — Tutorials, diagrams, API examples
- **Trust algorithms** — Better trust scoring, Sybil resistance, trust decay models

### Examples

The `examples/` directory has runnable demos:

- `encrypted_messaging.py` — Send and receive encrypted messages
- `trust_network_demo.py` — Build and query trust networks
- `crewai_integration.py` — Use AIP identity with CrewAI agents
- `mcp_client_with_aip.py` — MCP client with AIP identity verification
- `a2a_identity_demo.py` — A2A protocol identity extension demo
- `verify_skill.py` — Verify cryptographic skill signatures

## Submitting Changes

1. **Fork** the repo and create a branch (`git checkout -b feature/your-feature`)
2. **Write tests** for new functionality — we maintain 288+ tests and don't merge without coverage
3. **Follow existing patterns** — look at how similar features are implemented
4. **Run the full suite** — `pytest tests/ -v` must pass
5. **Submit a PR** with a clear description of what and why

### Commit Style

We don't enforce a strict commit format, but prefer:
- Clear, descriptive commit messages
- One logical change per commit
- Reference issue numbers when applicable (`fixes #42`)

### Code Style

- Python 3.8+ compatible
- Type hints encouraged but not required everywhere
- Docstrings for public functions
- Keep functions focused — if it's doing too much, split it

## Reporting Security Issues

**Do not open public issues for security vulnerabilities.** See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## Questions?

- **GitHub Discussions**: https://github.com/The-Nexus-Guard/aip/discussions — best place for questions and ideas
- **API docs**: https://aip-service.fly.dev/docs — interactive Swagger UI
- **Playground**: https://the-nexus-guard.github.io/aip/playground.html — try AIP without installing anything
- **Getting started**: [docs/getting-started.md](docs/getting-started.md)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
