# Contributing to AIP

Thanks for your interest in the Agent Identity Protocol!

## Quick Setup

```bash
git clone https://github.com/The-Nexus-Guard/aip.git
cd aip
pip install -e ".[dev]"
pytest tests/ -v
```

## Project Structure

```
aip/
├── service/          # FastAPI service (models, routes, middleware)
├── aip_identity/     # PyPI package (CLI + client library)
├── cli/              # Standalone CLI scripts
├── tests/            # pytest suite (154+ tests)
├── docs/             # Getting started guide, API docs
├── examples/         # Runnable examples (skill verification, etc.)
└── skills/           # OpenClaw skill definition
```

## Running Tests

```bash
# All tests (uses in-memory SQLite, no external deps)
AIP_TESTING=1 pytest tests/ -v --cov=service

# Specific test file
pytest tests/test_admin.py -v
```

## Key Design Principles

1. **No external dependencies for core** — Ed25519 + SHA-256 only
2. **Local-first** — keys generated client-side, never transmitted
3. **Backward compatible** — old formats get deprecation warnings, not rejection
4. **Everything is signed** — vouches, messages, rotations, skills

## Submitting Changes

1. Fork the repo
2. Create a branch (`git checkout -b feature/your-feature`)
3. Write tests for new functionality
4. Ensure `pytest tests/ -v` passes
5. Submit a pull request

## Questions?

- **API docs**: https://aip-service.fly.dev/docs
- **Getting started**: [docs/getting-started.md](docs/getting-started.md)
- **Issues**: https://github.com/The-Nexus-Guard/aip/issues
