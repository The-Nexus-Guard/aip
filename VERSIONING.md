# Versioning Guide

AIP has one version number across all surfaces. Here's where it lives and how to bump it.

## Version Surfaces

| Surface | File | Field | Auto-synced? |
|---------|------|-------|-------------|
| **PyPI package** | `pyproject.toml` | `version` | ❌ Manual |
| **Python module** | `aip_identity/__init__.py` | `__version__` | ❌ Manual |
| **Fly.io service** | `service/main.py` | `version=` in FastAPI() | ❌ Manual |
| **Landing page** | `docs/index.html` | Fetches from `/health` API | ✅ Auto |
| **ClawHub skill** | Published via `npx clawhub publish` | `--version` flag | ❌ Manual (separate versioning: 1.x.x) |

## How to Bump

1. **Update these 3 files** (must match):
   ```
   pyproject.toml          → version = "X.Y.Z"
   aip_identity/__init__.py → __version__ = "X.Y.Z"
   service/main.py          → version="X.Y.Z"
   ```

2. **Update CHANGELOG.md** with what changed.

3. **Commit + push** to GitHub.

4. **Publish to PyPI**: `python3 -m build && twine upload dist/*`
   Or push a git tag to trigger the auto-publish workflow.

5. **Deploy to Fly.io**: 
   ```bash
   FLY_API_TOKEN=$(cat credentials/fly_token.txt) ~/.fly/bin/flyctl deploy --remote-only
   ```

6. **Landing page** updates automatically (fetches version from `/health`).

7. **ClawHub** (if skill changed): 
   ```bash
   npx clawhub publish skills/aip-identity --version X.Y.Z --changelog "..."
   ```

## One-liner Version Check

```bash
# Check all surfaces at once
echo "pyproject.toml: $(grep '^version' pyproject.toml | head -1)"
echo "  __init__.py: $(grep '__version__' aip_identity/__init__.py)"
echo "    main.py: $(grep 'version=' service/main.py | head -1 | xargs)"
echo "     Fly.io: $(curl -s https://aip-service.fly.dev/health | python3 -c 'import json,sys;print(json.load(sys.stdin)["version"])')"
echo "      PyPI: $(pip index versions aip-identity 2>/dev/null | head -1)"
```

## ClawHub Versioning

ClawHub uses a separate version scheme (1.x.x) because it tracks the skill packaging, not the Python package. Bump ClawHub only when the OpenClaw skill itself changes.
