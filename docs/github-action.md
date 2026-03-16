# Using AIP in GitHub Actions

Give your CI/CD pipeline a cryptographic identity with the AIP GitHub Action.

## Quick Start

Add to any workflow:

```yaml
steps:
  - uses: The-Nexus-Guard/aip@main
    with:
      did: ${{ secrets.AIP_DID }}
      private-key: ${{ secrets.AIP_PRIVATE_KEY }}
```

Your pipeline now has a verifiable identity on the AIP network.

## Example: Sign and Publish

```yaml
name: Build and Sign
on:
  push:
    tags: ['v*']

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Build artifacts
        run: python -m build
      
      - uses: The-Nexus-Guard/aip@main
        id: aip
        with:
          did: ${{ secrets.AIP_DID }}
          private-key: ${{ secrets.AIP_PRIVATE_KEY }}
          sign-paths: 'dist/*'
      
      - name: Upload with signatures
        uses: softprops/action-gh-release@v2
        with:
          files: dist/*
```

## Example: Trust-Gated Deploy

Only deploy if an upstream dependency agent is still trusted:

```yaml
- uses: The-Nexus-Guard/aip@main
  with:
    did: ${{ secrets.AIP_DID }}
    private-key: ${{ secrets.AIP_PRIVATE_KEY }}
    verify-did: 'did:aip:upstream-agent-did'
    trust-threshold: '0.5'

- name: Deploy (only runs if trust gate passes)
  run: ./deploy.sh
```

## Setup

1. Install AIP and create an identity:
   ```bash
   pip install aip-identity
   aip init --platform github --username my-org
   ```

2. Get your credentials:
   ```bash
   aip whoami  # shows your DID
   cat ~/.aip/credentials.json  # shows private_key
   ```

3. Add GitHub secrets:
   - `AIP_DID` → your DID
   - `AIP_PRIVATE_KEY` → your base64 private key

4. Add the action to your workflow.

## Security Notes

- Private keys are passed via environment variables, never written to disk
- GitHub Actions masks secrets in logs automatically
- The action uses PyPI-published `aip-identity` — same package you'd install locally
- Trust scores are checked live against the AIP network

## See Also

- [AIP Documentation](https://the-nexus-guard.github.io/aip/)
- [Action source code](https://github.com/The-Nexus-Guard/aip/tree/main/action)
- [Getting Started](getting-started.md)
