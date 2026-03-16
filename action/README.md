# AIP Identity GitHub Action

Give your CI/CD pipeline a cryptographic identity. Sign build artifacts, verify peers, and gate deployments on trust scores.

## Quick Start

```yaml
- uses: The-Nexus-Guard/aip@main
  with:
    did: ${{ secrets.AIP_DID }}
    private-key: ${{ secrets.AIP_PRIVATE_KEY }}
```

That's it. Your pipeline now has a verifiable identity on the AIP network.

## Use Cases

### Sign release artifacts

```yaml
name: Release
on:
  push:
    tags: ['v*']

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build
        run: make build

      - uses: The-Nexus-Guard/aip@main
        with:
          did: ${{ secrets.AIP_DID }}
          private-key: ${{ secrets.AIP_PRIVATE_KEY }}
          sign-paths: 'dist/*'
```

Every artifact in `dist/` gets a cryptographic signature tied to your agent's DID. Anyone can verify the signature came from your pipeline.

### Trust-gated deployments

```yaml
- uses: The-Nexus-Guard/aip@main
  with:
    did: ${{ secrets.AIP_DID }}
    private-key: ${{ secrets.AIP_PRIVATE_KEY }}
    verify-did: 'did:aip:abc123...'
    trust-threshold: '0.5'
```

The step fails if the target DID's trust score is below the threshold. Use this to gate deployments on whether a dependency or upstream agent is still trusted.

### Agent-to-agent CI coordination

```yaml
- uses: The-Nexus-Guard/aip@main
  id: identity
  with:
    did: ${{ secrets.AIP_DID }}
    private-key: ${{ secrets.AIP_PRIVATE_KEY }}

- name: Call partner API with signed request
  run: |
    aip message ${{ env.PARTNER_DID }} "Build ${{ github.sha }} complete. Artifacts signed."
  env:
    AIP_DID: ${{ secrets.AIP_DID }}
    AIP_PRIVATE_KEY: ${{ secrets.AIP_PRIVATE_KEY }}
```

## Setup

1. **Get an AIP identity** (if you don't have one):
   ```bash
   pip install aip-identity
   aip init --platform github --username your-org
   ```

2. **Add secrets to your repo:**
   - `AIP_DID` — your agent's DID (from `aip whoami`)
   - `AIP_PRIVATE_KEY` — your base64-encoded private key

3. **Use the action** in any workflow.

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `did` | Yes | — | Your agent DID |
| `private-key` | Yes | — | Base64 Ed25519 private key (use GitHub secret) |
| `service-url` | No | `https://aip-service.fly.dev` | AIP service URL |
| `sign-paths` | No | — | Space-separated paths/globs to sign |
| `verify-did` | No | — | DID to verify (trust gate) |
| `trust-threshold` | No | `0.0` | Minimum trust score for verify-did |

## Outputs

| Output | Description |
|--------|-------------|
| `did` | The agent DID used |
| `trust-score` | Agent's current trust score |
| `signatures` | JSON array of signed file paths |
| `verified` | Whether trust gate passed |

## How It Works

1. Installs `aip-identity` from PyPI
2. Configures identity via environment variables (key never written to disk)
3. Optionally verifies a peer DID against a trust threshold
4. Optionally signs specified artifacts with Ed25519

The private key is passed as an environment variable and never persisted to the runner's filesystem. GitHub Secrets ensures it's masked in logs.

## Why?

Every CI pipeline produces artifacts — binaries, packages, container images, model weights. Without identity, there's no way to cryptographically prove *who* built them.

AIP gives your pipeline an Ed25519 keypair tied to a decentralized identifier (DID). Other agents and pipelines can verify your signatures, check your trust score, and decide whether to accept your artifacts — all without a central authority.

## License

MIT
