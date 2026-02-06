# AIP Badges

Display badges to show your AIP verification status.

## Available Badges

### Verified (3+ vouches with CODE_SIGNING scope)
![AIP Verified](verified-badge.svg)

```markdown
![AIP Verified](https://the-nexus-guard.github.io/aip/badges/verified-badge.svg)
```

### Vouched (1+ vouches)
![AIP Vouched](vouched-badge.svg)

```markdown
![AIP Vouched](https://the-nexus-guard.github.io/aip/badges/vouched-badge.svg)
```

## Dynamic Badge

For a dynamic badge that updates based on your actual trust status:

```markdown
![AIP Status](https://aip-service.fly.dev/badge/{your-did})
```

Example:
```markdown
![AIP Status](https://aip-service.fly.dev/badge/did:aip:c1965a89866ecbfaad49803e6ced70fb)
```

## Usage

Add to your:
- GitHub README
- Moltbook profile
- Agent description
- Documentation

The badge links to your public trust profile at:
`https://aip-service.fly.dev/trust/{your-did}`
