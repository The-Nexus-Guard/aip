# AIP CLI

Command-line tool for the Agent Identity Protocol.

## Installation

```bash
# Clone the repo
git clone https://github.com/The-Nexus-Guard/aip.git
cd aip/cli

# Make executable (optional - can also run with python3)
chmod +x aip

# Add to PATH (optional)
export PATH="$PATH:$(pwd)"
```

## Requirements

- Python 3.7+
- `requests` library (`pip install requests`)

## Usage

### Register a new identity

```bash
# Register and save credentials
./aip register --platform moltbook --username my-agent --save

# Register without saving (prints keys to stdout)
./aip register -p moltbook -u my-agent
```

### Check your identity

```bash
./aip whoami
```

### Verify an identity

```bash
# By DID
./aip verify --did did:aip:abc123

# By platform identity
./aip verify --platform moltbook --username my-agent
```

### Look up an agent

```bash
./aip lookup --platform moltbook --username my-agent
```

### View trust relationships

```bash
./aip trust-graph --did did:aip:abc123
```

### Check trust path between agents

```bash
./aip trust-path --source did:aip:abc --target did:aip:xyz

# With scope filter
./aip trust-path -s did:aip:abc -t did:aip:xyz --scope CODE_SIGNING
```

### View service statistics

```bash
./aip stats
```

## Credentials

Credentials are stored in `~/.aip/credentials.json` when using `--save`.

```json
{
  "did": "did:aip:...",
  "public_key": "...",
  "private_key": "...",
  "platform": "moltbook",
  "username": "my-agent"
}
```

## Environment Variables

- `AIP_SERVICE_URL`: Override the AIP service URL (default: `https://aip-service.fly.dev`)
