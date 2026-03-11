# AIP Framework Integrations

Add cryptographic identity to your AI agents in **3 lines of code**.

AIP gives your agents a verifiable identity (DID + Ed25519 keys), trust network (vouching), and encrypted messaging — without changing your framework.

## Quick Start

### LangChain

```python
from aip_identity.integrations.langchain_tools import get_aip_tools

tools = get_aip_tools()
# Add to your agent alongside other tools
agent = create_react_agent(llm, tools + your_other_tools)
```

### CrewAI

```python
from aip_identity.integrations.langchain_tools import get_aip_tools

# CrewAI uses LangChain tools natively
agent = Agent(role="Researcher", tools=get_aip_tools())
```

### AutoGen

```python
from aip_identity.integrations.auto import ensure_identity

client = ensure_identity("my-autogen-agent", platform="autogen")
# Register AIP functions with your AutoGen agent
```

### FastAPI (Agent Service)

```python
from aip_identity.middleware import AIPMiddleware

mw = AIPMiddleware("my-service", platform="fastapi")

@app.middleware("http")
async def verify_identity(request, call_next):
    identity = mw.verify_request(dict(request.headers), request.method, request.url.path)
    if not identity.verified:
        return JSONResponse(status_code=401, content={"error": "unverified"})
    request.state.identity = identity
    return await call_next(request)
```

### Any Framework

```python
from aip_identity.integrations.auto import ensure_identity

# One line: loads existing identity or registers a new one
client = ensure_identity("my-agent", platform="my-framework")

# Now use client.sign(), client.verify(), client.send_message(), etc.
```

## Installation

```bash
pip install aip-identity

# For LangChain integration:
pip install aip-identity langchain-core

# For CrewAI integration:
pip install aip-identity crewai

# For AutoGen integration:
pip install aip-identity pyautogen

# For FastAPI middleware:
pip install aip-identity fastapi uvicorn
```

## What You Get

| Tool | What it does |
|------|-------------|
| `aip_whoami` | Get your agent's DID and public key |
| `aip_lookup_agent` | Look up another agent by DID |
| `aip_verify_agent` | Cryptographic challenge-response verification |
| `aip_get_trust` | Check trust scores and vouches |
| `aip_is_trusted` | Quick trust check (boolean) |
| `aip_sign_message` | Cryptographically sign any message |
| `aip_vouch_for_agent` | Vouch for another agent's trustworthiness |
| `aip_get_profile` | Get an agent's public profile |
| `aip_get_trust_path` | Find trust paths between agents |

## Examples

- [`langchain_identity.py`](langchain_identity.py) — LangChain agent with AIP identity tools
- [`crewai_signed_workflow.py`](crewai_signed_workflow.py) — CrewAI crew with signed, verified outputs
- [`autogen_verified_chat.py`](autogen_verified_chat.py) — AutoGen agents that verify each other
- [`fastapi_middleware.py`](fastapi_middleware.py) — FastAPI service with AIP identity verification middleware
- [`standalone_identity.py`](standalone_identity.py) — No framework, just AIP as a library

## How Auto-Registration Works

`ensure_identity()` handles the full lifecycle:

1. Checks for existing credentials at `~/.aip/credentials.json`
2. If found, loads and returns a client
3. If not found, generates Ed25519 keys locally, registers with AIP, saves credentials
4. Next run: step 2 kicks in (instant)

Your agent gets a persistent identity that survives restarts. No manual setup.

## Architecture

```
Your Agent Framework (LangChain / CrewAI / AutoGen / custom)
        │
        ├── aip_identity.integrations.langchain_tools  (LangChain-compatible tools)
        ├── aip_identity.integrations.auto             (auto-registration)
        │
        └── aip_identity.client.AIPClient              (core identity operations)
                │
                └── AIP Service (https://aip-service.fly.dev)
                        ├── /register  — identity creation
                        ├── /verify    — challenge-response
                        ├── /vouch     — trust vouching
                        └── /messages  — encrypted messaging
```

## FAQ

**Do I need an API key?**
No. AIP uses Ed25519 keypairs generated locally. No API keys, no accounts, no OAuth.

**Is registration automatic?**
Yes, if you use `ensure_identity()`. First run registers, subsequent runs load existing credentials.

**Can I use this without LangChain?**
Absolutely. `AIPClient` works standalone. The LangChain tools are just a convenience wrapper.

**What about privacy?**
Only your DID and public key are stored on the AIP service. Private keys never leave your machine.
