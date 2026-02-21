"""
AIP tools for LangChain and CrewAI.

Usage with LangChain:
    from aip_identity.integrations.langchain_tools import get_aip_tools

    tools = get_aip_tools()
    # Pass to your agent: create_agent(model=..., tools=tools)

Usage with CrewAI:
    from aip_identity.integrations.langchain_tools import get_aip_tools

    tools = get_aip_tools()
    agent = Agent(role="...", tools=tools)

Requires: pip install langchain-core (or langchain)
AIP credentials must exist (~/.aip/credentials.json) or set AIP_CREDENTIALS_PATH.
"""

from __future__ import annotations

import json
from typing import List, Optional

try:
    from langchain_core.tools import tool as _lc_tool
except ImportError:
    raise ImportError(
        "langchain-core is required for AIP LangChain tools. "
        "Install it with: pip install langchain-core"
    )

from aip_identity import AIPClient


def _load_client() -> AIPClient:
    """Load AIP client from default credentials file."""
    return AIPClient.from_file()


@_lc_tool
def aip_whoami() -> str:
    """Get your AIP agent identity — DID and public key."""
    client = _load_client()
    return json.dumps({"did": client.did, "public_key": client.public_key_b64})


@_lc_tool
def aip_lookup_agent(did: str) -> str:
    """Look up another agent by DID and get their registration info.

    Args:
        did: The DID of the agent to look up (e.g. did:aip:abc123...)
    """
    client = _load_client()
    info = client.lookup(did)
    return json.dumps(info)


@_lc_tool
def aip_get_trust(did: str, scope: str = "") -> str:
    """Get trust information for an agent, optionally filtered by scope.

    Args:
        did: The DID of the agent to check trust for
        scope: Optional trust scope filter (e.g. GENERAL, CODE_SIGNING)
    """
    client = _load_client()
    result = client.get_trust(did, scope=scope if scope else None)
    return json.dumps(result)


@_lc_tool
def aip_is_trusted(did: str, scope: str = "") -> str:
    """Check if an agent is trusted (has valid vouches).

    Args:
        did: The DID of the agent to check
        scope: Optional trust scope filter
    """
    client = _load_client()
    trusted = client.is_trusted(did, scope=scope if scope else None)
    return json.dumps({"did": did, "trusted": trusted})


@_lc_tool
def aip_sign_message(message: str) -> str:
    """Cryptographically sign a message with your AIP identity to prove authorship.

    Args:
        message: The message text to sign
    """
    client = _load_client()
    sig = client.sign(message.encode())
    return json.dumps({"message": message, "signature": sig, "did": client.did})


@_lc_tool
def aip_verify_agent(target_did: str) -> str:
    """Perform a full cryptographic verification of another agent (challenge-response).

    Args:
        target_did: The DID of the agent to verify
    """
    client = _load_client()
    result = client.verify(target_did)
    return json.dumps(result)


@_lc_tool
def aip_vouch_for_agent(did: str, scope: str = "GENERAL") -> str:
    """Vouch for another agent's trustworthiness in a specific scope.

    Args:
        did: The DID of the agent to vouch for
        scope: Trust scope — GENERAL, CODE_SIGNING, DELEGATION, FINANCIAL, etc.
    """
    client = _load_client()
    result = client.vouch(did, scope=scope)
    return json.dumps(result)


@_lc_tool
def aip_get_profile(did: str) -> str:
    """Get the public profile of an agent.

    Args:
        did: The DID of the agent
    """
    client = _load_client()
    profile = client.get_profile(did)
    return json.dumps(profile)


@_lc_tool
def aip_get_trust_path(source_did: str, target_did: str) -> str:
    """Find the trust path between two agents (transitive trust).

    Args:
        source_did: The DID of the source agent
        target_did: The DID of the target agent
    """
    client = _load_client()
    path = client.get_trust_path(source_did, target_did)
    return json.dumps(path)


def get_aip_tools() -> list:
    """Get all AIP tools as a list, ready for LangChain or CrewAI agents.

    Returns:
        List of LangChain-compatible tools for agent identity operations.

    Example:
        >>> from aip_identity.integrations.langchain_tools import get_aip_tools
        >>> tools = get_aip_tools()
        >>> # Use with LangChain
        >>> from langchain.agents import create_agent
        >>> agent = create_agent(model="claude-sonnet-4-5-20250929", tools=tools)
    """
    return [
        aip_whoami,
        aip_lookup_agent,
        aip_verify_agent,
        aip_get_trust,
        aip_is_trusted,
        aip_sign_message,
        aip_vouch_for_agent,
        aip_get_profile,
        aip_get_trust_path,
    ]
