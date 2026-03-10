"""
Auto-identity management for AIP integrations.

One-liner to ensure your agent has an AIP identity:

    from aip_identity.integrations.auto import ensure_identity
    client = ensure_identity("my-langchain-agent", platform="langchain")

If credentials exist at ~/.aip/credentials.json (or AIP_CREDENTIALS_PATH),
loads them. Otherwise, registers a new agent and saves credentials.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from aip_identity.client import AIPClient


def _default_credentials_path() -> Path:
    """Get the default credentials path."""
    env_path = os.environ.get("AIP_CREDENTIALS_PATH")
    if env_path:
        return Path(env_path)
    return Path.home() / ".aip" / "credentials.json"


def ensure_identity(
    agent_name: str,
    platform: str = "agent",
    credentials_path: Optional[str] = None,
    service_url: str = AIPClient.DEFAULT_SERVICE,
) -> AIPClient:
    """
    Ensure an AIP identity exists, creating one if needed.

    This is the recommended entry point for framework integrations.
    It handles the full lifecycle:
    1. Check for existing credentials
    2. If found, load and return client
    3. If not found, register a new identity, save credentials, return client

    Args:
        agent_name: Display name / platform_id for the agent
        platform: Platform identifier (e.g., "langchain", "crewai", "autogen")
        credentials_path: Override credentials file location
        service_url: AIP service URL

    Returns:
        AIPClient ready for identity operations

    Example:
        >>> client = ensure_identity("my-research-agent", platform="langchain")
        >>> print(client.did)  # did:aip:abc123...
    """
    path = Path(credentials_path) if credentials_path else _default_credentials_path()

    # Try loading existing credentials
    if path.exists():
        try:
            return AIPClient.from_file(str(path), service_url=service_url)
        except (json.JSONDecodeError, KeyError):
            pass  # Corrupted file, re-register

    # Register new identity
    client = AIPClient.register(
        platform=platform,
        platform_id=agent_name,
        service_url=service_url,
    )

    # Save credentials
    path.parent.mkdir(parents=True, exist_ok=True)
    client.save(str(path))

    return client
