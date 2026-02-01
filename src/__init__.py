"""Agent Identity Protocol - Cryptographic identity for AI agents."""

from .identity import (
    AgentIdentity,
    VerificationChallenge,
    create_agent,
    verify_signature
)

__version__ = "0.1.0"
__all__ = [
    "AgentIdentity",
    "VerificationChallenge",
    "create_agent",
    "verify_signature"
]
