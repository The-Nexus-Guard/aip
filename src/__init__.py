"""Agent Identity Protocol - Cryptographic identity and trust for AI agents."""

from .identity import (
    AgentIdentity,
    VerificationChallenge,
    create_agent,
    verify_signature,
    get_backend
)

from .trust import (
    TrustLevel,
    TrustScope,
    Vouch,
    Revocation,
    TrustPath,
    TrustGraph,
    create_trust_graph,
    verify_vouch,
    verify_trust_path
)

__version__ = "0.2.0"
__all__ = [
    # Identity
    "AgentIdentity",
    "VerificationChallenge",
    "create_agent",
    "verify_signature",
    "get_backend",
    # Trust
    "TrustLevel",
    "TrustScope",
    "Vouch",
    "Revocation",
    "TrustPath",
    "TrustGraph",
    "create_trust_graph",
    "verify_vouch",
    "verify_trust_path"
]
