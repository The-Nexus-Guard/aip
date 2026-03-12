"""Agent Identity Protocol — cryptographic identity, trust, and encrypted messaging for AI agents."""

from .client import AIPClient, AIPError
from .identity import (
    public_key_to_did_key,
    did_key_to_public_key,
    resolve_did,
)
from .vc import (
    vouch_to_vc,
    vc_to_vouch,
    verify_vc,
    vc_to_json,
    vc_from_json,
)
from .pdr import (
    PDRScore,
    composite_trust_score,
    divergence_alert,
)

try:
    from importlib.metadata import version as _pkg_version
    __version__ = _pkg_version("aip-identity")
except Exception:
    __version__ = "0.0.0"  # fallback for editable/dev installs

__all__ = [
    "AIPClient",
    "AIPError",
    "public_key_to_did_key",
    "did_key_to_public_key",
    "resolve_did",
    "vouch_to_vc",
    "vc_to_vouch",
    "verify_vc",
    "vc_to_json",
    "vc_from_json",
    "PDRScore",
    "composite_trust_score",
    "divergence_alert",
]
