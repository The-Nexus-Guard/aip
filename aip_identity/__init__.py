"""Agent Identity Protocol — cryptographic identity, trust, and encrypted messaging for AI agents."""

from .client import AIPClient, AIPError

try:
    from importlib.metadata import version as _pkg_version
    __version__ = _pkg_version("aip-identity")
except Exception:
    __version__ = "0.0.0"  # fallback for editable/dev installs

__all__ = ["AIPClient", "AIPError"]
