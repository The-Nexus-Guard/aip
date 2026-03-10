"""
System Identity - The AIP service's own identity for auto-welcome vouches.

The system identity is a DID with a keypair managed by the service itself.
It provides a "welcome vouch" to every new registration, giving them an
immediate trust score > 0 and making the network feel alive from the start.

The private key is stored on the persistent volume (/data/system_key.b64).
If it doesn't exist, it's generated on first startup.
"""

import base64
import hashlib
import logging
import os
import uuid
from datetime import datetime, timezone

import nacl.signing

logger = logging.getLogger(__name__)

# Disable in test mode
TESTING = os.environ.get("AIP_TESTING") == "1"

# Where to store the system key (persistent volume on Fly.io)
SYSTEM_KEY_PATH = os.environ.get("AIP_SYSTEM_KEY_PATH", "/data/system_key.b64")
# Fallback for local dev
SYSTEM_KEY_PATH_LOCAL = os.path.join(os.path.dirname(__file__), "..", "data", "system_key.b64")

# Cached state
_signing_key: nacl.signing.SigningKey | None = None
_system_did: str | None = None
_public_key_b64: str | None = None


def _key_path() -> str:
    """Get the key path, preferring the persistent volume."""
    if os.path.exists(os.path.dirname(SYSTEM_KEY_PATH)):
        return SYSTEM_KEY_PATH
    # Local development fallback
    os.makedirs(os.path.dirname(SYSTEM_KEY_PATH_LOCAL), exist_ok=True)
    return SYSTEM_KEY_PATH_LOCAL


def _load_or_generate_key() -> nacl.signing.SigningKey:
    """Load or generate the system signing key."""
    path = _key_path()
    if os.path.exists(path):
        with open(path, "r") as f:
            key_b64 = f.read().strip()
        key_bytes = base64.b64decode(key_b64)
        return nacl.signing.SigningKey(key_bytes)
    else:
        key = nacl.signing.SigningKey.generate()
        key_b64 = base64.b64encode(bytes(key)).decode()
        with open(path, "w") as f:
            f.write(key_b64)
        logger.info(f"Generated new system identity key at {path}")
        return key


def init() -> tuple[str, str]:
    """
    Initialize the system identity. Call once at startup.
    
    Returns (system_did, public_key_b64).
    Also registers the system DID in the database if not already present.
    """
    global _signing_key, _system_did, _public_key_b64
    
    if TESTING:
        logger.info("System identity disabled in test mode")
        return ("did:aip:test_system", "")
    
    _signing_key = _load_or_generate_key()
    pub_bytes = bytes(_signing_key.verify_key)
    _public_key_b64 = base64.b64encode(pub_bytes).decode()
    key_hash = hashlib.sha256(pub_bytes).hexdigest()[:32]
    _system_did = f"did:aip:{key_hash}"
    
    # Register in DB if needed
    import database
    existing = database.get_registration(_system_did)
    if not existing:
        database.register_did(_system_did, _public_key_b64)
        database.add_platform_link(_system_did, "aip", "AIP_System", None, verified=True)
        logger.info(f"Registered system identity: {_system_did}")
    
    logger.info(f"System identity initialized: {_system_did}")
    return _system_did, _public_key_b64


def get_did() -> str | None:
    """Get the system DID (None if not initialized)."""
    return _system_did


def get_public_key() -> str | None:
    """Get the system public key base64 (None if not initialized)."""
    return _public_key_b64


def create_welcome_vouch(target_did: str) -> str | None:
    """
    Create a GENERAL welcome vouch for a newly registered agent.
    
    Returns the vouch_id on success, None on failure.
    """
    if TESTING or not _signing_key or not _system_did:
        return None
    
    if target_did == _system_did:
        return None  # Don't vouch for ourselves
    
    import database
    
    # Check if we already vouched for this agent
    if database.has_active_vouch(_system_did, target_did, "GENERAL"):
        logger.debug(f"Already have welcome vouch for {target_did}")
        return None
    
    # Create the signed vouch
    scope = "GENERAL"
    statement = "Welcome to AIP! This vouch confirms your successful registration."
    payload = f"{_system_did}|{target_did}|{scope}|{statement}"
    signature = _signing_key.sign(payload.encode("utf-8")).signature
    signature_b64 = base64.b64encode(signature).decode()
    
    vouch_id = str(uuid.uuid4())
    success = database.create_vouch(
        vouch_id=vouch_id,
        voucher_did=_system_did,
        target_did=target_did,
        scope=scope,
        statement=statement,
        signature=signature_b64,
        ttl_days=None,  # Permanent
    )
    
    if success:
        logger.info(f"Welcome vouch created for {target_did}: {vouch_id}")
        return vouch_id
    else:
        logger.error(f"Failed to create welcome vouch for {target_did}")
        return None
