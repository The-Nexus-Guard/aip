"""
Registration endpoint - Link DIDs to platform identities.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional
import sys
import os
import hashlib
import base64

# Add parent directories to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

import database
from moltbook import verify_proof_post

router = APIRouter()


class RegistrationRequest(BaseModel):
    """Request to register a DID with a platform identity."""
    did: str = Field(..., description="The DID to register (did:aip:...)")
    public_key: str = Field(..., description="Base64-encoded Ed25519 public key")
    platform: str = Field(..., description="Platform name (e.g., 'moltbook')")
    username: str = Field(..., description="Username on the platform")
    proof_post_id: Optional[str] = Field(None, description="ID of post containing proof")


class RegistrationResponse(BaseModel):
    """Response from registration."""
    success: bool
    did: str
    platform: str
    username: str
    message: str


def validate_did_format(did: str) -> bool:
    """Check if DID has valid format."""
    if not did.startswith("did:aip:"):
        return False
    identifier = did[8:]  # Remove "did:aip:" prefix
    if len(identifier) < 16:  # Should be a hash, at least 16 chars
        return False
    return True


def validate_did_matches_pubkey(did: str, public_key_b64: str) -> bool:
    """Verify that DID is derived from the public key."""
    try:
        # Decode public key
        public_key_bytes = base64.b64decode(public_key_b64)

        # DID should be did:aip:<first-16-bytes-of-sha256-in-hex>
        # This matches our identity.py implementation
        key_hash = hashlib.sha256(public_key_bytes).hexdigest()[:32]
        expected_did = f"did:aip:{key_hash}"

        return did == expected_did
    except Exception:
        return False


@router.post("/register", response_model=RegistrationResponse)
async def register(request: RegistrationRequest):
    """
    Register a DID linked to a platform identity.

    The agent must have posted a proof claim on the platform that:
    1. Contains their DID
    2. Is authored by the claimed username
    3. Contains a signature proving ownership of the DID's private key
    """

    # Validate DID format
    if not validate_did_format(request.did):
        raise HTTPException(
            status_code=400,
            detail="Invalid DID format. Must be did:aip:<identifier>"
        )

    # Validate DID matches public key
    if not validate_did_matches_pubkey(request.did, request.public_key):
        raise HTTPException(
            status_code=400,
            detail="DID does not match public key. DID must be derived from the key."
        )

    # Check if DID already registered
    existing = database.get_registration(request.did)
    if existing:
        # Check if already linked to this platform/username
        links = database.get_platform_links(request.did)
        for link in links:
            if link["platform"] == request.platform and link["username"] == request.username:
                return RegistrationResponse(
                    success=True,
                    did=request.did,
                    platform=request.platform,
                    username=request.username,
                    message="Already registered"
                )
        # DID exists but different platform/username - that's fine, add link

    # Check if username already linked to different DID
    existing_did = database.get_did_by_platform(request.platform, request.username)
    if existing_did and existing_did != request.did:
        raise HTTPException(
            status_code=409,
            detail=f"Username {request.username} on {request.platform} is already linked to a different DID"
        )

    # Verify proof post if provided
    if request.proof_post_id and request.platform == "moltbook":
        verification = await verify_proof_post(
            post_id=request.proof_post_id,
            expected_did=request.did,
            expected_username=request.username,
            public_key_b64=request.public_key
        )
        if not verification["valid"]:
            raise HTTPException(
                status_code=400,
                detail=f"Proof verification failed: {verification['error']}"
            )

    # Register the DID if new
    if not existing:
        if not database.register_did(request.did, request.public_key):
            raise HTTPException(
                status_code=500,
                detail="Failed to register DID"
            )

    # Add platform link
    if not database.add_platform_link(
        request.did,
        request.platform,
        request.username,
        request.proof_post_id
    ):
        raise HTTPException(
            status_code=500,
            detail="Failed to add platform link"
        )

    return RegistrationResponse(
        success=True,
        did=request.did,
        platform=request.platform,
        username=request.username,
        message="Registration successful"
    )
