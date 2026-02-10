"""
Registration endpoint - Link DIDs to platform identities.
"""

from fastapi import APIRouter, HTTPException, Request
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
from rate_limit import registration_limiter

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


class EasyRegistrationRequest(BaseModel):
    """Request for easy registration - we generate the keypair."""
    platform: str = Field(..., description="Platform name (e.g., 'moltbook')")
    username: str = Field(..., description="Username on the platform")


class EasyRegistrationResponse(BaseModel):
    """Response from easy registration - includes private key (SAVE THIS!)."""
    success: bool
    did: str
    public_key: str
    private_key: str  # Base64-encoded - agent must save this!
    platform: str
    username: str
    message: str
    warning: str


class KeyRotationRequest(BaseModel):
    """Request to rotate a DID's public key."""
    did: str = Field(..., description="The DID to rotate keys for")
    new_public_key: str = Field(..., description="New base64-encoded Ed25519 public key")
    signature: str = Field(..., description="Signature of 'rotate:<new_public_key>' with OLD private key")
    mark_compromised: bool = Field(False, description="If true, revoke all vouches made with old key")


class KeyRotationResponse(BaseModel):
    """Response from key rotation."""
    success: bool
    did: str
    new_public_key: str
    vouches_revoked: int = 0
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
async def register(request: RegistrationRequest, req: Request):
    """
    Register a DID linked to a platform identity.

    The agent must have posted a proof claim on the platform that:
    1. Contains their DID
    2. Is authored by the claimed username
    3. Contains a signature proving ownership of the DID's private key
    """
    # Rate limit check
    client_ip = req.client.host if req.client else "unknown"
    allowed, retry_after = registration_limiter.is_allowed(client_ip)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)}
        )

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


@router.post("/register/easy", response_model=EasyRegistrationResponse)
async def register_easy(request: EasyRegistrationRequest, req: Request):
    """
    Easy registration - we generate a keypair for you.

    IMPORTANT: Save the private_key from the response! You'll need it for:
    - Challenge-response verification
    - Creating vouches
    - Proving your identity

    If you lose the private key, you lose control of this identity.
    """
    # Rate limit check
    client_ip = req.client.host if req.client else "unknown"
    allowed, retry_after = registration_limiter.is_allowed(client_ip)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)}
        )

    # Check if username already registered
    existing_did = database.get_did_by_platform(request.platform, request.username)
    if existing_did:
        raise HTTPException(
            status_code=409,
            detail=f"Username {request.username} on {request.platform} is already registered. Use /verify to look it up."
        )

    # Generate keypair using PyNaCl
    import nacl.signing
    signing_key = nacl.signing.SigningKey.generate()
    private_key = bytes(signing_key)
    public_key = bytes(signing_key.verify_key)

    # Create DID from public key
    key_hash = hashlib.sha256(public_key).hexdigest()[:32]
    did = f"did:aip:{key_hash}"

    # Encode keys as base64
    public_key_b64 = base64.b64encode(public_key).decode()
    private_key_b64 = base64.b64encode(private_key).decode()

    # Register
    if not database.register_did(did, public_key_b64):
        raise HTTPException(
            status_code=500,
            detail="Failed to register DID"
        )

    if not database.add_platform_link(did, request.platform, request.username, None):
        raise HTTPException(
            status_code=500,
            detail="Failed to add platform link"
        )

    return EasyRegistrationResponse(
        success=True,
        did=did,
        public_key=public_key_b64,
        private_key=private_key_b64,
        platform=request.platform,
        username=request.username,
        message="Registration successful! SAVE YOUR PRIVATE KEY!",
        warning="Store your private_key securely. If you lose it, you lose this identity forever."
    )


@router.post("/rotate-key", response_model=KeyRotationResponse)
async def rotate_key(request: KeyRotationRequest):
    """
    Rotate the public key for a DID.

    This allows an agent to update their keypair while keeping the same DID.
    The request must be signed with the OLD private key to prove ownership.

    Use cases:
    - Periodic key rotation for security hygiene
    - Recovery after suspected compromise (with mark_compromised=true)
    - Migration to different key storage

    If mark_compromised=true, all vouches made by this DID will be revoked.
    This signals to others that previous attestations may not be trustworthy.
    """
    import nacl.signing
    import nacl.exceptions

    # Check if DID exists
    registration = database.get_registration(request.did)
    if not registration:
        raise HTTPException(
            status_code=404,
            detail=f"DID {request.did} is not registered"
        )

    # Verify signature with OLD public key
    old_public_key_b64 = registration["public_key"]
    try:
        old_public_key_bytes = base64.b64decode(old_public_key_b64)
        signature_bytes = base64.b64decode(request.signature)

        # Message format: "rotate:<new_public_key_b64>"
        message = f"rotate:{request.new_public_key}".encode('utf-8')

        verify_key = nacl.signing.VerifyKey(old_public_key_bytes)
        verify_key.verify(message, signature_bytes)

    except nacl.exceptions.BadSignatureError:
        raise HTTPException(
            status_code=400,
            detail="Invalid signature - must sign 'rotate:<new_public_key>' with OLD private key"
        )
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Signature verification error: {str(e)}"
        )

    # Validate new public key format
    try:
        new_key_bytes = base64.b64decode(request.new_public_key)
        if len(new_key_bytes) != 32:
            raise ValueError("Ed25519 public key must be 32 bytes")
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid new public key format: {str(e)}"
        )

    # Rotate the key
    if not database.rotate_key(request.did, request.new_public_key):
        raise HTTPException(
            status_code=500,
            detail="Failed to rotate key"
        )

    # Optionally mark old key as compromised (revokes vouches)
    vouches_revoked = 0
    if request.mark_compromised:
        vouches_revoked = database.mark_key_compromised(request.did)

    message = "Key rotated successfully"
    if request.mark_compromised:
        message += f". {vouches_revoked} vouch(es) revoked due to compromised key."

    return KeyRotationResponse(
        success=True,
        did=request.did,
        new_public_key=request.new_public_key,
        vouches_revoked=vouches_revoked,
        message=message
    )
