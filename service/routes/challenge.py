"""
Challenge-Response endpoints for live verification.
"""

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from typing import Optional
import sys
import os
import secrets
import base64
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

import database
from rate_limit import challenge_limiter

router = APIRouter()

# Challenge expiration in seconds
CHALLENGE_EXPIRY = 30


class ChallengeRequest(BaseModel):
    """Request for a verification challenge."""
    did: str = Field(..., description="DID to create challenge for")


class ChallengeResponse(BaseModel):
    """Response with challenge to sign."""
    challenge: str
    did: str
    expires_at: str
    message: str


class VerifyChallengeRequest(BaseModel):
    """Request to verify a signed challenge."""
    did: str = Field(..., description="DID that signed the challenge")
    challenge: str = Field(..., description="The challenge that was signed")
    signature: str = Field(..., description="Base64 Ed25519 signature of the challenge hex string (UTF-8 encoded)")


class VerifyChallengeResponse(BaseModel):
    """Response from challenge verification."""
    verified: bool
    did: Optional[str] = None
    timestamp: Optional[str] = None
    message: str


@router.post("/challenge", response_model=ChallengeResponse)
async def create_challenge(request: ChallengeRequest, req: Request):
    """
    Create a challenge for live identity verification.

    The returned challenge should be signed by the DID's private key
    and submitted to /verify-challenge within the expiration window.
    """
    # Rate limit by DID
    allowed, retry_after = challenge_limiter.is_allowed(f"challenge:{request.did}")
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)}
        )

    # Check if DID is registered
    registration = database.get_registration(request.did)
    if not registration:
        raise HTTPException(
            status_code=404,
            detail=f"DID {request.did} is not registered"
        )

    # Generate random challenge
    challenge = secrets.token_hex(32)

    # Calculate expiration
    from datetime import datetime, timedelta
    expires_at = datetime.utcnow() + timedelta(seconds=CHALLENGE_EXPIRY)

    # Store challenge
    database.create_challenge(request.did, challenge, CHALLENGE_EXPIRY)

    return ChallengeResponse(
        challenge=challenge,
        did=request.did,
        expires_at=expires_at.isoformat() + "Z",
        message=f"Sign this challenge and submit to /verify-challenge within {CHALLENGE_EXPIRY} seconds"
    )


@router.post("/verify-challenge", response_model=VerifyChallengeResponse)
async def verify_challenge(request: VerifyChallengeRequest, req: Request):
    """
    Verify a signed challenge to prove identity.

    The signature must be created by the private key corresponding
    to the DID's public key.
    """
    # Rate limit by DID
    allowed, retry_after = challenge_limiter.is_allowed(f"verify-challenge:{request.did}")
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)}
        )

    # Get the challenge
    challenge_record = database.get_challenge(request.challenge)
    if not challenge_record:
        return VerifyChallengeResponse(
            verified=False,
            message="Challenge not found or expired"
        )

    # Check if challenge is for the right DID
    if challenge_record["did"] != request.did:
        return VerifyChallengeResponse(
            verified=False,
            message="Challenge was not created for this DID"
        )

    # Check if already used
    if challenge_record["used"]:
        return VerifyChallengeResponse(
            verified=False,
            message="Challenge has already been used"
        )

    # Check expiration
    expires_at = datetime.fromisoformat(challenge_record["expires_at"])
    if datetime.utcnow() > expires_at:
        return VerifyChallengeResponse(
            verified=False,
            message="Challenge has expired"
        )

    # Get the registration to get public key
    registration = database.get_registration(request.did)
    if not registration:
        return VerifyChallengeResponse(
            verified=False,
            message="DID not registered"
        )

    # Verify signature
    try:
        public_key_b64 = registration["public_key"]
        public_key_bytes = base64.b64decode(public_key_b64)
        signature_bytes = base64.b64decode(request.signature)
        challenge_bytes = request.challenge.encode('utf-8')

        # Import Ed25519 verification
        try:
            # Try pure Python implementation first
            from pure25519.eddsa import verify as ed_verify
            from pure25519.eddsa import BadSignature

            try:
                ed_verify(public_key_bytes, challenge_bytes, signature_bytes)
                signature_valid = True
            except BadSignature:
                signature_valid = False
        except ImportError:
            # Fall back to nacl if available
            import nacl.signing
            verify_key = nacl.signing.VerifyKey(public_key_bytes)
            try:
                verify_key.verify(challenge_bytes, signature_bytes)
                signature_valid = True
            except nacl.exceptions.BadSignatureError:
                signature_valid = False

    except Exception as e:
        return VerifyChallengeResponse(
            verified=False,
            message=f"Signature verification error: {str(e)}"
        )

    if not signature_valid:
        return VerifyChallengeResponse(
            verified=False,
            message="Invalid signature"
        )

    # Mark challenge as used
    database.mark_challenge_used(request.challenge)

    return VerifyChallengeResponse(
        verified=True,
        did=request.did,
        timestamp=datetime.utcnow().isoformat() + "Z",
        message="Challenge verified - identity confirmed"
    )
