"""
Skill signing and verification endpoints.

Provides cryptographic provenance for skills:
- Sign a skill with your DID
- Verify a skill signature
- Get signing info for a skill hash
"""

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from typing import Optional, List
import sys
import os
import hashlib
import base64
import json
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

import database

router = APIRouter()


class SkillSignRequest(BaseModel):
    """Request to sign a skill."""
    author_did: str = Field(..., description="DID of the skill author")
    skill_content: str = Field(..., description="Full content of the skill.md file")
    signature: str = Field(..., description="Base64 signature of: author_did|sha256:hash|timestamp")


class SkillSignResponse(BaseModel):
    """Response from signing a skill."""
    success: bool
    content_hash: str
    timestamp: str
    signature_block: str = Field(..., description="Full signature block to embed in skill.md")
    verification_url: str


class SkillVerifyRequest(BaseModel):
    """Request to verify a skill signature."""
    content_hash: str = Field(..., description="SHA-256 hash of skill content (sha256:...)")
    author_did: str = Field(..., description="Claimed author DID")
    signature: str = Field(..., description="Base64 signature")
    timestamp: str = Field(..., description="ISO timestamp from signature")


class VouchInfo(BaseModel):
    """Information about a CODE_SIGNING vouch."""
    voucher_did: str
    voucher_platforms: List[dict]
    scope: str
    statement: Optional[str]
    created_at: str


class SkillVerifyResponse(BaseModel):
    """Response from verifying a skill signature."""
    verified: bool
    author_did: Optional[str] = None
    author_platforms: Optional[List[dict]] = None
    signed_at: Optional[str] = None
    code_signing_vouches: Optional[List[VouchInfo]] = None
    message: str


class SkillInfoResponse(BaseModel):
    """Information about a signed skill."""
    content_hash: str
    author_did: str
    author_platforms: List[dict]
    signed_at: str
    code_signing_vouches: List[VouchInfo]


@router.post("/skill/sign", response_model=SkillSignResponse, tags=["Skills"])
async def sign_skill(request: SkillSignRequest):
    """
    Generate a signature block for a skill.

    The author must:
    1. Be registered with AIP
    2. Sign the payload: {author_did}|sha256:{content_hash}|{timestamp}

    Returns a signature block that can be embedded at the top of skill.md.
    """

    # Verify author is registered
    author = database.get_registration(request.author_did)
    if not author:
        raise HTTPException(
            status_code=404,
            detail="Author DID is not registered with AIP"
        )

    # Calculate content hash
    content_hash = hashlib.sha256(request.skill_content.encode('utf-8')).hexdigest()
    hash_with_prefix = f"sha256:{content_hash}"

    # Generate timestamp
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Build expected payload
    expected_payload = f"{request.author_did}|{hash_with_prefix}|{timestamp}"

    # Verify signature
    try:
        public_key_bytes = base64.b64decode(author["public_key"])
        signature_bytes = base64.b64decode(request.signature)

        # Try to extract timestamp from signature verification
        # The signature should cover the payload including a timestamp
        # For flexibility, we'll accept signatures within a reasonable window

        # Verify using available crypto library
        try:
            from pure25519.eddsa import verify as ed_verify
            from pure25519.eddsa import BadSignature

            # Try with current timestamp
            payload_bytes = expected_payload.encode('utf-8')
            try:
                ed_verify(public_key_bytes, payload_bytes, signature_bytes)
                signature_valid = True
            except BadSignature:
                signature_valid = False
        except ImportError:
            import nacl.signing
            verify_key = nacl.signing.VerifyKey(public_key_bytes)
            payload_bytes = expected_payload.encode('utf-8')
            try:
                verify_key.verify(payload_bytes, signature_bytes)
                signature_valid = True
            except nacl.exceptions.BadSignatureError:
                signature_valid = False

        if not signature_valid:
            raise HTTPException(
                status_code=400,
                detail="Invalid signature. Sign the payload: {author_did}|sha256:{hash}|{timestamp}"
            )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Signature verification error: {str(e)}"
        )

    # Build signature block
    sig_data = {
        "version": "1.0",
        "author_did": request.author_did,
        "content_hash": hash_with_prefix,
        "timestamp": timestamp,
        "signature": request.signature
    }

    signature_block = f"""<!-- AIP-SIGNATURE
{json.dumps(sig_data, indent=2)}
-->

"""

    verification_url = f"https://aip-service.fly.dev/skill/verify?content_hash={hash_with_prefix}&author_did={request.author_did}"

    return SkillSignResponse(
        success=True,
        content_hash=hash_with_prefix,
        timestamp=timestamp,
        signature_block=signature_block,
        verification_url=verification_url
    )


@router.get("/skill/verify", response_model=SkillVerifyResponse, tags=["Skills"])
async def verify_skill(
    content_hash: str = Query(..., description="SHA-256 hash of skill content"),
    author_did: str = Query(..., description="Claimed author DID"),
    signature: str = Query(..., description="Base64 signature"),
    timestamp: str = Query(..., description="ISO timestamp from signature block")
):
    """
    Verify a skill signature.

    Checks:
    1. Author DID is registered
    2. Signature is valid for the claimed content hash
    3. Returns any CODE_SIGNING vouches for the author
    """

    # Get author registration
    author = database.get_registration(author_did)
    if not author:
        return SkillVerifyResponse(
            verified=False,
            message="Author DID is not registered with AIP"
        )

    # Build payload that should have been signed
    # Normalize hash format
    if not content_hash.startswith("sha256:"):
        content_hash = f"sha256:{content_hash}"

    payload = f"{author_did}|{content_hash}|{timestamp}"
    payload_bytes = payload.encode('utf-8')

    # Verify signature
    try:
        public_key_bytes = base64.b64decode(author["public_key"])
        signature_bytes = base64.b64decode(signature)

        try:
            from pure25519.eddsa import verify as ed_verify
            from pure25519.eddsa import BadSignature

            try:
                ed_verify(public_key_bytes, payload_bytes, signature_bytes)
                signature_valid = True
            except BadSignature:
                signature_valid = False
        except ImportError:
            import nacl.signing
            verify_key = nacl.signing.VerifyKey(public_key_bytes)
            try:
                verify_key.verify(payload_bytes, signature_bytes)
                signature_valid = True
            except nacl.exceptions.BadSignatureError:
                signature_valid = False

    except Exception as e:
        return SkillVerifyResponse(
            verified=False,
            message=f"Signature verification error: {str(e)}"
        )

    if not signature_valid:
        return SkillVerifyResponse(
            verified=False,
            message="Invalid signature - content may have been modified or wrong author"
        )

    # Get author's platform links
    platforms = database.get_platform_links(author_did)
    author_platforms = [
        {"platform": p["platform"], "username": p["username"]}
        for p in platforms
    ]

    # Get CODE_SIGNING vouches for the author
    vouches = database.get_vouches_for(author_did)
    code_signing_vouches = []

    for v in vouches:
        if v["scope"] == "CODE_SIGNING":
            # Get voucher's platforms
            voucher_platforms = database.get_platform_links(v["voucher_did"])
            code_signing_vouches.append(VouchInfo(
                voucher_did=v["voucher_did"],
                voucher_platforms=[
                    {"platform": p["platform"], "username": p["username"]}
                    for p in voucher_platforms
                ],
                scope=v["scope"],
                statement=v["statement"],
                created_at=str(v["created_at"])
            ))

    return SkillVerifyResponse(
        verified=True,
        author_did=author_did,
        author_platforms=author_platforms,
        signed_at=timestamp,
        code_signing_vouches=code_signing_vouches,
        message=f"Skill verified. Author has {len(code_signing_vouches)} CODE_SIGNING vouches."
    )


@router.post("/skill/hash", tags=["Skills"])
async def hash_skill(skill_content: str = Query(..., description="Skill content to hash")):
    """
    Calculate the SHA-256 hash of skill content.

    Utility endpoint for authors who want to calculate the hash
    before signing.
    """
    content_hash = hashlib.sha256(skill_content.encode('utf-8')).hexdigest()
    return {
        "content_hash": f"sha256:{content_hash}",
        "length": len(skill_content),
        "message": "Use this hash in your signature payload: {your_did}|sha256:{hash}|{timestamp}"
    }
