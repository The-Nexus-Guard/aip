"""
Vouch endpoints for trust management.
"""

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field
from typing import Optional, List
import sys
import os
import uuid
import base64
import json
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

import database
from rate_limit import vouch_limiter

router = APIRouter()

# Valid trust scopes
VALID_SCOPES = ["GENERAL", "CODE_SIGNING", "FINANCIAL", "INFORMATION", "IDENTITY"]


class VouchRequest(BaseModel):
    """Request to create a vouch."""
    voucher_did: str = Field(..., description="DID of the agent vouching")
    target_did: str = Field(..., description="DID being vouched for")
    scope: str = Field(..., description="Trust scope (GENERAL, CODE_SIGNING, etc.)")
    statement: Optional[str] = Field(None, description="Optional trust statement")
    signature: str = Field(..., description="Base64 signature of vouch payload")
    ttl_days: Optional[int] = Field(None, ge=1, le=365, description="Time-to-live in days (1-365, None=permanent)")


class VouchResponse(BaseModel):
    """Response from creating a vouch."""
    success: bool
    vouch_id: Optional[str] = None
    message: str


class VouchInfo(BaseModel):
    """Information about a vouch."""
    vouch_id: str
    voucher_did: str
    target_did: str
    scope: str
    statement: Optional[str]
    created_at: str
    expires_at: Optional[str] = None


class TrustGraphResponse(BaseModel):
    """Trust graph for a DID."""
    did: str
    vouched_by: List[VouchInfo]
    vouches_for: List[VouchInfo]


class RevokeRequest(BaseModel):
    """Request to revoke a vouch."""
    vouch_id: str = Field(..., description="ID of vouch to revoke")
    voucher_did: str = Field(..., description="DID of the voucher (must match)")
    signature: str = Field(..., description="Signature proving voucher identity")


class TrustPathResponse(BaseModel):
    """Response for trust path query."""
    source_did: str
    target_did: str
    scope: Optional[str] = None
    path_exists: bool
    path_length: Optional[int] = None
    path: Optional[List[str]] = None
    trust_chain: Optional[List[VouchInfo]] = None
    trust_score: Optional[float] = None  # 1.0 = direct trust, decays with each hop


class VouchCertificate(BaseModel):
    """
    Portable vouch certificate for offline verification.

    Contains all info needed to verify trust without querying the AIP service.
    The certificate is self-contained and cryptographically verifiable.
    """
    version: str = "1.0"
    vouch_id: str
    voucher_did: str
    voucher_public_key: str  # Base64 public key for offline verification
    target_did: str
    scope: str
    statement: Optional[str] = None
    created_at: str
    expires_at: Optional[str] = None
    signature: str  # Original vouch signature
    certificate_issued_at: str  # When this certificate was generated


@router.post("/vouch", response_model=VouchResponse)
async def create_vouch(request: VouchRequest, req: Request):
    """
    Create a vouch (trust statement) for another agent.

    The vouch must be signed by the voucher's private key.
    The signature should be over: voucher_did|target_did|scope|statement
    """
    # Rate limit check
    client_ip = req.client.host if req.client else "unknown"
    allowed, retry_after = vouch_limiter.is_allowed(client_ip)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)}
        )

    # Validate scope
    if request.scope not in VALID_SCOPES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid scope. Must be one of: {VALID_SCOPES}"
        )

    # Check voucher is registered
    voucher = database.get_registration(request.voucher_did)
    if not voucher:
        raise HTTPException(
            status_code=404,
            detail="Voucher DID is not registered"
        )

    # Check target is registered
    target = database.get_registration(request.target_did)
    if not target:
        raise HTTPException(
            status_code=404,
            detail="Target DID is not registered"
        )

    # Can't vouch for yourself
    if request.voucher_did == request.target_did:
        raise HTTPException(
            status_code=400,
            detail="Cannot vouch for yourself"
        )

    # Verify signature
    try:
        # Build payload that should have been signed
        payload = f"{request.voucher_did}|{request.target_did}|{request.scope}|{request.statement or ''}"
        payload_bytes = payload.encode('utf-8')

        public_key_bytes = base64.b64decode(voucher["public_key"])
        signature_bytes = base64.b64decode(request.signature)

        # Verify
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
            except nacl.exceptions.BadSignature:
                signature_valid = False

        if not signature_valid:
            raise HTTPException(
                status_code=400,
                detail="Invalid signature - vouch must be signed by voucher"
            )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Signature verification error: {str(e)}"
        )

    # Create vouch
    vouch_id = str(uuid.uuid4())
    success = database.create_vouch(
        vouch_id=vouch_id,
        voucher_did=request.voucher_did,
        target_did=request.target_did,
        scope=request.scope,
        statement=request.statement or "",
        signature=request.signature,
        ttl_days=request.ttl_days
    )

    if not success:
        raise HTTPException(
            status_code=500,
            detail="Failed to create vouch"
        )

    message = "Vouch created successfully"
    if request.ttl_days:
        message += f" (expires in {request.ttl_days} days)"

    return VouchResponse(
        success=True,
        vouch_id=vouch_id,
        message=message
    )


@router.get("/trust-graph", response_model=TrustGraphResponse)
async def get_trust_graph(
    did: str = Query(..., description="DID to get trust graph for")
):
    """
    Get the trust graph for a DID.

    Returns vouches received (vouched_by) and vouches given (vouches_for).
    """

    # Check DID is registered
    registration = database.get_registration(did)
    if not registration:
        raise HTTPException(
            status_code=404,
            detail="DID is not registered"
        )

    # Get vouches
    vouched_by = database.get_vouches_for(did)
    vouches_for = database.get_vouches_by(did)

    return TrustGraphResponse(
        did=did,
        vouched_by=[
            VouchInfo(
                vouch_id=v["id"],
                voucher_did=v["voucher_did"],
                target_did=did,
                scope=v["scope"],
                statement=v["statement"],
                created_at=str(v["created_at"]),
                expires_at=str(v["expires_at"]) if v.get("expires_at") else None
            )
            for v in vouched_by
        ],
        vouches_for=[
            VouchInfo(
                vouch_id=v["id"],
                voucher_did=did,
                target_did=v["target_did"],
                scope=v["scope"],
                statement=v["statement"],
                created_at=str(v["created_at"]),
                expires_at=str(v["expires_at"]) if v.get("expires_at") else None
            )
            for v in vouches_for
        ]
    )


@router.get("/trust-path", response_model=TrustPathResponse)
async def get_trust_path(
    source_did: str = Query(..., description="DID that wants to verify trust"),
    target_did: str = Query(..., description="DID being verified"),
    scope: Optional[str] = Query(None, description="Filter by trust scope"),
    max_depth: int = Query(5, ge=1, le=10, description="Maximum path length to search"),
    decay_factor: float = Query(0.8, ge=0.1, le=1.0, description="Trust decay per hop (0.8 = 80% retained per hop)")
):
    """
    Find a trust path between two DIDs with transitive trust decay.

    Returns the shortest path of vouches from source to target, along with
    a trust_score that decreases with each hop (isnad-style authentication).

    Trust scoring:
    - Direct trust (path length 0): trust_score = 1.0
    - 1 hop: trust_score = decay_factor (default 0.8)
    - 2 hops: trust_score = decay_factor^2 (default 0.64)
    - N hops: trust_score = decay_factor^N

    Example use cases:
    - Check if an MCP server is trusted via chain of vouches
    - Verify an agent before accepting their code
    - Find how two agents are connected in the trust network
    - Implement "trust but verify more for distant connections"
    """

    # Validate scope if provided
    if scope and scope not in VALID_SCOPES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid scope. Must be one of: {VALID_SCOPES}"
        )

    # Check both DIDs are registered
    source = database.get_registration(source_did)
    if not source:
        raise HTTPException(
            status_code=404,
            detail="Source DID is not registered"
        )

    target = database.get_registration(target_did)
    if not target:
        raise HTTPException(
            status_code=404,
            detail="Target DID is not registered"
        )

    # Same DID - trivially trusted
    if source_did == target_did:
        return TrustPathResponse(
            source_did=source_did,
            target_did=target_did,
            scope=scope,
            path_exists=True,
            path_length=0,
            path=[source_did],
            trust_chain=[],
            trust_score=1.0
        )

    # Find path
    path_vouches = database.find_trust_path(source_did, target_did, scope, max_depth)

    if path_vouches is None:
        return TrustPathResponse(
            source_did=source_did,
            target_did=target_did,
            scope=scope,
            path_exists=False,
            path_length=None,
            path=None,
            trust_chain=None,
            trust_score=0.0
        )

    # Build path of DIDs
    did_path = [source_did]
    for vouch in path_vouches:
        did_path.append(vouch["target_did"])

    # Convert vouches to VouchInfo
    trust_chain = [
        VouchInfo(
            vouch_id=v["id"],
            voucher_did=v["voucher_did"],
            target_did=v["target_did"],
            scope=v["scope"],
            statement=v["statement"],
            created_at=str(v["created_at"]),
            expires_at=str(v["expires_at"]) if v.get("expires_at") else None
        )
        for v in path_vouches
    ]

    # Calculate trust score with decay
    # Each hop reduces trust by decay_factor (isnad-style authentication)
    trust_score = decay_factor ** len(path_vouches)

    return TrustPathResponse(
        source_did=source_did,
        target_did=target_did,
        scope=scope,
        path_exists=True,
        path_length=len(path_vouches),
        path=did_path,
        trust_chain=trust_chain,
        trust_score=round(trust_score, 4)
    )


@router.post("/revoke", response_model=VouchResponse)
async def revoke_vouch(request: RevokeRequest):
    """
    Revoke a vouch.

    Only the original voucher can revoke their vouch.
    """

    # Get voucher registration
    voucher = database.get_registration(request.voucher_did)
    if not voucher:
        raise HTTPException(
            status_code=404,
            detail="Voucher DID is not registered"
        )

    # Verify signature (sign the vouch_id to prove identity)
    try:
        payload_bytes = request.vouch_id.encode('utf-8')
        public_key_bytes = base64.b64decode(voucher["public_key"])
        signature_bytes = base64.b64decode(request.signature)

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
            except nacl.exceptions.BadSignature:
                signature_valid = False

        if not signature_valid:
            raise HTTPException(
                status_code=400,
                detail="Invalid signature"
            )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Signature verification error: {str(e)}"
        )

    # Revoke
    success = database.revoke_vouch(request.vouch_id, request.voucher_did)
    if not success:
        raise HTTPException(
            status_code=404,
            detail="Vouch not found or already revoked"
        )

    return VouchResponse(
        success=True,
        vouch_id=request.vouch_id,
        message="Vouch revoked successfully"
    )


@router.get("/vouch/certificate/{vouch_id}", response_model=VouchCertificate)
async def get_vouch_certificate(vouch_id: str):
    """
    Export a vouch as a portable certificate for offline verification.

    The certificate contains:
    - The original vouch data (voucher, target, scope, statement)
    - The voucher's public key (for signature verification)
    - The original signature

    Clients can verify the certificate offline by:
    1. Reconstructing the signed payload: voucher_did|target_did|scope|statement
    2. Verifying the signature against voucher_public_key
    3. Checking expires_at hasn't passed

    This enables trust verification without querying AIP service.
    """
    # Get vouch from database
    with database.get_connection() as conn:
        cursor = conn.cursor()
        now = datetime.utcnow().isoformat()
        cursor.execute(
            """SELECT id, voucher_did, target_did, scope, statement, signature, created_at, expires_at
               FROM vouches
               WHERE id = ? AND revoked_at IS NULL
               AND (expires_at IS NULL OR expires_at > ?)""",
            (vouch_id, now)
        )
        row = cursor.fetchone()

    if not row:
        raise HTTPException(
            status_code=404,
            detail="Vouch not found, expired, or revoked"
        )

    vouch = dict(row)

    # Get voucher's public key
    voucher = database.get_registration(vouch["voucher_did"])
    if not voucher:
        raise HTTPException(
            status_code=404,
            detail="Voucher registration not found"
        )

    return VouchCertificate(
        version="1.0",
        vouch_id=vouch["id"],
        voucher_did=vouch["voucher_did"],
        voucher_public_key=voucher["public_key"],
        target_did=vouch["target_did"],
        scope=vouch["scope"],
        statement=vouch["statement"],
        created_at=str(vouch["created_at"]),
        expires_at=str(vouch["expires_at"]) if vouch.get("expires_at") else None,
        signature=vouch["signature"],
        certificate_issued_at=datetime.utcnow().isoformat()
    )


@router.post("/vouch/verify-certificate")
async def verify_vouch_certificate(certificate: VouchCertificate):
    """
    Verify a vouch certificate offline (no database lookup).

    This endpoint demonstrates certificate verification but the same logic
    can be performed entirely client-side without network access.

    Returns whether the certificate is cryptographically valid and not expired.
    """
    # Check expiration
    if certificate.expires_at:
        try:
            expires = datetime.fromisoformat(certificate.expires_at.replace('Z', '+00:00'))
            if expires < datetime.utcnow():
                return {
                    "valid": False,
                    "reason": "Certificate expired",
                    "expires_at": certificate.expires_at
                }
        except ValueError:
            pass  # Invalid date format, skip check

    # Reconstruct signed payload
    payload = f"{certificate.voucher_did}|{certificate.target_did}|{certificate.scope}|{certificate.statement or ''}"
    payload_bytes = payload.encode('utf-8')

    # Verify signature
    try:
        public_key_bytes = base64.b64decode(certificate.voucher_public_key)
        signature_bytes = base64.b64decode(certificate.signature)

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
            except nacl.exceptions.BadSignature:
                signature_valid = False

        if not signature_valid:
            return {
                "valid": False,
                "reason": "Invalid signature"
            }

    except Exception as e:
        return {
            "valid": False,
            "reason": f"Verification error: {str(e)}"
        }

    return {
        "valid": True,
        "voucher_did": certificate.voucher_did,
        "target_did": certificate.target_did,
        "scope": certificate.scope,
        "expires_at": certificate.expires_at
    }
