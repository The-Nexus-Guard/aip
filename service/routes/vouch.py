"""
Vouch endpoints for trust management.
"""

from fastapi import APIRouter, HTTPException, Query
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


@router.post("/vouch", response_model=VouchResponse)
async def create_vouch(request: VouchRequest):
    """
    Create a vouch (trust statement) for another agent.

    The vouch must be signed by the voucher's private key.
    The signature should be over: voucher_did|target_did|scope|statement
    """

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
