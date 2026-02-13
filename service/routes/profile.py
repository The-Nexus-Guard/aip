"""
Profile endpoints - Agent profile CRUD with challenge-response auth for writes.
"""

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Optional, List
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

import database
from rate_limit import default_limiter

router = APIRouter()


class ProfileUpdate(BaseModel):
    """Profile update request — requires challenge-response auth."""
    did: str
    display_name: Optional[str] = Field(None, max_length=200)
    bio: Optional[str] = Field(None, max_length=500)
    avatar_url: Optional[str] = Field(None, max_length=200)
    website: Optional[str] = Field(None, max_length=200)
    tags: Optional[List[str]] = Field(None, max_length=10)
    # Auth: challenge-response
    challenge: str
    signature: str


@router.get("/agent/{did}/profile")
async def get_profile(did: str, request: Request):
    """Get an agent's public profile."""
    client_ip = request.client.host if request.client else "unknown"
    allowed, retry_after = default_limiter.is_allowed(client_ip)
    if not allowed:
        raise HTTPException(status_code=429, detail=f"Rate limit exceeded. Retry in {retry_after}s.")

    # Check agent exists
    reg = database.get_registration(did)
    if not reg:
        raise HTTPException(status_code=404, detail="Agent not found")

    profile = database.get_profile(did)
    if not profile:
        # Return empty profile for registered agents
        return JSONResponse(content={
            "did": did,
            "display_name": None,
            "bio": None,
            "avatar_url": None,
            "website": None,
            "tags": [],
            "updated_at": None,
        })

    return JSONResponse(content=profile)


@router.put("/agent/{did}/profile")
async def update_profile(did: str, body: ProfileUpdate, request: Request):
    """Update an agent's profile. Requires challenge-response authentication."""
    client_ip = request.client.host if request.client else "unknown"
    allowed, retry_after = default_limiter.is_allowed(client_ip)
    if not allowed:
        raise HTTPException(status_code=429, detail=f"Rate limit exceeded. Retry in {retry_after}s.")

    if body.did != did:
        raise HTTPException(status_code=400, detail="DID in path must match DID in body")

    # Verify the agent exists
    reg = database.get_registration(did)
    if not reg:
        raise HTTPException(status_code=404, detail="Agent not found")

    # Verify challenge-response
    challenge_record = database.get_challenge(body.challenge)
    if not challenge_record:
        raise HTTPException(status_code=401, detail="Invalid challenge")
    if challenge_record["did"] != did:
        raise HTTPException(status_code=401, detail="Challenge does not match DID")
    if challenge_record["used"]:
        raise HTTPException(status_code=401, detail="Challenge already used")

    # Check expiry
    from datetime import datetime, timezone
    now = datetime.now(tz=timezone.utc).isoformat()
    if challenge_record["expires_at"] < now:
        raise HTTPException(status_code=401, detail="Challenge expired")

    # Verify signature
    import base64
    try:
        from nacl.signing import VerifyKey
        public_key_bytes = base64.b64decode(reg["public_key"])
        verify_key = VerifyKey(public_key_bytes)
        signature_bytes = base64.b64decode(body.signature)
        verify_key.verify(body.challenge.encode(), signature_bytes)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid signature")

    # Mark challenge as used
    database.mark_challenge_used(body.challenge)

    # Update profile
    fields = {}
    if body.display_name is not None:
        fields["display_name"] = body.display_name
    if body.bio is not None:
        fields["bio"] = body.bio
    if body.avatar_url is not None:
        fields["avatar_url"] = body.avatar_url
    if body.website is not None:
        fields["website"] = body.website
    if body.tags is not None:
        fields["tags"] = body.tags

    if not fields:
        raise HTTPException(status_code=400, detail="No profile fields provided")

    try:
        database.upsert_profile(did, **fields)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    profile = database.get_profile(did)
    return JSONResponse(content={"status": "updated", "profile": profile})
