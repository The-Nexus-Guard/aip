"""
Verification endpoint - Check if a DID is registered.
"""

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import Optional, List
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import database

router = APIRouter()


class PlatformLink(BaseModel):
    """A link between a DID and a platform identity."""
    platform: str
    username: str
    proof_post_id: Optional[str]
    registered_at: str


class VerifyResponse(BaseModel):
    """Response from verification."""
    verified: bool
    did: Optional[str] = None
    public_key: Optional[str] = None
    platforms: Optional[List[PlatformLink]] = None
    message: str


@router.get("/verify", response_model=VerifyResponse)
async def verify(
    did: Optional[str] = Query(None, description="DID to verify"),
    platform: Optional[str] = Query(None, description="Platform name"),
    username: Optional[str] = Query(None, description="Username on platform")
):
    """
    Verify a DID registration.

    Can query by:
    - DID: Returns all platform links for that DID
    - Platform + Username: Returns the DID linked to that identity

    Examples:
    - GET /verify?did=did:aip:abc123
    - GET /verify?platform=moltbook&username=The_Nexus_Guard_001
    """

    # Must provide either DID or (platform + username)
    if not did and not (platform and username):
        raise HTTPException(
            status_code=400,
            detail="Must provide either 'did' or both 'platform' and 'username'"
        )

    # If querying by platform + username, look up the DID first
    if platform and username and not did:
        did = database.get_did_by_platform(platform, username)
        if not did:
            return VerifyResponse(
                verified=False,
                message=f"No DID registered for {username} on {platform}"
            )

    # Get registration
    registration = database.get_registration(did)
    if not registration:
        return VerifyResponse(
            verified=False,
            message=f"DID {did} is not registered"
        )

    # Get platform links
    links = database.get_platform_links(did)

    return VerifyResponse(
        verified=True,
        did=did,
        public_key=registration["public_key"],
        platforms=[
            PlatformLink(
                platform=link["platform"],
                username=link["username"],
                proof_post_id=link["proof_post_id"],
                registered_at=str(link["registered_at"])
            )
            for link in links
        ],
        message="DID is registered and verified"
    )


@router.get("/lookup/{platform}/{username}", response_model=VerifyResponse)
async def lookup_by_platform(platform: str, username: str):
    """
    Shorthand lookup by platform and username.

    Example: GET /lookup/moltbook/The_Nexus_Guard_001
    """
    # Look up the DID for this platform/username
    did = database.get_did_by_platform(platform, username)
    if not did:
        return VerifyResponse(
            verified=False,
            message=f"No DID registered for {username} on {platform}"
        )

    # Get registration
    registration = database.get_registration(did)
    if not registration:
        return VerifyResponse(
            verified=False,
            message=f"DID {did} is not registered"
        )

    # Get platform links
    links = database.get_platform_links(did)

    return VerifyResponse(
        verified=True,
        did=did,
        public_key=registration["public_key"],
        platforms=[
            PlatformLink(
                platform=link["platform"],
                username=link["username"],
                proof_post_id=link["proof_post_id"],
                registered_at=str(link["registered_at"])
            )
            for link in links
        ],
        message="DID is registered and verified"
    )


class RegistrationSummary(BaseModel):
    """Summary of a registration."""
    did: str
    created_at: str
    platforms: List[dict]


class ListRegistrationsResponse(BaseModel):
    """Response listing all registrations."""
    total: int
    limit: int
    offset: int
    registrations: List[RegistrationSummary]


@router.get("/registrations", response_model=ListRegistrationsResponse)
async def list_registrations(
    limit: int = Query(50, ge=1, le=100, description="Max results (1-100)"),
    offset: int = Query(0, ge=0, description="Offset for pagination")
):
    """
    List all registered agents.

    Returns DIDs with their linked platform identities.
    Useful for discovering who has registered with AIP.

    Example: GET /registrations?limit=20&offset=0
    """
    registrations = database.list_registrations(limit=limit, offset=offset)

    # Get total count from stats
    stats = database.get_stats()
    total = stats["registrations"]

    return ListRegistrationsResponse(
        total=total,
        limit=limit,
        offset=offset,
        registrations=[
            RegistrationSummary(
                did=reg["did"],
                created_at=str(reg["created_at"]),
                platforms=reg["platforms"]
            )
            for reg in registrations
        ]
    )


class GenerateProofRequest(BaseModel):
    """Request to generate a proof claim for posting."""
    did: str
    platform: str
    username: str


class GenerateProofResponse(BaseModel):
    """Response with proof claim template."""
    claim: dict
    post_template: str
    instructions: str


@router.post("/generate-proof", response_model=GenerateProofResponse)
async def generate_proof(request: GenerateProofRequest):
    """
    Generate a proof claim template that an agent can sign and post.

    The agent should:
    1. Sign the claim JSON with their private key
    2. Post the template (with signature) on the platform
    3. Use the post ID when calling /register

    This ensures only the private key holder can claim the identity.
    """
    import time

    claim = {
        "type": "aip-identity-claim",
        "did": request.did,
        "platform": request.platform,
        "username": request.username,
        "timestamp": int(time.time())
    }

    post_template = f"""I am claiming my AIP identity.

My DID: `{request.did}`
Platform: {request.platform}
Username: {request.username}

```aip-proof
{{
  "claim": {{"type": "aip-identity-claim", "did": "{request.did}", "platform": "{request.platform}", "username": "{request.username}", "timestamp": {int(time.time())}}},
  "signature": "<YOUR_SIGNATURE_HERE>"
}}
```

To verify: `curl "https://aip-service.fly.dev/verify?platform={request.platform}&username={request.username}"`
"""

    instructions = """To complete the proof:
1. Serialize the claim as JSON (keys sorted, no extra whitespace)
2. Sign the JSON bytes with your Ed25519 private key
3. Base64-encode the signature
4. Replace <YOUR_SIGNATURE_HERE> with your signature
5. Post this on the platform
6. Call /register with the post ID"""

    return GenerateProofResponse(
        claim=claim,
        post_template=post_template,
        instructions=instructions
    )
