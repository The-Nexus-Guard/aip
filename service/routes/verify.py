"""
Verification endpoint - Check if a DID is registered.
"""

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel
from typing import Optional, List
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import database
from rate_limit import default_limiter

router = APIRouter()


class PlatformLink(BaseModel):
    """A link between a DID and a platform identity."""
    platform: str
    username: str
    proof_post_id: Optional[str]
    verified: bool = False
    registered_at: str


class KeyHistoryEntry(BaseModel):
    """A historical key record for a DID."""
    public_key: str
    valid_from: str
    valid_until: Optional[str] = None
    is_current: bool


class VerifyResponse(BaseModel):
    """Response from verification."""
    verified: bool
    did: Optional[str] = None
    public_key: Optional[str] = None
    key_rotated: bool = False
    key_history: Optional[List[KeyHistoryEntry]] = None
    platforms: Optional[List[PlatformLink]] = None
    message: str


@router.get("/verify", response_model=VerifyResponse)
async def verify(
    req: Request,
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
    # Rate limit
    client_ip = req.client.host if req.client else "unknown"
    allowed, retry_after = default_limiter.is_allowed(client_ip)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)}
        )

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

    # Get platform links and key history
    links = database.get_platform_links(did)
    key_history = database.get_key_history(did)
    key_rotated = len(key_history) > 1

    return VerifyResponse(
        verified=True,
        did=did,
        public_key=registration["public_key"],
        key_rotated=key_rotated,
        key_history=[
            KeyHistoryEntry(
                public_key=kh["public_key"],
                valid_from=str(kh["valid_from"]),
                valid_until=str(kh["valid_until"]) if kh["valid_until"] else None,
                is_current=bool(kh["is_current"])
            )
            for kh in key_history
        ] if key_rotated else None,
        platforms=[
            PlatformLink(
                platform=link["platform"],
                username=link["username"],
                proof_post_id=link["proof_post_id"],
                verified=bool(link.get("verified")),
                registered_at=str(link["registered_at"])
            )
            for link in links
        ],
        message="DID is registered and verified" + (" (key has been rotated)" if key_rotated else "")
    )


class BatchVerifyRequest(BaseModel):
    """Batch verify multiple DIDs at once."""
    dids: List[str]


class BatchVerifyResult(BaseModel):
    did: str
    registered: bool
    platforms: Optional[List[PlatformLink]] = None


@router.post("/verify/batch")
async def verify_batch(request: BatchVerifyRequest, req: Request):
    """
    Verify multiple DIDs in a single request. Max 50 DIDs per call.
    """
    client_ip = req.client.host if req.client else "unknown"
    allowed, retry_after = default_limiter.is_allowed(client_ip)
    if not allowed:
        raise HTTPException(status_code=429, detail=f"Rate limit exceeded. Try again in {retry_after}s.")

    if len(request.dids) > 50:
        raise HTTPException(status_code=400, detail="Maximum 50 DIDs per batch request")

    results = []
    for did in request.dids:
        reg = database.get_registration(did)
        if not reg:
            results.append(BatchVerifyResult(did=did, registered=False))
        else:
            links = database.get_platform_links(did)
            results.append(BatchVerifyResult(
                did=did,
                registered=True,
                platforms=[
                    PlatformLink(
                        platform=l["platform"],
                        username=l["username"],
                        proof_post_id=l.get("proof_post_id"),
                        verified=bool(l.get("verified")),
                        registered_at=l.get("registered_at", ""),
                    )
                    for l in links
                ],
            ))

    return {"results": results, "count": len(results)}


@router.get("/lookup/{platform}/{username}", response_model=VerifyResponse)
async def lookup_by_platform(platform: str, username: str, req: Request = None):
    """
    Shorthand lookup by platform and username.

    Example: GET /lookup/moltbook/The_Nexus_Guard_001
    """
    # Rate limit
    client_ip = req.client.host if req and req.client else "unknown"
    allowed, retry_after = default_limiter.is_allowed(client_ip)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)}
        )

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

    # Get platform links and key history
    links = database.get_platform_links(did)
    key_history = database.get_key_history(did)
    key_rotated = len(key_history) > 1

    return VerifyResponse(
        verified=True,
        did=did,
        public_key=registration["public_key"],
        key_rotated=key_rotated,
        key_history=[
            KeyHistoryEntry(
                public_key=kh["public_key"],
                valid_from=str(kh["valid_from"]),
                valid_until=str(kh["valid_until"]) if kh["valid_until"] else None,
                is_current=bool(kh["is_current"])
            )
            for kh in key_history
        ] if key_rotated else None,
        platforms=[
            PlatformLink(
                platform=link["platform"],
                username=link["username"],
                proof_post_id=link["proof_post_id"],
                verified=bool(link.get("verified")),
                registered_at=str(link["registered_at"])
            )
            for link in links
        ],
        message="DID is registered and verified" + (" (key has been rotated)" if key_rotated else "")
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
    req: Request,
    limit: int = Query(50, ge=1, le=100, description="Max results (1-100)"),
    offset: int = Query(0, ge=0, description="Offset for pagination")
):
    """
    List all registered agents.

    Returns DIDs with their linked platform identities.
    Useful for discovering who has registered with AIP.

    Example: GET /registrations?limit=20&offset=0
    """
    # Rate limit
    client_ip = req.client.host if req.client else "unknown"
    allowed, retry_after = default_limiter.is_allowed(client_ip)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)}
        )

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
async def generate_proof(request: GenerateProofRequest, req: Request = None):
    """
    Generate a proof claim template that an agent can sign and post.

    The agent should:
    1. Sign the claim JSON with their private key
    2. Post the template (with signature) on the platform
    3. Use the post ID when calling /register

    This ensures only the private key holder can claim the identity.
    """
    # Rate limit
    client_ip = req.client.host if req and req.client else "unknown"
    allowed, retry_after = default_limiter.is_allowed(client_ip)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)}
        )

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
1. Serialize the claim as compact JSON with sorted keys: json.dumps(claim, sort_keys=True, separators=(',', ':'))
2. Encode to UTF-8 bytes
3. Sign the bytes with your Ed25519 private key (using nacl.signing.SigningKey.sign())
4. Base64-encode the 64-byte signature (not the combined signed message)
5. Replace <YOUR_SIGNATURE_HERE> with the base64 signature string
6. Post the ENTIRE template (including the ```aip-proof``` code block) on the platform
7. Call POST /register with the proof_post_id field set to the post's ID

IMPORTANT: The ```aip-proof``` code block is required. Posts without it will be rejected."""

    return GenerateProofResponse(
        claim=claim,
        post_template=post_template,
        instructions=instructions
    )


# --- Cross-Protocol DID Resolution ---

class ResolveResponse(BaseModel):
    """W3C DID Document-inspired response for cross-protocol identity resolution."""
    did: str
    public_key: str
    public_key_type: str = "Ed25519VerificationKey2020"
    registered_at: str
    last_active: Optional[str] = None
    platforms: Optional[List[PlatformLink]] = None
    trust: Optional[dict] = None
    verification_endpoint: str
    challenge_endpoint: str


@router.get("/resolve/{did}", response_model=ResolveResponse)
async def resolve_did(did: str, req: Request, include_trust: bool = True):
    """
    Resolve a DID to its identity document.

    Returns public key, platform links, trust metadata, and verification endpoints.
    Designed for cross-protocol identity resolution (e.g., APS ↔ AIP bridge).

    The response format is inspired by W3C DID Documents but simplified for
    practical agent-to-agent use.

    Examples:
    - GET /resolve/did:aip:abc123
    - GET /resolve/did:aip:abc123?include_trust=false
    """
    # Rate limit
    client_ip = req.client.host if req.client else "unknown"
    allowed, retry_after = default_limiter.is_allowed(client_ip)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)}
        )

    # Validate DID format
    if not did.startswith("did:aip:"):
        raise HTTPException(status_code=400, detail="Invalid DID format. Expected did:aip:<hash>")

    registration = database.get_registration(did)
    if not registration:
        raise HTTPException(status_code=404, detail="DID not found")

    # Get platform links
    platform_links = database.get_platform_links(did) if hasattr(database, 'get_platform_links') else []
    platforms = None
    if platform_links:
        platforms = [
            PlatformLink(
                platform=link.get("platform", ""),
                username=link.get("username", ""),
                proof_post_id=link.get("proof_post_id"),
                verified=link.get("verified", False),
                registered_at=link.get("registered_at", "")
            )
            for link in platform_links
        ]

    # Get trust info if requested
    trust_info = None
    if include_trust:
        vouches = database.get_vouches_for(did)
        vouch_summary = []
        for v in vouches[:10]:  # Limit to 10 most recent
            vouch_summary.append({
                "voucher_did": v["voucher_did"],
                "scope": v.get("scope", "IDENTITY"),
                "created_at": v["created_at"],
            })

        trust_info = {
            "vouch_count": len(vouches),
            "vouches": vouch_summary,
            "trust_query_endpoint": f"/trust-path?target_did={did}",
        }

    # Build base URL from request
    base_url = str(req.base_url).rstrip("/")

    return ResolveResponse(
        did=did,
        public_key=registration["public_key"],
        public_key_type="Ed25519VerificationKey2020",
        registered_at=registration["created_at"],
        last_active=registration.get("last_active"),
        platforms=platforms,
        trust=trust_info,
        verification_endpoint=f"{base_url}/verify?did={did}",
        challenge_endpoint=f"{base_url}/challenge/create",
    )
