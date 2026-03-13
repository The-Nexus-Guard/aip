"""
Verification endpoint - Check if a DID is registered.
Cross-protocol DID resolution for did:aip, did:key, did:web.
"""

import base64
import base58
import hashlib
import logging

import httpx
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
    registered_at: Optional[str] = None
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

    # Cross-protocol DID resolution
    logger = logging.getLogger("aip.resolve")

    if did.startswith("did:key:"):
        return await _resolve_did_key(did, req)
    elif did.startswith("did:web:"):
        return await _resolve_did_web(did, req)
    elif did.startswith("did:aps:"):
        return await _resolve_did_aps(did, req)
    elif not did.startswith("did:aip:"):
        raise HTTPException(
            status_code=400,
            detail="Unsupported DID method. Supported: did:aip, did:key, did:web, did:aps"
        )

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


async def _resolve_did_key(did: str, req: Request) -> ResolveResponse:
    """
    Resolve a did:key identifier.

    did:key encodes a public key directly in the identifier using multicodec.
    Format: did:key:z<multibase-encoded-multicodec-key>

    For Ed25519: multicodec prefix is 0xed01, multibase is z (base58btc).
    """
    logger = logging.getLogger("aip.resolve")

    try:
        # Extract the multibase-encoded key (z = base58btc)
        key_part = did[len("did:key:"):]
        if not key_part.startswith("z"):
            raise HTTPException(
                status_code=400,
                detail="did:key must use z (base58btc) multibase encoding"
            )

        decoded = base58.b58decode(key_part[1:])  # Skip 'z' prefix

        # Check multicodec prefix for Ed25519 (0xed 0x01)
        if len(decoded) < 34 or decoded[0] != 0xed or decoded[1] != 0x01:
            raise HTTPException(
                status_code=400,
                detail="Only Ed25519 did:key identifiers are supported (multicodec 0xed01)"
            )

        raw_pubkey = decoded[2:]  # 32 bytes Ed25519 public key
        pubkey_b64 = base64.b64encode(raw_pubkey).decode()

        # Check if this key is registered in AIP (cross-reference)
        pubkey_hash = hashlib.md5(raw_pubkey).hexdigest()
        aip_did = f"did:aip:{pubkey_hash}"
        aip_registration = database.get_registration(aip_did)

        base_url = str(req.base_url).rstrip("/")

        trust_info = None
        if aip_registration:
            vouches = database.get_vouches_for(aip_did)
            trust_info = {
                "vouch_count": len(vouches),
                "aip_did": aip_did,
                "cross_referenced": True,
                "trust_query_endpoint": f"/trust-path?target_did={aip_did}",
            }

        return ResolveResponse(
            did=did,
            public_key=pubkey_b64,
            public_key_type="Ed25519VerificationKey2020",
            registered_at=aip_registration["created_at"] if aip_registration else None,
            last_active=aip_registration.get("last_active") if aip_registration else None,
            platforms=None,
            trust=trust_info,
            verification_endpoint=f"{base_url}/verify?did={aip_did}" if aip_registration else f"{base_url}/resolve/{did}",
            challenge_endpoint=f"{base_url}/challenge/create",
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to resolve did:key: {e}")
        raise HTTPException(status_code=400, detail=f"Invalid did:key format: {str(e)}")


async def _resolve_did_web(did: str, req: Request) -> ResolveResponse:
    """
    Resolve a did:web identifier by fetching the DID document from the web.

    did:web:example.com -> https://example.com/.well-known/did.json
    did:web:example.com:path:to:doc -> https://example.com/path/to/doc/did.json
    """
    logger = logging.getLogger("aip.resolve")

    try:
        # Parse did:web to URL
        parts = did[len("did:web:"):].split(":")
        domain = parts[0].replace("%3A", ":")  # Handle port encoding
        path_parts = parts[1:] if len(parts) > 1 else [".well-known"]

        url = f"https://{domain}/{'/'.join(path_parts)}/did.json"

        # Fetch DID document with timeout and safety checks
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=True) as client:
            resp = await client.get(url)

        if resp.status_code != 200:
            raise HTTPException(
                status_code=502,
                detail=f"Failed to fetch DID document from {url} (status: {resp.status_code})"
            )

        did_doc = resp.json()

        # Extract Ed25519 public key from DID document
        pubkey_b64 = None
        pubkey_type = "Unknown"

        verification_methods = did_doc.get("verificationMethod", [])
        for vm in verification_methods:
            vm_type = vm.get("type", "")
            if "Ed25519" in vm_type:
                # Try publicKeyBase64, publicKeyMultibase, publicKeyBase58
                if "publicKeyBase64" in vm:
                    pubkey_b64 = vm["publicKeyBase64"]
                elif "publicKeyMultibase" in vm:
                    mb = vm["publicKeyMultibase"]
                    if mb.startswith("z"):
                        raw = base58.b58decode(mb[1:])
                        # Skip multicodec prefix if present
                        if len(raw) > 32 and raw[0] == 0xed and raw[1] == 0x01:
                            raw = raw[2:]
                        pubkey_b64 = base64.b64encode(raw).decode()
                elif "publicKeyBase58" in vm:
                    raw = base58.b58decode(vm["publicKeyBase58"])
                    pubkey_b64 = base64.b64encode(raw).decode()
                pubkey_type = "Ed25519VerificationKey2020"
                break

        if not pubkey_b64:
            raise HTTPException(
                status_code=422,
                detail="No Ed25519 verification method found in DID document"
            )

        base_url = str(req.base_url).rstrip("/")

        return ResolveResponse(
            did=did,
            public_key=pubkey_b64,
            public_key_type=pubkey_type,
            registered_at=did_doc.get("created"),
            last_active=did_doc.get("updated"),
            platforms=None,
            trust={"source": "did:web", "document_url": url},
            verification_endpoint=f"{base_url}/resolve/{did}",
            challenge_endpoint=f"{base_url}/challenge/create",
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to resolve did:web: {e}")
        raise HTTPException(status_code=400, detail=f"Failed to resolve did:web: {str(e)}")


# APS (Agent Passport System) endpoint for cross-protocol bridge
APS_API_BASE = "https://api.aeoess.com"


async def _resolve_did_aps(did: str, req: Request) -> ResolveResponse:
    """
    Resolve a did:aps identifier by querying the AEOESS Agent Passport System.

    did:aps:<agentId> -> proxy to api.aeoess.com for agent resolution.

    This is part of the AIP ↔ APS cross-protocol identity bridge.
    APS uses Ed25519 keys (hex-encoded) and a tiered reputation system (0-4)
    with Bayesian scoring (mu/sigma).
    """
    logger = logging.getLogger("aip.resolve")

    try:
        agent_id = did[len("did:aps:"):]
        if not agent_id:
            raise HTTPException(status_code=400, detail="did:aps requires an agent ID")

        # Query AEOESS API for the agent's card
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=True) as client:
            resp = await client.get(f"{APS_API_BASE}/api/cards/{agent_id}")

        base_url = str(req.base_url).rstrip("/")

        if resp.status_code == 200:
            card = resp.json()
            # Extract public key from card (APS uses hex-encoded Ed25519)
            pubkey_hex = card.get("publicKey", "")
            pubkey_b64 = None
            if pubkey_hex:
                try:
                    raw_key = bytes.fromhex(pubkey_hex)
                    pubkey_b64 = base64.b64encode(raw_key).decode()
                except ValueError:
                    pubkey_b64 = pubkey_hex  # Pass through if not valid hex

            # Extract trust/reputation info
            reputation = card.get("reputation", {})
            tier = card.get("tier")
            trust_info = {
                "source": "did:aps",
                "aps_agent_id": agent_id,
                "aps_tier": tier,
                "cross_referenced": False,
            }
            if reputation:
                trust_info["aps_reputation"] = reputation

            # Build trust summary in unified bridge format
            if reputation.get("mu") is not None:
                trust_info["trust_summary"] = {
                    "behavioral": reputation["mu"],
                    "behavioral_uncertainty": reputation.get("sigma"),
                }

            return ResolveResponse(
                did=did,
                public_key=pubkey_b64 or "",
                public_key_type="Ed25519VerificationKey2020",
                registered_at=card.get("createdAt"),
                last_active=card.get("updatedAt"),
                platforms=None,
                trust=trust_info,
                verification_endpoint=f"{APS_API_BASE}/api/cards/{agent_id}",
                challenge_endpoint=f"{base_url}/challenge/create",
            )
        elif resp.status_code == 404 or "No active card" in resp.text:
            # Agent exists but has no active card — return minimal info
            raise HTTPException(
                status_code=404,
                detail=f"APS agent '{agent_id}' not found or has no active card"
            )
        else:
            raise HTTPException(
                status_code=502,
                detail=f"Failed to query APS API (status: {resp.status_code})"
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to resolve did:aps: {e}")
        raise HTTPException(status_code=400, detail=f"Failed to resolve did:aps: {str(e)}")
