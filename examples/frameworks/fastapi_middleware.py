"""
FastAPI + AIP Identity Middleware Example

Demonstrates how to add cryptographic identity verification to a FastAPI
agent service. Every incoming request is verified against the AIP registry,
and trust scores are checked before processing.

Usage:
    pip install aip-identity fastapi uvicorn
    python fastapi_middleware.py

    # In another terminal, send a signed request:
    python -c "
    from aip_identity.middleware import AIPMiddleware
    import requests
    mw = AIPMiddleware('client-agent')
    headers = mw.sign_request('POST', '/api/task', body='{\"task\": \"analyze\"}')
    r = requests.post('http://localhost:8000/api/task', headers=headers, json={'task': 'analyze'})
    print(r.json())
    "
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse

from aip_identity.middleware import AIPMiddleware, AIPIdentity


# --- Configuration ---
MIN_TRUST_SCORE = 0.0  # Minimum trust to accept requests (0.0 = any registered agent)
REQUIRE_VERIFICATION = True  # If True, reject unsigned requests


# --- Middleware setup ---
mw: Optional[AIPMiddleware] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize AIP identity on startup."""
    global mw
    mw = AIPMiddleware("fastapi-agent", platform="fastapi")
    print(f"🔐 Agent identity: {mw.did}")
    yield


app = FastAPI(
    title="AIP-Authenticated Agent Service",
    description="A FastAPI service with cryptographic agent identity verification",
    lifespan=lifespan,
)


# --- AIP verification middleware ---
@app.middleware("http")
async def verify_aip_identity(request: Request, call_next):
    """Verify AIP identity headers on incoming requests."""
    # Skip verification for docs and health endpoints
    if request.url.path in ("/docs", "/openapi.json", "/health", "/"):
        return await call_next(request)

    # Read body for signature verification
    body = await request.body()
    body_str = body.decode("utf-8") if body else None

    # Verify the request
    identity = mw.verify_request(
        headers=dict(request.headers),
        method=request.method,
        path=request.url.path,
        body=body_str,
    )

    # Store identity on request state for handlers to access
    request.state.identity = identity

    if REQUIRE_VERIFICATION and not identity.verified:
        return JSONResponse(
            status_code=401,
            content={
                "error": "unverified_identity",
                "message": "Request must include valid AIP identity headers",
                "required_headers": [
                    "X-AIP-DID",
                    "X-AIP-Signature",
                    "X-AIP-Timestamp",
                    "X-AIP-Nonce",
                ],
            },
        )

    if identity.trust_score < MIN_TRUST_SCORE:
        return JSONResponse(
            status_code=403,
            content={
                "error": "insufficient_trust",
                "message": f"Trust score {identity.trust_score} below minimum {MIN_TRUST_SCORE}",
                "did": identity.did,
            },
        )

    return await call_next(request)


# --- Routes ---
@app.get("/")
async def root():
    """Public endpoint — no verification required."""
    return {
        "service": "AIP-Authenticated Agent Service",
        "did": mw.did if mw else None,
        "endpoints": {
            "/api/task": "POST — Submit a task (requires AIP identity)",
            "/api/whoami": "GET — Check your verified identity",
            "/api/peers": "GET — List trusted peers on the network",
            "/health": "GET — Health check",
        },
    }


@app.get("/health")
async def health():
    return {"status": "ok", "did": mw.did if mw else None}


@app.get("/api/whoami")
async def whoami(request: Request):
    """Returns the verified identity of the caller."""
    identity: AIPIdentity = request.state.identity
    return {
        "your_did": identity.did,
        "verified": identity.verified,
        "trust_score": identity.trust_score,
        "platform": identity.platform,
    }


@app.post("/api/task")
async def submit_task(request: Request):
    """
    Submit a task for processing.
    Requires verified AIP identity.
    """
    identity: AIPIdentity = request.state.identity
    body = await request.json()

    return {
        "status": "accepted",
        "task": body.get("task", "unknown"),
        "submitted_by": identity.did,
        "trust_score": identity.trust_score,
        "message": f"Task accepted from verified agent (trust: {identity.trust_score})",
    }


@app.get("/api/peers")
async def list_peers(request: Request, min_trust: float = 0.0):
    """Discover other agents on the AIP network."""
    peers = mw.discover_peers(min_trust=min_trust)
    return {
        "count": len(peers),
        "peers": [
            {
                "did": p.get("did", ""),
                "name": p.get("name", ""),
                "platform": p.get("platform", ""),
                "trust_score": p.get("trust_score", 0),
            }
            for p in peers
        ],
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
