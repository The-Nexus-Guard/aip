"""
AIP Verification Service - Main FastAPI Application

Provides identity verification and trust management for AI agents.
"""

import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel, Field
from typing import Optional, List
import asyncio
import logging
import time
import os

# Import routes
from routes import register, verify, challenge, vouch, messaging, skill, onboard, admin, webhooks, profile
from rate_limit import default_limiter, check_rate_limit, rate_limit_headers

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage startup and shutdown lifecycle."""
    app.state.start_time = int(time.time())
    app.state.last_cleanup_stats = {}
    cleanup_task = asyncio.create_task(_periodic_cleanup())
    yield
    cleanup_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError:
        pass

app = FastAPI(
    title="AIP - Agent Identity Protocol",
    description="Cryptographic identity and trust verification for AI agents",
    version="0.5.18",
    lifespan=lifespan,
)

# CORS - restricted to known origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://the-nexus-guard.github.io",
        "https://aip-service.fly.dev",
        "https://www.moltbook.com",
    ],
    allow_origin_regex=r"http://(localhost|127\.0\.0\.1)(:\d+)?" if os.environ.get("AIP_DEV_MODE") else None,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
)

@app.middleware("http")
async def add_rate_limit_headers(request: Request, call_next):
    """Add X-RateLimit-* headers to all API responses."""
    response = await call_next(request)
    # Skip health/root endpoints (no rate limiting)
    path = request.url.path
    if path in ("/", "/health", "/docs", "/openapi.json", "/redoc"):
        return response
    # Add default rate limit info based on client IP
    client_ip = request.client.host if request.client else "unknown"
    remaining = default_limiter.get_remaining(client_ip)
    now = int(time.time())
    window_start = now - (now % default_limiter.window_seconds)
    reset_at = window_start + default_limiter.window_seconds
    # Only add headers if not already present (route-specific headers take priority)
    if "X-RateLimit-Limit" not in response.headers:
        response.headers["X-RateLimit-Limit"] = str(default_limiter.max_requests)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(reset_at)
    return response


# Include routers
app.include_router(register.router, tags=["Registration"])
app.include_router(verify.router, tags=["Verification"])
app.include_router(challenge.router, tags=["Challenge-Response"])
app.include_router(vouch.router, tags=["Trust"])
app.include_router(messaging.router, tags=["Messaging"])
app.include_router(skill.router, tags=["Skills"])
app.include_router(onboard.router, tags=["Onboarding"])
app.include_router(admin.router, tags=["Admin"])
app.include_router(webhooks.router, tags=["Webhooks"])
app.include_router(profile.router, tags=["Profiles"])


logger = logging.getLogger("aip.cleanup")

CLEANUP_INTERVAL_SECONDS = 300  # 5 minutes


async def _periodic_cleanup():
    """Background task that cleans up expired data every 5 minutes."""
    import database

    while True:
        try:
            await asyncio.sleep(CLEANUP_INTERVAL_SECONDS)
            stats = database.run_all_cleanup()
            app.state.last_cleanup_stats = {
                **stats,
                "last_run": int(time.time()),
            }
            total = sum(v for v in stats.values() if isinstance(v, int) and v > 0)
            if total > 0:
                logger.info(f"Cleanup completed: {stats}")
        except Exception as e:
            logger.error(f"Cleanup error: {e}")


@app.get("/")
async def root():
    """Service health check and info."""
    return {
        "service": "AIP - Agent Identity Protocol",
        "version": app.version,
        "status": "operational",
        "endpoints": {
            "register": "POST /register - Register a DID with platform identity",
            "verify": "GET /verify - Verify a DID's registration",
            "challenge": "POST /challenge - Get a verification challenge",
            "verify_challenge": "POST /verify-challenge - Verify a signed challenge",
            "vouch": "POST /vouch - Create a trust vouch",
            "trust_graph": "GET /trust-graph - Get trust relationships",
            "trust_path": "GET /trust-path - Find trust path between two DIDs",
            "rotate_key": "POST /rotate-key - Rotate DID keypair",
            "message": "POST /message - Send encrypted message to another agent",
            "messages": "POST /messages - Get your messages (requires challenge-response)",
            "lookup": "GET /lookup/{did} - Get public key for encryption",
            "skill_sign": "POST /skill/sign - Sign a skill with your DID",
            "skill_verify": "GET /skill/verify - Verify a skill signature",
        },
        "docs": "/docs",
    }


@app.get("/health")
async def health():
    """Detailed health check with service status."""
    import database

    # Check database connectivity
    try:
        db_stats = database.get_stats()
        db_ok = True
        db_error = None
    except Exception as e:
        db_ok = False
        db_error = str(e)
        db_stats = {}

    uptime_seconds = int(time.time()) - app.state.start_time if hasattr(app.state, 'start_time') else 0

    cleanup_stats = getattr(app.state, 'last_cleanup_stats', {})

    return {
        "status": "healthy" if db_ok else "degraded",
        "timestamp": int(time.time()),
        "version": app.version,
        "checks": {
            "database": {"ok": db_ok, "error": db_error},
        },
        "metrics": {
            "registrations": db_stats.get("registrations", 0),
            "active_vouches": db_stats.get("active_vouches", 0),
            "uptime_seconds": uptime_seconds
        },
        "cleanup": cleanup_stats
    }


@app.get("/badge/{did}")
async def get_badge(did: str, req: Request, size: str = "medium"):
    """
    Generate a dynamic SVG badge based on DID trust status.

    Args:
        did: The DID to generate a badge for
        size: Badge size - "small" (80x20), "medium" (120x28), or "large" (160x36)

    Returns:
        SVG badge showing: "Not Found", "Registered", "Verified", "Vouched (N)", or "Trusted"
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
    import database

    # Size presets
    sizes = {
        "small": {"w": 80, "h": 20, "r": 6, "fs1": 8, "fs2": 9, "fs3": 7, "cx": 10, "cy": 10, "tx1": 20, "tx2": 36},
        "medium": {"w": 120, "h": 28, "r": 8, "fs1": 10, "fs2": 12, "fs3": 10, "cx": 14, "cy": 14, "tx1": 28, "tx2": 50},
        "large": {"w": 160, "h": 36, "r": 10, "fs1": 12, "fs2": 14, "fs3": 12, "cx": 18, "cy": 18, "tx1": 36, "tx2": 66}
    }
    s = sizes.get(size, sizes["medium"])

    # Check if DID is registered
    agent = database.get_registration(did)
    if not agent:
        # Not registered - gray badge
        color = "#666"
        text = "Not Found"
        icon = "?"
    else:
        # Get vouch count
        vouches = database.get_vouches_for(did, include_expired=False)
        vouch_count = len(vouches)

        # Check for CODE_SIGNING scope
        has_code_signing = any(v.get('scope') == 'CODE_SIGNING' for v in vouches)

        # Check platform verification status
        platform_links = database.get_platform_links(did)
        is_platform_verified = any(pl.get('verified') for pl in platform_links)

        if vouch_count >= 3 and has_code_signing:
            # Trusted - green (vouched + code signing)
            color = "#00d4aa"
            text = "Trusted"
            icon = "✓"
        elif is_platform_verified:
            # Verified - blue (platform identity proven)
            color = "#4a9eff"
            text = "Verified"
            icon = "✓"
        elif vouch_count >= 1:
            # Vouched - blue
            color = "#4a9eff"
            text = f"Vouched ({vouch_count})"
            icon = "+"
        else:
            # Registered but no vouches and not verified - gray
            color = "#888"
            text = "Registered"
            icon = "○"

    # Generate SVG with size parameters
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{s['w']}" height="{s['h']}" viewBox="0 0 {s['w']} {s['h']}">
  <defs>
    <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" style="stop-color:#1a1a2e"/>
      <stop offset="100%" style="stop-color:#16213e"/>
    </linearGradient>
  </defs>
  <rect width="{s['w']}" height="{s['h']}" rx="4" fill="url(#bg)"/>
  <circle cx="{s['cx']}" cy="{s['cy']}" r="{s['r']}" fill="{color}"/>
  <text x="{s['cx']}" y="{s['cy'] + 4}" font-family="system-ui, sans-serif" font-size="{s['fs1']}" font-weight="bold" fill="white" text-anchor="middle">{icon}</text>
  <text x="{s['tx1']}" y="{s['cy'] + 4}" font-family="system-ui, sans-serif" font-size="{s['fs2']}" font-weight="bold" fill="{color}">AIP</text>
  <text x="{s['tx2']}" y="{s['cy'] + 4}" font-family="system-ui, sans-serif" font-size="{s['fs3']}" fill="#888">{text}</text>
</svg>'''

    # Cache for 5 minutes - badges update when vouches change
    headers = {
        "Cache-Control": "public, max-age=300",
        "ETag": f'"{did}-{vouch_count if agent else 0}"'
    }
    return Response(content=svg, media_type="image/svg+xml", headers=headers)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
