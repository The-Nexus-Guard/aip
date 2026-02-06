"""
AIP Verification Service - Main FastAPI Application

Provides identity verification and trust management for AI agents.
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel, Field
from typing import Optional, List
import time
import os

# Import routes
from routes import register, verify, challenge, vouch, messaging, skill

app = FastAPI(
    title="AIP - Agent Identity Protocol",
    description="Cryptographic identity and trust verification for AI agents",
    version="0.2.0",
)

# CORS - allow all origins for now (agents calling from anywhere)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(register.router, tags=["Registration"])
app.include_router(verify.router, tags=["Verification"])
app.include_router(challenge.router, tags=["Challenge-Response"])
app.include_router(vouch.router, tags=["Trust"])
app.include_router(messaging.router, tags=["Messaging"])
app.include_router(skill.router, tags=["Skills"])


@app.get("/")
async def root():
    """Service health check and info."""
    return {
        "service": "AIP - Agent Identity Protocol",
        "version": "0.3.0",
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
    """Simple health check."""
    return {"status": "ok", "timestamp": int(time.time())}


@app.get("/stats")
async def stats():
    """Service statistics."""
    import database
    db_stats = database.get_stats()
    return {
        "service": "AIP - Agent Identity Protocol",
        "status": "operational",
        "stats": db_stats,
        "timestamp": int(time.time())
    }


@app.get("/badge/{did}")
async def get_badge(did: str):
    """
    Generate a dynamic SVG badge based on DID trust status.

    Returns:
        SVG badge showing: "Not Found", "Registered", "Vouched", or "Verified"
    """
    import database

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

        if vouch_count >= 3 and has_code_signing:
            # Verified - green
            color = "#00d4aa"
            text = "Verified"
            icon = "✓"
        elif vouch_count >= 1:
            # Vouched - blue
            color = "#4a9eff"
            text = f"Vouched ({vouch_count})"
            icon = "+"
        else:
            # Registered but no vouches - gray
            color = "#888"
            text = "Registered"
            icon = "○"

    # Generate SVG
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="120" height="28" viewBox="0 0 120 28">
  <defs>
    <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" style="stop-color:#1a1a2e"/>
      <stop offset="100%" style="stop-color:#16213e"/>
    </linearGradient>
  </defs>
  <rect width="120" height="28" rx="4" fill="url(#bg)"/>
  <circle cx="14" cy="14" r="8" fill="{color}"/>
  <text x="14" y="18" font-family="system-ui, sans-serif" font-size="10" font-weight="bold" fill="white" text-anchor="middle">{icon}</text>
  <text x="28" y="18" font-family="system-ui, sans-serif" font-size="12" font-weight="bold" fill="{color}">AIP</text>
  <text x="50" y="18" font-family="system-ui, sans-serif" font-size="10" fill="#888">{text}</text>
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
