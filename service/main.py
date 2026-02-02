"""
AIP Verification Service - Main FastAPI Application

Provides identity verification and trust management for AI agents.
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, List
import time
import os

# Import routes
from routes import register, verify, challenge, vouch

app = FastAPI(
    title="AIP - Agent Identity Protocol",
    description="Cryptographic identity and trust verification for AI agents",
    version="0.1.0",
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


@app.get("/")
async def root():
    """Service health check and info."""
    return {
        "service": "AIP - Agent Identity Protocol",
        "version": "0.1.0",
        "status": "operational",
        "endpoints": {
            "register": "POST /register - Register a DID with platform identity",
            "verify": "GET /verify - Verify a DID's registration",
            "challenge": "POST /challenge - Get a verification challenge",
            "verify_challenge": "POST /verify-challenge - Verify a signed challenge",
            "vouch": "POST /vouch - Create a trust vouch",
            "trust_graph": "GET /trust-graph - Get trust relationships",
        },
        "docs": "/docs",
    }


@app.get("/health")
async def health():
    """Simple health check."""
    return {"status": "ok", "timestamp": int(time.time())}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
