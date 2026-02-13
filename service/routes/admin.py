"""
Admin endpoints - Monitoring, listing, and management.

Write operations (DELETE) require AIP_ADMIN_KEY bearer token.
"""

from fastapi import APIRouter, Query, Header, HTTPException
from fastapi.responses import JSONResponse
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

import database

router = APIRouter()

AIP_ADMIN_KEY = os.environ.get("AIP_ADMIN_KEY", "")


def _require_admin(authorization: str | None):
    """Validate admin bearer token."""
    if not AIP_ADMIN_KEY:
        raise HTTPException(status_code=503, detail="Admin key not configured")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    token = authorization[7:]
    if token != AIP_ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Invalid admin key")


@router.get("/admin/registrations")
async def list_registrations(
    limit: int = Query(default=50, ge=1, le=200, description="Max results"),
    offset: int = Query(default=0, ge=0, description="Pagination offset"),
):
    """List all registrations with platform links. Read-only monitoring endpoint."""
    registrations = database.list_registrations(limit=limit, offset=offset)
    return JSONResponse(content={
        "registrations": registrations,
        "count": len(registrations),
        "limit": limit,
        "offset": offset,
    })


@router.get("/stats")
async def get_stats():
    """Public network statistics — total agents, vouches, messages, platform breakdown, growth."""
    import time as _time
    stats = database.get_stats()

    # Add recent activity stats
    with database.get_connection() as conn:
        cursor = conn.cursor()

        # Recent registrations (last 7 days)
        cursor.execute(
            "SELECT COUNT(*) as count FROM registrations WHERE created_at > datetime('now', '-7 days')"
        )
        stats["registrations_last_7d"] = cursor.fetchone()["count"]

        # Recent vouches (last 7 days)
        cursor.execute(
            "SELECT COUNT(*) as count FROM vouches WHERE created_at > datetime('now', '-7 days') AND revoked_at IS NULL"
        )
        stats["vouches_last_7d"] = cursor.fetchone()["count"]

    return JSONResponse(content={
        "service": "AIP - Agent Identity Protocol",
        "status": "operational",
        "stats": stats,
        "timestamp": int(_time.time())
    })


@router.get("/admin/registrations/{did}")
async def get_registration(did: str):
    """Get details for a specific DID registration."""
    reg = database.get_registration(did)
    if not reg:
        return JSONResponse(status_code=404, content={"error": "DID not found"})

    # Get vouches for this DID
    vouches_given = database.get_vouches_by(did)
    vouches_received = database.get_vouches_for(did)

    return JSONResponse(content={
        "registration": reg,
        "vouches_given": vouches_given,
        "vouches_received": vouches_received,
    })


@router.delete("/admin/registrations/{did}")
async def delete_registration(did: str, authorization: str | None = Header(default=None)):
    """Delete a registration and all associated data. Requires admin bearer token."""
    _require_admin(authorization)

    deleted = database.delete_registration(did)
    if not deleted:
        return JSONResponse(status_code=404, content={"error": "DID not found"})

    return JSONResponse(content={"deleted": did, "status": "ok"})


@router.delete("/admin/registrations")
async def bulk_delete_registrations(
    pattern: str = Query(description="Username pattern to match (e.g. '*_daec21')"),
    dry_run: bool = Query(default=True, description="If true, only list matches without deleting"),
    authorization: str | None = Header(default=None),
):
    """Bulk delete registrations matching a username pattern. Requires admin bearer token.
    
    Default is dry_run=true for safety.
    """
    _require_admin(authorization)

    # Get all registrations and filter by platform username pattern
    all_regs = database.list_registrations(limit=200)
    import fnmatch
    matches = []
    for reg in all_regs:
        for platform in reg.get("platforms", []):
            if fnmatch.fnmatch(platform["username"], pattern):
                matches.append({"did": reg["did"], "username": platform["username"], "platform": platform["platform"]})
                break

    if dry_run:
        return JSONResponse(content={"matches": matches, "count": len(matches), "dry_run": True})

    deleted = []
    for match in matches:
        if database.delete_registration(match["did"]):
            deleted.append(match)

    return JSONResponse(content={"deleted": deleted, "count": len(deleted), "dry_run": False})
