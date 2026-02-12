"""
Admin endpoints - Read-only monitoring and listing.
"""

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

import database

router = APIRouter()


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
