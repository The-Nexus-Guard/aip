"""
Handshake relay endpoints.

Allows agents to perform trust handshakes through the AIP service when they
can't reach each other directly. The service acts as a message relay, not a
verifier — agents verify each other's signatures themselves.

Flow:
  POST /handshake/initiate   — Agent A starts a handshake with Agent B
  GET  /handshake/pending     — Agent B checks for pending handshakes
  POST /handshake/respond     — Agent B responds to a handshake
  GET  /handshake/check       — Agent A checks for responses
  POST /handshake/confirm     — Agent A sends confirmation
  GET  /handshake/result      — Either side retrieves the final result
"""

import time
import uuid
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/handshake", tags=["Handshake"])

# In-memory store for handshake sessions (ephemeral — cleared on restart)
# In production, use the database, but for MVP this is fine.
_handshake_sessions = {}
_EXPIRY_SECONDS = 600  # 10 minutes


class InitiateRequest(BaseModel):
    initiator_did: str
    target_did: str
    message: dict  # The handshake initiate message


class RespondRequest(BaseModel):
    handshake_id: str
    message: dict  # The handshake respond message


class ConfirmRequest(BaseModel):
    handshake_id: str
    message: dict  # The handshake confirm message


def _cleanup_expired():
    """Remove expired handshake sessions."""
    now = time.time()
    expired = [k for k, v in _handshake_sessions.items()
               if now - v["created_at"] > _EXPIRY_SECONDS]
    for k in expired:
        del _handshake_sessions[k]


@router.post("/initiate")
async def initiate_handshake(req: InitiateRequest):
    """Start a handshake with another agent via the relay."""
    _cleanup_expired()

    handshake_id = str(uuid.uuid4())
    _handshake_sessions[handshake_id] = {
        "id": handshake_id,
        "initiator_did": req.initiator_did,
        "target_did": req.target_did,
        "state": "initiated",
        "initiate_message": req.message,
        "respond_message": None,
        "confirm_message": None,
        "created_at": time.time(),
    }

    return {
        "handshake_id": handshake_id,
        "state": "initiated",
        "message": "Handshake initiated. Target agent should check /handshake/pending.",
    }


@router.get("/pending")
async def pending_handshakes(did: str):
    """Check for pending handshakes addressed to this DID."""
    _cleanup_expired()

    pending = []
    for session in _handshake_sessions.values():
        if session["target_did"] == did and session["state"] == "initiated":
            pending.append({
                "handshake_id": session["id"],
                "initiator_did": session["initiator_did"],
                "message": session["initiate_message"],
                "created_at": session["created_at"],
            })

    return {"pending": pending, "count": len(pending)}


@router.post("/respond")
async def respond_handshake(req: RespondRequest):
    """Respond to a pending handshake."""
    session = _handshake_sessions.get(req.handshake_id)
    if not session:
        raise HTTPException(status_code=404, detail="Handshake not found or expired")
    if session["state"] != "initiated":
        raise HTTPException(status_code=409, detail=f"Handshake in state '{session['state']}', expected 'initiated'")

    session["respond_message"] = req.message
    session["state"] = "responded"

    return {
        "handshake_id": req.handshake_id,
        "state": "responded",
        "message": "Response recorded. Initiator should check /handshake/check.",
    }


@router.get("/check")
async def check_handshake(handshake_id: str):
    """Check the state of a handshake (initiator polls for response)."""
    session = _handshake_sessions.get(handshake_id)
    if not session:
        raise HTTPException(status_code=404, detail="Handshake not found or expired")

    result = {
        "handshake_id": handshake_id,
        "state": session["state"],
    }

    if session["state"] == "responded":
        result["message"] = session["respond_message"]
    elif session["state"] == "confirmed":
        result["message"] = session["confirm_message"]

    return result


@router.post("/confirm")
async def confirm_handshake(req: ConfirmRequest):
    """Send confirmation to complete the handshake."""
    session = _handshake_sessions.get(req.handshake_id)
    if not session:
        raise HTTPException(status_code=404, detail="Handshake not found or expired")
    if session["state"] != "responded":
        raise HTTPException(status_code=409, detail=f"Handshake in state '{session['state']}', expected 'responded'")

    session["confirm_message"] = req.message
    session["state"] = "confirmed"

    return {
        "handshake_id": req.handshake_id,
        "state": "confirmed",
        "message": "Handshake complete. Both sides can verify results.",
    }


@router.get("/result")
async def handshake_result(handshake_id: str):
    """Get the full handshake result (available to both parties)."""
    session = _handshake_sessions.get(handshake_id)
    if not session:
        raise HTTPException(status_code=404, detail="Handshake not found or expired")

    return {
        "handshake_id": handshake_id,
        "state": session["state"],
        "initiator_did": session["initiator_did"],
        "target_did": session["target_did"],
        "complete": session["state"] == "confirmed",
    }
