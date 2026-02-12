"""
Messaging endpoints - Encrypted agent-to-agent communication.

Both sender and recipient must have registered DIDs.
Messages are end-to-end encrypted - AIP service cannot read content.

BREAKING CHANGE (2026-02-10): Message signing payload changed from just
encrypted_content to: sender_did|recipient_did|timestamp|encrypted_content
Clients MUST include a timestamp field. Old format accepted with deprecation warning.
"""

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from typing import Optional, List
import sys
import os
import uuid
import base64
import hashlib
import time
import nacl.signing
import nacl.exceptions

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import database
from rate_limit import message_send_limiter, message_read_limiter, default_limiter

router = APIRouter()

# Replay protection: store recent signature hashes with their expiry time
# Format: {sig_hash: expiry_timestamp}
_recent_signatures: dict[str, float] = {}
_REPLAY_WINDOW_SECONDS = 300  # 5 minutes


def _cleanup_expired_signatures():
    """Remove expired entries from the replay cache."""
    now = time.time()
    expired = [k for k, v in _recent_signatures.items() if v < now]
    for k in expired:
        del _recent_signatures[k]


def _check_replay(signature: str) -> bool:
    """Check if signature was recently seen. Returns True if it's a replay."""
    _cleanup_expired_signatures()
    sig_hash = hashlib.sha256(signature.encode()).hexdigest()
    if sig_hash in _recent_signatures:
        return True
    _recent_signatures[sig_hash] = time.time() + _REPLAY_WINDOW_SECONDS
    return False


class SendMessageRequest(BaseModel):
    """Request to send an encrypted message."""
    sender_did: str = Field(..., description="Sender's DID")
    recipient_did: str = Field(..., description="Recipient's DID")
    encrypted_content: str = Field(..., description="Base64-encoded encrypted message")
    # BREAKING CHANGE: signature payload is now sender_did|recipient_did|timestamp|encrypted_content
    signature: str = Field(..., description="Base64 Ed25519 signature of: sender_did|recipient_did|timestamp|encrypted_content (UTF-8 encoded)")
    timestamp: Optional[str] = Field(None, description="ISO 8601 timestamp of message creation (required for new format)")


class SendMessageResponse(BaseModel):
    """Response from sending a message."""
    success: bool
    message_id: str
    sent_at: str
    deprecation_warning: Optional[str] = None


class GetMessagesRequest(BaseModel):
    """Request to get messages - requires proof of ownership."""
    did: str = Field(..., description="Your DID")
    challenge: str = Field(..., description="Challenge from /challenge endpoint")
    signature: str = Field(..., description="Base64 Ed25519 signature of the challenge string (UTF-8 encoded)")
    unread_only: bool = Field(False, description="Only return unread messages")


class Message(BaseModel):
    """A single message."""
    id: str
    sender_did: str
    encrypted_content: str
    signature: str
    created_at: str
    read_at: Optional[str] = None


class GetMessagesResponse(BaseModel):
    """Response with messages."""
    success: bool
    messages: List[Message]
    count: int


class DeleteMessageRequest(BaseModel):
    """Request to delete a message."""
    did: str = Field(..., description="Your DID (must be recipient)")
    message_id: str = Field(..., description="Message ID to delete")
    signature: str = Field(..., description="Base64 Ed25519 signature of the `message_id` string (UTF-8 encoded)")


def verify_signature(did: str, message: str, signature_b64: str) -> bool:
    """Verify a signature matches the DID's public key."""
    registration = database.get_registration(did)
    if not registration:
        return False

    try:
        public_key_bytes = base64.b64decode(registration["public_key"])
        signature_bytes = base64.b64decode(signature_b64)
        verify_key = nacl.signing.VerifyKey(public_key_bytes)
        verify_key.verify(message.encode(), signature_bytes)
        return True
    except (nacl.exceptions.BadSignatureError, Exception):
        return False


@router.post("/message", response_model=SendMessageResponse)
async def send_message(request: SendMessageRequest, req: Request):
    """
    Send an encrypted message to another agent.

    Requirements:
    - Sender must be registered
    - Recipient must be registered
    - Message must be encrypted with recipient's public key
    - Signature must be valid for sender's DID
    """
    # Rate limit by sender DID
    allowed, retry_after = message_send_limiter.is_allowed(f"msg-send:{request.sender_did}")
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)}
        )

    # Verify sender exists
    sender = database.get_registration(request.sender_did)
    if not sender:
        raise HTTPException(
            status_code=400,
            detail="Sender DID not registered"
        )

    # Verify recipient exists
    recipient = database.get_registration(request.recipient_did)
    if not recipient:
        raise HTTPException(
            status_code=400,
            detail="Recipient DID not registered. They must register at /register/easy first."
        )

    # Check for replay attacks
    if _check_replay(request.signature):
        raise HTTPException(
            status_code=409,
            detail="Duplicate message detected (replay). Each message must have a unique signature."
        )

    # Verify signature — new format includes sender, recipient, and timestamp
    deprecation_warning = None
    if request.timestamp:
        # New format: sender_did|recipient_did|timestamp|encrypted_content
        from datetime import datetime, timezone
        try:
            msg_time = datetime.fromisoformat(request.timestamp.replace("Z", "+00:00"))
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid timestamp format. Use ISO 8601.")

        now = datetime.now(timezone.utc)
        diff = abs((now - msg_time).total_seconds())
        if diff > _REPLAY_WINDOW_SECONDS:
            raise HTTPException(
                status_code=400,
                detail=f"Timestamp too far from server time ({int(diff)}s drift, max {_REPLAY_WINDOW_SECONDS}s). Check your clock."
            )

        sign_payload = f"{request.sender_did}|{request.recipient_did}|{request.timestamp}|{request.encrypted_content}"
        if not verify_signature(request.sender_did, sign_payload, request.signature):
            raise HTTPException(status_code=401, detail="Invalid signature")
    else:
        # Legacy format: just encrypted_content — accept with deprecation warning
        if not verify_signature(request.sender_did, request.encrypted_content, request.signature):
            raise HTTPException(status_code=401, detail="Invalid signature")
        deprecation_warning = (
            "DEPRECATED: Message signed with legacy format (encrypted_content only). "
            "Please sign: sender_did|recipient_did|timestamp|encrypted_content and include a timestamp field. "
            "Legacy format will be removed in a future version."
        )

    # Store message
    message_id = f"msg_{uuid.uuid4().hex[:16]}"
    if not database.store_message(
        message_id=message_id,
        sender_did=request.sender_did,
        recipient_did=request.recipient_did,
        encrypted_content=request.encrypted_content,
        signature=request.signature
    ):
        raise HTTPException(
            status_code=500,
            detail="Failed to store message"
        )

    from datetime import datetime, timezone
    response = SendMessageResponse(
        success=True,
        message_id=message_id,
        sent_at=datetime.now(tz=timezone.utc).isoformat()
    )
    if deprecation_warning:
        response.deprecation_warning = deprecation_warning
    return response


@router.post("/messages", response_model=GetMessagesResponse)
async def get_messages(request: GetMessagesRequest, req: Request):
    """
    Get your messages. Requires challenge-response proof.

    Flow:
    1. Call POST /challenge with your DID to get a challenge
    2. Sign the challenge with your private key
    3. Call this endpoint with the challenge and signature
    """
    # Rate limit by DID
    allowed, retry_after = message_read_limiter.is_allowed(f"msg-read:{request.did}")
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)}
        )

    # Verify the challenge exists and is valid
    challenge_data = database.get_challenge(request.challenge)
    if not challenge_data:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired challenge. Get a new one from /challenge"
        )

    if challenge_data["did"] != request.did:
        raise HTTPException(
            status_code=400,
            detail="Challenge was issued for a different DID"
        )

    if challenge_data["used"]:
        raise HTTPException(
            status_code=400,
            detail="Challenge already used. Get a new one from /challenge"
        )

    # Check expiry
    from datetime import datetime, timezone
    expires_at = datetime.fromisoformat(challenge_data["expires_at"])
    if datetime.now(tz=timezone.utc) > expires_at:
        raise HTTPException(
            status_code=400,
            detail="Challenge expired. Get a new one from /challenge"
        )

    # Verify signature
    if not verify_signature(request.did, request.challenge, request.signature):
        raise HTTPException(
            status_code=401,
            detail="Invalid signature"
        )

    # Mark challenge as used
    database.mark_challenge_used(request.challenge)

    # Get messages
    messages = database.get_messages_for(request.did, request.unread_only)

    return GetMessagesResponse(
        success=True,
        messages=[Message(**msg) for msg in messages],
        count=len(messages)
    )


@router.patch("/message/{message_id}/read")
async def mark_message_read(message_id: str, did: str, signature: str, req: Request = None):
    """
    Mark a message as read without deleting it.

    Query params:
    - did: Your DID (must be the recipient)
    - signature: Your signature of the message_id
    """
    allowed, retry_after = default_limiter.is_allowed(f"msg-read-mark:{did}")
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)}
        )

    if not verify_signature(did, message_id, signature):
        raise HTTPException(status_code=401, detail="Invalid signature")

    if not database.mark_message_read(message_id, did):
        raise HTTPException(
            status_code=404,
            detail="Message not found, already read, or you are not the recipient"
        )

    return {"success": True, "marked_read": message_id}


@router.delete("/message/{message_id}")
async def delete_message(message_id: str, did: str, signature: str, req: Request = None):
    """
    Delete a message. Only the recipient can delete.

    Query params:
    - did: Your DID (must be the recipient)
    - signature: Your signature of the message_id
    """
    # Rate limit
    allowed, retry_after = default_limiter.is_allowed(f"msg-del:{did}")
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)}
        )

    # Verify signature
    if not verify_signature(did, message_id, signature):
        raise HTTPException(
            status_code=401,
            detail="Invalid signature"
        )

    # Delete message
    if not database.delete_message(message_id, did):
        raise HTTPException(
            status_code=404,
            detail="Message not found or you are not the recipient"
        )

    return {"success": True, "deleted": message_id}


@router.get("/messages/count")
async def message_count(did: str, req: Request = None):
    """
    Get message count for a DID. No auth required - just returns counts.
    """
    # Rate limit
    allowed, retry_after = default_limiter.is_allowed(f"msg-count:{did}")
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)}
        )

    registration = database.get_registration(did)
    if not registration:
        raise HTTPException(
            status_code=404,
            detail="DID not registered"
        )

    counts = database.get_message_count(did)
    return {
        "did": did,
        "unread": counts["unread"],
        "sent": counts["sent"]
    }


@router.get("/lookup/{did}")
async def lookup_public_key(did: str, req: Request = None):
    """
    Look up a DID's public key for encryption.

    Use this to get the recipient's public key before sending them a message.
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

    registration = database.get_registration(did)
    if not registration:
        raise HTTPException(
            status_code=404,
            detail="DID not registered"
        )

    return {
        "did": did,
        "public_key": registration["public_key"],
        "registered_at": registration["created_at"]
    }
