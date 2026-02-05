"""
Messaging endpoints - Encrypted agent-to-agent communication.

Both sender and recipient must have registered DIDs.
Messages are end-to-end encrypted - AIP service cannot read content.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, List
import sys
import os
import uuid
import base64
import nacl.signing
import nacl.exceptions

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import database

router = APIRouter()


class SendMessageRequest(BaseModel):
    """Request to send an encrypted message."""
    sender_did: str = Field(..., description="Sender's DID")
    recipient_did: str = Field(..., description="Recipient's DID")
    encrypted_content: str = Field(..., description="Base64-encoded encrypted message")
    signature: str = Field(..., description="Sender's signature of the encrypted content")


class SendMessageResponse(BaseModel):
    """Response from sending a message."""
    success: bool
    message_id: str
    sent_at: str


class GetMessagesRequest(BaseModel):
    """Request to get messages - requires proof of ownership."""
    did: str = Field(..., description="Your DID")
    challenge: str = Field(..., description="Challenge from /challenge endpoint")
    signature: str = Field(..., description="Your signature of the challenge")
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
    signature: str = Field(..., description="Your signature of message_id")


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
async def send_message(request: SendMessageRequest):
    """
    Send an encrypted message to another agent.

    Requirements:
    - Sender must be registered
    - Recipient must be registered
    - Message must be encrypted with recipient's public key
    - Signature must be valid for sender's DID
    """

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

    # Verify signature
    if not verify_signature(request.sender_did, request.encrypted_content, request.signature):
        raise HTTPException(
            status_code=401,
            detail="Invalid signature"
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

    from datetime import datetime
    return SendMessageResponse(
        success=True,
        message_id=message_id,
        sent_at=datetime.utcnow().isoformat()
    )


@router.post("/messages", response_model=GetMessagesResponse)
async def get_messages(request: GetMessagesRequest):
    """
    Get your messages. Requires challenge-response proof.

    Flow:
    1. Call POST /challenge with your DID to get a challenge
    2. Sign the challenge with your private key
    3. Call this endpoint with the challenge and signature
    """

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
    from datetime import datetime
    expires_at = datetime.fromisoformat(challenge_data["expires_at"])
    if datetime.utcnow() > expires_at:
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


@router.delete("/message/{message_id}")
async def delete_message(message_id: str, did: str, signature: str):
    """
    Delete a message. Only the recipient can delete.

    Query params:
    - did: Your DID (must be the recipient)
    - signature: Your signature of the message_id
    """

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
async def message_count(did: str):
    """
    Get message count for a DID. No auth required - just returns counts.
    """
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
async def lookup_public_key(did: str):
    """
    Look up a DID's public key for encryption.

    Use this to get the recipient's public key before sending them a message.
    """
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
