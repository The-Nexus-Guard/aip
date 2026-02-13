"""
Webhook endpoints - Register callbacks for AIP events.

Supported events: registration, vouch, message
"""

import asyncio
import hashlib
import hmac
import json
import logging
import time
import uuid
from typing import Optional, List

import httpx
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import database
from rate_limit import default_limiter

router = APIRouter()
logger = logging.getLogger("aip.webhooks")

VALID_EVENTS = {"registration", "vouch", "message"}


class WebhookCreateRequest(BaseModel):
    """Register a new webhook."""
    owner_did: str = Field(..., description="DID of the webhook owner")
    url: str = Field(..., description="HTTPS URL to receive POST notifications")
    events: List[str] = Field(default=["registration"], description="Events to subscribe to")
    secret: Optional[str] = Field(None, description="Shared secret for HMAC signature verification")
    signature: str = Field(..., description="Base64 Ed25519 signature of 'webhook:{url}' with owner's private key")


class WebhookResponse(BaseModel):
    id: str
    owner_did: str
    url: str
    events: List[str]
    created_at: str
    active: bool


class WebhookDeleteRequest(BaseModel):
    owner_did: str = Field(..., description="DID of the webhook owner")
    signature: str = Field(..., description="Base64 Ed25519 signature of 'delete-webhook:{webhook_id}' with owner's private key")


def _verify_signature(did: str, message: str, signature_b64: str) -> bool:
    """Verify an Ed25519 signature for a DID."""
    import base64
    import nacl.signing
    import nacl.exceptions

    reg = database.get_registration(did)
    if not reg:
        return False
    try:
        pub_key = base64.b64decode(reg["public_key"])
        sig = base64.b64decode(signature_b64)
        verify_key = nacl.signing.VerifyKey(pub_key)
        verify_key.verify(message.encode("utf-8"), sig)
        return True
    except (nacl.exceptions.BadSignatureError, Exception):
        return False


@router.post("/webhooks", response_model=WebhookResponse)
async def create_webhook(request: WebhookCreateRequest, req: Request):
    """Register a webhook to receive event notifications."""
    client_ip = req.client.host if req.client else "unknown"
    allowed, retry_after = default_limiter.is_allowed(client_ip)
    if not allowed:
        raise HTTPException(status_code=429, detail=f"Rate limit exceeded. Try again in {retry_after}s.")

    # Validate events
    invalid = set(request.events) - VALID_EVENTS - {"*"}
    if invalid:
        raise HTTPException(status_code=400, detail=f"Invalid events: {invalid}. Valid: {VALID_EVENTS}")

    # Validate URL
    if not request.url.startswith("https://"):
        raise HTTPException(status_code=400, detail="Webhook URL must use HTTPS")

    # Verify ownership
    if not _verify_signature(request.owner_did, f"webhook:{request.url}", request.signature):
        raise HTTPException(status_code=403, detail="Invalid signature - must sign 'webhook:{url}' with your private key")

    # Limit webhooks per DID
    existing = database.get_webhooks_by_owner(request.owner_did)
    if len(existing) >= 5:
        raise HTTPException(status_code=400, detail="Maximum 5 webhooks per DID")

    webhook_id = str(uuid.uuid4())
    events_str = ",".join(request.events)

    if not database.add_webhook(webhook_id, request.owner_did, request.url, events_str, request.secret):
        raise HTTPException(status_code=500, detail="Failed to create webhook")

    return WebhookResponse(
        id=webhook_id,
        owner_did=request.owner_did,
        url=request.url,
        events=request.events,
        created_at=str(int(time.time())),
        active=True,
    )


@router.get("/webhooks/{owner_did}")
async def list_webhooks(owner_did: str, req: Request):
    """List webhooks for a DID."""
    client_ip = req.client.host if req.client else "unknown"
    allowed, retry_after = default_limiter.is_allowed(client_ip)
    if not allowed:
        raise HTTPException(status_code=429, detail=f"Rate limit exceeded.")

    hooks = database.get_webhooks_by_owner(owner_did)
    return {
        "webhooks": [
            {
                "id": h["id"],
                "url": h["url"],
                "events": h["events"].split(","),
                "active": bool(h["active"]),
                "failure_count": h["failure_count"],
                "created_at": h["created_at"],
            }
            for h in hooks
        ],
        "count": len(hooks),
    }


@router.delete("/webhooks/{webhook_id}")
async def delete_webhook(webhook_id: str, request: WebhookDeleteRequest, req: Request):
    """Delete a webhook."""
    client_ip = req.client.host if req.client else "unknown"
    allowed, retry_after = default_limiter.is_allowed(client_ip)
    if not allowed:
        raise HTTPException(status_code=429, detail=f"Rate limit exceeded.")

    if not _verify_signature(request.owner_did, f"delete-webhook:{webhook_id}", request.signature):
        raise HTTPException(status_code=403, detail="Invalid signature")

    if not database.delete_webhook(webhook_id, request.owner_did):
        raise HTTPException(status_code=404, detail="Webhook not found or not owned by you")

    return {"success": True, "message": "Webhook deleted"}


@router.get("/webhooks/{webhook_id}/deliveries")
async def get_webhook_deliveries(webhook_id: str, req: Request, limit: int = 20):
    """Get delivery logs for a webhook. Limited to last 20 by default."""
    client_ip = req.client.host if req.client else "unknown"
    allowed, retry_after = default_limiter.is_allowed(client_ip)
    if not allowed:
        raise HTTPException(status_code=429, detail=f"Rate limit exceeded.")

    limit = min(limit, 100)
    deliveries = database.get_webhook_deliveries(webhook_id, limit=limit)
    return {
        "webhook_id": webhook_id,
        "deliveries": deliveries,
        "count": len(deliveries),
    }


async def fire_webhooks(event: str, payload: dict):
    """Fire all webhooks subscribed to an event. Non-blocking."""
    hooks = database.get_webhooks_for_event(event)
    if not hooks:
        return

    payload_json = json.dumps(payload, default=str)

    async def _send(hook):
        headers = {"Content-Type": "application/json", "X-AIP-Event": event}
        if hook.get("secret"):
            sig = hmac.new(hook["secret"].encode(), payload_json.encode(), hashlib.sha256).hexdigest()
            headers["X-AIP-Signature"] = f"sha256={sig}"

        start_ms = int(time.time() * 1000)
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(hook["url"], content=payload_json, headers=headers)
                duration = int(time.time() * 1000) - start_ms
                success = 200 <= resp.status_code < 300
                database.update_webhook_status(hook["id"], success)
                database.log_webhook_delivery(
                    hook["id"], event, success,
                    status_code=resp.status_code, duration_ms=duration
                )
                if not success:
                    logger.warning(f"Webhook {hook['id']} returned {resp.status_code}")
        except Exception as e:
            duration = int(time.time() * 1000) - start_ms
            database.update_webhook_status(hook["id"], False)
            database.log_webhook_delivery(
                hook["id"], event, False,
                error=str(e)[:500], duration_ms=duration
            )
            logger.error(f"Webhook {hook['id']} failed: {e}")

    # Fire all in background
    for hook in hooks:
        asyncio.create_task(_send(hook))
