"""
Webhook endpoints - Register callbacks for AIP events.

Supported events: registration, vouch, message
"""

import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
import socket
import time
import uuid
from typing import Optional, List
from urllib.parse import urlparse

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


def _is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is private/internal."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast
    except ValueError:
        return True  # If we can't parse it, block it


def _resolve_safe_ips(url: str) -> list:
    """Resolve a URL's hostname and return list of safe IPs, or empty list if any are private."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return []
        addrs = socket.getaddrinfo(hostname, parsed.port or 443, proto=socket.IPPROTO_TCP)
        ips = list(set(sockaddr[0] for _, _, _, _, sockaddr in addrs))
        for ip_str in ips:
            if _is_private_ip(ip_str):
                return []
        return ips
    except (socket.gaierror, ValueError):
        return []


def _is_safe_url(url: str) -> bool:
    """Check that a webhook URL doesn't resolve to private/internal IPs (SSRF protection)."""
    return len(_resolve_safe_ips(url)) > 0


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

    # Validate URL (SSRF protection)
    if not request.url.startswith("https://"):
        raise HTTPException(status_code=400, detail="Webhook URL must use HTTPS")

    if not _is_safe_url(request.url):
        raise HTTPException(status_code=400, detail="Webhook URL resolves to a private/internal IP address")

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
async def get_webhook_deliveries(webhook_id: str, req: Request, owner_did: str = None, limit: int = 20):
    """Get delivery logs for a webhook. Requires owner_did for ownership verification."""
    client_ip = req.client.host if req.client else "unknown"
    allowed, retry_after = default_limiter.is_allowed(client_ip)
    if not allowed:
        raise HTTPException(status_code=429, detail=f"Rate limit exceeded.")

    if not owner_did:
        raise HTTPException(status_code=400, detail="owner_did query parameter required")

    # Verify the webhook belongs to this DID
    owner_hooks = database.get_webhooks_by_owner(owner_did)
    if not any(h["id"] == webhook_id for h in owner_hooks):
        raise HTTPException(status_code=403, detail="Webhook not found or not owned by this DID")

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
        # SSRF check at delivery time too (DNS could change)
        if not _is_safe_url(hook["url"]):
            logger.warning(f"Webhook {hook['id']} blocked: URL resolves to private IP")
            database.update_webhook_status(hook["id"], False)
            database.log_webhook_delivery(hook["id"], event, False, error="SSRF: private IP")
            return

        headers = {"Content-Type": "application/json", "X-AIP-Event": event}
        if hook.get("secret"):
            sig = hmac.new(hook["secret"].encode(), payload_json.encode(), hashlib.sha256).hexdigest()
            headers["X-AIP-Signature"] = f"sha256={sig}"

        start_ms = int(time.time() * 1000)
        try:
            # Disable redirects to prevent SSRF via redirect to internal IP
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
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
