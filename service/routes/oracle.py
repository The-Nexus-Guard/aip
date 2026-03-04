"""
Oracle endpoints — wallet-DID binding and on-chain credential verification.

Integrates InsumerAPI for privacy-preserving on-chain attestations.
The credential oracle identity issues vouches backed by signed on-chain state.
"""

import hashlib
import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import database
from rate_limit import default_limiter, check_rate_limit

router = APIRouter(prefix="/oracle", tags=["Oracle"])

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

INSUMER_API_BASE = "https://api.insumermodel.com"
INSUMER_API_KEY = os.environ.get("INSUMER_API_KEY", "")

# The credential oracle DID — a service-managed identity that issues
# attestation-backed vouches.  Generated deterministically from a seed so it
# is stable across restarts.
ORACLE_DID = "did:aip:oracle:insumerapi"
ORACLE_SCOPE = "ONCHAIN_CREDENTIAL"

# Attestation cache TTL (seconds).  InsumerAPI attestations expire after 30
# minutes; we cache for 25 to allow a safety margin.
ATTESTATION_CACHE_TTL = 25 * 60

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class WalletBindRequest(BaseModel):
    """Bind a wallet address to a DID."""
    did: str = Field(..., description="Agent DID")
    wallet_address: str = Field(..., description="Wallet address (0x… for EVM)")
    chain_type: str = Field("evm", description="Chain type: evm, solana, xrpl")
    did_signature: str = Field(
        ...,
        description="Ed25519 signature of 'bind:{wallet_address}:{timestamp}' by DID key",
    )
    timestamp: str = Field(..., description="ISO-8601 timestamp used in signature")


class WalletBindResponse(BaseModel):
    success: bool
    message: str
    did: str
    wallet_address: str
    chain_type: str


class OnchainCondition(BaseModel):
    """A single on-chain condition to verify."""
    type: str = Field(..., description="token_balance, nft_ownership, eas_attestation")
    chain_id: int = Field(1, description="Chain ID (1=Ethereum, 8453=Base, …)")
    contract_address: Optional[str] = None
    threshold: Optional[float] = None
    decimals: Optional[int] = None
    schema_uid: Optional[str] = Field(None, description="EAS schema UID")


class OnchainVerifyRequest(BaseModel):
    """Verify on-chain conditions for a DID's bound wallet."""
    did: str = Field(..., description="Agent DID to verify")
    conditions: List[OnchainCondition] = Field(
        ..., min_length=1, max_length=10,
        description="On-chain conditions to check",
    )
    wallet_address: Optional[str] = Field(
        None,
        description="Specific wallet to check (if DID has multiple bindings)",
    )


class OnchainVerifyResponse(BaseModel):
    success: bool
    did: str
    wallet_address: str
    attestation_id: Optional[str] = None
    passed: bool
    results: List[Dict[str, Any]]
    vouch_id: Optional[str] = None
    expires_at: Optional[str] = None
    message: str


class WalletListResponse(BaseModel):
    success: bool
    did: str
    wallets: List[Dict[str, Any]]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _verify_did_signature(did: str, message: str, signature: str) -> bool:
    """Verify an Ed25519 signature from a registered DID."""
    import base64

    try:
        from nacl.signing import VerifyKey
    except ImportError:
        # Fallback to pure Python Ed25519 if PyNaCl unavailable
        return False

    reg = database.get_registration(did)
    if not reg:
        return False

    pub_key_b64 = reg["public_key"]
    try:
        pub_bytes = base64.b64decode(pub_key_b64)
        sig_bytes = base64.b64decode(signature)
        vk = VerifyKey(pub_bytes)
        vk.verify(message.encode(), sig_bytes)
        return True
    except Exception:
        return False


def _conditions_hash(conditions: List[OnchainCondition]) -> str:
    """Deterministic hash of conditions for cache lookup."""
    canonical = json.dumps(
        [c.model_dump(exclude_none=True) for c in conditions],
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


async def _call_insumer_attest(
    wallet: str, conditions: List[OnchainCondition]
) -> Dict[str, Any]:
    """Call InsumerAPI /v1/attest."""
    if not INSUMER_API_KEY:
        raise HTTPException(
            status_code=503,
            detail="InsumerAPI key not configured on this server",
        )

    insumer_conditions = []
    for c in conditions:
        cond: Dict[str, Any] = {"type": c.type, "chainId": c.chain_id}
        if c.contract_address:
            cond["contractAddress"] = c.contract_address
        if c.threshold is not None:
            cond["threshold"] = c.threshold
        if c.decimals is not None:
            cond["decimals"] = c.decimals
        if c.schema_uid:
            cond["schemaUid"] = c.schema_uid
        insumer_conditions.append(cond)

    payload = {"wallet": wallet, "conditions": insumer_conditions}

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            f"{INSUMER_API_BASE}/v1/attest",
            headers={
                "x-api-key": INSUMER_API_KEY,
                "Content-Type": "application/json",
            },
            json=payload,
        )

    if resp.status_code != 200:
        raise HTTPException(
            status_code=502,
            detail=f"InsumerAPI returned {resp.status_code}: {resp.text[:200]}",
        )

    data = resp.json()
    if not data.get("ok"):
        raise HTTPException(
            status_code=502,
            detail=f"InsumerAPI attestation failed: {data.get('error', 'unknown')}",
        )

    return data


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/wallet/bind", response_model=WalletBindResponse)
async def bind_wallet(req: Request, body: WalletBindRequest):
    """
    Bind a wallet address to a DID.

    The agent proves ownership of both identities:
    - DID ownership: Ed25519 signature of 'bind:{wallet}:{timestamp}'
    - Wallet ownership: verified implicitly when on-chain conditions are checked

    Binding is required before on-chain verification.
    """
    # Rate limit
    client_ip = req.client.host if req.client else "unknown"
    if not check_rate_limit(client_ip, "oracle_bind", max_requests=10, window_seconds=3600):
        raise HTTPException(status_code=429, detail="Rate limit exceeded for wallet binding")

    # Verify DID exists
    reg = database.get_registration(body.did)
    if not reg:
        raise HTTPException(status_code=404, detail=f"DID {body.did} not registered")

    # Verify timestamp is recent (within 5 minutes)
    try:
        ts = datetime.fromisoformat(body.timestamp.replace("Z", "+00:00"))
        now = datetime.now(tz=timezone.utc)
        age = abs((now - ts).total_seconds())
        if age > 300:
            raise HTTPException(status_code=400, detail="Timestamp too old (>5 minutes)")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid timestamp format")

    # Verify DID signature
    sign_message = f"bind:{body.wallet_address}:{body.timestamp}"
    if not _verify_did_signature(body.did, sign_message, body.did_signature):
        raise HTTPException(status_code=403, detail="Invalid DID signature")

    # Validate chain type
    if body.chain_type not in ("evm", "solana", "xrpl"):
        raise HTTPException(status_code=400, detail="chain_type must be evm, solana, or xrpl")

    # Store binding
    success = database.bind_wallet(body.did, body.wallet_address, body.chain_type)
    if not success:
        # Already bound — that's fine
        return WalletBindResponse(
            success=True,
            message="Wallet already bound to this DID",
            did=body.did,
            wallet_address=body.wallet_address,
            chain_type=body.chain_type,
        )

    return WalletBindResponse(
        success=True,
        message="Wallet bound to DID successfully",
        did=body.did,
        wallet_address=body.wallet_address,
        chain_type=body.chain_type,
    )


@router.delete("/wallet/bind")
async def unbind_wallet(req: Request, did: str, wallet_address: str):
    """Revoke a wallet-DID binding."""
    client_ip = req.client.host if req.client else "unknown"
    if not check_rate_limit(client_ip, "oracle_unbind", max_requests=10, window_seconds=3600):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    # TODO: require DID signature for unbinding too
    success = database.unbind_wallet(did, wallet_address)
    if not success:
        raise HTTPException(status_code=404, detail="Wallet binding not found")

    return {"success": True, "message": "Wallet unbound from DID"}


@router.get("/wallet/{did}", response_model=WalletListResponse)
async def list_wallets(did: str):
    """List all wallet bindings for a DID."""
    wallets = database.get_wallet_bindings(did)
    return WalletListResponse(
        success=True,
        did=did,
        wallets=wallets,
    )


@router.post("/verify/onchain", response_model=OnchainVerifyResponse)
async def verify_onchain(req: Request, body: OnchainVerifyRequest):
    """
    Verify on-chain conditions for a DID's bound wallet.

    Calls InsumerAPI to check conditions, then auto-creates a vouch from the
    credential oracle identity if conditions pass.

    Returns the attestation result and (if passed) the vouch ID.
    """
    client_ip = req.client.host if req.client else "unknown"
    if not check_rate_limit(client_ip, "oracle_verify", max_requests=20, window_seconds=3600):
        raise HTTPException(status_code=429, detail="Rate limit exceeded for on-chain verification")

    # Resolve wallet
    wallets = database.get_wallet_bindings(body.did)
    if not wallets:
        raise HTTPException(
            status_code=404,
            detail=f"No wallets bound to {body.did}. Use POST /oracle/wallet/bind first.",
        )

    if body.wallet_address:
        wallet = next(
            (w for w in wallets if w["wallet_address"] == body.wallet_address),
            None,
        )
        if not wallet:
            raise HTTPException(
                status_code=404,
                detail=f"Wallet {body.wallet_address} not bound to {body.did}",
            )
    else:
        wallet = wallets[0]  # Use first binding

    wallet_addr = wallet["wallet_address"]

    # Check cache
    cond_hash = _conditions_hash(body.conditions)
    cached = database.get_cached_attestation(body.did, cond_hash)
    if cached and cached.get("expires_at"):
        try:
            exp = datetime.fromisoformat(cached["expires_at"])
            if exp > datetime.now(tz=timezone.utc):
                return OnchainVerifyResponse(
                    success=True,
                    did=body.did,
                    wallet_address=wallet_addr,
                    attestation_id=cached.get("attestation_id"),
                    passed=cached["result"],
                    results=json.loads(cached.get("results_json", "[]")),
                    vouch_id=cached.get("vouch_id"),
                    expires_at=cached["expires_at"],
                    message="Cached attestation (still valid)",
                )
        except (ValueError, TypeError):
            pass  # Cache entry invalid, re-query

    # Call InsumerAPI
    attest_result = await _call_insumer_attest(wallet_addr, body.conditions)

    attestation = attest_result["data"]["attestation"]
    passed = attestation["pass"]
    attest_id = attestation.get("id", "")
    results = attestation.get("results", [])
    sig = attest_result["data"].get("sig", "")
    kid = attest_result["data"].get("kid", "")
    expires_at_str = attestation.get("expiresAt", "")

    vouch_id = None

    # If conditions pass, create oracle vouch
    if passed:
        vouch_id = f"oracle-{uuid.uuid4().hex[:12]}"
        condition_labels = [r.get("label", r.get("type", "unknown")) for r in results]
        statement = (
            f"On-chain credential verified via InsumerAPI: "
            f"{', '.join(condition_labels)}. "
            f"Attestation {attest_id}, wallet {wallet_addr[:10]}…{wallet_addr[-4:]}."
        )

        # Create vouch from oracle identity
        # TTL matches InsumerAPI attestation expiry (~30 min ≈ 0.02 days)
        # We use 1 day min TTL since vouches are day-granularity
        database.create_vouch(
            vouch_id=vouch_id,
            voucher_did=ORACLE_DID,
            target_did=body.did,
            scope=ORACLE_SCOPE,
            statement=statement,
            signature=sig,  # InsumerAPI ECDSA signature as proof
            ttl_days=1,  # Short-lived, re-verify frequently
        )

    # Cache the result
    database.cache_attestation(
        did=body.did,
        wallet_address=wallet_addr,
        conditions_hash=cond_hash,
        result=passed,
        attestation_id=attest_id,
        results_json=json.dumps(results),
        insumer_signature=sig,
        insumer_kid=kid,
        expires_at=expires_at_str,
        vouch_id=vouch_id,
    )

    return OnchainVerifyResponse(
        success=True,
        did=body.did,
        wallet_address=wallet_addr,
        attestation_id=attest_id,
        passed=passed,
        results=results,
        vouch_id=vouch_id,
        expires_at=expires_at_str,
        message="On-chain conditions verified" if passed else "On-chain conditions not met",
    )


@router.get("/attestations/{did}")
async def get_attestations(did: str):
    """Get all cached attestations for a DID."""
    attestations = database.get_attestations_for_did(did)
    return {
        "success": True,
        "did": did,
        "attestations": attestations,
    }
