"""
W3C Verifiable Credentials support for AIP vouches.

Converts AIP trust vouches to/from W3C Verifiable Credentials format,
enabling interoperability with MCP-I, DIF standards, and any system
that supports the VC data model (W3C Recommendation).

References:
- W3C VC Data Model: https://www.w3.org/TR/vc-data-model/
- Ed25519Signature2020: https://w3c-ccg.github.io/di-eddsa-2020/
- MCP-I: Uses VCs for delegation chains
"""

import base64
import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

try:
    from .identity import public_key_to_did_key
    from .trust import Vouch, TrustLevel
except ImportError:
    from identity import public_key_to_did_key
    from trust import Vouch, TrustLevel

# W3C VC contexts
VC_CONTEXT_V1 = "https://www.w3.org/2018/credentials/v1"
VC_CONTEXT_ED25519 = "https://w3id.org/security/suites/ed25519-2020/v1"
AIP_CONTEXT = "https://aip-service.fly.dev/contexts/v1"

# AIP-specific VC types
AIP_VOUCH_TYPE = "AIPVouchCredential"
AIP_TRUST_TYPE = "AIPTrustAssertion"


def vouch_to_vc(
    vouch: Vouch,
    voucher_public_key_bytes: Optional[bytes] = None,
    include_proof: bool = True,
) -> Dict[str, Any]:
    """
    Convert an AIP Vouch to a W3C Verifiable Credential.

    Args:
        vouch: The AIP vouch to convert
        voucher_public_key_bytes: Raw public key bytes for did:key derivation.
            If None, uses the base64-decoded voucher_pubkey from the vouch.
        include_proof: Whether to include the proof section (requires signature)

    Returns:
        A dictionary conforming to the W3C VC Data Model
    """
    # Derive did:key identifiers for W3C interop
    if voucher_public_key_bytes is None:
        voucher_public_key_bytes = base64.b64decode(vouch.voucher_pubkey)

    target_public_key_bytes = base64.b64decode(vouch.target_pubkey)

    issuer_did_key = public_key_to_did_key(voucher_public_key_bytes)
    subject_did_key = public_key_to_did_key(target_public_key_bytes)

    # Build the credential
    vc: Dict[str, Any] = {
        "@context": [
            VC_CONTEXT_V1,
            VC_CONTEXT_ED25519,
            AIP_CONTEXT,
        ],
        "id": f"urn:uuid:{_vouch_to_uuid(vouch)}",
        "type": ["VerifiableCredential", AIP_VOUCH_TYPE],
        "issuer": {
            "id": issuer_did_key,
            "aipDid": vouch.voucher_did,
        },
        "issuanceDate": _normalize_iso(vouch.created_at),
        "credentialSubject": {
            "id": subject_did_key,
            "aipDid": vouch.target_did,
            "type": AIP_TRUST_TYPE,
            "trustScope": vouch.scope,
            "trustLevel": int(vouch.level),
            "trustLevelName": vouch.level.name if hasattr(vouch.level, 'name') else str(vouch.level),
            "statement": vouch.statement,
        },
    }

    # Add expiration if present
    if vouch.expires_at:
        vc["expirationDate"] = _normalize_iso(vouch.expires_at)

    # Add proof section if signature exists and requested
    if include_proof and vouch.signature:
        vc["proof"] = {
            "type": "Ed25519Signature2020",
            "created": _normalize_iso(vouch.created_at),
            "verificationMethod": f"{issuer_did_key}#keys-1",
            "proofPurpose": "assertionMethod",
            "proofValue": _to_multibase(vouch.signature),
        }

    return vc


def vc_to_vouch(vc: Dict[str, Any]) -> Vouch:
    """
    Parse a W3C Verifiable Credential back into an AIP Vouch.

    Args:
        vc: A dictionary conforming to the W3C VC Data Model with AIP extensions

    Returns:
        An AIP Vouch object

    Raises:
        ValueError: If the VC is not a valid AIP vouch credential
    """
    # Validate type
    vc_types = vc.get("type", [])
    if AIP_VOUCH_TYPE not in vc_types:
        raise ValueError(
            f"Not an AIP vouch credential. Types: {vc_types}"
        )

    # Extract issuer info
    issuer = vc.get("issuer", {})
    if isinstance(issuer, str):
        issuer_did_key = issuer
        voucher_aip_did = ""
    else:
        issuer_did_key = issuer.get("id", "")
        voucher_aip_did = issuer.get("aipDid", "")

    # Extract subject info
    subject = vc.get("credentialSubject", {})
    subject_did_key = subject.get("id", "")
    target_aip_did = subject.get("aipDid", "")

    # Derive public keys from did:key identifiers
    try:
        from .identity import did_key_to_public_key
    except ImportError:
        from identity import did_key_to_public_key

    voucher_pubkey_bytes = did_key_to_public_key(issuer_did_key)
    target_pubkey_bytes = did_key_to_public_key(subject_did_key)

    voucher_pubkey_b64 = base64.b64encode(voucher_pubkey_bytes).decode()
    target_pubkey_b64 = base64.b64encode(target_pubkey_bytes).decode()

    # If AIP DIDs not provided, derive them
    if not voucher_aip_did:
        key_hash = hashlib.sha256(voucher_pubkey_bytes).hexdigest()[:32]
        voucher_aip_did = f"did:aip:{key_hash}"
    if not target_aip_did:
        key_hash = hashlib.sha256(target_pubkey_bytes).hexdigest()[:32]
        target_aip_did = f"did:aip:{key_hash}"

    # Extract trust info
    scope = subject.get("trustScope", "identity")
    level_int = subject.get("trustLevel", 1)
    statement = subject.get("statement", "")

    # Extract dates
    created_at = vc.get("issuanceDate", "")
    expires_at = vc.get("expirationDate")

    # Extract signature from proof
    signature = ""
    proof = vc.get("proof", {})
    if proof:
        proof_value = proof.get("proofValue", "")
        if proof_value:
            signature = _from_multibase(proof_value)

    return Vouch(
        voucher_did=voucher_aip_did,
        voucher_pubkey=voucher_pubkey_b64,
        target_did=target_aip_did,
        target_pubkey=target_pubkey_b64,
        scope=scope,
        level=TrustLevel(level_int),
        statement=statement,
        created_at=created_at,
        expires_at=expires_at,
        signature=signature,
    )


def verify_vc(vc: Dict[str, Any]) -> bool:
    """
    Verify the proof on a VC-format AIP vouch.

    Extracts the public key from the issuer's did:key, reconstructs
    the original vouch signable content, and verifies the Ed25519 signature.

    Args:
        vc: A Verifiable Credential dictionary with proof

    Returns:
        True if the signature is valid, False otherwise
    """
    proof = vc.get("proof")
    if not proof:
        return False

    # Reconstruct the vouch and verify
    try:
        vouch = vc_to_vouch(vc)
    except (ValueError, Exception):
        return False

    if not vouch.signature:
        return False

    # Verify signature using the vouch's own verification
    try:
        import nacl.signing
        import nacl.exceptions

        pubkey_bytes = base64.b64decode(vouch.voucher_pubkey)
        verify_key = nacl.signing.VerifyKey(pubkey_bytes)
        sig_bytes = base64.b64decode(vouch.signature)
        signable = vouch.to_signable()
        verify_key.verify(signable, sig_bytes)
        return True
    except (nacl.exceptions.BadSignatureError, Exception):
        return False


def vc_to_json(vc: Dict[str, Any], indent: int = 2) -> str:
    """Serialize a VC to pretty-printed JSON."""
    return json.dumps(vc, indent=indent, ensure_ascii=False)


def vc_from_json(json_str: str) -> Dict[str, Any]:
    """Parse a VC from JSON string."""
    return json.loads(json_str)


# --- Internal helpers ---


def _vouch_to_uuid(vouch: Vouch) -> str:
    """Generate a deterministic UUID v5 from the vouch ID."""
    # Use the AIP namespace with the vouch_id for deterministic UUIDs
    namespace = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # URL namespace
    return str(uuid.uuid5(namespace, f"aip:vouch:{vouch.vouch_id}"))


def _normalize_iso(timestamp: str) -> str:
    """Normalize an ISO timestamp to W3C format (with Z suffix)."""
    if not timestamp:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    # Already has Z or timezone info
    if timestamp.endswith("Z") or "+" in timestamp:
        return timestamp
    return timestamp + "Z"


def _to_multibase(signature_b64: str) -> str:
    """
    Convert a base64 signature to multibase format.
    Uses 'z' prefix for base58btc encoding (standard for Ed25519Signature2020).
    Falls back to 'M' prefix (base64) if base58 not available.
    """
    try:
        import base58
        sig_bytes = base64.b64decode(signature_b64)
        return "z" + base58.b58encode(sig_bytes).decode()
    except ImportError:
        # Fall back to base64 multibase ('M' prefix)
        return "M" + signature_b64


def _from_multibase(multibase_str: str) -> str:
    """
    Convert a multibase-encoded value back to base64.
    Supports 'z' (base58btc) and 'M' (base64) prefixes.
    """
    if not multibase_str:
        return ""

    prefix = multibase_str[0]
    value = multibase_str[1:]

    if prefix == "z":
        try:
            import base58
            raw_bytes = base58.b58decode(value)
            return base64.b64encode(raw_bytes).decode()
        except ImportError:
            raise ValueError("base58 package required to decode base58btc multibase")
    elif prefix == "M":
        return value
    else:
        # Assume it's raw base64 (legacy)
        return multibase_str
