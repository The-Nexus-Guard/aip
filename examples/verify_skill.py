#!/usr/bin/env python3
"""
Verify a signed AIP skill in 10 lines.

This example shows how to verify that a skill/directory was signed by a
specific agent and hasn't been tampered with — no account or API key needed.

Usage:
    # First, sign a skill (requires AIP credentials):
    aip sign ./my-skill/

    # Then anyone can verify it:
    python verify_skill.py ./my-skill/

    # Or use the CLI directly:
    aip verify ./my-skill/

Requirements:
    pip install aip-identity pynacl
"""

import json
import hashlib
import sys
from pathlib import Path

import nacl.signing
import nacl.exceptions


def verify_skill(path: str) -> dict:
    """Verify a signed skill directory. Returns signer info or raises."""
    target = Path(path)
    sig_file = target / ".aip-signature.json"

    if not sig_file.exists():
        raise FileNotFoundError(f"No .aip-signature.json in {path}")

    data = json.loads(sig_file.read_text())
    signature = bytes.fromhex(data.pop("signature"))
    manifest = data

    # 1. Verify the cryptographic signature
    import base64
    pub_bytes = base64.b64decode(manifest["public_key"])
    verify_key = nacl.signing.VerifyKey(pub_bytes)
    payload = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()

    try:
        verify_key.verify(payload, signature)
    except nacl.exceptions.BadSignatureError:
        raise ValueError("❌ Invalid signature — possible tampering!")

    # 2. Verify file hashes match
    for rel_path, expected_hash in manifest["files"].items():
        file_path = target / rel_path
        if not file_path.exists():
            raise ValueError(f"❌ Missing file: {rel_path}")
        actual_hash = hashlib.sha256(file_path.read_bytes()).hexdigest()
        if actual_hash != expected_hash:
            raise ValueError(f"❌ Modified file: {rel_path}")

    return {
        "valid": True,
        "signer_did": manifest["did"],
        "files_verified": len(manifest["files"]),
        "timestamp": manifest["timestamp"],
    }


# --- Optional: Check signer's trust on the AIP network ---

def check_signer_trust(did: str, service: str = "https://aip-service.fly.dev") -> dict:
    """Look up a signer's trust score and vouches (no auth needed)."""
    import requests
    resp = requests.get(f"{service}/verify/{did}", timeout=10)
    resp.raise_for_status()
    return resp.json()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python verify_skill.py <path-to-skill>")
        sys.exit(1)

    path = sys.argv[1]
    try:
        result = verify_skill(path)
        print(f"✅ Signature valid!")
        print(f"   Signer: {result['signer_did']}")
        print(f"   Files:  {result['files_verified']} verified")

        # Optional: check trust
        try:
            trust = check_signer_trust(result["signer_did"])
            print(f"   Trust:  {trust.get('trust_score', 'N/A')}")
            print(f"   Vouches: {trust.get('vouch_count', 0)}")
        except Exception:
            print("   Trust:  (couldn't reach AIP service)")

    except (FileNotFoundError, ValueError) as e:
        print(str(e))
        sys.exit(1)
