"""
Moltbook API client for proof verification.
"""

import httpx
import base64
import json
from typing import Dict, Any

MOLTBOOK_API_BASE = "https://www.moltbook.com/api/v1"


async def get_post(post_id: str) -> Dict[str, Any]:
    """Fetch a post from Moltbook."""
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{MOLTBOOK_API_BASE}/posts/{post_id}",
            timeout=10.0
        )

        if response.status_code == 404:
            return {"error": "Post not found"}

        if response.status_code != 200:
            return {"error": f"API error: {response.status_code}"}

        data = response.json()
        if data.get("success") == False:
            return {"error": data.get("error", "Unknown error")}

        return data.get("post", data)


async def verify_proof_post(
    post_id: str,
    expected_did: str,
    expected_username: str,
    public_key_b64: str
) -> Dict[str, Any]:
    """
    Verify that a Moltbook post is a valid proof of DID ownership.

    The post should:
    1. Be authored by expected_username
    2. Contain a signed claim with the DID
    3. Have a valid signature from the DID's private key

    Returns: {"valid": True/False, "error": "..." if invalid}
    """

    # Fetch the post
    post = await get_post(post_id)
    if "error" in post:
        return {"valid": False, "error": post["error"]}

    # Check author
    author = post.get("author", {})
    author_name = author.get("name") if isinstance(author, dict) else None

    if not author_name:
        return {"valid": False, "error": "Could not determine post author"}

    if author_name.lower() != expected_username.lower():
        return {
            "valid": False,
            "error": f"Post authored by {author_name}, not {expected_username}"
        }

    # Check content contains the DID
    content = post.get("content", "") or post.get("body", "")
    if expected_did not in content:
        return {
            "valid": False,
            "error": f"Post does not contain the DID {expected_did}"
        }

    # Try to extract and verify signed claim
    # Look for AIP-PROOF block in content
    try:
        import re
        import nacl.signing
        import nacl.exceptions

        # Look for signed proof block: ```aip-proof\n{JSON}\n```
        proof_match = re.search(r'```aip-proof\s*\n(.*?)\n```', content, re.DOTALL)

        if proof_match:
            # Parse the proof JSON
            proof_json = proof_match.group(1).strip()
            proof = json.loads(proof_json)

            # Extract claim and signature
            claim = proof.get("claim", {})
            signature_b64 = proof.get("signature", "")

            if not claim or not signature_b64:
                return {"valid": False, "error": "Invalid proof format: missing claim or signature"}

            # Verify claim contains correct DID
            if claim.get("did") != expected_did:
                return {"valid": False, "error": f"Proof DID mismatch: expected {expected_did}"}

            # Verify signature
            try:
                public_key_bytes = base64.b64decode(public_key_b64)
                signature_bytes = base64.b64decode(signature_b64)
                claim_bytes = json.dumps(claim, sort_keys=True, separators=(',', ':')).encode()

                verify_key = nacl.signing.VerifyKey(public_key_bytes)
                verify_key.verify(claim_bytes, signature_bytes)

                return {"valid": True, "verified_claim": claim}

            except nacl.exceptions.BadSignatureError:
                return {"valid": False, "error": "Invalid signature - does not match public key"}
            except Exception as e:
                return {"valid": False, "error": f"Signature verification failed: {str(e)}"}
        else:
            return {
                "valid": False,
                "error": "No cryptographic proof block found in post. "
                         "Post must contain a signed DID claim in an ```aip-proof``` code block. "
                         "Use the /generate-proof endpoint to create the required proof content."
            }

    except json.JSONDecodeError as e:
        return {"valid": False, "error": f"Invalid proof JSON: {str(e)}"}
    except Exception as e:
        return {"valid": False, "error": f"Verification error: {str(e)}"}


async def get_user_profile(username: str) -> Dict[str, Any]:
    """Fetch a user profile from Moltbook."""
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{MOLTBOOK_API_BASE}/agents/{username}",
            timeout=10.0
        )

        if response.status_code == 404:
            return {"error": "User not found"}

        if response.status_code != 200:
            return {"error": f"API error: {response.status_code}"}

        return response.json()
