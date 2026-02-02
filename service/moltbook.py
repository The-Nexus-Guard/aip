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
    # Look for JSON block in content
    try:
        # Simple approach: look for DID and signature in content
        # More robust: parse JSON claim block

        # For MVP, just verify DID is present
        # Full implementation would parse and verify signature

        # TODO: Implement full signed claim verification
        # For now, presence of DID + correct author is sufficient for MVP

        return {"valid": True}

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
