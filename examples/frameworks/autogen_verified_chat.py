#!/usr/bin/env python3
"""
AutoGen + AIP Verified Chat Example

Shows how AutoGen agents can verify each other's identity
before exchanging information, using AIP for cryptographic trust.

Requirements:
    pip install aip-identity pyautogen

Usage:
    python autogen_verified_chat.py
"""

import json
from aip_identity.integrations.auto import ensure_identity

# === Setup: Two agents with independent AIP identities ===

alice = ensure_identity(
    "autogen-alice",
    platform="autogen",
    credentials_path="/tmp/aip_alice.json",
)

bob = ensure_identity(
    "autogen-bob",
    platform="autogen",
    credentials_path="/tmp/aip_bob.json",
)

print(f"Alice: {alice.did}")
print(f"Bob:   {bob.did}")

# === Demo: Identity verification before collaboration ===

# Alice wants to verify Bob is who he claims to be
print("\n--- Identity Verification ---")

# In a real scenario, this would go through the AIP service challenge-response
# Here we demonstrate the local signing/verification pattern
challenge = "prove-your-identity-" + bob.did
bob_response = bob.sign(challenge.encode())

import base64
from nacl.signing import VerifyKey

bob_verify_key = VerifyKey(base64.b64decode(bob.public_key))
try:
    bob_verify_key.verify(challenge.encode(), bob_response)
    print(f"✓ Alice verified Bob's identity: {bob.did}")
except Exception:
    print(f"✗ Bob failed verification — refusing to collaborate")

# === Demo: Signed message exchange ===
print("\n--- Signed Message Exchange ---")

# Alice sends a signed message to Bob
message = "The quarterly analysis shows revenue up 23%."
alice_sig = alice.sign(message.encode())

print(f"Alice → Bob: {message}")
print(f"  Signature: {alice_sig.hex()[:40]}...")

# Bob verifies Alice's message
alice_verify_key = VerifyKey(base64.b64decode(alice.public_key))
try:
    alice_verify_key.verify(message.encode(), alice_sig)
    print(f"✓ Bob verified: message is from Alice ({alice.did})")
except Exception:
    print(f"✗ Bob: signature invalid — message may be tampered")

# === AutoGen Integration Pattern ===
print("""
# === Full AutoGen Integration ===
#
# import autogen
# from aip_identity.integrations.auto import ensure_identity
#
# # Each AutoGen agent gets an AIP identity
# client = ensure_identity("my-autogen-agent", platform="autogen")
#
# # Register AIP functions that AutoGen agents can call
# @autogen.register_function
# def verify_agent(did: str) -> dict:
#     \"\"\"Verify another agent's identity via AIP.\"\"\"
#     result = client.verify(did)
#     return result
#
# @autogen.register_function
# def sign_output(content: str) -> dict:
#     \"\"\"Sign content with your AIP identity.\"\"\"
#     sig = client.sign(content.encode())
#     return {"content": content, "signature": sig.hex(), "did": client.did}
#
# @autogen.register_function
# def check_trust(did: str) -> dict:
#     \"\"\"Check if an agent is trusted in the AIP network.\"\"\"
#     return client.get_trust(did)
#
# # Use in AutoGen group chat
# assistant = autogen.AssistantAgent(
#     name="analyst",
#     system_message="You have an AIP identity. Verify agents before trusting their data. Sign your outputs.",
#     function_map={
#         "verify_agent": verify_agent,
#         "sign_output": sign_output,
#         "check_trust": check_trust,
#     }
# )
""")

print("✓ AutoGen integration ready")
print(f"  Alice DID: {alice.did}")
print(f"  Bob DID: {bob.did}")
