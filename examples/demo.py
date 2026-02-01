#!/usr/bin/env python3
"""
Agent Identity Protocol - Demo

Demonstrates:
1. Creating agent identities
2. Signing messages
3. Verifying signatures
4. Challenge-response authentication
"""

import sys
sys.path.insert(0, '../src')

from identity import AgentIdentity, VerificationChallenge

def main():
    print("=" * 60)
    print("Agent Identity Protocol - Demo")
    print("=" * 60)

    # 1. Create two agents
    print("\n[1] Creating agent identities...")
    alice = AgentIdentity.create("alice", {"role": "assistant", "platform": "moltbook"})
    bob = AgentIdentity.create("bob", {"role": "researcher", "platform": "openclaw"})

    print(f"   Alice DID: {alice.did}")
    print(f"   Bob DID:   {bob.did}")

    # 2. Alice signs a message
    print("\n[2] Alice signs a message...")
    message = b"Hello Bob, this is Alice. Let's collaborate!"
    signature = alice.sign(message)
    print(f"   Message: {message.decode()}")
    print(f"   Signature: {signature[:50]}...")

    # 3. Bob verifies Alice's signature
    print("\n[3] Bob verifies Alice's signature...")
    is_valid = AgentIdentity.verify(alice.public_key, message, signature)
    print(f"   Valid: {is_valid}")

    # 4. Verify with wrong key fails
    print("\n[4] Verification with wrong key fails...")
    is_valid_wrong = AgentIdentity.verify(bob.public_key, message, signature)
    print(f"   Valid with Bob's key: {is_valid_wrong}")

    # 5. Challenge-response authentication
    print("\n[5] Challenge-response authentication...")

    # Bob creates a challenge
    challenge = VerificationChallenge.create_challenge()
    print(f"   Challenge nonce: {challenge['nonce'][:20]}...")

    # Alice responds to the challenge
    response = VerificationChallenge.respond_to_challenge(alice, challenge)
    print(f"   Alice signed the challenge")

    # Bob verifies Alice's response
    verified = VerificationChallenge.verify_response(challenge, response)
    print(f"   Bob verified Alice: {verified}")

    # 6. Generate DID Document
    print("\n[6] Alice's DID Document:")
    import json
    did_doc = alice.create_did_document()
    print(json.dumps(did_doc, indent=2))

    # 7. Save and load identity
    print("\n[7] Save and load identity...")
    alice.save("/tmp/aip-demo")
    print("   Saved to /tmp/aip-demo/")

    alice_restored = AgentIdentity.load("/tmp/aip-demo", "alice")
    print(f"   Restored DID: {alice_restored.did}")
    print(f"   DIDs match: {alice.did == alice_restored.did}")

    print("\n" + "=" * 60)
    print("Demo complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
