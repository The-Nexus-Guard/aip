#!/usr/bin/env python3
"""
AIP Demo: Two Agents Verifying Each Other

This demonstrates the core AIP functionality:
1. Creating agent identities
2. Generating DID documents
3. Challenge-response verification between agents
4. Signing and verifying messages
"""

import sys
import os

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from identity import AgentIdentity, VerificationChallenge, get_backend
import json


def print_section(title):
    print(f"\n{'='*60}")
    print(f" {title}")
    print('='*60)


def main():
    print_section("AIP Demo: Agent-to-Agent Verification")
    print(f"\nCrypto backend: {get_backend()}")

    # Create two agents
    print_section("Step 1: Creating Agent Identities")

    alice = AgentIdentity.create("alice", metadata={"role": "coordinator"})
    print(f"\nAlice created:")
    print(f"  Name: {alice.name}")
    print(f"  DID:  {alice.did}")
    print(f"  Public Key: {alice.public_key[:40]}...")

    bob = AgentIdentity.create("bob", metadata={"role": "worker"})
    print(f"\nBob created:")
    print(f"  Name: {bob.name}")
    print(f"  DID:  {bob.did}")
    print(f"  Public Key: {bob.public_key[:40]}...")

    # Show DID documents
    print_section("Step 2: DID Documents")

    alice_did_doc = alice.create_did_document()
    print(f"\nAlice's DID Document (truncated):")
    print(json.dumps(alice_did_doc, indent=2)[:500] + "...")

    # Challenge-response verification
    print_section("Step 3: Challenge-Response Verification")

    # Bob challenges Alice
    print("\nBob creates a challenge for Alice...")
    challenge = VerificationChallenge.create_challenge()
    print(f"  Challenge nonce: {challenge['nonce'][:32]}...")

    # Alice responds
    print("\nAlice responds to the challenge...")
    response = VerificationChallenge.respond_to_challenge(alice, challenge)
    print(f"  Response signature: {response['response']['signature'][:40]}...")

    # Bob verifies
    print("\nBob verifies Alice's response...")
    is_valid = VerificationChallenge.verify_response(challenge, response)
    print(f"  Verification result: {'VALID' if is_valid else 'INVALID'}")

    # Now Alice challenges Bob
    print("\n--- Now Alice challenges Bob ---")

    challenge2 = VerificationChallenge.create_challenge()
    print(f"\nAlice creates challenge: {challenge2['nonce'][:32]}...")

    response2 = VerificationChallenge.respond_to_challenge(bob, challenge2)
    print(f"Bob responds: {response2['response']['signature'][:40]}...")

    is_valid2 = VerificationChallenge.verify_response(challenge2, response2)
    print(f"Verification: {'VALID' if is_valid2 else 'INVALID'}")

    # Message signing
    print_section("Step 4: Signed Messages")

    message = {"task": "process_data", "priority": "high", "data_id": "12345"}
    signed = alice.sign_json(message)

    print(f"\nAlice signs a task message:")
    print(f"  Payload: {signed['payload']}")
    print(f"  Signature: {signed['signature'][:40]}...")
    print(f"  Signer DID: {signed['signer']}")

    # Bob verifies Alice's signed message
    print("\nBob verifies the signed message...")
    payload_bytes = json.dumps(signed['payload'], sort_keys=True, separators=(',', ':')).encode()
    msg_valid = AgentIdentity.verify(alice.public_key, payload_bytes, signed['signature'])
    print(f"  Message signature valid: {msg_valid}")

    # Test tampering detection
    print_section("Step 5: Tampering Detection")

    print("\nBob tries to verify with tampered message...")
    tampered = json.dumps({"task": "TAMPERED", "priority": "low"}, sort_keys=True, separators=(',', ':')).encode()
    tamper_check = AgentIdentity.verify(alice.public_key, tampered, signed['signature'])
    print(f"  Tampered message valid: {tamper_check}")
    print(f"  Tampering detected: {not tamper_check}")

    # Save and restore
    print_section("Step 6: Persistence")

    print("\nSaving Alice's identity to disk...")
    alice.save("/tmp/aip-demo")
    print("  Saved to /tmp/aip-demo/")

    print("\nRestoring Alice's identity...")
    alice_restored = AgentIdentity.load("/tmp/aip-demo", "alice")
    print(f"  Restored DID: {alice_restored.did}")
    print(f"  DIDs match: {alice.did == alice_restored.did}")

    # Summary
    print_section("Summary")

    print(f"""
Two agents (Alice and Bob) successfully:
  1. Created unique cryptographic identities
  2. Generated W3C-compatible DID documents
  3. Verified each other using challenge-response protocol
  4. Signed and verified JSON messages
  5. Detected message tampering
  6. Saved and restored identities

All without any central authority or platform dependency.

This is the foundation of agent-to-agent trust.
""")


if __name__ == "__main__":
    main()
