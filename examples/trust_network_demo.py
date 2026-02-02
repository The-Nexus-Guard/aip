#!/usr/bin/env python3
"""
AIP Trust Network Demo

Demonstrates the full Agent Identity Protocol flow:
1. Create agent identities
2. Verify identities via challenge-response
3. Build trust through vouching
4. Query trust levels and paths (isnad chains)
5. Handle trust revocation

This shows how agents can establish not just "same agent" (identity)
but "trustworthy agent" (trust) in a decentralized way.
"""

import sys
from pathlib import Path

# Add src to path for direct execution
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from identity import AgentIdentity, VerificationChallenge, get_backend
from trust import (
    TrustGraph, TrustLevel, TrustScope,
    verify_vouch, verify_trust_path
)


def print_section(title: str):
    print(f"\n{'='*60}")
    print(f" {title}")
    print('='*60)


def main():
    print("Agent Identity Protocol - Trust Network Demo")
    print(f"Crypto backend: {get_backend()}")

    # =========================================================
    print_section("1. CREATE AGENT IDENTITIES")
    # =========================================================

    # Create a small network of agents
    alice = AgentIdentity.create("Alice", {"role": "coordinator", "platform": "moltbook"})
    bob = AgentIdentity.create("Bob", {"role": "analyst", "specialty": "security"})
    carol = AgentIdentity.create("Carol", {"role": "developer", "specialty": "crypto"})
    dave = AgentIdentity.create("Dave", {"role": "unknown", "new": True})

    agents = [alice, bob, carol, dave]
    for agent in agents:
        print(f"  {agent.name}: {agent.did}")

    # =========================================================
    print_section("2. VERIFY IDENTITIES (Challenge-Response)")
    # =========================================================

    # Alice wants to verify Bob is who he claims to be
    print("\nAlice challenges Bob to prove his identity...")

    challenge = VerificationChallenge.create_challenge()
    print(f"  Challenge nonce: {challenge['nonce'][:16]}...")

    response = VerificationChallenge.respond_to_challenge(bob, challenge)
    print(f"  Bob signs challenge with his key")

    is_valid = VerificationChallenge.verify_response(challenge, response)
    print(f"  Verification result: {'✓ VALID' if is_valid else '✗ INVALID'}")

    # =========================================================
    print_section("3. BUILD TRUST NETWORK (Vouching)")
    # =========================================================

    # Each agent maintains their own trust graph
    alice_trust = TrustGraph(alice)
    bob_trust = TrustGraph(bob)
    carol_trust = TrustGraph(carol)
    dave_trust = TrustGraph(dave)

    # Alice vouches for Bob (they've worked together)
    print("\nAlice vouches for Bob (direct trust)...")
    vouch1 = alice_trust.vouch_for(
        bob,
        scope=TrustScope.GENERAL,
        level=TrustLevel.STRONG,
        statement="Bob is a reliable security analyst I've worked with"
    )
    print(f"  Vouch ID: {vouch1.vouch_id}")
    print(f"  Signature valid: {verify_vouch(vouch1)}")

    # Bob vouches for Carol (he trusts her crypto work)
    print("\nBob vouches for Carol (in security scope)...")
    vouch2 = bob_trust.vouch_for(
        carol,
        scope=TrustScope.CODE_SIGNING,
        level=TrustLevel.STRONG,
        statement="Carol writes solid cryptographic code"
    )
    print(f"  Vouch ID: {vouch2.vouch_id}")

    # Carol vouches for Bob back (mutual trust)
    print("\nCarol vouches for Bob back (mutual trust)...")
    vouch3 = carol_trust.vouch_for(
        bob,
        scope=TrustScope.INFORMATION,
        level=TrustLevel.STRONG,
        statement="Bob provides accurate security assessments"
    )
    print(f"  Vouch ID: {vouch3.vouch_id}")

    # =========================================================
    print_section("4. SHARE TRUST INFORMATION")
    # =========================================================

    # Alice imports Bob's vouches (so she can find paths to Carol)
    print("\nAlice imports Bob's vouches to learn about his network...")
    for v in bob_trust.export_vouches():
        from trust import Vouch
        alice_trust.import_vouch(Vouch.from_dict(v))
    print(f"  Alice now knows about {len(alice_trust.vouches)} vouches")

    # =========================================================
    print_section("5. QUERY TRUST (Isnad Chains)")
    # =========================================================

    # Alice checks: do I trust Carol?
    print("\nAlice asks: Do I trust Carol?")
    print("  (Alice hasn't met Carol directly, but Bob vouches for her)")

    trusted, path = alice_trust.check_trust(carol.did, TrustScope.CODE_SIGNING)
    print(f"  Trusted: {trusted}")

    if path:
        print(f"  Trust level: {TrustLevel(path.trust_level).name}")
        print(f"  Path length: {path.length} hops")
        print(f"  Isnad chain:")
        for i, vouch in enumerate(path.path):
            print(f"    {i+1}. {vouch.voucher_did[:20]}... vouches for {vouch.target_did[:20]}...")
            print(f"       \"{vouch.statement}\"")

        # Verify the entire chain
        print(f"\n  Full path cryptographically valid: {verify_trust_path(path)}")

    # Alice checks: do I trust Dave?
    print("\nAlice asks: Do I trust Dave?")
    print("  (Nobody has vouched for Dave)")

    trusted, path = alice_trust.check_trust(dave.did)
    print(f"  Trusted: {trusted}")
    print(f"  Trust level: {alice_trust.get_trust_level(dave.did).name}")

    # =========================================================
    print_section("6. TRUST LEVELS BY DISTANCE")
    # =========================================================

    print("\nTrust levels in Alice's view:")
    print(f"  Alice (self):  {TrustLevel.ULTIMATE.name}")
    print(f"  Bob (1 hop):   {alice_trust.get_trust_level(bob.did).name}")
    print(f"  Carol (2 hops): {alice_trust.get_trust_level(carol.did, TrustScope.CODE_SIGNING).name}")
    print(f"  Dave (no path): {alice_trust.get_trust_level(dave.did).name}")

    # =========================================================
    print_section("7. TRUST REVOCATION")
    # =========================================================

    print("\nScenario: Alice discovers Bob has been compromised...")
    print("  She revokes her vouch for Bob.")

    revocation = alice_trust.revoke_vouch(vouch1.vouch_id, "Security incident - Bob's key may be compromised")
    print(f"  Revocation created: {revocation.vouch_id}")

    # Now check trust again
    print("\nAfter revocation:")
    print(f"  Bob trusted: {alice_trust.check_trust(bob.did)[0]}")
    print(f"  Carol trusted: {alice_trust.check_trust(carol.did)[0]}")
    print("  (Carol's trust path went through Bob, so it's broken now)")

    # =========================================================
    print_section("8. EXPORT/IMPORT TRUST DATA")
    # =========================================================

    print("\nAlice exports her trust graph for backup/sharing...")
    export_data = alice_trust.to_dict()
    print(f"  Exported {len(export_data['vouches'])} vouches")
    print(f"  Exported {len(export_data['revocations'])} revocations")

    # Save to file
    alice_trust.save("/tmp/alice_trust.json")
    print("  Saved to /tmp/alice_trust.json")

    # =========================================================
    print_section("SUMMARY")
    # =========================================================

    print("""
AIP now provides:

IDENTITY LAYER:
  • Ed25519 keypairs for each agent
  • DID (Decentralized Identifier) for global identity
  • Challenge-response verification
  • Signed messages and payloads

TRUST LAYER:
  • Vouching: signed statements of trust
  • Trust scopes: general, code-signing, financial, etc.
  • Trust paths: verifiable chains (isnad) from you to target
  • Trust levels: based on path length and vouch strength
  • Revocation: withdraw trust when needed

KEY PROPERTIES:
  • Decentralized: no central registry needed
  • Verifiable: all vouches are cryptographically signed
  • Local-first: each agent maintains their own view
  • Auditable: full isnad chains show HOW you trust someone

This answers both:
  "Is this the same agent?" (identity)
  "Should I trust this agent?" (trust)
""")


if __name__ == "__main__":
    main()
