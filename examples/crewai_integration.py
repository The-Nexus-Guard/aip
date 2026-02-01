#!/usr/bin/env python3
"""
AIP + CrewAI Integration Example

CrewAI fingerprints are UUIDs - useful for tracking, not cryptographic.
AIP adds the missing cryptographic identity layer.

This example shows how to:
1. Wrap CrewAI agents with AIP identity
2. Sign agent outputs before sharing
3. Verify outputs from other agents

Note: This is a conceptual demo. In production, you'd integrate
this into CrewAI's callback system or create a proper SDK decorator.
"""

import sys
import os
import json
from datetime import datetime, timezone
from typing import Optional, Dict, Any

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from identity import AgentIdentity, VerificationChallenge, get_backend


# Simulated CrewAI agent (since we can't import the actual library)
class MockCrewAIAgent:
    """Mock CrewAI Agent for demonstration."""

    def __init__(self, role: str, goal: str, backstory: str):
        self.role = role
        self.goal = goal
        self.backstory = backstory
        # CrewAI's fingerprint is just a UUID
        self.fingerprint = self._generate_fingerprint()

    def _generate_fingerprint(self):
        """CrewAI generates UUID fingerprints - no crypto."""
        import uuid
        return str(uuid.uuid4())

    def execute_task(self, task: str) -> str:
        """Simulate task execution."""
        return f"[{self.role}] Completed: {task}"


class AIPSecureAgent:
    """
    Wrapper that adds AIP cryptographic identity to any agent.

    This is the pattern for integrating AIP with CrewAI:
    1. Wrap your CrewAI agent
    2. Sign outputs before sharing
    3. Verify inputs from other agents
    """

    def __init__(self, crewai_agent: MockCrewAIAgent):
        self.crewai_agent = crewai_agent
        # Create AIP identity linked to CrewAI fingerprint
        self.identity = AgentIdentity.create(
            name=crewai_agent.role,
            metadata={
                "crewai_fingerprint": crewai_agent.fingerprint,
                "role": crewai_agent.role,
                "goal": crewai_agent.goal,
                "wrapped_at": datetime.now(timezone.utc).isoformat()
            }
        )
        self.trusted_peers = {}  # DID -> public_key

    @property
    def did(self) -> str:
        return self.identity.did

    @property
    def public_key(self) -> str:
        return self.identity.public_key

    def verify_peer(self, other: 'AIPSecureAgent') -> bool:
        """Challenge-response verification with another secure agent."""
        challenge = VerificationChallenge.create_challenge()
        response = VerificationChallenge.respond_to_challenge(other.identity, challenge)

        if VerificationChallenge.verify_response(challenge, response):
            self.trusted_peers[other.did] = other.public_key
            return True
        return False

    def execute_task_signed(self, task: str) -> Dict[str, Any]:
        """
        Execute a task and return cryptographically signed output.

        This is the key addition to CrewAI:
        - CrewAI output: just a string
        - AIP output: string + signature + verification data
        """
        # Execute with underlying CrewAI agent
        result = self.crewai_agent.execute_task(task)

        # Sign the output
        output = {
            "task": task,
            "result": result,
            "agent_did": self.did,
            "crewai_fingerprint": self.crewai_agent.fingerprint,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        return self.identity.sign_json(output)

    def verify_and_process_output(
        self,
        signed_output: Dict[str, Any],
        sender_public_key: str
    ) -> tuple[bool, Optional[Dict]]:
        """
        Verify output from another agent before processing.

        Returns (valid, payload) - only process if valid is True.
        """
        sender_did = signed_output.get('payload', {}).get('agent_did')

        # Check if sender is in our trust network
        if sender_did not in self.trusted_peers:
            return False, {"error": "Sender not in trusted peers"}

        # Verify signature
        payload_bytes = json.dumps(
            signed_output['payload'],
            sort_keys=True,
            separators=(',', ':')
        ).encode()

        if AgentIdentity.verify(sender_public_key, payload_bytes, signed_output['signature']):
            return True, signed_output['payload']
        return False, {"error": "Invalid signature"}


def print_section(title):
    print(f"\n{'='*65}")
    print(f" {title}")
    print('='*65)


def main():
    print_section("AIP + CrewAI Integration Demo")
    print(f"\nCrypto backend: {get_backend()}")
    print("\nCrewAI fingerprints = UUIDs (tracking only)")
    print("AIP adds cryptographic verification layer\n")

    # Create mock CrewAI agents
    print_section("Step 1: Create CrewAI Agents")

    researcher = MockCrewAIAgent(
        role="Senior Researcher",
        goal="Find comprehensive information",
        backstory="Expert in data analysis"
    )
    print(f"Researcher created:")
    print(f"  Role: {researcher.role}")
    print(f"  CrewAI Fingerprint: {researcher.fingerprint}")

    writer = MockCrewAIAgent(
        role="Content Writer",
        goal="Create engaging content",
        backstory="Skilled in storytelling"
    )
    print(f"\nWriter created:")
    print(f"  Role: {writer.role}")
    print(f"  CrewAI Fingerprint: {writer.fingerprint}")

    # Wrap with AIP identity
    print_section("Step 2: Add AIP Cryptographic Identity")

    secure_researcher = AIPSecureAgent(researcher)
    print(f"Researcher now has AIP identity:")
    print(f"  DID: {secure_researcher.did}")
    print(f"  Public Key: {secure_researcher.public_key[:40]}...")

    secure_writer = AIPSecureAgent(writer)
    print(f"\nWriter now has AIP identity:")
    print(f"  DID: {secure_writer.did}")
    print(f"  Public Key: {secure_writer.public_key[:40]}...")

    # Establish trust
    print_section("Step 3: Establish Cryptographic Trust")

    print("Researcher verifying Writer...")
    if secure_researcher.verify_peer(secure_writer):
        print("  ✓ Writer verified and trusted")

    print("Writer verifying Researcher...")
    if secure_writer.verify_peer(secure_researcher):
        print("  ✓ Researcher verified and trusted")

    # Execute signed workflow
    print_section("Step 4: Execute Signed Workflow")

    print("\nResearcher executing task with signed output...")
    research_output = secure_researcher.execute_task_signed("Research market trends for Q4")
    print(f"  Task result: {research_output['payload']['result']}")
    print(f"  Signature: {research_output['signature'][:40]}...")

    print("\nWriter verifying researcher's output before processing...")
    valid, payload = secure_writer.verify_and_process_output(
        research_output,
        secure_researcher.public_key
    )
    if valid:
        print(f"  ✓ Output verified!")
        print(f"  Processing: {payload['result']}")

        # Writer produces signed output based on verified research
        print("\nWriter executing follow-up task...")
        writer_output = secure_writer.execute_task_signed(
            f"Write article based on: {payload['result']}"
        )
        print(f"  Task result: {writer_output['payload']['result']}")
        print(f"  Signature: {writer_output['signature'][:40]}...")

    # Show tampering detection
    print_section("Step 5: Tampering Detection")

    print("Simulating output tampering...")
    tampered_output = research_output.copy()
    tampered_output['payload'] = research_output['payload'].copy()
    tampered_output['payload']['result'] = "TAMPERED RESULT!"

    valid, result = secure_writer.verify_and_process_output(
        tampered_output,
        secure_researcher.public_key
    )
    if not valid:
        print(f"  ✗ Tampering detected! {result['error']}")

    # Show untrusted agent rejection
    print_section("Step 6: Untrusted Agent Rejection")

    rogue_agent = MockCrewAIAgent(
        role="Rogue Agent",
        goal="Malicious",
        backstory="Unknown"
    )
    secure_rogue = AIPSecureAgent(rogue_agent)
    print(f"Rogue agent created: {secure_rogue.did}")

    # Rogue tries to send output without being verified
    rogue_output = secure_rogue.execute_task_signed("Steal data")

    print("Writer checking output from unverified agent...")
    valid, result = secure_writer.verify_and_process_output(
        rogue_output,
        secure_rogue.public_key
    )
    if not valid:
        print(f"  ✗ Rejected: {result['error']}")

    # Summary
    print_section("Integration Summary")

    print("""
What AIP adds to CrewAI:

  CrewAI Fingerprints (UUID):
    ✓ Unique identifier per agent
    ✓ Tracks agent through lifecycle
    ✗ Cannot verify authenticity
    ✗ No cryptographic guarantees
    ✗ Easily spoofed across systems

  AIP Layer (Ed25519):
    ✓ Cryptographically verifiable identity
    ✓ Challenge-response peer verification
    ✓ Signed outputs (non-repudiation)
    ✓ Tamper detection
    ✓ Trust network management

Integration pattern:
  1. Wrap CrewAI agents with AIPSecureAgent
  2. Link AIP identity to CrewAI fingerprint in metadata
  3. Use execute_task_signed() instead of execute_task()
  4. Verify peer outputs before processing

Production implementation would:
  - Hook into CrewAI's callback system
  - Create decorator like AIM: @aip_secure
  - Persist identities across sessions
  - Log signed outputs for audit trails
""")


if __name__ == "__main__":
    main()
