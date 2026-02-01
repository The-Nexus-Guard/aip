#!/usr/bin/env python3
"""
AIP Demo: Multi-Agent Workflow with Peer-to-Peer Verification

This demonstrates AIP's key differentiator: decentralized agent-to-agent
trust without any external registry or edge infrastructure.

Scenario: A coordinator agent delegates a task to worker agents.
Each agent cryptographically verifies the others before trusting messages.

Unlike MCP-I (which requires KnowThat.ai registry or edge proxy), AIP enables
direct peer-to-peer verification - works anywhere with just Python.
"""

import sys
import os
import json
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from identity import AgentIdentity, VerificationChallenge, get_backend


def print_section(title):
    print(f"\n{'='*70}")
    print(f" {title}")
    print('='*70)


def print_agent(name, msg):
    """Color-coded agent output."""
    colors = {
        'Coordinator': '\033[94m',  # Blue
        'Analyst': '\033[92m',      # Green
        'Executor': '\033[93m',     # Yellow
    }
    reset = '\033[0m'
    color = colors.get(name, '')
    print(f"{color}[{name}]{reset} {msg}")


class AgentMessage:
    """Signed message between agents."""

    @staticmethod
    def create(sender: AgentIdentity, recipient_did: str, action: str, payload: dict) -> dict:
        """Create a signed message from sender to recipient."""
        message = {
            "protocol": "aip/1.0",
            "type": "agent-message",
            "from": sender.did,
            "to": recipient_did,
            "action": action,
            "payload": payload,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        return sender.sign_json(message)

    @staticmethod
    def verify(message: dict, sender_public_key: str) -> tuple[bool, dict]:
        """Verify a message from a known sender. Returns (valid, payload)."""
        payload_bytes = json.dumps(
            message['payload'],
            sort_keys=True,
            separators=(',', ':')
        ).encode()

        valid = AgentIdentity.verify(sender_public_key, payload_bytes, message['signature'])
        return valid, message['payload'] if valid else None


class TrustNetwork:
    """
    Peer-to-peer trust network - AIP's core differentiator.

    Unlike MCP-I (which uses KnowThat.ai registry), this is fully decentralized.
    Each agent maintains its own view of trusted peers.
    """

    def __init__(self):
        self.trusted_peers = {}  # DID -> public_key
        self.verified_at = {}    # DID -> timestamp

    def add_peer(self, did: str, public_key: str):
        """Add a peer after verification."""
        self.trusted_peers[did] = public_key
        self.verified_at[did] = datetime.now(timezone.utc)

    def is_trusted(self, did: str) -> bool:
        return did in self.trusted_peers

    def get_public_key(self, did: str) -> str:
        return self.trusted_peers.get(did)

    def peer_count(self) -> int:
        return len(self.trusted_peers)


class WorkflowAgent:
    """Agent with AIP identity and peer-to-peer trust."""

    def __init__(self, name: str, role: str):
        self.identity = AgentIdentity.create(name, metadata={"role": role})
        self.trust_network = TrustNetwork()
        self.name = name
        self.role = role

    def verify_and_trust(self, other: 'WorkflowAgent') -> bool:
        """
        Full challenge-response verification with another agent.
        On success, adds them to our trust network.
        """
        # Create challenge
        challenge = VerificationChallenge.create_challenge()

        # Other agent responds
        response = VerificationChallenge.respond_to_challenge(other.identity, challenge)

        # Verify response
        if VerificationChallenge.verify_response(challenge, response):
            # Add to trust network
            self.trust_network.add_peer(other.identity.did, other.identity.public_key)
            return True
        return False

    def send_task(self, recipient: 'WorkflowAgent', action: str, payload: dict) -> dict:
        """Send a signed task to a trusted peer."""
        if not self.trust_network.is_trusted(recipient.identity.did):
            raise ValueError(f"Recipient {recipient.name} not in trust network!")

        return AgentMessage.create(
            self.identity,
            recipient.identity.did,
            action,
            payload
        )

    def receive_message(self, message: dict) -> tuple[bool, dict]:
        """Verify and process a message from a trusted peer."""
        sender_did = message['payload']['from']

        if not self.trust_network.is_trusted(sender_did):
            return False, {"error": "Sender not trusted"}

        sender_key = self.trust_network.get_public_key(sender_did)
        valid, payload = AgentMessage.verify(message, sender_key)

        return valid, payload


def main():
    print_section("AIP Multi-Agent Workflow Demo")
    print(f"\nCrypto backend: {get_backend()}")
    print("\nThis demo shows AIP's key differentiator: peer-to-peer verification")
    print("without any external registry or edge infrastructure.\n")

    # Create agents
    print_section("Step 1: Create Agent Identities")

    coordinator = WorkflowAgent("Coordinator", "workflow_coordinator")
    analyst = WorkflowAgent("Analyst", "data_analyst")
    executor = WorkflowAgent("Executor", "task_executor")

    print_agent("Coordinator", f"Created with DID: {coordinator.identity.did[:40]}...")
    print_agent("Analyst", f"Created with DID: {analyst.identity.did[:40]}...")
    print_agent("Executor", f"Created with DID: {executor.identity.did[:40]}...")

    # Establish trust network (peer-to-peer, no registry needed!)
    print_section("Step 2: Establish Peer-to-Peer Trust Network")
    print("\nUnlike MCP-I, no KnowThat.ai registry or edge proxy needed!")
    print("Agents verify each other directly using challenge-response.\n")

    # Coordinator verifies both workers
    print_agent("Coordinator", "Challenging Analyst...")
    if coordinator.verify_and_trust(analyst):
        print_agent("Coordinator", f"✓ Analyst verified and trusted")

    print_agent("Coordinator", "Challenging Executor...")
    if coordinator.verify_and_trust(executor):
        print_agent("Coordinator", f"✓ Executor verified and trusted")

    # Workers verify coordinator
    print_agent("Analyst", "Challenging Coordinator...")
    if analyst.verify_and_trust(coordinator):
        print_agent("Analyst", f"✓ Coordinator verified and trusted")

    print_agent("Executor", "Challenging Coordinator...")
    if executor.verify_and_trust(coordinator):
        print_agent("Executor", f"✓ Coordinator verified and trusted")

    # Workers can also verify each other for direct communication
    print_agent("Analyst", "Challenging Executor...")
    if analyst.verify_and_trust(executor):
        print_agent("Analyst", f"✓ Executor verified and trusted")

    print(f"\nTrust network established:")
    print(f"  Coordinator trusts: {coordinator.trust_network.peer_count()} peers")
    print(f"  Analyst trusts: {analyst.trust_network.peer_count()} peers")
    print(f"  Executor trusts: {executor.trust_network.peer_count()} peers")

    # Simulate multi-agent workflow
    print_section("Step 3: Execute Signed Workflow")

    # Coordinator sends analysis task
    print_agent("Coordinator", "Sending analysis task to Analyst...")
    task1 = coordinator.send_task(analyst, "analyze", {
        "task_id": "task-001",
        "data_source": "quarterly_metrics",
        "analysis_type": "trend_detection"
    })
    print(f"  Task signed: {task1['signature'][:40]}...")

    # Analyst receives and verifies
    print_agent("Analyst", "Receiving task from Coordinator...")
    valid, payload = analyst.receive_message(task1)
    if valid:
        print_agent("Analyst", f"✓ Message verified! Task: {payload['action']}")

        # Analyst sends results back
        print_agent("Analyst", "Analysis complete. Sending results...")
        result = analyst.send_task(coordinator, "analysis_result", {
            "task_id": "task-001",
            "result": "Trend detected: 15% growth in Q4",
            "confidence": 0.92
        })

    # Coordinator receives analysis, forwards to executor
    print_agent("Coordinator", "Receiving analysis results...")
    valid, payload = coordinator.receive_message(result)
    if valid:
        print_agent("Coordinator", f"✓ Results verified! Forwarding to Executor...")

        exec_task = coordinator.send_task(executor, "execute", {
            "task_id": "task-002",
            "action_type": "generate_report",
            "based_on": payload['payload']
        })

    # Executor receives and processes
    print_agent("Executor", "Receiving execution task...")
    valid, payload = executor.receive_message(exec_task)
    if valid:
        print_agent("Executor", f"✓ Task verified! Executing: {payload['payload']['action_type']}")
        print_agent("Executor", "Report generated successfully!")

    # Test tampering detection
    print_section("Step 4: Tampering Detection")

    print_agent("Coordinator", "Simulating message tampering attack...")

    # Create a legitimate task
    legit_task = coordinator.send_task(analyst, "analyze", {
        "task_id": "task-003",
        "data_source": "sensitive_data"
    })

    # Tamper with it
    tampered = legit_task.copy()
    tampered['payload']['payload']['data_source'] = "HACKED_DATA"

    # Try to receive
    print_agent("Analyst", "Receiving potentially tampered message...")
    valid, _ = analyst.receive_message(tampered)
    if not valid:
        print_agent("Analyst", "✗ TAMPERING DETECTED! Message rejected.")
    else:
        print_agent("Analyst", "✓ Message valid")

    # Test untrusted sender
    print_section("Step 5: Untrusted Agent Rejection")

    rogue = WorkflowAgent("Rogue", "unknown")
    print_agent("Rogue", f"Created with DID: {rogue.identity.did[:40]}...")

    # Rogue tries to send message to Analyst (not in trust network)
    print_agent("Rogue", "Attempting to send message to Analyst...")

    # Create a fake message
    fake_msg = rogue.identity.sign_json({
        "protocol": "aip/1.0",
        "type": "agent-message",
        "from": rogue.identity.did,
        "to": analyst.identity.did,
        "action": "analyze",
        "payload": {"task": "malicious_task"},
        "timestamp": datetime.now(timezone.utc).isoformat()
    })

    # Analyst tries to receive
    valid, result = analyst.receive_message(fake_msg)
    if not valid:
        print_agent("Analyst", f"✗ Message rejected: {result['error']}")

    # Summary
    print_section("Summary: AIP vs MCP-I")

    print("""
What we just demonstrated:

  1. DECENTRALIZED TRUST: Agents verified each other directly
     - No KnowThat.ai registry needed
     - No edge proxy infrastructure
     - Works offline, air-gapped, or anywhere

  2. PEER-TO-PEER VERIFICATION: Challenge-response protocol
     - Ed25519 signatures (fast, secure)
     - Each agent maintains its own trust network
     - No central authority required

  3. SIGNED WORKFLOWS: Every message cryptographically verified
     - Tamper detection built-in
     - Non-repudiation of agent actions
     - Full audit trail possible

  4. ZERO EXTERNAL DEPENDENCIES:
     - Pure Python implementation
     - No external services
     - Works with just standard library + our vendored crypto

This is AIP's differentiator:
  - MCP-I: Enterprise-focused, requires infrastructure
  - AIP: Simple, local-first, works anywhere

Perfect for:
  - Agent social platforms (Moltbook)
  - Research/lab environments
  - Air-gapped systems
  - Quick prototyping
  - Agents that need to verify each other without setup
""")


if __name__ == "__main__":
    main()
