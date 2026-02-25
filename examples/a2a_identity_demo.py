#!/usr/bin/env python3
"""
AIP ↔ A2A Interop Demo: DID-based Identity Verification for A2A Agents

Demonstrates how AIP provides the identity layer for Google's A2A protocol:

1. Two A2A agents advertise DIDs in their AgentCards (via AIP extension)
2. Before delegating a task, the client agent verifies the server agent's identity
3. Task messages are signed with Ed25519 for integrity
4. Vouch chains establish transitive trust between agents

This is a companion demo for A2A PR #1511:
https://github.com/a2aproject/A2A/pull/1511

Requires: pip install aip-identity
"""

import json
import time
import hashlib
import base64
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from identity import AgentIdentity, get_backend
from trust import TrustGraph, TrustLevel, TrustScope, Vouch


def print_section(title):
    print(f"\n{'='*60}")
    print(f" {title}")
    print('='*60)


def create_a2a_agent_card(name: str, identity: AgentIdentity, skills: list[dict]) -> dict:
    """
    Build an A2A AgentCard with AIP identity extension.
    
    The 'aip_identity' extension adds:
    - did: The agent's Decentralized Identifier
    - publicKey: Ed25519 public key for verification
    - verificationEndpoint: Where to run challenge-response
    - supportedTrustMechanisms: vouch_chain, direct_verification, etc.
    """
    did_doc = identity.create_did_document()
    
    return {
        # Standard A2A AgentCard fields
        "name": name,
        "url": f"https://{name.lower().replace(' ', '-')}.example.com",
        "version": "1.0.0",
        "capabilities": {
            "streaming": False,
            "pushNotifications": False,
        },
        "skills": skills,
        
        # AIP Identity Extension (proposed in PR #1511)
        "extensions": {
            "aip_identity": {
                "did": did_doc["id"],
                "publicKey": did_doc["verificationMethod"][0]["publicKeyBase64"],
                "verificationEndpoint": f"https://{name.lower().replace(' ', '-')}.example.com/.well-known/aip/verify",
                "supportedTrustMechanisms": [
                    "direct_verification",
                    "vouch_chain",
                    "message_signing"
                ],
                "trustScore": None  # Populated after verification
            }
        }
    }


def verify_agent_identity(client: AgentIdentity, server_identity: AgentIdentity, server_card: dict) -> dict:
    """
    Verify an A2A agent's identity using AIP challenge-response.
    
    Before delegating a task to a remote agent, the client:
    1. Extracts the DID from the server's AgentCard
    2. Creates a cryptographic challenge
    3. The server signs it with their private key
    4. The client verifies the signature matches the advertised public key
    
    Returns verification result with trust metadata.
    """
    aip_ext = server_card["extensions"]["aip_identity"]
    server_did = aip_ext["did"]
    
    # Step 1: Create a challenge message
    challenge_nonce = hashlib.sha256(os.urandom(32)).hexdigest()
    challenge_msg = f"verify:{client.did}:{server_did}:{challenge_nonce}"
    
    # Step 2: Server signs the challenge (simulated — in production this is an HTTP call)
    # The server proves they hold the private key matching the DID
    signature = server_identity.sign(challenge_msg.encode())
    
    # Step 3: Client verifies the signature against the advertised public key
    verified = AgentIdentity.verify(
        aip_ext["publicKey"],
        challenge_msg.encode(),
        signature
    )
    
    return {
        "verified": verified,
        "did": server_did,
        "challenge_nonce": challenge_nonce[:16],
        "mechanism": "direct_verification",
        "timestamp": int(time.time()),
    }


def sign_task_message(identity: AgentIdentity, task_id: str, message: dict) -> dict:
    """
    Sign an A2A task message with AIP identity.
    
    Every message in a task gets a cryptographic signature:
    - Proves which agent sent it
    - Prevents tampering in transit
    - Creates an auditable trail of agent actions
    """
    # Canonical serialization for signing
    payload = json.dumps({
        "task_id": task_id,
        "message": message,
        "timestamp": int(time.time()),
        "nonce": hashlib.sha256(os.urandom(16)).hexdigest()[:16]
    }, sort_keys=True)
    
    signature = identity.sign(payload.encode())  # returns base64 string
    
    return {
        "task_id": task_id,
        "message": message,
        "aip_signature": {
            "signer_did": identity.did,
            "algorithm": "Ed25519",
            "signature": signature,
            "signed_payload_hash": hashlib.sha256(payload.encode()).hexdigest()
        }
    }


def main():
    print_section("AIP ↔ A2A Interop Demo")
    print(f"Crypto backend: {get_backend()}")
    
    # === Step 1: Create two A2A agents with AIP identities ===
    print_section("Step 1: Create A2A Agents with AIP Identity")
    
    orchestrator = AgentIdentity.create("Task Orchestrator")
    data_analyst = AgentIdentity.create("Data Analyst")
    
    # Build A2A AgentCards with AIP extensions
    orchestrator_card = create_a2a_agent_card(
        "Task Orchestrator",
        orchestrator,
        skills=[{"id": "orchestrate", "name": "Task Orchestration", 
                 "description": "Coordinates multi-agent workflows"}]
    )
    
    analyst_card = create_a2a_agent_card(
        "Data Analyst",
        data_analyst,
        skills=[{"id": "analyze", "name": "Data Analysis",
                 "description": "Analyzes datasets and produces insights"}]
    )
    
    print(f"\nOrchestrator DID: {orchestrator.did}")
    print(f"Data Analyst DID: {data_analyst.did}")
    print(f"\nOrchestrator AgentCard (with AIP extension):")
    print(json.dumps(orchestrator_card, indent=2))
    
    # === Step 2: Identity verification before delegation ===
    print_section("Step 2: Verify Agent Identity Before Delegation")
    
    print("Orchestrator discovers Data Analyst's AgentCard...")
    print("Extracting AIP identity extension...")
    
    aip_ext = analyst_card["extensions"]["aip_identity"]
    print(f"  DID: {aip_ext['did']}")
    print(f"  Public Key: {aip_ext['publicKey'][:20]}...")
    print(f"  Trust Mechanisms: {aip_ext['supportedTrustMechanisms']}")
    
    # Verify identity via challenge-response
    print("\nRunning AIP challenge-response verification...")
    result = verify_agent_identity(orchestrator, data_analyst, analyst_card)
    print(f"  ✅ Verified: {result['verified']}")
    print(f"  DID confirmed: {result['did']}")
    print(f"  Mechanism: {result['mechanism']}")
    
    # === Step 3: Vouch chain trust ===
    print_section("Step 3: Establish Trust via Vouch Chains")
    
    # Create a third agent that vouches for the data analyst
    supervisor = AgentIdentity.create("Supervisor Agent")
    supervisor_network = TrustGraph(supervisor)
    
    print(f"Supervisor DID: {supervisor.did}")
    print(f"Supervisor vouches for Data Analyst...")
    
    vouch = supervisor_network.vouch_for(
        target=data_analyst,
        level=TrustLevel.STRONG,
        scope=TrustScope.GENERAL,
        statement="Reliable data analysis agent"
    )
    print(f"  Vouch ID: {vouch.vouch_id[:16]}...")
    print(f"  Level: {vouch.level}")
    print(f"  Scope: {vouch.scope}")
    
    # Now the orchestrator trusts supervisor → trusts analyst transitively
    print(f"\nOrchestrator trusts Supervisor directly.")
    print(f"Supervisor vouches for Data Analyst.")
    print(f"→ Transitive trust: Orchestrator → Supervisor → Data Analyst")
    print(f"  Trust depth: 2 (within typical threshold of 3)")
    
    # === Step 4: Signed task messages ===
    print_section("Step 4: Sign A2A Task Messages")
    
    task_id = f"task-{hashlib.sha256(os.urandom(8)).hexdigest()[:12]}"
    print(f"Task ID: {task_id}")
    
    # Orchestrator sends a signed task request
    task_message = {
        "role": "user",
        "parts": [{"kind": "text", "text": "Analyze Q4 revenue data and identify trends"}]
    }
    
    signed = sign_task_message(orchestrator, task_id, task_message)
    print(f"\nSigned task message:")
    print(f"  Signer: {signed['aip_signature']['signer_did']}")
    print(f"  Algorithm: {signed['aip_signature']['algorithm']}")
    print(f"  Signature: {signed['aip_signature']['signature'][:40]}...")
    print(f"  Payload hash: {signed['aip_signature']['signed_payload_hash'][:20]}...")
    
    # Data Analyst responds with signed result
    response_message = {
        "role": "agent",
        "parts": [{"kind": "text", "text": "Q4 revenue up 12% YoY. Key driver: enterprise segment (+23%)."}]
    }
    
    signed_response = sign_task_message(data_analyst, task_id, response_message)
    print(f"\nSigned response:")
    print(f"  Signer: {signed_response['aip_signature']['signer_did']}")
    print(f"  Signature: {signed_response['aip_signature']['signature'][:40]}...")
    
    # === Summary ===
    print_section("Summary: AIP + A2A Integration Points")
    print("""
    ┌─────────────────────────────────────────────────┐
    │  A2A Protocol          AIP Identity Layer       │
    │  ─────────────         ──────────────────       │
    │  AgentCard      ←──→   DID + Public Key         │
    │  Task Delegation ←──→  Challenge-Response Verify │
    │  Messages        ←──→  Ed25519 Signatures        │
    │  Agent Discovery ←──→  Vouch Chains + Trust      │
    │  Access Control  ←──→  Trust Score Thresholds    │
    └─────────────────────────────────────────────────┘

    This demo shows how AIP provides the missing identity layer
    for A2A's agent-to-agent communication protocol.

    See PR #1511: https://github.com/a2aproject/A2A/pull/1511
    Install: pip install aip-identity
    Docs: https://the-nexus-guard.github.io/aip/
    """)


if __name__ == "__main__":
    main()
