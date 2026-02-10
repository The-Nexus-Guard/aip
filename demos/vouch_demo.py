#!/usr/bin/env python3
"""
AIP Vouch Demonstration

Shows how the vouch system works:
1. Two agents register
2. Agent A vouches for Agent B
3. Anyone can verify B's trust status

Usage:
    python vouch_demo.py
"""

import requests
import json
import time

AIP_BASE = "https://aip-service.fly.dev"

def print_step(step_num, description):
    print(f"\n{'='*60}")
    print(f"STEP {step_num}: {description}")
    print('='*60)
    time.sleep(0.5)

def print_json(data):
    print(json.dumps(data, indent=2))

def demo_vouch_system():
    print("\n" + "="*60)
    print("  AIP Vouch System Demonstration")
    print("="*60)

    # Step 1: Register Agent A (the voucher)
    print_step(1, "Register Agent A (will vouch for others)")

    agent_a_name = f"VouchDemo_AgentA_{int(time.time())}"
    resp = requests.post(f"{AIP_BASE}/register", json={
        "platform": "moltbook",
        "platform_id": agent_a_name
    })
    agent_a = resp.json()
    print(f"Agent A registered:")
    print(f"  DID: {agent_a['did']}")
    print(f"  Name: {agent_a_name}")

    # Step 2: Register Agent B (will receive vouch)
    print_step(2, "Register Agent B (will receive vouch)")

    agent_b_name = f"VouchDemo_AgentB_{int(time.time())}"
    resp = requests.post(f"{AIP_BASE}/register", json={
        "platform": "moltbook",
        "platform_id": agent_b_name
    })
    agent_b = resp.json()
    print(f"Agent B registered:")
    print(f"  DID: {agent_b['did']}")
    print(f"  Name: {agent_b_name}")

    # Step 3: Check B's trust status (before vouch)
    print_step(3, "Check Agent B's trust status (before vouch)")

    resp = requests.get(f"{AIP_BASE}/trust/{agent_b['did']}")
    trust_before = resp.json()
    print_json(trust_before)
    print(f"\n→ Agent B has {trust_before.get('vouches_received', 0)} vouches")

    # Step 4: Agent A vouches for Agent B
    print_step(4, "Agent A vouches for Agent B (CODE_SIGNING scope)")

    # Build the vouch payload: voucher_did|target_did|scope|statement
    # This pipe-delimited format is what the /vouch endpoint verifies
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    import base64

    statement = "Trusted collaborator for code signing"
    payload = f"{agent_a['did']}|{agent_b['did']}|CODE_SIGNING|{statement}"
    print(f"Signing payload: {payload[:60]}...")

    key_bytes = bytes.fromhex(agent_a['private_key'])
    private_key = Ed25519PrivateKey.from_private_bytes(key_bytes)
    signature = base64.b64encode(private_key.sign(payload.encode('utf-8'))).decode()
    print(f"Signature generated: {signature[:30]}...")

    # Submit the vouch
    resp = requests.post(f"{AIP_BASE}/vouch", json={
        "voucher_did": agent_a['did'],
        "target_did": agent_b['did'],
        "scope": "CODE_SIGNING",
        "statement": statement,
        "signature": signature,
        "ttl_days": 30
    })
    vouch_result = resp.json()
    print(f"\nVouch result:")
    print_json(vouch_result)

    # Step 5: Check B's trust status (after vouch)
    print_step(5, "Check Agent B's trust status (after vouch)")

    resp = requests.get(f"{AIP_BASE}/trust/{agent_b['did']}")
    trust_after = resp.json()
    print_json(trust_after)
    print(f"\n→ Agent B now has {trust_after.get('vouches_received', 0)} vouch(es)")

    # Step 6: Check specific scope
    print_step(6, "Check if Agent B is trusted for CODE_SIGNING")

    resp = requests.get(f"{AIP_BASE}/trust/{agent_b['did']}?scope=CODE_SIGNING")
    scoped_trust = resp.json()
    print_json(scoped_trust)

    # Summary
    print("\n" + "="*60)
    print("  DEMONSTRATION COMPLETE")
    print("="*60)
    print(f"""
What happened:
  1. Agent A ({agent_a_name}) registered and got a DID
  2. Agent B ({agent_b_name}) registered and got a DID
  3. Agent A vouched for Agent B with scope CODE_SIGNING
  4. Anyone can now verify that B is vouched by A

Trust chain:
  Agent A --[CODE_SIGNING vouch]--> Agent B

This vouch will expire in 30 days (TTL).

Use cases:
  - MCP servers can require CODE_SIGNING vouches to run code
  - Skill installers can verify the author is vouched
  - Agents can build reputation through vouches from trusted peers
    """)

    return agent_a, agent_b

if __name__ == "__main__":
    demo_vouch_system()
