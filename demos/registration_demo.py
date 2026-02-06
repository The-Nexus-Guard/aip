#!/usr/bin/env python3
"""
AIP Registration Demo Script

This script demonstrates the complete registration flow for AIP.
Can be used to generate screenshots/recordings for documentation.

Usage:
    python registration_demo.py [--agent-name YOUR_NAME]
"""

import requests
import json
import time
import sys

AIP_BASE = "https://aip-service.fly.dev"

def print_step(step_num, description):
    """Print a formatted step header."""
    print(f"\n{'='*60}")
    print(f"STEP {step_num}: {description}")
    print('='*60)
    time.sleep(1)  # Pause for demo effect

def print_response(data):
    """Pretty print JSON response."""
    print(json.dumps(data, indent=2))

def demo_registration(agent_name="DemoAgent"):
    """
    Walk through the complete AIP registration flow.
    """
    print("\n" + "="*60)
    print("  AIP - Agent Identity Protocol")
    print("  Registration Demo")
    print("="*60)

    # Step 1: Check service health
    print_step(1, "Check Service Health")
    print(f"GET {AIP_BASE}/stats")

    resp = requests.get(f"{AIP_BASE}/stats")
    stats = resp.json()
    print_response(stats)
    print(f"\n✓ Service is {stats['status']}")
    print(f"✓ {stats['stats']['registrations']} agents already registered")

    # Step 2: Register new agent
    print_step(2, f"Register Agent '{agent_name}'")
    print(f"POST {AIP_BASE}/register")

    register_data = {
        "platform": "moltbook",
        "platform_id": agent_name
    }
    print(f"Request body: {json.dumps(register_data)}")

    resp = requests.post(f"{AIP_BASE}/register", json=register_data)
    result = resp.json()
    print_response(result)

    if "did" in result:
        did = result["did"]
        private_key = result.get("private_key", "[stored securely]")
        print(f"\n✓ Registration successful!")
        print(f"✓ Your DID: {did}")
        print(f"✓ Your private key: {private_key[:20]}... (KEEP THIS SECRET)")
    else:
        print(f"\n✗ Registration failed: {result}")
        return None

    # Step 3: Verify the registration
    print_step(3, "Verify Your Identity")
    print(f"GET {AIP_BASE}/verify/{did}")

    resp = requests.get(f"{AIP_BASE}/verify/{did}")
    verify_result = resp.json()
    print_response(verify_result)

    if verify_result.get("verified"):
        print(f"\n✓ Identity verified!")
        print(f"✓ Platforms: {verify_result.get('platforms', [])}")

    # Step 4: Check your trust status
    print_step(4, "Check Trust Status")
    print(f"GET {AIP_BASE}/trust/{did}")

    resp = requests.get(f"{AIP_BASE}/trust/{did}")
    trust_result = resp.json()
    print_response(trust_result)

    print(f"\n✓ Vouches received: {trust_result.get('vouches_received', 0)}")
    print(f"✓ Vouches given: {trust_result.get('vouches_given', 0)}")

    # Summary
    print("\n" + "="*60)
    print("  REGISTRATION COMPLETE")
    print("="*60)
    print(f"""
What you now have:
  1. A unique DID: {did}
  2. A cryptographic keypair for signing
  3. A verifiable identity other agents can check

Next steps:
  - Get vouched by trusted agents
  - Sign your skills with your DID
  - Use your DID to authenticate with other services

Documentation: {AIP_BASE}/docs
    """)

    return did

if __name__ == "__main__":
    agent_name = sys.argv[1] if len(sys.argv) > 1 else f"DemoAgent_{int(time.time())}"
    demo_registration(agent_name)
