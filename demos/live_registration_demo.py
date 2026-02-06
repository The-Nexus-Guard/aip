#!/usr/bin/env python3
"""
Live AIP registration demo.

This script demonstrates the actual registration flow against the live service.
Run it to see real API responses.

Usage:
    python3 live_registration_demo.py [agent_name]
"""

import sys
import json
import time
import requests

SERVICE_URL = "https://aip-service.fly.dev"

def print_slow(text, delay=0.03):
    """Print text character by character for demo effect."""
    for char in text:
        print(char, end='', flush=True)
        time.sleep(delay)
    print()

def print_json(data):
    """Pretty print JSON with syntax highlighting simulation."""
    formatted = json.dumps(data, indent=2)
    print(formatted)

def main():
    agent_name = sys.argv[1] if len(sys.argv) > 1 else f"demo_agent_{int(time.time())}"

    print("\n" + "="*50)
    print("  AIP Registration Demo (LIVE)")
    print("="*50 + "\n")
    time.sleep(1)

    # Step 1: Register
    print_slow("Step 1: Registering with AIP...")
    print()
    print(f'  POST {SERVICE_URL}/register')
    print(f'  {{"platform": "moltbook", "platform_id": "{agent_name}"}}')
    print()

    try:
        response = requests.post(
            f"{SERVICE_URL}/register",
            json={"platform": "moltbook", "platform_id": agent_name},
            timeout=10
        )
        data = response.json()

        if data.get("success"):
            print("  Response:")
            # Mask private key for security
            display_data = data.copy()
            if "private_key" in display_data:
                display_data["private_key"] = display_data["private_key"][:20] + "...[SAVE SECURELY]"
            print_json(display_data)
            did = data.get("did")
        else:
            print(f"  Error: {data}")
            return

    except Exception as e:
        print(f"  Error: {e}")
        return

    print()
    time.sleep(2)

    # Step 2: Verify
    print_slow("Step 2: Verifying registration...")
    print()
    print(f'  GET {SERVICE_URL}/verify?platform=moltbook&platform_id={agent_name}')
    print()

    try:
        response = requests.get(
            f"{SERVICE_URL}/verify",
            params={"platform": "moltbook", "platform_id": agent_name},
            timeout=10
        )
        print("  Response:")
        print_json(response.json())
    except Exception as e:
        print(f"  Error: {e}")

    print()
    time.sleep(2)

    # Step 3: Check stats
    print_slow("Step 3: Checking service stats...")
    print()
    print(f'  GET {SERVICE_URL}/stats')
    print()

    try:
        response = requests.get(f"{SERVICE_URL}/stats", timeout=10)
        stats = response.json()
        print("  Response:")
        print_json({
            "status": stats.get("status"),
            "registrations": stats.get("stats", {}).get("registrations"),
            "active_vouches": stats.get("stats", {}).get("active_vouches")
        })
    except Exception as e:
        print(f"  Error: {e}")

    print()
    print("="*50)
    print("  Done! Your agent now has cryptographic identity.")
    print("="*50)
    print()
    print(f"  Your DID: {did}")
    print(f"  Docs: {SERVICE_URL}/docs")
    print(f"  GitHub: https://github.com/The-Nexus-Guard/aip")
    print()

if __name__ == "__main__":
    main()
