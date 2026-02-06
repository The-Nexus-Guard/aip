#!/bin/bash
# Script to demonstrate AIP registration flow
# Run with: asciinema rec demo.cast
# Convert to GIF: agg demo.cast demo.gif

echo "=== AIP Registration Demo ==="
echo ""
sleep 1

echo "# Step 1: Register with AIP"
echo ""
sleep 0.5

echo '$ curl -X POST https://aip-service.fly.dev/register \'
echo '    -H "Content-Type: application/json" \'
echo '    -d '\''{"platform": "moltbook", "platform_id": "demo_agent"}'\'''
echo ""
sleep 1

# Simulated response (use actual API in real recording)
cat << 'EOF'
{
  "success": true,
  "did": "did:aip:7f3a9b2c1d4e5f6a8b9c0d1e2f3a4b5c",
  "public_key": "X7Jk9mP2qR5tV8wZ1aB3cD6eF9gH2jK5",
  "private_key": "pR1vAtEkEy...SAVE_THIS_SECURELY"
}
EOF
echo ""
sleep 2

echo "# Step 2: Verify registration"
echo ""
sleep 0.5

echo '$ curl "https://aip-service.fly.dev/verify?platform=moltbook&platform_id=demo_agent"'
echo ""
sleep 1

cat << 'EOF'
{
  "registered": true,
  "did": "did:aip:7f3a9b2c1d4e5f6a8b9c0d1e2f3a4b5c",
  "platform": "moltbook",
  "platform_id": "demo_agent"
}
EOF
echo ""
sleep 2

echo "# Step 3: Check trust path to another agent"
echo ""
sleep 0.5

echo '$ curl "https://aip-service.fly.dev/trust-path?source_did=did:aip:abc&target_did=did:aip:xyz"'
echo ""
sleep 1

cat << 'EOF'
{
  "path_exists": true,
  "path_length": 2,
  "trust_score": 0.64,
  "path": ["did:aip:abc", "did:aip:middle", "did:aip:xyz"]
}
EOF
echo ""
sleep 2

echo "=== Done! Your agent now has cryptographic identity ==="
echo ""
echo "Docs: https://aip-service.fly.dev/docs"
echo "GitHub: https://github.com/The-Nexus-Guard/aip"
sleep 3
