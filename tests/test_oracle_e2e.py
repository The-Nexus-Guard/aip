"""
End-to-end oracle test — runs against the live service.

Usage:
    AIP_E2E=1 pytest tests/test_oracle_e2e.py -v

Requires:
    - Live service at AIP_SERVICE_URL (default: https://aip-service.fly.dev)
    - AIP_ADMIN_KEY environment variable for cleanup
    - INSUMER_API_KEY configured on the live service

Skipped unless AIP_E2E=1 is set.
"""

import base64
import hashlib
import json
import os
import time
from datetime import datetime, timezone

import pytest
import requests
from nacl.signing import SigningKey

pytestmark = pytest.mark.skipif(
    os.environ.get("AIP_E2E") != "1",
    reason="E2E tests require AIP_E2E=1",
)

SERVICE_URL = os.environ.get("AIP_SERVICE_URL", "https://aip-service.fly.dev")
ADMIN_KEY = os.environ.get("AIP_ADMIN_KEY", "")

# Vitalik's well-known wallet (always has USDC)
VITALIK_WALLET = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
USDC_CONTRACT = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"


@pytest.fixture
def registered_agent():
    """Register a test agent and clean up after."""
    resp = requests.post(
        f"{SERVICE_URL}/register/easy",
        json={
            "platform": "test",
            "platform_id": f"e2e_oracle_{int(time.time())}",
            "username": f"e2e_oracle_{int(time.time())}",
        },
    )
    assert resp.status_code == 200, f"Registration failed: {resp.text}"
    data = resp.json()

    sk_bytes = base64.b64decode(data["private_key"])
    sk = SigningKey(sk_bytes[:32])

    yield {
        "did": data["did"],
        "public_key": data["public_key"],
        "signing_key": sk,
    }

    # Cleanup
    if ADMIN_KEY:
        requests.delete(
            f"{SERVICE_URL}/admin/registrations/{data['did']}",
            headers={"Authorization": f"Bearer {ADMIN_KEY}"},
        )


class TestOracleE2E:
    def test_health(self):
        """Service is healthy."""
        resp = requests.get(f"{SERVICE_URL}/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert data["checks"]["database"]["ok"] is True

    def test_wallet_bind(self, registered_agent):
        """Can bind a wallet to a DID."""
        ts = datetime.now(tz=timezone.utc).isoformat()
        sign_msg = f"bind:{VITALIK_WALLET}:{ts}"
        sig = registered_agent["signing_key"].sign(sign_msg.encode()).signature
        sig_b64 = base64.b64encode(sig).decode()

        resp = requests.post(
            f"{SERVICE_URL}/oracle/wallet/bind",
            json={
                "did": registered_agent["did"],
                "wallet_address": VITALIK_WALLET,
                "chain_type": "evm",
                "did_signature": sig_b64,
                "timestamp": ts,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["wallet_address"] == VITALIK_WALLET

    def test_wallet_list(self, registered_agent):
        """Can list wallet bindings."""
        # Bind first
        ts = datetime.now(tz=timezone.utc).isoformat()
        sign_msg = f"bind:{VITALIK_WALLET}:{ts}"
        sig = registered_agent["signing_key"].sign(sign_msg.encode()).signature
        sig_b64 = base64.b64encode(sig).decode()

        requests.post(
            f"{SERVICE_URL}/oracle/wallet/bind",
            json={
                "did": registered_agent["did"],
                "wallet_address": VITALIK_WALLET,
                "chain_type": "evm",
                "did_signature": sig_b64,
                "timestamp": ts,
            },
        )

        # List
        resp = requests.get(f"{SERVICE_URL}/oracle/wallet/{registered_agent['did']}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert len(data["wallets"]) >= 1

    def test_verify_onchain_usdc(self, registered_agent):
        """Full flow: bind wallet → verify USDC balance → oracle vouch created."""
        # Step 1: Bind wallet
        ts = datetime.now(tz=timezone.utc).isoformat()
        sign_msg = f"bind:{VITALIK_WALLET}:{ts}"
        sig = registered_agent["signing_key"].sign(sign_msg.encode()).signature
        sig_b64 = base64.b64encode(sig).decode()

        bind_resp = requests.post(
            f"{SERVICE_URL}/oracle/wallet/bind",
            json={
                "did": registered_agent["did"],
                "wallet_address": VITALIK_WALLET,
                "chain_type": "evm",
                "did_signature": sig_b64,
                "timestamp": ts,
            },
        )
        assert bind_resp.status_code == 200

        # Step 2: Verify USDC balance
        verify_resp = requests.post(
            f"{SERVICE_URL}/oracle/verify/onchain",
            json={
                "did": registered_agent["did"],
                "conditions": [
                    {
                        "type": "token_balance",
                        "chain_id": 1,
                        "contract_address": USDC_CONTRACT,
                        "threshold": 1,
                        "decimals": 6,
                        "label": "USDC >= 1",
                    }
                ],
            },
        )

        if verify_resp.status_code == 503:
            # InsumerAPI RPC failure — transient, skip
            pytest.skip("InsumerAPI RPC temporarily unavailable")

        assert verify_resp.status_code == 200
        data = verify_resp.json()
        assert data["success"] is True
        assert data["passed"] is True
        assert data["vouch_id"] is not None
        assert data["attestation_id"] is not None
        assert len(data["results"]) == 1
        assert data["results"][0]["met"] is True

    def test_attestation_cached(self, registered_agent):
        """Attestations are cached after first verification."""
        # Bind + verify
        ts = datetime.now(tz=timezone.utc).isoformat()
        sign_msg = f"bind:{VITALIK_WALLET}:{ts}"
        sig = registered_agent["signing_key"].sign(sign_msg.encode()).signature
        sig_b64 = base64.b64encode(sig).decode()

        requests.post(
            f"{SERVICE_URL}/oracle/wallet/bind",
            json={
                "did": registered_agent["did"],
                "wallet_address": VITALIK_WALLET,
                "chain_type": "evm",
                "did_signature": sig_b64,
                "timestamp": ts,
            },
        )

        verify_resp = requests.post(
            f"{SERVICE_URL}/oracle/verify/onchain",
            json={
                "did": registered_agent["did"],
                "conditions": [
                    {
                        "type": "token_balance",
                        "chain_id": 1,
                        "contract_address": USDC_CONTRACT,
                        "threshold": 1,
                        "decimals": 6,
                        "label": "USDC >= 1",
                    }
                ],
            },
        )

        if verify_resp.status_code == 503:
            pytest.skip("InsumerAPI RPC temporarily unavailable")

        assert verify_resp.status_code == 200

        # Check attestation cache
        cache_resp = requests.get(
            f"{SERVICE_URL}/oracle/attestations/{registered_agent['did']}"
        )
        assert cache_resp.status_code == 200
        data = cache_resp.json()
        assert data["success"] is True
        assert len(data["attestations"]) >= 1

    def test_invalid_signature_rejected(self, registered_agent):
        """Wallet bind with invalid signature is rejected."""
        ts = datetime.now(tz=timezone.utc).isoformat()
        fake_sig = base64.b64encode(b"x" * 64).decode()

        resp = requests.post(
            f"{SERVICE_URL}/oracle/wallet/bind",
            json={
                "did": registered_agent["did"],
                "wallet_address": VITALIK_WALLET,
                "chain_type": "evm",
                "did_signature": fake_sig,
                "timestamp": ts,
            },
        )
        assert resp.status_code == 403

    def test_unregistered_did_rejected(self):
        """Wallet bind for non-existent DID is rejected."""
        ts = datetime.now(tz=timezone.utc).isoformat()
        fake_sig = base64.b64encode(b"x" * 64).decode()

        resp = requests.post(
            f"{SERVICE_URL}/oracle/wallet/bind",
            json={
                "did": "did:aip:nonexistent000000000000000000",
                "wallet_address": VITALIK_WALLET,
                "chain_type": "evm",
                "did_signature": fake_sig,
                "timestamp": ts,
            },
        )
        assert resp.status_code == 404
