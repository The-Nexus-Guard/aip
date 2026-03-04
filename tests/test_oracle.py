"""
Tests for the oracle module — wallet-DID binding and on-chain credential verification.
"""

import base64
import json
import os
import sys
import time
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Set up paths
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'service'))

import database


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path):
    """Use a temporary database for each test."""
    db_path = str(tmp_path / "test_oracle.db")
    database.DATABASE_PATH = db_path
    database.init_database()
    yield
    database.DATABASE_PATH = "aip.db"


@pytest.fixture
def sample_did():
    """Register a sample DID and return its info."""
    from nacl.signing import SigningKey
    sk = SigningKey.generate()
    pk_b64 = base64.b64encode(sk.verify_key.encode()).decode()

    import hashlib
    did_hash = hashlib.sha256(sk.verify_key.encode()).hexdigest()[:32]
    did = f"did:aip:{did_hash}"

    database.register_did(did, pk_b64)
    return {
        "did": did,
        "public_key": pk_b64,
        "signing_key": sk,
    }


class TestWalletBindings:
    def test_bind_wallet(self, sample_did):
        """Test binding a wallet to a DID."""
        result = database.bind_wallet(
            sample_did["did"], "0x1234567890abcdef1234567890abcdef12345678", "evm"
        )
        assert result is True

    def test_bind_duplicate_wallet(self, sample_did):
        """Test binding the same wallet twice returns False."""
        wallet = "0xabcdef1234567890abcdef1234567890abcdef12"
        database.bind_wallet(sample_did["did"], wallet, "evm")
        result = database.bind_wallet(sample_did["did"], wallet, "evm")
        assert result is False

    def test_list_wallets(self, sample_did):
        """Test listing wallet bindings."""
        wallet1 = "0x1111111111111111111111111111111111111111"
        wallet2 = "0x2222222222222222222222222222222222222222"

        database.bind_wallet(sample_did["did"], wallet1, "evm")
        database.bind_wallet(sample_did["did"], wallet2, "solana")

        wallets = database.get_wallet_bindings(sample_did["did"])
        assert len(wallets) == 2
        assert wallets[0]["wallet_address"] == wallet1
        assert wallets[0]["chain_type"] == "evm"
        assert wallets[1]["wallet_address"] == wallet2
        assert wallets[1]["chain_type"] == "solana"

    def test_unbind_wallet(self, sample_did):
        """Test revoking a wallet binding."""
        wallet = "0x3333333333333333333333333333333333333333"
        database.bind_wallet(sample_did["did"], wallet, "evm")

        result = database.unbind_wallet(sample_did["did"], wallet)
        assert result is True

        # Should no longer appear in list
        wallets = database.get_wallet_bindings(sample_did["did"])
        assert len(wallets) == 0

    def test_unbind_nonexistent(self, sample_did):
        """Test unbinding a non-existent wallet."""
        result = database.unbind_wallet(sample_did["did"], "0xnope")
        assert result is False

    def test_empty_wallets(self, sample_did):
        """Test listing wallets when none are bound."""
        wallets = database.get_wallet_bindings(sample_did["did"])
        assert wallets == []

    def test_bind_multiple_chains(self, sample_did):
        """Test binding wallets across different chain types."""
        database.bind_wallet(sample_did["did"], "0xEVM", "evm")
        database.bind_wallet(sample_did["did"], "SolAddr", "solana")
        database.bind_wallet(sample_did["did"], "rXRPL", "xrpl")

        wallets = database.get_wallet_bindings(sample_did["did"])
        chains = {w["chain_type"] for w in wallets}
        assert chains == {"evm", "solana", "xrpl"}


class TestAttestationCache:
    def test_cache_and_retrieve(self, sample_did):
        """Test caching and retrieving an attestation."""
        did = sample_did["did"]
        expires = "2099-12-31T23:59:59Z"

        database.cache_attestation(
            did=did,
            wallet_address="0xtest",
            conditions_hash="abc123",
            result=True,
            attestation_id="ATST-TEST",
            results_json='[{"met": true, "type": "token_balance"}]',
            insumer_signature="sig123",
            insumer_kid="insumer-attest-v1",
            expires_at=expires,
            vouch_id="oracle-test123",
        )

        cached = database.get_cached_attestation(did, "abc123")
        assert cached is not None
        assert cached["result"] == 1  # SQLite stores True as 1
        assert cached["attestation_id"] == "ATST-TEST"
        assert cached["vouch_id"] == "oracle-test123"
        assert cached["expires_at"] == expires

    def test_cache_miss(self, sample_did):
        """Test cache miss returns None."""
        cached = database.get_cached_attestation(sample_did["did"], "nonexistent")
        assert cached is None

    def test_cache_replace(self, sample_did):
        """Test updating a cached attestation."""
        did = sample_did["did"]

        database.cache_attestation(
            did=did, wallet_address="0xtest", conditions_hash="hash1",
            result=False, attestation_id="ATST-1", results_json="[]",
            insumer_signature="sig1", insumer_kid="v1",
            expires_at="2099-01-01T00:00:00Z",
        )

        database.cache_attestation(
            did=did, wallet_address="0xtest", conditions_hash="hash1",
            result=True, attestation_id="ATST-2", results_json="[]",
            insumer_signature="sig2", insumer_kid="v1",
            expires_at="2099-06-01T00:00:00Z",
        )

        cached = database.get_cached_attestation(did, "hash1")
        assert cached["attestation_id"] == "ATST-2"
        assert cached["result"] == 1

    def test_get_attestations_for_did(self, sample_did):
        """Test getting all attestations for a DID."""
        did = sample_did["did"]

        database.cache_attestation(
            did=did, wallet_address="0xtest", conditions_hash="h1",
            result=True, attestation_id="A1", results_json="[]",
            insumer_signature="s1", insumer_kid="v1",
            expires_at="2099-12-31T23:59:59Z",
        )
        database.cache_attestation(
            did=did, wallet_address="0xtest", conditions_hash="h2",
            result=False, attestation_id="A2", results_json="[]",
            insumer_signature="s2", insumer_kid="v1",
            expires_at="2099-12-31T23:59:59Z",
        )

        attestations = database.get_attestations_for_did(did)
        assert len(attestations) == 2

    def test_cleanup_expired(self, sample_did):
        """Test cleaning up expired attestations."""
        did = sample_did["did"]

        # Expired
        database.cache_attestation(
            did=did, wallet_address="0xtest", conditions_hash="expired",
            result=True, attestation_id="OLD", results_json="[]",
            insumer_signature="s", insumer_kid="v1",
            expires_at="2020-01-01T00:00:00Z",
        )
        # Still valid
        database.cache_attestation(
            did=did, wallet_address="0xtest", conditions_hash="valid",
            result=True, attestation_id="NEW", results_json="[]",
            insumer_signature="s", insumer_kid="v1",
            expires_at="2099-12-31T23:59:59Z",
        )

        cleaned = database.cleanup_expired_attestations()
        assert cleaned == 1

        # Only valid one remains
        attestations = database.get_attestations_for_did(did)
        assert len(attestations) == 1
        assert attestations[0]["attestation_id"] == "NEW"


class TestOracleVouchCreation:
    def test_oracle_vouch_created_on_pass(self, sample_did):
        """Test that a passing attestation creates an oracle vouch."""
        did = sample_did["did"]

        # Create oracle vouch directly (simulating what the endpoint does)
        vouch_id = "oracle-test456"
        success = database.create_vouch(
            vouch_id=vouch_id,
            voucher_did="did:aip:oracle:insumerapi",
            target_did=did,
            scope="ONCHAIN_CREDENTIAL",
            statement="On-chain credential verified: USDC >= 1000",
            signature="mock-insumer-sig",
            ttl_days=1,
        )
        assert success is True

        # Verify vouch exists
        vouches = database.get_vouches_for(did)
        oracle_vouches = [v for v in vouches if v["voucher_did"] == "did:aip:oracle:insumerapi"]
        assert len(oracle_vouches) == 1
        assert oracle_vouches[0]["scope"] == "ONCHAIN_CREDENTIAL"


class TestConditionsHash:
    def test_deterministic(self):
        """Test that conditions hash is deterministic."""
        from routes.oracle import _conditions_hash, OnchainCondition

        conditions = [
            OnchainCondition(type="token_balance", chain_id=1, contract_address="0xA0b8", threshold=100, decimals=18),
        ]

        h1 = _conditions_hash(conditions)
        h2 = _conditions_hash(conditions)
        assert h1 == h2

    def test_different_conditions_different_hash(self):
        """Test that different conditions produce different hashes."""
        from routes.oracle import _conditions_hash, OnchainCondition

        c1 = [OnchainCondition(type="token_balance", chain_id=1, threshold=100)]
        c2 = [OnchainCondition(type="token_balance", chain_id=1, threshold=200)]

        assert _conditions_hash(c1) != _conditions_hash(c2)


class TestSignatureVerification:
    def test_valid_signature(self, sample_did):
        """Test signature verification with valid sig."""
        from routes.oracle import _verify_did_signature

        sk = sample_did["signing_key"]
        message = "bind:0xtest:2026-01-01T00:00:00Z"
        sig = sk.sign(message.encode()).signature
        sig_b64 = base64.b64encode(sig).decode()

        assert _verify_did_signature(sample_did["did"], message, sig_b64) is True

    def test_invalid_signature(self, sample_did):
        """Test signature verification with invalid sig."""
        from routes.oracle import _verify_did_signature

        # Wrong message
        assert _verify_did_signature(
            sample_did["did"], "wrong message", base64.b64encode(b"x" * 64).decode()
        ) is False

    def test_nonexistent_did(self):
        """Test signature verification with nonexistent DID."""
        from routes.oracle import _verify_did_signature

        assert _verify_did_signature("did:aip:nonexistent", "msg", "sig") is False
