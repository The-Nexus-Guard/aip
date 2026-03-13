"""
Tests for /trust-path PDR integration.

Tests that the trust-path endpoint correctly handles optional PDR parameters
and returns composite trust scores when PDR data is provided.
"""

import uuid
import base64
import nacl.signing
import pytest
from fastapi.testclient import TestClient

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'service'))

from service.main import app

client = TestClient(app)


def _register(suffix="agent"):
    """Register a test agent and return (did, signing_key)."""
    resp = client.post("/register/easy", json={
        "platform": "test",
        "username": f"pdr_{suffix}_{uuid.uuid4().hex[:8]}"
    })
    assert resp.status_code == 200
    data = resp.json()
    sk = nacl.signing.SigningKey(base64.b64decode(data["private_key"])[:32])
    return data["did"], sk


def _sign(sk, msg):
    """Sign a message and return base64 signature."""
    return base64.b64encode(sk.sign(msg.encode("utf-8")).signature).decode()


def _vouch(voucher_did, voucher_sk, target_did):
    """Create a vouch from voucher to target."""
    payload = f"{voucher_did}|{target_did}|GENERAL|trust"
    sig = _sign(voucher_sk, payload)
    resp = client.post("/vouch", json={
        "voucher_did": voucher_did,
        "target_did": target_did,
        "scope": "GENERAL",
        "statement": "trust",
        "signature": sig,
    })
    assert resp.status_code == 200
    return resp.json()


class TestTrustPathPDRBasic:
    """Test /trust-path still works without PDR params (backward compat)."""

    def test_no_pdr_params_no_pdr_fields(self):
        """Without PDR params, response should have no PDR fields."""
        a_did, a_sk = _register("a")
        b_did, _ = _register("b")
        _vouch(a_did, a_sk, b_did)

        resp = client.get("/trust-path", params={
            "source_did": a_did, "target_did": b_did
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["path_exists"] is True
        assert data["trust_score"] == 0.8  # default decay
        assert data["composite_trust_score"] is None
        assert data["behavioral_reliability"] is None
        assert data["pdr"] is None
        assert data["trust_divergence_alert"] is None


class TestTrustPathPDRIntegration:
    """Test /trust-path with PDR parameters."""

    def test_direct_trust_with_pdr(self):
        """Direct vouch + PDR scores → composite = 0.8 × behavioral."""
        a_did, a_sk = _register("a")
        b_did, _ = _register("b")
        _vouch(a_did, a_sk, b_did)

        resp = client.get("/trust-path", params={
            "source_did": a_did,
            "target_did": b_did,
            "pdr_calibration": 0.9,
            "pdr_adaptation": 0.8,
            "pdr_robustness": 0.85,
            "pdr_window_days": 30,
        })
        assert resp.status_code == 200
        data = resp.json()

        assert data["path_exists"] is True
        assert data["trust_score"] == 0.8

        # PDR fields should be present
        assert data["composite_trust_score"] is not None
        assert data["behavioral_reliability"] is not None
        assert data["pdr"] is not None

        # Behavioral = 0.5*0.9 + 0.2*0.8 + 0.3*0.85 = 0.45 + 0.16 + 0.255 = 0.865
        assert abs(data["behavioral_reliability"] - 0.865) < 0.001

        # Composite = 0.8 × 0.865 = 0.692
        assert abs(data["composite_trust_score"] - 0.692) < 0.001

        # PDR breakdown
        pdr = data["pdr"]
        assert pdr["calibration"] == 0.9
        assert pdr["adaptation"] == 0.8
        assert pdr["robustness"] == 0.85
        assert pdr["is_provisional"] is False
        assert pdr["confidence"] == "high"
        assert pdr["measurement_window_days"] == 30

    def test_two_hop_trust_with_pdr(self):
        """Two-hop vouch chain + PDR → composite uses decayed social trust."""
        a_did, a_sk = _register("a")
        b_did, b_sk = _register("b")
        c_did, _ = _register("c")
        _vouch(a_did, a_sk, b_did)
        _vouch(b_did, b_sk, c_did)

        resp = client.get("/trust-path", params={
            "source_did": a_did,
            "target_did": c_did,
            "pdr_calibration": 1.0,
            "pdr_adaptation": 1.0,
            "pdr_robustness": 1.0,
        })
        assert resp.status_code == 200
        data = resp.json()

        # 2 hops → social trust = 0.8^2 = 0.64
        assert data["trust_score"] == 0.64
        # Perfect PDR → behavioral = 1.0 → composite = 0.64
        assert abs(data["composite_trust_score"] - 0.64) < 0.001
        assert abs(data["behavioral_reliability"] - 1.0) < 0.001

    def test_no_path_with_pdr(self):
        """No trust path → composite still 0.0 regardless of PDR."""
        a_did, _ = _register("a")
        b_did, _ = _register("b")

        resp = client.get("/trust-path", params={
            "source_did": a_did,
            "target_did": b_did,
            "pdr_calibration": 1.0,
            "pdr_adaptation": 1.0,
            "pdr_robustness": 1.0,
        })
        assert resp.status_code == 200
        data = resp.json()

        assert data["path_exists"] is False
        assert data["trust_score"] == 0.0
        # Even perfect PDR can't save zero social trust
        assert data["composite_trust_score"] == 0.0

    def test_self_trust_with_pdr(self):
        """Same DID → social = 1.0, composite = behavioral."""
        a_did, _ = _register("a")

        resp = client.get("/trust-path", params={
            "source_did": a_did,
            "target_did": a_did,
            "pdr_calibration": 0.7,
            "pdr_adaptation": 0.6,
            "pdr_robustness": 0.5,
        })
        assert resp.status_code == 200
        data = resp.json()

        assert data["trust_score"] == 1.0
        # Behavioral = 0.5*0.7 + 0.2*0.6 + 0.3*0.5 = 0.35 + 0.12 + 0.15 = 0.62
        assert abs(data["behavioral_reliability"] - 0.62) < 0.001
        assert abs(data["composite_trust_score"] - 0.62) < 0.001

    def test_divergence_alert_high_social_low_behavioral(self):
        """High social trust + low behavioral → divergence alert."""
        a_did, a_sk = _register("a")
        b_did, _ = _register("b")
        _vouch(a_did, a_sk, b_did)

        resp = client.get("/trust-path", params={
            "source_did": a_did,
            "target_did": b_did,
            "pdr_calibration": 0.3,
            "pdr_adaptation": 0.2,
            "pdr_robustness": 0.1,
            "pdr_window_days": 30,
        })
        assert resp.status_code == 200
        data = resp.json()

        # Social = 0.8, behavioral = 0.4*0.3 + 0.35*0.2 + 0.25*0.1 = 0.12 + 0.07 + 0.025 = 0.215
        # Gap = 0.8 - 0.215 = 0.585 > 0.3 threshold
        assert data["trust_divergence_alert"] is not None
        assert "over-vouching" in data["trust_divergence_alert"].lower() or "re-evaluating" in data["trust_divergence_alert"].lower()

    def test_no_divergence_when_aligned(self):
        """When social and behavioral are aligned, no alert."""
        a_did, a_sk = _register("a")
        b_did, _ = _register("b")
        _vouch(a_did, a_sk, b_did)

        resp = client.get("/trust-path", params={
            "source_did": a_did,
            "target_did": b_did,
            "pdr_calibration": 0.9,
            "pdr_adaptation": 0.85,
            "pdr_robustness": 0.9,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["trust_divergence_alert"] is None

    def test_provisional_pdr_flagged(self):
        """PDR with short measurement window is flagged as provisional."""
        a_did, a_sk = _register("a")
        b_did, _ = _register("b")
        _vouch(a_did, a_sk, b_did)

        resp = client.get("/trust-path", params={
            "source_did": a_did,
            "target_did": b_did,
            "pdr_calibration": 0.8,
            "pdr_adaptation": 0.8,
            "pdr_robustness": 0.8,
            "pdr_window_days": 5,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["pdr"]["is_provisional"] is True
        assert data["pdr"]["confidence"] == "very_low"

    def test_no_window_means_unknown_confidence(self):
        """PDR without window_days → unknown confidence, provisional."""
        a_did, a_sk = _register("a")
        b_did, _ = _register("b")
        _vouch(a_did, a_sk, b_did)

        resp = client.get("/trust-path", params={
            "source_did": a_did,
            "target_did": b_did,
            "pdr_calibration": 0.8,
            "pdr_adaptation": 0.8,
            "pdr_robustness": 0.8,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["pdr"]["is_provisional"] is True
        assert data["pdr"]["confidence"] == "unknown"
        assert data["pdr"]["measurement_window_days"] is None


class TestTrustPathPDRValidation:
    """Test validation of PDR parameters."""

    def test_partial_pdr_params_ignored(self):
        """If only some PDR params provided, they're ignored (all 3 required)."""
        a_did, a_sk = _register("a")
        b_did, _ = _register("b")
        _vouch(a_did, a_sk, b_did)

        # Only calibration, missing adaptation and robustness
        resp = client.get("/trust-path", params={
            "source_did": a_did,
            "target_did": b_did,
            "pdr_calibration": 0.9,
        })
        assert resp.status_code == 200
        data = resp.json()
        # Should behave as if no PDR params
        assert data["composite_trust_score"] is None
        assert data["pdr"] is None

    def test_pdr_out_of_range_rejected(self):
        """PDR values outside [0,1] should be rejected by FastAPI."""
        a_did, _ = _register("a")
        b_did, _ = _register("b")

        resp = client.get("/trust-path", params={
            "source_did": a_did,
            "target_did": b_did,
            "pdr_calibration": 1.5,
            "pdr_adaptation": 0.8,
            "pdr_robustness": 0.8,
        })
        assert resp.status_code == 422  # Validation error

    def test_pdr_zero_scores(self):
        """All-zero PDR → behavioral = 0, composite = 0."""
        a_did, a_sk = _register("a")
        b_did, _ = _register("b")
        _vouch(a_did, a_sk, b_did)

        resp = client.get("/trust-path", params={
            "source_did": a_did,
            "target_did": b_did,
            "pdr_calibration": 0.0,
            "pdr_adaptation": 0.0,
            "pdr_robustness": 0.0,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["composite_trust_score"] == 0.0
        assert data["behavioral_reliability"] == 0.0

    def test_pdr_perfect_scores(self):
        """All-1.0 PDR → behavioral = 1.0, composite = social_trust."""
        a_did, a_sk = _register("a")
        b_did, _ = _register("b")
        _vouch(a_did, a_sk, b_did)

        resp = client.get("/trust-path", params={
            "source_did": a_did,
            "target_did": b_did,
            "pdr_calibration": 1.0,
            "pdr_adaptation": 1.0,
            "pdr_robustness": 1.0,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["behavioral_reliability"] == 1.0
        assert data["composite_trust_score"] == data["trust_score"]
