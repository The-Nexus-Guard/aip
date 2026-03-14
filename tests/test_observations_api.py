"""Tests for the observation submission and PDR scoring API."""
import base64
import hashlib
import time
import pytest
import requests

from nacl.signing import SigningKey


def _make_agent(signing_key):
    """Create agent DID and public key (base64) from signing key."""
    pub_bytes = signing_key.verify_key.encode()
    pub_b64 = base64.b64encode(pub_bytes).decode()
    did = "did:aip:" + hashlib.sha256(pub_bytes).hexdigest()[:32]
    return did, pub_b64


def _sign_nonce(signing_key, nonce: str) -> str:
    signed = signing_key.sign(nonce.encode())
    return signed.signature.hex()


def _register_agent(base_url, did, pub_b64, username):
    r = requests.post(f"{base_url}/register", json={
        "did": did, "public_key": pub_b64, "username": username,
        "platform": "test",
    })
    assert r.status_code == 200, r.text
    return r.json()


class TestObservationsAPI:
    """Test observation submission and PDR scoring."""

    def test_submit_observations(self, local_service):
        sk = SigningKey.generate()
        did, pub_hex = _make_agent(sk)
        _register_agent(local_service, did, pub_hex, f"obs_submit_{time.time_ns()}")

        nonce = f"submit-{time.time_ns()}"
        sig = _sign_nonce(sk, nonce)

        r = requests.post(f"{local_service}/observations", json={
            "did": did,
            "observations": [
                {"promised": ["feature_a", "bugfix_b"], "delivered": ["feature_a", "bugfix_b"],
                 "timestamp": "2026-03-01T00:00:00", "conditions": {"load": "normal"}},
                {"promised": ["feature_c"], "delivered": ["feature_c"],
                 "timestamp": "2026-03-02T00:00:00"},
            ],
            "signature": sig,
            "nonce": nonce,
        })
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["observations_stored"] == 2
        assert data["did"] == did

    def test_get_observations(self, local_service):
        sk = SigningKey.generate()
        did, pub_hex = _make_agent(sk)
        _register_agent(local_service, did, pub_hex, f"obs_get_{time.time_ns()}")

        nonce = f"get-{time.time_ns()}"
        sig = _sign_nonce(sk, nonce)

        requests.post(f"{local_service}/observations", json={
            "did": did,
            "observations": [
                {"promised": ["task_a"], "delivered": ["task_a"], "timestamp": "2026-03-01T00:00:00"},
                {"promised": ["task_b"], "delivered": [], "timestamp": "2026-03-02T00:00:00"},
            ],
            "signature": sig,
            "nonce": nonce,
        })

        r = requests.get(f"{local_service}/observations/{did}")
        assert r.status_code == 200
        data = r.json()
        assert data["count"] == 2

    def test_pdr_scores_no_observations(self, local_service):
        r = requests.get(f"{local_service}/observations/did:aip:nonexistent_agent/scores")
        assert r.status_code == 200
        data = r.json()
        assert data["observation_count"] == 0
        assert data["calibration"] is None

    def test_pdr_scores_with_enough_data(self, local_service):
        sk = SigningKey.generate()
        did, pub_hex = _make_agent(sk)
        _register_agent(local_service, did, pub_hex, f"pdr_score_{time.time_ns()}")

        nonce = f"pdr-{time.time_ns()}"
        sig = _sign_nonce(sk, nonce)

        # 7 observations over 7 days (above min_observations=5, min_window_days=3)
        observations = []
        for i in range(7):
            observations.append({
                "promised": [f"task_{i}"],
                "delivered": [f"task_{i}"],
                "timestamp": f"2026-03-{i+1:02d}T00:00:00",
                "conditions": {"load": "normal"},
            })

        r = requests.post(f"{local_service}/observations", json={
            "did": did, "observations": observations,
            "signature": sig, "nonce": nonce,
        })
        assert r.status_code == 200, r.text

        r = requests.get(f"{local_service}/observations/{did}/scores")
        assert r.status_code == 200
        data = r.json()
        assert data["observation_count"] == 7
        assert data["calibration"] is not None
        assert data["calibration"] > 0.9  # perfect delivery

    def test_nonce_replay_rejected(self, local_service):
        sk = SigningKey.generate()
        did, pub_hex = _make_agent(sk)
        _register_agent(local_service, did, pub_hex, f"replay_{time.time_ns()}")

        nonce = f"replay-{time.time_ns()}"
        sig = _sign_nonce(sk, nonce)
        payload = {
            "did": did,
            "observations": [{"promised": ["a"], "delivered": ["a"]}],
            "signature": sig,
            "nonce": nonce,
        }

        r1 = requests.post(f"{local_service}/observations", json=payload)
        assert r1.status_code == 200

        r2 = requests.post(f"{local_service}/observations", json=payload)
        assert r2.status_code == 409

    def test_unregistered_agent_rejected(self, local_service):
        sk = SigningKey.generate()
        nonce = f"unreg-{time.time_ns()}"
        sig = _sign_nonce(sk, nonce)

        r = requests.post(f"{local_service}/observations", json={
            "did": "did:aip:nonexistent_unregistered",
            "observations": [{"promised": ["a"], "delivered": ["a"]}],
            "signature": sig,
            "nonce": nonce,
        })
        assert r.status_code == 404

    def test_bad_signature_rejected(self, local_service):
        sk = SigningKey.generate()
        did, pub_hex = _make_agent(sk)
        _register_agent(local_service, did, pub_hex, f"badsig_{time.time_ns()}")

        r = requests.post(f"{local_service}/observations", json={
            "did": did,
            "observations": [{"promised": ["a"], "delivered": ["a"]}],
            "signature": "00" * 64,
            "nonce": f"bad-{time.time_ns()}",
        })
        assert r.status_code == 401

    def test_mixed_delivery_scores_lower(self, local_service):
        """Agent with partial delivery should score lower than perfect delivery."""
        sk = SigningKey.generate()
        did, pub_hex = _make_agent(sk)
        _register_agent(local_service, did, pub_hex, f"mixed_{time.time_ns()}")

        nonce = f"mixed-{time.time_ns()}"
        sig = _sign_nonce(sk, nonce)

        # Mix of full and partial deliveries
        observations = [
            {"promised": ["a", "b"], "delivered": ["a", "b"], "timestamp": "2026-03-01T00:00:00"},
            {"promised": ["c", "d"], "delivered": ["c"], "timestamp": "2026-03-02T00:00:00"},
            {"promised": ["e"], "delivered": ["e"], "timestamp": "2026-03-03T00:00:00"},
            {"promised": ["f", "g"], "delivered": ["f"], "timestamp": "2026-03-04T00:00:00"},
            {"promised": ["h"], "delivered": ["h"], "timestamp": "2026-03-05T00:00:00"},
            {"promised": ["i", "j"], "delivered": [], "timestamp": "2026-03-06T00:00:00"},
            {"promised": ["k"], "delivered": ["k"], "timestamp": "2026-03-07T00:00:00"},
        ]

        r = requests.post(f"{local_service}/observations", json={
            "did": did, "observations": observations,
            "signature": sig, "nonce": nonce,
        })
        assert r.status_code == 200

        r = requests.get(f"{local_service}/observations/{did}/scores")
        data = r.json()
        assert data["calibration"] is not None
        assert data["calibration"] < 0.9  # imperfect delivery
        assert data["calibration"] > 0.4  # not terrible
