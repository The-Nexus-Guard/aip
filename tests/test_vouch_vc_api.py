#!/usr/bin/env python3
"""Tests for server-side /vouch-vc endpoints (W3C Verifiable Credentials)."""

import sys
import os
import tempfile
import base64
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "service"))
sys.path.insert(0, str(Path(__file__).parent.parent))

os.environ["AIP_TESTING"] = "1"
_test_db_fd, _test_db_path = tempfile.mkstemp(suffix=".db")
os.close(_test_db_fd)
os.environ["AIP_DATABASE_PATH"] = _test_db_path

import database
database.init_database()

from fastapi.testclient import TestClient
from main import app
import unittest
import nacl.signing

client = TestClient(app)


def _register_agent(name: str):
    """Register a test agent and return (did, signing_key, pubkey_b64)."""
    signing_key = nacl.signing.SigningKey.generate()
    pubkey = signing_key.verify_key.encode()
    pubkey_b64 = base64.b64encode(pubkey).decode()

    import hashlib
    did = f"did:aip:{hashlib.sha256(pubkey).hexdigest()[:32]}"

    # Register directly in DB
    database.register_did(did, pubkey_b64)
    database.add_platform_link(did, "test", name)
    return did, signing_key, pubkey_b64


def _create_vouch(voucher_did, voucher_key, target_did, scope="GENERAL", statement="Test vouch"):
    """Create a vouch and return the vouch_id."""
    payload = f"{voucher_did}|{target_did}|{scope}|{statement}"
    signature = voucher_key.sign(payload.encode("utf-8")).signature
    sig_b64 = base64.b64encode(signature).decode()

    resp = client.post("/vouch", json={
        "voucher_did": voucher_did,
        "target_did": target_did,
        "scope": scope,
        "statement": statement,
        "signature": sig_b64,
    })
    assert resp.status_code == 200, f"Vouch failed: {resp.text}"
    return resp.json()["vouch_id"]


class TestVouchVCEndpoint(unittest.TestCase):

    def setUp(self):
        """Reset database and create test agents."""
        import sqlite3
        conn = sqlite3.connect(_test_db_path)
        for table in ["registrations", "vouches", "platform_links", "key_history",
                       "messages", "skill_signatures"]:
            try:
                conn.execute(f"DELETE FROM {table}")
            except sqlite3.OperationalError:
                pass
        conn.commit()
        conn.close()

        # Create two test agents
        self.alice_did, self.alice_key, self.alice_pubkey = _register_agent("alice")
        self.bob_did, self.bob_key, self.bob_pubkey = _register_agent("bob")

    def test_single_vouch_vc(self):
        """GET /vouch-vc/{vouch_id} returns a valid W3C VC."""
        vouch_id = _create_vouch(self.alice_did, self.alice_key, self.bob_did,
                                  scope="IDENTITY", statement="I trust Bob")

        resp = client.get(f"/vouch-vc/{vouch_id}")
        assert resp.status_code == 200, resp.text

        vc = resp.json()
        # Check W3C VC structure
        assert "https://www.w3.org/2018/credentials/v1" in vc["@context"]
        assert "VerifiableCredential" in vc["type"]
        assert "AIPVouchCredential" in vc["type"]

        # Check issuer
        assert vc["issuer"]["aipDid"] == self.alice_did
        assert vc["issuer"]["id"].startswith("did:key:")

        # Check subject
        assert vc["credentialSubject"]["aipDid"] == self.bob_did
        assert vc["credentialSubject"]["id"].startswith("did:key:")
        assert vc["credentialSubject"]["trustScope"] == "IDENTITY"
        assert vc["credentialSubject"]["statement"] == "I trust Bob"

        # Check proof
        assert "proof" in vc
        assert vc["proof"]["type"] == "Ed25519Signature2020"
        assert "proofValue" in vc["proof"]

    def test_vouch_vc_not_found(self):
        """GET /vouch-vc/{nonexistent_id} returns 404."""
        resp = client.get("/vouch-vc/nonexistent-vouch-id")
        assert resp.status_code == 404

    def test_list_vouches_as_vc_received(self):
        """GET /vouch-vc?did=X returns VCs for vouches received."""
        vouch_id = _create_vouch(self.alice_did, self.alice_key, self.bob_did,
                                  scope="GENERAL", statement="General trust")

        resp = client.get("/vouch-vc", params={"did": self.bob_did, "direction": "received"})
        assert resp.status_code == 200

        data = resp.json()
        assert data["did"] == self.bob_did
        assert data["direction"] == "received"
        assert data["count"] == 1
        assert len(data["verifiableCredentials"]) == 1

        vc = data["verifiableCredentials"][0]
        assert "AIPVouchCredential" in vc["type"]
        assert vc["issuer"]["aipDid"] == self.alice_did
        assert vc["credentialSubject"]["aipDid"] == self.bob_did

    def test_list_vouches_as_vc_given(self):
        """GET /vouch-vc?did=X&direction=given returns VCs for vouches given."""
        _create_vouch(self.alice_did, self.alice_key, self.bob_did)

        resp = client.get("/vouch-vc", params={"did": self.alice_did, "direction": "given"})
        assert resp.status_code == 200

        data = resp.json()
        assert data["did"] == self.alice_did
        assert data["direction"] == "given"
        assert data["count"] == 1

    def test_list_vouches_as_vc_scope_filter(self):
        """GET /vouch-vc?did=X&scope=Y filters by scope."""
        # Create a third agent for second vouch
        carol_did, carol_key, _ = _register_agent("carol")

        _create_vouch(self.alice_did, self.alice_key, self.bob_did, scope="GENERAL")
        _create_vouch(carol_did, carol_key, self.bob_did, scope="CODE_SIGNING", statement="Code trust")

        # Filter for CODE_SIGNING only
        resp = client.get("/vouch-vc", params={"did": self.bob_did, "scope": "CODE_SIGNING"})
        assert resp.status_code == 200

        data = resp.json()
        assert data["count"] == 1
        assert data["verifiableCredentials"][0]["credentialSubject"]["trustScope"] == "CODE_SIGNING"

    def test_list_vouches_as_vc_no_vouches(self):
        """GET /vouch-vc for agent with no vouches returns empty list."""
        resp = client.get("/vouch-vc", params={"did": self.alice_did, "direction": "received"})
        assert resp.status_code == 200

        data = resp.json()
        assert data["count"] == 0
        assert data["verifiableCredentials"] == []

    def test_list_vouches_as_vc_unregistered_did(self):
        """GET /vouch-vc with unregistered DID returns 404."""
        resp = client.get("/vouch-vc", params={"did": "did:aip:nonexistent"})
        assert resp.status_code == 404

    def test_list_vouches_invalid_direction(self):
        """GET /vouch-vc with invalid direction returns 400."""
        resp = client.get("/vouch-vc", params={"did": self.alice_did, "direction": "sideways"})
        assert resp.status_code == 400

    def test_list_vouches_invalid_scope(self):
        """GET /vouch-vc with invalid scope returns 400."""
        resp = client.get("/vouch-vc", params={"did": self.alice_did, "scope": "INVALID"})
        assert resp.status_code == 400

    def test_vouch_vc_has_issuance_date(self):
        """VC includes issuanceDate from the vouch creation time."""
        vouch_id = _create_vouch(self.alice_did, self.alice_key, self.bob_did)
        resp = client.get(f"/vouch-vc/{vouch_id}")
        vc = resp.json()
        assert "issuanceDate" in vc
        assert len(vc["issuanceDate"]) > 0

    def test_vouch_vc_round_trip(self):
        """VC from server can be parsed back to a Vouch object."""
        vouch_id = _create_vouch(self.alice_did, self.alice_key, self.bob_did,
                                  scope="IDENTITY", statement="Round trip test")
        resp = client.get(f"/vouch-vc/{vouch_id}")
        vc = resp.json()

        # Parse back to Vouch
        from aip_identity.vc import vc_to_vouch
        vouch = vc_to_vouch(vc)
        assert vouch.voucher_did == self.alice_did
        assert vouch.target_did == self.bob_did
        assert vouch.scope == "IDENTITY"
        assert vouch.statement == "Round trip test"


if __name__ == "__main__":
    unittest.main()
