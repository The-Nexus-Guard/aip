"""Tests for W3C Verifiable Credentials support."""

import base64
import json
import unittest
from datetime import datetime, timezone, timedelta

import nacl.signing

from aip_identity.identity import AgentIdentity, public_key_to_did_key
from aip_identity.trust import Vouch, TrustLevel, TrustGraph
from aip_identity.vc import (
    vouch_to_vc,
    vc_to_vouch,
    verify_vc,
    vc_to_json,
    vc_from_json,
    AIP_VOUCH_TYPE,
    VC_CONTEXT_V1,
    VC_CONTEXT_ED25519,
    AIP_CONTEXT,
    AIP_TRUST_TYPE,
    _normalize_iso,
    _vouch_to_uuid,
)


def _make_vouch(voucher, target, scope="identity", level=TrustLevel.STRONG, statement="Test vouch"):
    """Helper to create a signed vouch using TrustGraph."""
    tg = TrustGraph(voucher)
    return tg.vouch_for(target, scope=scope, level=level, statement=statement)


class TestVouchToVC(unittest.TestCase):
    """Test converting AIP vouches to W3C Verifiable Credentials."""

    def setUp(self):
        self.voucher = AgentIdentity.create("test")
        self.target = AgentIdentity.create("test")
        self.vouch = _make_vouch(self.voucher, self.target, statement="Verified peer agent")

    def test_basic_structure(self):
        """VC has required W3C fields."""
        vc = vouch_to_vc(self.vouch)
        self.assertIn("@context", vc)
        self.assertIn("id", vc)
        self.assertIn("type", vc)
        self.assertIn("issuer", vc)
        self.assertIn("issuanceDate", vc)
        self.assertIn("credentialSubject", vc)

    def test_contexts(self):
        """VC includes all required contexts."""
        vc = vouch_to_vc(self.vouch)
        contexts = vc["@context"]
        self.assertIn(VC_CONTEXT_V1, contexts)
        self.assertIn(VC_CONTEXT_ED25519, contexts)
        self.assertIn(AIP_CONTEXT, contexts)

    def test_types(self):
        """VC has correct types."""
        vc = vouch_to_vc(self.vouch)
        types = vc["type"]
        self.assertIn("VerifiableCredential", types)
        self.assertIn(AIP_VOUCH_TYPE, types)

    def test_issuer_has_both_dids(self):
        """Issuer includes both did:key and did:aip."""
        vc = vouch_to_vc(self.vouch)
        issuer = vc["issuer"]
        self.assertTrue(issuer["id"].startswith("did:key:z"))
        self.assertEqual(issuer["aipDid"], self.voucher.did)

    def test_subject_has_both_dids(self):
        """Subject includes both did:key and did:aip."""
        vc = vouch_to_vc(self.vouch)
        subject = vc["credentialSubject"]
        self.assertTrue(subject["id"].startswith("did:key:z"))
        self.assertEqual(subject["aipDid"], self.target.did)

    def test_trust_fields(self):
        """VC credentialSubject has AIP trust fields."""
        vc = vouch_to_vc(self.vouch)
        subject = vc["credentialSubject"]
        self.assertEqual(subject["trustScope"], "identity")
        self.assertEqual(subject["trustLevel"], int(TrustLevel.STRONG))
        self.assertEqual(subject["statement"], "Verified peer agent")
        self.assertEqual(subject["type"], AIP_TRUST_TYPE)

    def test_proof_section(self):
        """VC includes Ed25519Signature2020 proof."""
        vc = vouch_to_vc(self.vouch)
        proof = vc.get("proof")
        self.assertIsNotNone(proof)
        self.assertEqual(proof["type"], "Ed25519Signature2020")
        self.assertEqual(proof["proofPurpose"], "assertionMethod")
        self.assertTrue(proof["proofValue"].startswith("M") or proof["proofValue"].startswith("z"))
        self.assertIn("#keys-1", proof["verificationMethod"])

    def test_no_proof_when_disabled(self):
        """VC omits proof when include_proof=False."""
        vc = vouch_to_vc(self.vouch, include_proof=False)
        self.assertNotIn("proof", vc)

    def test_no_proof_when_unsigned(self):
        """VC omits proof when vouch has no signature."""
        unsigned = Vouch(
            voucher_did=self.voucher.did,
            voucher_pubkey=self.voucher.public_key,
            target_did=self.target.did,
            target_pubkey=self.target.public_key,
            scope="identity",
            level=TrustLevel.UNKNOWN,
            statement="Test",
            created_at=datetime.now(timezone.utc).isoformat(),
            expires_at=None,
            signature="",
        )
        vc = vouch_to_vc(unsigned)
        self.assertNotIn("proof", vc)

    def test_expiration_included(self):
        """VC includes expirationDate when vouch has expires_at."""
        tg = TrustGraph(self.voucher)
        vouch = tg.vouch_for(self.target, expires_in_days=30, statement="Expiring")
        vc = vouch_to_vc(vouch)
        self.assertIn("expirationDate", vc)

    def test_no_expiration_when_none(self):
        """VC omits expirationDate when vouch doesn't expire."""
        vc = vouch_to_vc(self.vouch)
        self.assertNotIn("expirationDate", vc)

    def test_deterministic_id(self):
        """Same vouch produces same VC id."""
        vc1 = vouch_to_vc(self.vouch)
        vc2 = vouch_to_vc(self.vouch)
        self.assertEqual(vc1["id"], vc2["id"])
        self.assertTrue(vc1["id"].startswith("urn:uuid:"))

    def test_did_key_derivation(self):
        """did:key in VC matches direct derivation."""
        vc = vouch_to_vc(self.vouch)
        expected = public_key_to_did_key(self.voucher.public_key_bytes)
        self.assertEqual(vc["issuer"]["id"], expected)

    def test_custom_public_key_bytes(self):
        """Can provide explicit public key bytes."""
        vc = vouch_to_vc(self.vouch, voucher_public_key_bytes=self.voucher.public_key_bytes)
        expected = public_key_to_did_key(self.voucher.public_key_bytes)
        self.assertEqual(vc["issuer"]["id"], expected)


class TestVCToVouch(unittest.TestCase):
    """Test parsing VCs back into AIP vouches."""

    def setUp(self):
        self.voucher = AgentIdentity.create("test")
        self.target = AgentIdentity.create("test")
        self.vouch = _make_vouch(
            self.voucher, self.target,
            scope="code_signing", level=TrustLevel.ULTIMATE,
            statement="Trusted code signer",
        )

    def test_roundtrip(self):
        """Vouch → VC → Vouch preserves key fields."""
        vc = vouch_to_vc(self.vouch)
        recovered = vc_to_vouch(vc)
        self.assertEqual(recovered.voucher_did, self.vouch.voucher_did)
        self.assertEqual(recovered.target_did, self.vouch.target_did)
        self.assertEqual(recovered.scope, self.vouch.scope)
        self.assertEqual(recovered.level, self.vouch.level)
        self.assertEqual(recovered.statement, self.vouch.statement)

    def test_roundtrip_preserves_pubkeys(self):
        """Roundtrip preserves public keys via did:key derivation."""
        vc = vouch_to_vc(self.vouch)
        recovered = vc_to_vouch(vc)
        self.assertEqual(recovered.voucher_pubkey, self.vouch.voucher_pubkey)
        self.assertEqual(recovered.target_pubkey, self.vouch.target_pubkey)

    def test_roundtrip_preserves_signature(self):
        """Signature survives roundtrip."""
        vc = vouch_to_vc(self.vouch)
        recovered = vc_to_vouch(vc)
        self.assertTrue(len(recovered.signature) > 0)

    def test_invalid_type_rejected(self):
        """VCs without AIPVouchCredential type are rejected."""
        vc = {"type": ["VerifiableCredential"], "issuer": "did:key:z...", "credentialSubject": {}}
        with self.assertRaises(ValueError):
            vc_to_vouch(vc)

    def test_did_aip_fallback(self):
        """When aipDid is missing, it's derived from the key."""
        vc = vouch_to_vc(self.vouch)
        del vc["issuer"]["aipDid"]
        del vc["credentialSubject"]["aipDid"]
        recovered = vc_to_vouch(vc)
        self.assertTrue(recovered.voucher_did.startswith("did:aip:"))
        self.assertEqual(recovered.voucher_did, self.vouch.voucher_did)
        self.assertEqual(recovered.target_did, self.vouch.target_did)

    def test_string_issuer(self):
        """Handles issuer as plain string (minimal VC)."""
        vc = vouch_to_vc(self.vouch)
        issuer_did = vc["issuer"]["id"]
        vc["issuer"] = issuer_did
        recovered = vc_to_vouch(vc)
        self.assertEqual(recovered.voucher_pubkey, self.vouch.voucher_pubkey)


class TestVerifyVC(unittest.TestCase):
    """Test VC signature verification."""

    def setUp(self):
        self.voucher = AgentIdentity.create("test")
        self.target = AgentIdentity.create("test")
        self.vouch = _make_vouch(self.voucher, self.target, statement="Verified")

    def test_valid_signature(self):
        """Properly signed vouch verifies as VC."""
        vc = vouch_to_vc(self.vouch)
        self.assertTrue(verify_vc(vc))

    def test_tampered_statement(self):
        """Tampering with statement invalidates signature."""
        vc = vouch_to_vc(self.vouch)
        vc["credentialSubject"]["statement"] = "Tampered!"
        self.assertFalse(verify_vc(vc))

    def test_tampered_scope(self):
        """Tampering with scope invalidates signature."""
        vc = vouch_to_vc(self.vouch)
        vc["credentialSubject"]["trustScope"] = "code_signing"
        self.assertFalse(verify_vc(vc))

    def test_tampered_subject(self):
        """Changing subject DID invalidates signature."""
        other = AgentIdentity.create("test")
        vc = vouch_to_vc(self.vouch)
        vc["credentialSubject"]["id"] = public_key_to_did_key(other.public_key_bytes)
        self.assertFalse(verify_vc(vc))

    def test_no_proof(self):
        """VC without proof fails verification."""
        vc = vouch_to_vc(self.vouch, include_proof=False)
        self.assertFalse(verify_vc(vc))

    def test_wrong_issuer_key(self):
        """VC with wrong issuer key fails verification."""
        other = AgentIdentity.create("test")
        vc = vouch_to_vc(self.vouch)
        vc["issuer"]["id"] = public_key_to_did_key(other.public_key_bytes)
        self.assertFalse(verify_vc(vc))

    def test_empty_proof_value(self):
        """VC with empty proof value fails verification."""
        vc = vouch_to_vc(self.vouch)
        vc["proof"]["proofValue"] = ""
        self.assertFalse(verify_vc(vc))


class TestSerialization(unittest.TestCase):
    """Test JSON serialization of VCs."""

    def setUp(self):
        self.voucher = AgentIdentity.create("test")
        self.target = AgentIdentity.create("test")
        self.vouch = _make_vouch(self.voucher, self.target, statement="Test")

    def test_json_roundtrip(self):
        """VC survives JSON serialization/deserialization."""
        vc = vouch_to_vc(self.vouch)
        json_str = vc_to_json(vc)
        recovered = vc_from_json(json_str)
        self.assertEqual(vc, recovered)

    def test_json_is_valid(self):
        """Serialized VC is valid JSON."""
        vc = vouch_to_vc(self.vouch)
        json_str = vc_to_json(vc)
        parsed = json.loads(json_str)
        self.assertIsInstance(parsed, dict)

    def test_full_roundtrip_with_verification(self):
        """Vouch → VC → JSON → VC → verify → Vouch — full pipeline."""
        vc = vouch_to_vc(self.vouch)
        json_str = vc_to_json(vc)
        vc_parsed = vc_from_json(json_str)
        self.assertTrue(verify_vc(vc_parsed))
        recovered = vc_to_vouch(vc_parsed)
        self.assertEqual(recovered.voucher_did, self.vouch.voucher_did)
        self.assertEqual(recovered.target_did, self.vouch.target_did)
        self.assertEqual(recovered.scope, self.vouch.scope)


class TestHelpers(unittest.TestCase):
    """Test internal helper functions."""

    def test_normalize_iso_with_z(self):
        self.assertEqual(_normalize_iso("2026-03-11T12:00:00Z"), "2026-03-11T12:00:00Z")

    def test_normalize_iso_without_z(self):
        self.assertEqual(_normalize_iso("2026-03-11T12:00:00"), "2026-03-11T12:00:00Z")

    def test_normalize_iso_with_offset(self):
        ts = "2026-03-11T12:00:00+01:00"
        self.assertEqual(_normalize_iso(ts), ts)

    def test_normalize_iso_empty(self):
        result = _normalize_iso("")
        self.assertTrue(result.endswith("Z"))

    def test_deterministic_uuid(self):
        voucher = AgentIdentity.create("test")
        target = AgentIdentity.create("test")
        vouch = Vouch(
            voucher_did=voucher.did, voucher_pubkey=voucher.public_key,
            target_did=target.did, target_pubkey=target.public_key,
            scope="identity", level=TrustLevel.UNKNOWN, statement="Test",
            created_at="2026-01-01T00:00:00Z", expires_at=None,
        )
        self.assertEqual(_vouch_to_uuid(vouch), _vouch_to_uuid(vouch))


class TestTrustLevels(unittest.TestCase):
    """Test all trust levels convert correctly."""

    def setUp(self):
        self.voucher = AgentIdentity.create("test")
        self.target = AgentIdentity.create("test")

    def test_all_levels_roundtrip(self):
        """All trust levels survive VC roundtrip."""
        for level in TrustLevel:
            vouch = _make_vouch(self.voucher, self.target, level=level, statement=f"Level {level.name}")
            vc = vouch_to_vc(vouch)
            recovered = vc_to_vouch(vc)
            self.assertEqual(recovered.level, level, f"Failed for {level.name}")

    def test_all_levels_verify(self):
        """All trust levels produce verifiable VCs."""
        for level in TrustLevel:
            vouch = _make_vouch(self.voucher, self.target, level=level)
            vc = vouch_to_vc(vouch)
            self.assertTrue(verify_vc(vc), f"Verification failed for {level.name}")


class TestScopes(unittest.TestCase):
    """Test various vouch scopes convert correctly."""

    def setUp(self):
        self.voucher = AgentIdentity.create("test")
        self.target = AgentIdentity.create("test")

    def test_common_scopes(self):
        """Common AIP scopes roundtrip through VC format."""
        for scope in ["identity", "code_signing", "messaging", "data_access", "custom_scope"]:
            vouch = _make_vouch(self.voucher, self.target, scope=scope)
            vc = vouch_to_vc(vouch)
            recovered = vc_to_vouch(vc)
            self.assertEqual(recovered.scope, scope)


if __name__ == "__main__":
    unittest.main()
