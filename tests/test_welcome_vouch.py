"""
Tests for the auto-welcome vouch system identity feature.

These tests directly test system_identity.py in non-testing mode.
"""

import sys
import os
import tempfile
import base64
import hashlib

# Must set up DB before importing anything
_test_db_fd, _test_db_path = tempfile.mkstemp(suffix=".db")
os.close(_test_db_fd)
os.environ["AIP_DATABASE_PATH"] = _test_db_path

# Disable rate limiting
os.environ["AIP_TESTING"] = "1"

from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "service"))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import database
import nacl.signing


def setup_module(module):
    """Initialize DB."""
    database.init_database()


def teardown_module(module):
    """Clean up."""
    if os.path.exists(_test_db_path):
        os.unlink(_test_db_path)


class TestSystemIdentity:
    def _make_agent(self):
        """Create a test agent and register it."""
        sk = nacl.signing.SigningKey.generate()
        pk = bytes(sk.verify_key)
        pk_b64 = base64.b64encode(pk).decode()
        did = f"did:aip:{hashlib.sha256(pk).hexdigest()[:32]}"
        database.register_did(did, pk_b64)
        database.add_platform_link(did, "test", f"user_{did[-8:]}", None)
        return did, sk, pk_b64

    def test_init_creates_system_identity(self):
        """System identity initializes and registers itself."""
        import system_identity
        # Override TESTING flag for this test
        system_identity.TESTING = False
        
        # Use temp key path
        key_dir = tempfile.mkdtemp()
        system_identity.SYSTEM_KEY_PATH = os.path.join(key_dir, "system_key.b64")
        system_identity.SYSTEM_KEY_PATH_LOCAL = os.path.join(key_dir, "local_key.b64")
        
        # Reset cached state
        system_identity._signing_key = None
        system_identity._system_did = None
        system_identity._public_key_b64 = None
        
        did, pubkey = system_identity.init()
        
        assert did.startswith("did:aip:")
        assert len(pubkey) > 0
        
        # Should be registered
        reg = database.get_registration(did)
        assert reg is not None
        assert reg["public_key"] == pubkey

    def test_welcome_vouch_created(self):
        """New agent gets a welcome vouch from system identity."""
        import system_identity
        
        # Make sure system identity is initialized
        assert system_identity.get_did() is not None
        
        agent_did, _, _ = self._make_agent()
        vouch_id = system_identity.create_welcome_vouch(agent_did)
        
        assert vouch_id is not None
        
        # Check trust
        vouches = database.get_vouches_for(agent_did)
        system_vouches = [v for v in vouches if v["voucher_did"] == system_identity.get_did()]
        assert len(system_vouches) == 1
        assert system_vouches[0]["scope"] == "GENERAL"

    def test_no_duplicate_welcome_vouch(self):
        """Welcome vouch is idempotent."""
        import system_identity
        
        agent_did, _, _ = self._make_agent()
        v1 = system_identity.create_welcome_vouch(agent_did)
        v2 = system_identity.create_welcome_vouch(agent_did)
        
        assert v1 is not None
        assert v2 is None  # Already exists

    def test_no_self_vouch(self):
        """System identity doesn't vouch for itself."""
        import system_identity
        
        result = system_identity.create_welcome_vouch(system_identity.get_did())
        assert result is None

    def test_vouch_signature_valid(self):
        """The welcome vouch has a valid cryptographic signature."""
        import system_identity
        
        agent_did, _, _ = self._make_agent()
        vouch_id = system_identity.create_welcome_vouch(agent_did)
        assert vouch_id is not None
        
        # Get the vouch directly from DB with signature column
        with database.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT voucher_did, target_did, scope, statement, signature FROM vouches WHERE id = ?",
                (vouch_id,)
            )
            row = dict(cursor.fetchone())
        
        # Reconstruct and verify
        sys_reg = database.get_registration(system_identity.get_did())
        pk_bytes = base64.b64decode(sys_reg["public_key"])
        sig_bytes = base64.b64decode(row["signature"])
        
        payload = f"{row['voucher_did']}|{row['target_did']}|{row['scope']}|{row['statement']}"
        
        verify_key = nacl.signing.VerifyKey(pk_bytes)
        # Should not raise
        verify_key.verify(payload.encode("utf-8"), sig_bytes)
