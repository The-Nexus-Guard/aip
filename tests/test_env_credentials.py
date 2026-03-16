"""Tests for environment variable credential loading (CI/CD path)."""

import base64
import hashlib
import os
import pytest


def test_env_var_credentials():
    """AIP_DID + AIP_PRIVATE_KEY env vars should be usable as credentials."""
    import nacl.signing

    # Generate a test keypair
    sk = nacl.signing.SigningKey.generate()
    pub_bytes = bytes(sk.verify_key)
    priv_b64 = base64.b64encode(bytes(sk)).decode()
    did = "did:aip:" + hashlib.sha256(pub_bytes).hexdigest()[:32]

    # Set env vars
    os.environ["AIP_DID"] = did
    os.environ["AIP_PRIVATE_KEY"] = priv_b64
    try:
        from aip_identity.cli import find_credentials

        creds = find_credentials()
        assert creds is not None
        assert creds["did"] == did
        assert creds["private_key"] == priv_b64
    finally:
        del os.environ["AIP_DID"]
        del os.environ["AIP_PRIVATE_KEY"]


def test_env_var_credentials_partial():
    """Only AIP_DID without AIP_PRIVATE_KEY should not return env creds."""
    os.environ["AIP_DID"] = "did:aip:test"
    if "AIP_PRIVATE_KEY" in os.environ:
        del os.environ["AIP_PRIVATE_KEY"]
    try:
        from aip_identity.cli import find_credentials

        # Should fall through to file-based (may return None or file creds)
        creds = find_credentials()
        # If creds returned, should NOT be from the env (no private_key set)
        if creds and creds.get("did") == "did:aip:test":
            # This means it returned partial env creds — bug
            assert False, "Should not return credentials with only DID set"
    finally:
        del os.environ["AIP_DID"]


def test_env_credentials_can_sign():
    """Credentials from env vars should produce valid signatures."""
    import nacl.signing

    sk = nacl.signing.SigningKey.generate()
    pub_bytes = bytes(sk.verify_key)
    priv_b64 = base64.b64encode(bytes(sk)).decode()
    did = "did:aip:" + hashlib.sha256(pub_bytes).hexdigest()[:32]

    os.environ["AIP_DID"] = did
    os.environ["AIP_PRIVATE_KEY"] = priv_b64
    try:
        from aip_identity.cli import find_credentials

        creds = find_credentials()
        assert creds is not None

        # Verify we can sign with the loaded key
        priv_bytes = base64.b64decode(creds["private_key"])
        loaded_sk = nacl.signing.SigningKey(priv_bytes)
        message = b"test message for CI/CD signing"
        signed = loaded_sk.sign(message)

        # Verify the signature
        vk = nacl.signing.VerifyKey(pub_bytes)
        vk.verify(signed)  # Should not raise
    finally:
        del os.environ["AIP_DID"]
        del os.environ["AIP_PRIVATE_KEY"]


def test_env_var_priority_over_file():
    """Env var credentials should take priority over file-based ones."""
    import nacl.signing

    sk = nacl.signing.SigningKey.generate()
    priv_b64 = base64.b64encode(bytes(sk)).decode()
    pub_bytes = bytes(sk.verify_key)
    did = "did:aip:" + hashlib.sha256(pub_bytes).hexdigest()[:32]

    os.environ["AIP_DID"] = did
    os.environ["AIP_PRIVATE_KEY"] = priv_b64
    try:
        from aip_identity.cli import find_credentials

        creds = find_credentials()
        assert creds is not None
        assert creds["did"] == did, "Env var DID should take priority"
    finally:
        del os.environ["AIP_DID"]
        del os.environ["AIP_PRIVATE_KEY"]
