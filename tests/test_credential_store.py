"""Tests for encrypted credential storage."""

import json
import os
import tempfile
from pathlib import Path

import pytest

from aip_identity.credential_store import (
    encrypt_credentials,
    decrypt_credentials,
    is_encrypted,
    load_credentials,
    save_credentials_encrypted,
    save_credentials_plaintext,
    ENCRYPTED_MARKER,
)


@pytest.fixture
def sample_creds():
    return {
        "did": "did:aip:test1234567890abcdef",
        "public_key": "dGVzdHB1YmxpY2tleQ==",
        "private_key": "dGVzdHByaXZhdGVrZXk=",
        "platform": "test",
        "username": "test_agent",
    }


@pytest.fixture
def passphrase():
    return "test-passphrase-123"


class TestEncryptDecrypt:
    def test_roundtrip(self, sample_creds, passphrase):
        encrypted = encrypt_credentials(sample_creds, passphrase)
        decrypted = decrypt_credentials(encrypted, passphrase)
        assert decrypted == sample_creds

    def test_encrypted_format_marker(self, sample_creds, passphrase):
        encrypted = encrypt_credentials(sample_creds, passphrase)
        assert encrypted["format"] == ENCRYPTED_MARKER
        assert "ciphertext" in encrypted
        assert "salt" in encrypted
        assert "did" in encrypted

    def test_did_preserved_in_cleartext(self, sample_creds, passphrase):
        encrypted = encrypt_credentials(sample_creds, passphrase)
        assert encrypted["did"] == sample_creds["did"]

    def test_private_key_not_in_cleartext(self, sample_creds, passphrase):
        encrypted = encrypt_credentials(sample_creds, passphrase)
        raw = json.dumps(encrypted)
        assert sample_creds["private_key"] not in raw

    def test_wrong_passphrase_fails(self, sample_creds, passphrase):
        encrypted = encrypt_credentials(sample_creds, passphrase)
        with pytest.raises(ValueError, match="Wrong passphrase"):
            decrypt_credentials(encrypted, "wrong-passphrase")

    def test_different_salts_each_time(self, sample_creds, passphrase):
        enc1 = encrypt_credentials(sample_creds, passphrase)
        enc2 = encrypt_credentials(sample_creds, passphrase)
        assert enc1["salt"] != enc2["salt"]
        assert enc1["ciphertext"] != enc2["ciphertext"]

    def test_corrupted_ciphertext_fails(self, sample_creds, passphrase):
        encrypted = encrypt_credentials(sample_creds, passphrase)
        # Corrupt the ciphertext
        encrypted["ciphertext"] = "AAAA" + encrypted["ciphertext"][4:]
        with pytest.raises(ValueError, match="Wrong passphrase|corrupted"):
            decrypt_credentials(encrypted, passphrase)


class TestIsEncrypted:
    def test_encrypted_detected(self, sample_creds, passphrase):
        encrypted = encrypt_credentials(sample_creds, passphrase)
        assert is_encrypted(encrypted) is True

    def test_plaintext_not_detected(self, sample_creds):
        assert is_encrypted(sample_creds) is False

    def test_empty_dict(self):
        assert is_encrypted({}) is False


class TestFileOperations:
    def test_save_and_load_encrypted(self, sample_creds, passphrase):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "creds.json"
            save_credentials_encrypted(sample_creds, path, passphrase)

            # File should exist with 600 perms
            assert path.exists()
            assert oct(path.stat().st_mode)[-3:] == "600"

            # Should contain encrypted format
            with open(path) as f:
                raw = json.load(f)
            assert raw["format"] == ENCRYPTED_MARKER
            assert sample_creds["private_key"] not in json.dumps(raw)

            # Should load correctly
            loaded = load_credentials(path, passphrase)
            assert loaded == sample_creds

    def test_save_and_load_plaintext(self, sample_creds):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "creds.json"
            save_credentials_plaintext(sample_creds, path)

            loaded = load_credentials(path)
            assert loaded == sample_creds

    def test_load_nonexistent(self):
        loaded = load_credentials(Path("/nonexistent/path.json"))
        assert loaded is None

    def test_load_invalid_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "creds.json"
            path.write_text("not json")
            loaded = load_credentials(path)
            assert loaded is None

    def test_load_encrypted_with_env_passphrase(self, sample_creds, passphrase):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "creds.json"
            save_credentials_encrypted(sample_creds, path, passphrase)

            # Set env var
            old = os.environ.get("AIP_PASSPHRASE")
            try:
                os.environ["AIP_PASSPHRASE"] = passphrase
                loaded = load_credentials(path)
                assert loaded == sample_creds
            finally:
                if old is None:
                    os.environ.pop("AIP_PASSPHRASE", None)
                else:
                    os.environ["AIP_PASSPHRASE"] = old

    def test_load_encrypted_wrong_passphrase(self, sample_creds, passphrase):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "creds.json"
            save_credentials_encrypted(sample_creds, path, passphrase)
            loaded = load_credentials(path, "wrong-passphrase")
            assert loaded is None

    def test_creates_parent_dirs(self, sample_creds, passphrase):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "deep" / "nested" / "creds.json"
            save_credentials_encrypted(sample_creds, path, passphrase)
            assert path.exists()


class TestEdgeCases:
    def test_empty_passphrase(self, sample_creds):
        """Empty passphrase should still work (user's choice)."""
        encrypted = encrypt_credentials(sample_creds, "")
        decrypted = decrypt_credentials(encrypted, "")
        assert decrypted == sample_creds

    def test_unicode_passphrase(self, sample_creds):
        passphrase = "пароль🔑密码"
        encrypted = encrypt_credentials(sample_creds, passphrase)
        decrypted = decrypt_credentials(encrypted, passphrase)
        assert decrypted == sample_creds

    def test_large_credentials(self, passphrase):
        """Handle credentials with extra fields."""
        creds = {
            "did": "did:aip:test1234567890abcdef",
            "public_key": "a" * 1000,
            "private_key": "b" * 1000,
            "platform": "test",
            "username": "test_agent",
            "extra_field": "some_data",
            "nested": {"key": "value"},
        }
        encrypted = encrypt_credentials(creds, passphrase)
        decrypted = decrypt_credentials(encrypted, passphrase)
        assert decrypted == creds

    def test_not_encrypted_format_raises(self, sample_creds, passphrase):
        with pytest.raises(ValueError, match="Not an encrypted"):
            decrypt_credentials(sample_creds, passphrase)
