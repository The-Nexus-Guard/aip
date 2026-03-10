"""Tests for aip_identity.integrations.auto module."""

import json
import os
import tempfile
from unittest.mock import patch, MagicMock

import pytest

from aip_identity.integrations.auto import ensure_identity, _default_credentials_path


class TestDefaultCredentialsPath:
    def test_returns_home_aip_default(self):
        with patch.dict(os.environ, {}, clear=True):
            # Remove AIP_CREDENTIALS_PATH if set
            os.environ.pop("AIP_CREDENTIALS_PATH", None)
            path = _default_credentials_path()
            assert str(path).endswith(".aip/credentials.json")

    def test_respects_env_override(self):
        with patch.dict(os.environ, {"AIP_CREDENTIALS_PATH": "/tmp/custom.json"}):
            path = _default_credentials_path()
            assert str(path) == "/tmp/custom.json"


class TestEnsureIdentity:
    def test_loads_existing_credentials(self, tmp_path):
        creds_file = tmp_path / "creds.json"
        creds_file.write_text(json.dumps({
            "did": "did:aip:test123",
            "public_key": "dGVzdHB1YmtleQ==",  # base64 of "testpubkey"
            "private_key": "dGVzdHByaXZrZXk=",  # base64 of "testprivkey"
        }))

        client = ensure_identity(
            "test-agent",
            credentials_path=str(creds_file),
        )
        assert client.did == "did:aip:test123"

    def test_creates_new_identity_when_no_file(self, tmp_path):
        creds_file = tmp_path / "subdir" / "creds.json"
        assert not creds_file.exists()

        with patch("aip_identity.integrations.auto.AIPClient.register") as mock_reg:
            mock_client = MagicMock()
            mock_client.did = "did:aip:new123"
            mock_client.public_key = "newpubkey"
            mock_client.private_key = "newprivkey"
            mock_reg.return_value = mock_client

            client = ensure_identity(
                "new-agent",
                platform="test",
                credentials_path=str(creds_file),
            )

            mock_reg.assert_called_once_with(
                platform="test",
                platform_id="new-agent",
                service_url="https://aip-service.fly.dev",
            )
            mock_client.save.assert_called_once_with(str(creds_file))
            assert client.did == "did:aip:new123"

    def test_re_registers_on_corrupted_file(self, tmp_path):
        creds_file = tmp_path / "creds.json"
        creds_file.write_text("not json")

        with patch("aip_identity.integrations.auto.AIPClient.register") as mock_reg:
            mock_client = MagicMock()
            mock_client.did = "did:aip:fresh123"
            mock_reg.return_value = mock_client

            client = ensure_identity(
                "test-agent",
                credentials_path=str(creds_file),
            )

            mock_reg.assert_called_once()
            assert client.did == "did:aip:fresh123"

    def test_package_level_import(self):
        from aip_identity.integrations import ensure_identity as ei
        assert ei is ensure_identity
