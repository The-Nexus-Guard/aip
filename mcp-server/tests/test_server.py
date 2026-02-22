"""Tests for AIP MCP Server."""

import json
import os
import pytest
from unittest.mock import patch, MagicMock

# Set a dummy credentials path so we can control behavior
os.environ.setdefault("AIP_CREDENTIALS_PATH", "/tmp/nonexistent-aip-creds.json")

from aip_mcp_server.server import (
    _find_credentials,
    _load_client,
    mcp,
)


class TestCredentials:
    """Test credential loading."""

    def test_find_credentials_missing(self):
        with patch.dict(os.environ, {"AIP_CREDENTIALS_PATH": "/tmp/nonexistent.json"}):
            result = _find_credentials()
            assert result is None

    def test_find_credentials_from_env(self, tmp_path):
        creds = {
            "did": "did:aip:test123",
            "public_key": "dGVzdA==",
            "private_key": "dGVzdA==",
        }
        creds_file = tmp_path / "creds.json"
        creds_file.write_text(json.dumps(creds))

        with patch.dict(os.environ, {"AIP_CREDENTIALS_PATH": str(creds_file)}):
            result = _find_credentials()
            assert result is not None
            assert result["did"] == "did:aip:test123"

    def test_load_client_no_creds_raises(self):
        with patch.dict(os.environ, {"AIP_CREDENTIALS_PATH": "/tmp/nonexistent.json"}):
            with pytest.raises(RuntimeError, match="No AIP credentials found"):
                _load_client()


class TestMCPServer:
    """Test the MCP server is properly configured."""

    def test_server_name(self):
        assert mcp.name == "AIP Identity Server"

    def test_tools_registered(self):
        # FastMCP stores tools internally — verify they exist by checking the decorated functions
        from aip_mcp_server import server

        tool_functions = [
            "aip_whoami",
            "aip_verify",
            "aip_trust_score",
            "aip_sign",
            "aip_verify_signature",
            "aip_send_message",
            "aip_check_messages",
            "aip_register",
        ]
        for name in tool_functions:
            assert hasattr(server, name), f"Missing tool function: {name}"

    def test_aip_whoami_with_mock_client(self):
        mock_client = MagicMock()
        mock_client.did = "did:aip:test123"
        mock_client.public_key = "dGVzdA=="
        mock_client.service_url = "https://aip-service.fly.dev"

        with patch("aip_mcp_server.server._load_client", return_value=mock_client):
            from aip_mcp_server.server import aip_whoami

            result = aip_whoami()
            assert result["did"] == "did:aip:test123"
            assert result["public_key"] == "dGVzdA=="

    def test_aip_sign_with_mock_client(self):
        mock_client = MagicMock()
        mock_client.did = "did:aip:test123"
        mock_client.sign.return_value = "fakesig=="

        with patch("aip_mcp_server.server._load_client", return_value=mock_client):
            from aip_mcp_server.server import aip_sign

            result = aip_sign("hello world")
            assert result["signature"] == "fakesig=="
            assert result["did"] == "did:aip:test123"
            mock_client.sign.assert_called_once_with(b"hello world")

    def test_aip_verify_with_mock_client(self):
        mock_client = MagicMock()
        mock_client.verify.return_value = {"verified": True, "did": "did:aip:other"}

        with patch("aip_mcp_server.server._load_client", return_value=mock_client):
            from aip_mcp_server.server import aip_verify

            result = aip_verify("did:aip:other")
            assert result["verified"] is True

    def test_aip_register_already_registered(self):
        creds = {"did": "did:aip:existing", "private_key": "x", "public_key": "y"}
        with patch("aip_mcp_server.server._find_credentials", return_value=creds):
            from aip_mcp_server.server import aip_register

            result = aip_register("github", "testuser")
            assert result["already_registered"] is True
            assert result["did"] == "did:aip:existing"
