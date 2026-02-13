"""Tests for `aip doctor` command."""
import json
from unittest.mock import patch, MagicMock
import pytest

from aip_identity.cli import cmd_doctor


CREDS = {"did": "did:aip:abc123", "private_key": "dGVzdA==", "public_key": "cHVi", "platform": "moltbook", "username": "testuser"}


def mock_urlopen(responses):
    def side_effect(url, **kwargs):
        for pattern, data in responses.items():
            if pattern in str(url):
                resp = MagicMock()
                resp.read.return_value = json.dumps(data).encode()
                resp.__enter__ = lambda s: s
                resp.__exit__ = MagicMock(return_value=False)
                return resp
        raise Exception(f"No mock for {url}")
    return side_effect


class TestDoctor:
    def test_doctor_all_healthy(self, capsys):
        args = MagicMock()
        args.service = "https://test.example.com"
        responses = {
            "/health": {"status": "healthy", "version": "0.5.15", "checks": {"database": {"ok": True}}, "metrics": {"registrations": 12}},
            "/identity/did:aip:abc123": {"did": "did:aip:abc123", "trust_score": 0.8, "vouches_received": 2},
        }
        with patch("aip_identity.cli.Path") as mock_path, \
             patch("urllib.request.urlopen", side_effect=mock_urlopen(responses)):
            # Make credentials findable
            mock_file = MagicMock()
            mock_file.exists.return_value = True
            mock_file.__str__ = lambda s: "~/.aip/credentials.json"
            mock_path.home.return_value.__truediv__ = lambda s, x: MagicMock(__truediv__=lambda s2, x2: mock_file)
            mock_path.return_value = MagicMock(exists=MagicMock(return_value=False))
            with patch("builtins.open", MagicMock(return_value=MagicMock(
                __enter__=lambda s: MagicMock(read=lambda: json.dumps(CREDS)),
                __exit__=MagicMock(return_value=False)
            ))):
                with patch("json.load", return_value=CREDS):
                    cmd_doctor(args)
        out = capsys.readouterr().out
        assert "All" in out and "passed" in out

    def test_doctor_no_service(self, capsys):
        args = MagicMock()
        args.service = "https://test.example.com"
        with patch("urllib.request.urlopen", side_effect=Exception("Connection refused")):
            cmd_doctor(args)
        out = capsys.readouterr().out
        assert "Connection refused" in out
        assert "❌" in out

    def test_doctor_no_credentials(self, capsys):
        args = MagicMock()
        args.service = "https://test.example.com"
        responses = {
            "/health": {"status": "healthy", "version": "0.5.15", "checks": {"database": {"ok": True}}},
        }
        with patch("urllib.request.urlopen", side_effect=mock_urlopen(responses)), \
             patch("aip_identity.cli.Path") as mock_path:
            mock_path.home.return_value.__truediv__ = lambda s, x: MagicMock(
                __truediv__=lambda s2, x2: MagicMock(exists=MagicMock(return_value=False))
            )
            mock_path.return_value = MagicMock(exists=MagicMock(return_value=False))
            cmd_doctor(args)
        out = capsys.readouterr().out
        assert "not found" in out
