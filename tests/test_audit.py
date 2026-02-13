"""Tests for `aip audit` command."""
import json
from unittest.mock import patch, MagicMock
import pytest

from aip_identity.cli import cmd_audit


def make_urlopen_mock(responses):
    """Create a mock urlopen that returns different responses per URL."""
    def side_effect(url, **kwargs):
        for pattern, data in responses.items():
            if pattern in url:
                resp = MagicMock()
                resp.read.return_value = json.dumps(data).encode()
                resp.__enter__ = lambda s: s
                resp.__exit__ = MagicMock(return_value=False)
                return resp
        raise Exception(f"No mock for {url}")
    return side_effect


CREDS = {"did": "did:aip:abc123", "private_key": "dGVzdA==", "platform": "moltbook", "username": "testuser"}


class TestAudit:
    def test_audit_no_credentials(self, capsys):
        args = MagicMock()
        args.service = "https://test.example.com"
        with patch("aip_identity.cli.find_credentials", return_value=None):
            cmd_audit(args)
        out = capsys.readouterr().out
        assert "No AIP credentials" in out

    def test_audit_perfect_score(self, capsys):
        args = MagicMock()
        args.service = "https://test.example.com"
        identity = {"trust_score": 0.9, "verified": True, "vouches_received": 5, "vouches_given": 3}
        messages = {"unread": 0, "sent": 2}
        profile = {"display_name": "Test", "bio": "Hello", "website": "https://example.com",
                    "avatar_url": "https://example.com/img.png", "tags": ["ai"]}
        mock = make_urlopen_mock({
            "/identity/": identity,
            "/messages/count": messages,
            "/agent/": profile,
        })
        with patch("aip_identity.cli.find_credentials", return_value=CREDS), \
             patch("urllib.request.urlopen", mock):
            cmd_audit(args)
        out = capsys.readouterr().out
        assert "Self-Audit" in out
        assert "100%" in out
        assert "Perfect score" in out

    def test_audit_low_trust(self, capsys):
        args = MagicMock()
        args.service = "https://test.example.com"
        identity = {"trust_score": 0.2, "verified": False, "vouches_received": 1, "vouches_given": 0}
        messages = {"unread": 3, "sent": 0}
        profile = {"display_name": "Test", "bio": None, "website": None, "avatar_url": None, "tags": []}
        mock = make_urlopen_mock({
            "/identity/": identity,
            "/messages/count": messages,
            "/agent/": profile,
        })
        with patch("aip_identity.cli.find_credentials", return_value=CREDS), \
             patch("urllib.request.urlopen", mock):
            cmd_audit(args)
        out = capsys.readouterr().out
        assert "Self-Audit" in out
        assert "Recommendations" in out
        assert "unread" in out.lower()

    def test_audit_zero_vouches(self, capsys):
        args = MagicMock()
        args.service = "https://test.example.com"
        identity = {"trust_score": 0, "verified": False, "vouches_received": 0, "vouches_given": 0}
        messages = {"unread": 0, "sent": 0}
        profile = {}
        mock = make_urlopen_mock({
            "/identity/": identity,
            "/messages/count": messages,
            "/agent/": profile,
        })
        with patch("aip_identity.cli.find_credentials", return_value=CREDS), \
             patch("urllib.request.urlopen", mock):
            cmd_audit(args)
        out = capsys.readouterr().out
        assert "No vouches" in out
        assert "Recommendations" in out
