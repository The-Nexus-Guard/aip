"""Tests for `aip status` command."""
import json
from unittest.mock import patch, MagicMock
import pytest

from aip_identity.cli import cmd_status


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


class TestStatus:
    def test_status_no_credentials(self, capsys, tmp_path):
        args = MagicMock()
        args.service = "https://test.example.com"
        health = {"status": "healthy", "version": "0.5.5",
                  "checks": {"database": {"ok": True}},
                  "metrics": {"registrations": 6, "active_vouches": 3}}
        mock = make_urlopen_mock({"/health": health})
        with patch("urllib.request.urlopen", mock), \
             patch("pathlib.Path.exists", return_value=False):
            cmd_status(args)
        out = capsys.readouterr().out
        assert "AIP Status" in out
        assert "0.5.5" in out
        assert "6 agents" in out
        assert "not configured" in out

    def test_status_with_credentials(self, capsys, tmp_path):
        args = MagicMock()
        args.service = "https://test.example.com"
        health = {"status": "healthy", "version": "0.5.5",
                  "checks": {"database": {"ok": True}},
                  "metrics": {"registrations": 6, "active_vouches": 3}}
        identity = {"trust_score": 0.85, "vouches_received": 2}
        messages = {"unread": 1, "sent": 0}
        mock = make_urlopen_mock({
            "/health": health,
            "/identity/": identity,
            "/messages/count": messages,
        })
        creds = {"did": "did:aip:abc", "platform": "moltbook", "username": "test"}
        creds_file = tmp_path / ".aip" / "credentials.json"
        creds_file.parent.mkdir(parents=True)
        creds_file.write_text(json.dumps(creds))

        with patch("urllib.request.urlopen", mock), \
             patch("pathlib.Path.home", return_value=tmp_path):
            cmd_status(args)
        out = capsys.readouterr().out
        assert "moltbook/test" in out
        assert "0.85" in out
        assert "1 unread" in out

    def test_status_service_down(self, capsys):
        args = MagicMock()
        args.service = "https://down.example.com"
        with patch("urllib.request.urlopen", side_effect=Exception("timeout")):
            cmd_status(args)
        out = capsys.readouterr().out
        assert "unreachable" in out
