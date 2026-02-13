"""Tests for `aip init` command."""
import json
from unittest.mock import patch, MagicMock
import pytest

from aip_identity.cli import cmd_init


class TestInit:
    def test_init_already_registered(self, capsys, tmp_path):
        """Should warn if credentials already exist (no --force)."""
        creds = {"did": "did:aip:abc123", "public_key": "aa", "private_key": "bb"}
        args = MagicMock()
        args.force = False
        args.platform = "moltbook"
        args.username = "test"
        args.service = None

        with patch("aip_identity.cli.find_credentials", return_value=creds):
            cmd_init(args)

        out = capsys.readouterr().out
        assert "Already registered" in out
        assert "did:aip:abc123" in out

    def test_init_registers_new_agent(self, capsys, tmp_path):
        """Should register and save credentials."""
        args = MagicMock()
        args.force = False
        args.platform = "github"
        args.username = "testuser"
        args.service = "https://test.example.com"
        args.name = None
        args.bio = None
        args.tags = None

        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.json.return_value = {"did": "did:aip:newdid123"}

        with patch("aip_identity.cli.find_credentials", return_value=None), \
             patch("aip_identity.cli.save_credentials") as mock_save, \
             patch("requests.post", return_value=mock_resp):
            cmd_init(args)

        out = capsys.readouterr().out
        assert "did:aip:newdid123" in out
        assert "You're on AIP" in out
        mock_save.assert_called_once()
        saved = mock_save.call_args[0][0]
        assert saved["did"] == "did:aip:newdid123"
        assert saved["platform"] == "github"

    def test_init_with_profile(self, capsys, tmp_path):
        """Should register and set profile when --name/--bio/--tags provided."""
        args = MagicMock()
        args.force = False
        args.platform = "moltbook"
        args.username = "agent1"
        args.service = "https://test.example.com"
        args.name = "Agent One"
        args.bio = "I'm a test agent"
        args.tags = "ai,security"

        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.json.return_value = {"did": "did:aip:profiletest"}

        mock_client = MagicMock()
        mock_client.update_profile.return_value = {
            "profile": {"display_name": "Agent One", "bio": "I'm a test agent", "tags": ["ai", "security"]}
        }

        with patch("aip_identity.cli.find_credentials", return_value=None), \
             patch("aip_identity.cli.save_credentials"), \
             patch("requests.post", return_value=mock_resp), \
             patch("aip_identity.cli.get_client", return_value=mock_client):
            cmd_init(args)

        out = capsys.readouterr().out
        assert "Agent One" in out
        assert "Profile set" in out
        mock_client.update_profile.assert_called_once_with(
            display_name="Agent One", bio="I'm a test agent", tags=["ai", "security"]
        )

    def test_init_force_reregister(self, capsys):
        """Should re-register when --force is set even with existing creds."""
        existing = {"did": "did:aip:old", "public_key": "aa", "private_key": "bb"}
        args = MagicMock()
        args.force = True
        args.platform = "github"
        args.username = "newuser"
        args.service = "https://test.example.com"
        args.name = None
        args.bio = None
        args.tags = None

        mock_resp = MagicMock()
        mock_resp.ok = True
        mock_resp.json.return_value = {"did": "did:aip:newone"}

        with patch("aip_identity.cli.find_credentials", return_value=existing), \
             patch("aip_identity.cli.save_credentials") as mock_save, \
             patch("requests.post", return_value=mock_resp):
            cmd_init(args)

        out = capsys.readouterr().out
        assert "did:aip:newone" in out
        assert "You're on AIP" in out
        mock_save.assert_called_once()
