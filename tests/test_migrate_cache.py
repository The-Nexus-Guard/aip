"""Tests for aip migrate and aip cache commands."""
import json
import os
import sys
import types
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
from aip_identity.cli import cmd_migrate, cmd_cache


@pytest.fixture
def creds_dir(tmp_path):
    """Create a temp credentials file."""
    creds = {
        "did": "did:aip:test123",
        "private_key": "dGVzdHByaXZhdGVrZXkxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMg==",
        "public_key": "dGVzdHB1YmxpY2tleTEyMzQ1Njc4OTAxMjM0NTY=",
        "platform": "moltbook",
        "username": "test_agent",
    }
    creds_file = tmp_path / "creds.json"
    with open(creds_file, "w") as f:
        json.dump(creds, f)
    return tmp_path, creds_file, creds


class TestMigrate:
    def test_migrate_finds_credentials(self, creds_dir, capsys):
        tmp_path, creds_file, creds = creds_dir
        target = tmp_path / "migrated" / "credentials.json"
        args = types.SimpleNamespace(target=str(target), cleanup=False, dry_run=False)
        with patch("aip_identity.cli.CREDENTIALS_PATHS", [creds_file]):
            cmd_migrate(args)
        out = capsys.readouterr().out
        assert "Migrated" in out
        assert target.exists()
        with open(target) as f:
            data = json.load(f)
        assert data["did"] == "did:aip:test123"

    def test_migrate_dry_run(self, creds_dir, capsys):
        tmp_path, creds_file, creds = creds_dir
        target = tmp_path / "dry" / "credentials.json"
        args = types.SimpleNamespace(target=str(target), cleanup=False, dry_run=True)
        with patch("aip_identity.cli.CREDENTIALS_PATHS", [creds_file]):
            cmd_migrate(args)
        out = capsys.readouterr().out
        assert "DRY RUN" in out
        assert not target.exists()

    def test_migrate_no_credentials(self, tmp_path, capsys):
        args = types.SimpleNamespace(target=None, cleanup=False, dry_run=False)
        with patch("aip_identity.cli.CREDENTIALS_PATHS", [tmp_path / "nonexistent.json"]):
            cmd_migrate(args)
        out = capsys.readouterr().out
        assert "No credentials found" in out

    def test_migrate_normalizes_old_fields(self, creds_dir, capsys):
        tmp_path, creds_file, _ = creds_dir
        # Write old-format credentials
        old_creds = {
            "did": "did:aip:old",
            "private_key": "dGVzdHByaXZhdGVrZXkxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMg==",
            "public_key": "dGVzdHB1YmxpY2tleTEyMzQ1Njc4OTAxMjM0NTY=",
            "platform_id": "moltbook",
            "platform_username": "old_agent",
        }
        with open(creds_file, "w") as f:
            json.dump(old_creds, f)
        target = tmp_path / "migrated.json"
        args = types.SimpleNamespace(target=str(target), cleanup=False, dry_run=False)
        with patch("aip_identity.cli.CREDENTIALS_PATHS", [creds_file]):
            cmd_migrate(args)
        with open(target) as f:
            data = json.load(f)
        assert "platform" in data
        assert "username" in data
        assert "platform_id" not in data


class TestCache:
    def test_cache_sync(self, tmp_path, capsys):
        cache_dir = tmp_path / "cache"
        mock_agents = {
            "registrations": [
                {"did": "did:aip:a1", "public_key": "pk1", "platform": "moltbook", "username": "agent1"},
                {"did": "did:aip:a2", "public_key": "pk2", "platform": "github", "username": "agent2"},
            ]
        }
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(mock_agents).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        args = types.SimpleNamespace(cache_action="sync", cache_dir=str(cache_dir), service="http://test", did=None)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            cmd_cache(args)
        out = capsys.readouterr().out
        assert "Cached 2 agents" in out
        assert (cache_dir / "index.json").exists()
        assert (cache_dir / "did_aip_a1.json").exists()

    def test_cache_lookup(self, tmp_path, capsys):
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()
        agent = {"did": "did:aip:a1", "public_key": "pk1", "platform": "moltbook", "username": "agent1", "cached_at": "2026-02-13T00:00:00Z"}
        with open(cache_dir / "did_aip_a1.json", "w") as f:
            json.dump(agent, f)
        args = types.SimpleNamespace(cache_action="lookup", cache_dir=str(cache_dir), did="did:aip:a1", service=None)
        cmd_cache(args)
        out = capsys.readouterr().out
        assert "did:aip:a1" in out
        assert "agent1" in out

    def test_cache_status_empty(self, tmp_path, capsys):
        args = types.SimpleNamespace(cache_action="status", cache_dir=str(tmp_path / "empty"), service=None, did=None)
        cmd_cache(args)
        out = capsys.readouterr().out
        assert "No cache found" in out

    def test_cache_clear(self, tmp_path, capsys):
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()
        (cache_dir / "test.json").write_text("{}")
        args = types.SimpleNamespace(cache_action="clear", cache_dir=str(cache_dir), service=None, did=None)
        cmd_cache(args)
        out = capsys.readouterr().out
        assert "cleared" in out
        assert not cache_dir.exists()
