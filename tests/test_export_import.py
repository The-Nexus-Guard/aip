"""Tests for aip export and aip import CLI commands."""
import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
from aip_identity.cli import cmd_export, cmd_import


@pytest.fixture
def mock_creds():
    return {
        "did": "did:aip:test123",
        "public_key": "dGVzdHB1YmtleQ==",
        "private_key": "dGVzdHByaXZrZXk=",
        "platform_id": "moltbook",
        "username": "TestAgent",
    }


@pytest.fixture
def mock_args():
    args = MagicMock()
    args.output = None
    args.include_private = False
    return args


class TestExport:
    def test_export_stdout(self, mock_creds, mock_args, capsys):
        with patch("aip_identity.cli.find_credentials", return_value=mock_creds):
            cmd_export(mock_args)
        out = json.loads(capsys.readouterr().out)
        assert out["did"] == "did:aip:test123"
        assert out["public_key"] == "dGVzdHB1YmtleQ=="
        assert "private_key" not in out

    def test_export_with_private_key(self, mock_creds, mock_args, capsys):
        mock_args.include_private = True
        with patch("aip_identity.cli.find_credentials", return_value=mock_creds):
            cmd_export(mock_args)
        out = json.loads(capsys.readouterr().out)
        assert out["private_key"] == "dGVzdHByaXZrZXk="

    def test_export_to_file(self, mock_creds, mock_args):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            mock_args.output = f.name
        try:
            with patch("aip_identity.cli.find_credentials", return_value=mock_creds):
                cmd_export(mock_args)
            data = json.loads(Path(mock_args.output).read_text())
            assert data["did"] == "did:aip:test123"
        finally:
            os.unlink(mock_args.output)


class TestImport:
    def test_import_from_file(self, capsys):
        with tempfile.TemporaryDirectory() as keyring, tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump({"did": "did:aip:abc", "public_key": "key123"}, f)
            f.flush()
            args = MagicMock()
            args.source = f.name
            args.keyring_dir = keyring
            cmd_import(args)
            saved = json.loads(Path(keyring, "did_aip_abc.json").read_text())
            assert saved["did"] == "did:aip:abc"
            assert saved["public_key"] == "key123"
            os.unlink(f.name)

    def test_import_invalid_file(self):
        with tempfile.TemporaryDirectory() as keyring, tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump({"foo": "bar"}, f)
            f.flush()
            args = MagicMock()
            args.source = f.name
            args.keyring_dir = keyring
            with pytest.raises(SystemExit):
                cmd_import(args)
            os.unlink(f.name)

    def test_import_from_did(self):
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "registration": {"did": "did:aip:remote", "public_key": "remotekey"}
        }).encode()
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with tempfile.TemporaryDirectory() as keyring:
            args = MagicMock()
            args.source = "did:aip:remote"
            args.keyring_dir = keyring
            with patch("urllib.request.urlopen", return_value=mock_response):
                cmd_import(args)
            saved = json.loads(Path(keyring, "did_aip_remote.json").read_text())
            assert saved["did"] == "did:aip:remote"
            assert saved["public_key"] == "remotekey"
