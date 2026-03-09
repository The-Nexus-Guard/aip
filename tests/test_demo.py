"""Tests for aip demo command."""
import json
from unittest.mock import patch, MagicMock
from io import BytesIO
from aip_identity.cli import cmd_demo


def _mock_urlopen(responses):
    """Create a mock urlopen that returns different responses per URL."""
    def side_effect(req, timeout=None):
        url = req.full_url if hasattr(req, 'full_url') else str(req)
        for pattern, data in responses.items():
            if pattern in url:
                resp = MagicMock()
                resp.read.return_value = json.dumps(data).encode()
                resp.__enter__ = lambda s: s
                resp.__exit__ = MagicMock(return_value=False)
                return resp
        raise Exception("not found")
    return side_effect


def test_demo_interactive_default(capsys):
    """Default demo runs interactive crypto walkthrough."""
    args = MagicMock()
    args.service = None
    args.interactive = False
    args.network = False
    cmd_demo(args)
    out = capsys.readouterr().out
    assert "AIP in 60 Seconds" in out
    assert "Create Agent Identities" in out
    assert "Digital Signatures" in out
    assert "Encrypted Messaging" in out
    assert "Trust & Vouching" in out
    assert "VALID" in out
    assert "INVALID" in out
    assert "What Just Happened" in out
    assert "aip init" in out


def test_demo_interactive_flag(capsys):
    """--interactive flag runs same crypto demo."""
    args = MagicMock()
    args.service = None
    args.interactive = True
    args.network = False
    cmd_demo(args)
    out = capsys.readouterr().out
    assert "AIP in 60 Seconds" in out
    assert "Create Agent Identities" in out


def test_demo_network_mode(capsys):
    """--network flag shows live network stats."""
    responses = {
        "/stats": {
            "stats": {
                "registrations": 7,
                "active_vouches": 3,
                "messages": 1,
                "skill_signatures": 0,
                "by_platform": {"test": 5, "cli": 2},
            }
        },
        "/trust/": {"registered": True, "vouch_count": 3, "scopes": ["GENERAL"]},
    }
    args = MagicMock()
    args.service = None
    args.interactive = False
    args.network = True
    with patch("urllib.request.urlopen", side_effect=_mock_urlopen(responses)):
        cmd_demo(args)
    out = capsys.readouterr().out
    assert "Network Overview" in out
    assert "Agent Directory" in out
    assert "Trust Verification" in out
    assert "aip demo --interactive" in out


def test_demo_network_handles_errors(capsys):
    """Network demo gracefully handles service errors."""
    args = MagicMock()
    args.service = "http://localhost:9999"
    args.interactive = False
    args.network = True
    with patch("urllib.request.urlopen", side_effect=Exception("connection refused")):
        cmd_demo(args)
    out = capsys.readouterr().out
    assert "Could not reach service" in out
    assert "aip demo --interactive" in out
