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


def test_demo_runs(capsys):
    """Demo command runs and shows all sections."""
    responses = {
        "/stats": {"total_agents": 7, "active_vouches": 3, "total_messages": 1, "skill_signatures": 0},
        "/admin/registrations": [{"did": "did:aip:abc", "platform": "test", "platform_id": "user1"}],
        "/verify/": {"verified": True, "vouches_received": 3, "trust_score": 0.8},
        "/badge/": {"level": "trusted", "score": 0.8},
    }
    args = MagicMock()
    args.service = None
    with patch("urllib.request.urlopen", side_effect=_mock_urlopen(responses)):
        cmd_demo(args)
    out = capsys.readouterr().out
    assert "Network Overview" in out
    assert "Agent Directory" in out
    assert "Trust Verification" in out
    assert "Trust Badge" in out
    assert "Ready to join?" in out
    assert "pip install aip-identity" in out


def test_demo_handles_errors(capsys):
    """Demo gracefully handles service errors."""
    args = MagicMock()
    args.service = "http://localhost:9999"
    with patch("urllib.request.urlopen", side_effect=Exception("connection refused")):
        cmd_demo(args)
    out = capsys.readouterr().out
    assert "Could not reach service" in out
    assert "Ready to join?" in out  # still shows next steps
