"""Tests for `aip trust-score` CLI command."""
import argparse
import sys
from unittest.mock import patch, MagicMock
import pytest


def make_args(source="did:aip:aaa", target="did:aip:bbb", scope=None, service="http://test"):
    return argparse.Namespace(source=source, target=target, scope=scope, service=service)


class MockResponse:
    def __init__(self, json_data, status_code=200):
        self._json = json_data
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise Exception(f"HTTP {self.status_code}")

    def json(self):
        return self._json


def test_trust_score_path_exists(capsys):
    from aip_identity.cli import cmd_trust_score
    mock_resp = MockResponse({
        "source_did": "did:aip:aaa",
        "target_did": "did:aip:bbb",
        "path_exists": True,
        "path_length": 1,
        "path": ["did:aip:aaa", "did:aip:bbb"],
        "trust_chain": [{"voucher_did": "did:aip:aaa", "target_did": "did:aip:bbb", "scope": "GENERAL"}],
        "trust_score": 0.8
    })
    with patch("requests.get", return_value=mock_resp):
        cmd_trust_score(make_args())
    out = capsys.readouterr().out
    assert "Trust Path Found" in out
    assert "0.8000" in out
    assert "Hops:  1" in out


def test_trust_score_no_path(capsys):
    from aip_identity.cli import cmd_trust_score
    mock_resp = MockResponse({
        "source_did": "did:aip:aaa",
        "target_did": "did:aip:ccc",
        "path_exists": False,
    })
    with patch("requests.get", return_value=mock_resp):
        cmd_trust_score(make_args(target="did:aip:ccc"))
    out = capsys.readouterr().out
    assert "No trust path found" in out
    assert "0.0" in out


def test_trust_score_with_scope(capsys):
    from aip_identity.cli import cmd_trust_score
    mock_resp = MockResponse({
        "path_exists": True, "path_length": 0, "path": ["did:aip:aaa"],
        "trust_chain": [], "trust_score": 1.0
    })
    with patch("requests.get", return_value=mock_resp) as mock_get:
        cmd_trust_score(make_args(scope="CODE_SIGNING"))
    # Verify scope was passed
    call_kwargs = mock_get.call_args
    assert "CODE_SIGNING" in str(call_kwargs)


def test_trust_score_api_error(capsys):
    from aip_identity.cli import cmd_trust_score
    import requests
    with patch("requests.get", side_effect=requests.RequestException("timeout")):
        with pytest.raises(SystemExit):
            cmd_trust_score(make_args())
    out = capsys.readouterr().out
    assert "Error" in out
