"""Tests for the `aip observe` CLI command."""
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock

# Ensure aip_identity is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from aip_identity.cli import cmd_observe


def _make_creds():
    """Generate test credentials."""
    from nacl.signing import SigningKey
    import base64

    sk = SigningKey.generate()
    return {
        "did": "did:aip:test1234567890abcdef",
        "private_key": base64.b64encode(bytes(sk)).decode(),
        "public_key": base64.b64encode(bytes(sk.verify_key)).decode(),
    }


class TestCLIObserveSubmit(unittest.TestCase):
    """Test aip observe submit."""

    @patch("aip_identity.cli.find_credentials")
    @patch("requests.post")
    def test_submit_inline(self, mock_post, mock_creds):
        """Submit inline --promised/--delivered works."""
        mock_creds.return_value = _make_creds()
        mock_post.return_value = MagicMock(
            status_code=200,
            json=lambda: {"status": "ok", "observations_stored": 1, "did": "did:aip:test1234567890abcdef"},
        )

        args = MagicMock()
        args.observe_action = "submit"
        args.service = None
        args.promised = "task1,task2"
        args.delivered = "task1"
        args.file = None

        cmd_observe(args)

        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        payload = call_kwargs[1]["json"] if "json" in call_kwargs[1] else call_kwargs.kwargs["json"]
        self.assertEqual(payload["did"], "did:aip:test1234567890abcdef")
        self.assertEqual(len(payload["observations"]), 1)
        self.assertEqual(payload["observations"][0]["promised"], ["task1", "task2"])
        self.assertEqual(payload["observations"][0]["delivered"], ["task1"])
        self.assertIn("signature", payload)
        self.assertIn("nonce", payload)

    @patch("aip_identity.cli.find_credentials")
    @patch("requests.post")
    def test_submit_from_file(self, mock_post, mock_creds):
        """Submit from JSON file works."""
        mock_creds.return_value = _make_creds()
        mock_post.return_value = MagicMock(
            status_code=200,
            json=lambda: {"status": "ok", "observations_stored": 2, "did": "did:aip:test1234567890abcdef"},
        )

        obs_data = [
            {"promised": ["a", "b"], "delivered": ["a"]},
            {"promised": ["c"], "delivered": ["c"], "conditions": {"env": "test"}},
        ]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(obs_data, f)
            f.flush()
            tmp_path = f.name

        try:
            args = MagicMock()
            args.observe_action = "submit"
            args.service = None
            args.promised = None
            args.delivered = None
            args.file = tmp_path

            cmd_observe(args)

            call_kwargs = mock_post.call_args
            payload = call_kwargs[1]["json"] if "json" in call_kwargs[1] else call_kwargs.kwargs["json"]
            self.assertEqual(len(payload["observations"]), 2)
        finally:
            os.unlink(tmp_path)

    def test_submit_no_creds(self):
        """Submit without credentials exits."""
        with patch("aip_identity.cli.find_credentials", return_value=None):
            args = MagicMock()
            args.observe_action = "submit"
            args.service = None
            args.promised = "x"
            args.delivered = "x"
            args.file = None
            with self.assertRaises(SystemExit):
                cmd_observe(args)

    def test_submit_no_args(self):
        """Submit without --promised/--delivered/--file exits."""
        with patch("aip_identity.cli.find_credentials", return_value=_make_creds()):
            args = MagicMock()
            args.observe_action = "submit"
            args.service = None
            args.promised = None
            args.delivered = None
            args.file = None
            with self.assertRaises(SystemExit):
                cmd_observe(args)


class TestCLIObserveScores(unittest.TestCase):
    """Test aip observe scores."""

    @patch("requests.get")
    def test_scores_with_data(self, mock_get):
        """Scores display works with data."""
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {
                "did": "did:aip:abc",
                "calibration": 0.85,
                "robustness": 0.91,
                "observation_count": 15,
                "window_days": 21,
                "chain_hash": "abcdef1234567890",
            },
        )

        args = MagicMock()
        args.observe_action = "scores"
        args.service = None
        args.did = "did:aip:abc"
        args.window = 28

        cmd_observe(args)
        mock_get.assert_called_once()

    @patch("aip_identity.cli.find_credentials")
    @patch("requests.get")
    def test_scores_default_did(self, mock_get, mock_creds):
        """Scores uses own DID when none provided."""
        mock_creds.return_value = _make_creds()
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {"did": "did:aip:test1234567890abcdef", "observation_count": 0},
        )

        args = MagicMock()
        args.observe_action = "scores"
        args.service = None
        args.did = None
        args.window = 28

        cmd_observe(args)
        mock_get.assert_called_once()


class TestCLIObserveList(unittest.TestCase):
    """Test aip observe list."""

    @patch("requests.get")
    def test_list_observations(self, mock_get):
        """List observations works."""
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {
                "did": "did:aip:abc",
                "observations": [
                    {"id": 1, "promised": ["a"], "delivered": ["a"], "timestamp": "2026-03-14T00:00:00Z"},
                ],
                "count": 1,
            },
        )

        args = MagicMock()
        args.observe_action = "list"
        args.service = None
        args.did = "did:aip:abc"
        args.limit = 50

        cmd_observe(args)
        mock_get.assert_called_once()

    @patch("requests.get")
    def test_list_empty(self, mock_get):
        """List with no observations."""
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {"did": "did:aip:abc", "observations": [], "count": 0},
        )

        args = MagicMock()
        args.observe_action = "list"
        args.service = None
        args.did = "did:aip:abc"
        args.limit = 50

        cmd_observe(args)


if __name__ == "__main__":
    unittest.main()
