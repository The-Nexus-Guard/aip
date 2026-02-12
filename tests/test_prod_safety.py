"""Tests for production safety guard in AIP CLI.

Ensures that write operations (register, vouch, revoke, skill-sign, message)
are blocked when AIP_TESTING=1 and the target is production.
"""

import os
import subprocess
import sys

import pytest

CLI_PATH = os.path.join(os.path.dirname(__file__), "..", "cli", "aip")

WRITE_COMMANDS = [
    ["register", "--platform", "moltbook", "--username", "test"],
    ["vouch", "did:aip:fake"],
    ["revoke", "fake-id"],
    ["skill-sign", "/dev/null"],
]

READ_COMMANDS = [
    ["health"],
    ["stats"],
    ["whoami"],
    ["verify", "--did", "did:aip:fake"],
]


@pytest.mark.parametrize("cmd_args", WRITE_COMMANDS, ids=lambda a: a[0])
def test_write_blocked_in_testing_mode(cmd_args):
    """Write commands must exit 99 when AIP_TESTING=1 and targeting production."""
    env = os.environ.copy()
    env["AIP_TESTING"] = "1"
    env.pop("AIP_SERVICE_URL", None)  # ensure default (production)

    result = subprocess.run(
        [sys.executable, CLI_PATH] + cmd_args,
        capture_output=True, text=True, env=env, timeout=10,
    )
    assert result.returncode == 99, f"Expected exit 99, got {result.returncode}: {result.stderr}"
    assert "BLOCKED" in result.stdout


@pytest.mark.parametrize("cmd_args", READ_COMMANDS, ids=lambda a: a[0])
def test_read_allowed_in_testing_mode(cmd_args):
    """Read-only commands must NOT be blocked even with AIP_TESTING=1."""
    env = os.environ.copy()
    env["AIP_TESTING"] = "1"
    env.pop("AIP_SERVICE_URL", None)

    result = subprocess.run(
        [sys.executable, CLI_PATH] + cmd_args,
        capture_output=True, text=True, env=env, timeout=10,
    )
    # Should not exit 99
    assert result.returncode != 99, f"Read command was blocked: {result.stdout}"


@pytest.mark.parametrize("cmd_args", WRITE_COMMANDS[:1], ids=lambda a: a[0])
def test_write_allowed_with_local_url(cmd_args):
    """Write commands should NOT be blocked when targeting a local server."""
    env = os.environ.copy()
    env["AIP_TESTING"] = "1"
    env["AIP_SERVICE_URL"] = "http://127.0.0.1:9999"

    result = subprocess.run(
        [sys.executable, CLI_PATH] + cmd_args,
        capture_output=True, text=True, env=env, timeout=10,
    )
    # Should not exit 99 (will fail for other reasons like connection refused, that's fine)
    assert result.returncode != 99, f"Write to local was blocked: {result.stdout}"
