"""Smoke tests for the AIP CLI.

Tests that CLI commands parse correctly (--help) and that commands
which can run without credentials/network produce expected output.
"""

import subprocess
import sys
import pytest


def run_cli(*args, expect_rc=0):
    """Run `python -m aip_identity.cli` with given args."""
    result = subprocess.run(
        [sys.executable, "-m", "aip_identity.cli", *args],
        capture_output=True, text=True, timeout=15,
        env={**__import__("os").environ, "AIP_SERVICE_URL": "http://localhost:1"},  # no real network
    )
    if expect_rc is not None:
        assert result.returncode == expect_rc, (
            f"Expected rc={expect_rc}, got {result.returncode}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
    return result


# ── Help flags parse correctly ──

COMMANDS = [
    "register", "verify", "vouch", "revoke", "sign", "message", "messages",
    "reply", "rotate-key", "badge", "trust-score", "trust-graph", "list",
    "search", "whoami", "status", "stats", "webhook", "audit", "changelog",
    "export", "import", "profile", "init", "demo", "migrate", "cache", "doctor",
]


@pytest.mark.parametrize("cmd", COMMANDS)
def test_help_flag(cmd):
    """Every subcommand should accept --help and exit 0."""
    result = run_cli(cmd, "--help")
    assert "usage:" in result.stdout.lower() or cmd in result.stdout.lower()


def test_main_help():
    """Top-level --help works."""
    result = run_cli("--help")
    assert "aip" in result.stdout.lower()


# ── Commands that work without credentials ──

def test_changelog():
    """changelog prints version history."""
    result = run_cli("changelog")
    # Should contain version numbers
    assert "v0." in result.stdout or "0." in result.stdout or "No changelog" in result.stdout


# ── Commands that fail gracefully without credentials ──

def test_whoami_no_creds(tmp_path, monkeypatch):
    """whoami without credentials should exit with error message."""
    monkeypatch.setenv("HOME", str(tmp_path))  # no creds here
    result = run_cli("whoami", expect_rc=1)
    assert "credentials" in result.stdout.lower() or "register" in result.stdout.lower()


def test_audit_no_creds(tmp_path, monkeypatch):
    """audit without credentials should mention missing creds."""
    monkeypatch.setenv("HOME", str(tmp_path))
    result = run_cli("audit", expect_rc=None)
    assert "credentials" in result.stdout.lower() or "register" in result.stdout.lower()


def test_export_no_creds(tmp_path, monkeypatch):
    """export without credentials should exit with error."""
    monkeypatch.setenv("HOME", str(tmp_path))
    result = run_cli("export", expect_rc=1)
    assert "credentials" in result.stdout.lower() or "register" in result.stdout.lower()


# ── Cache subcommands ──

def test_cache_status(tmp_path, monkeypatch):
    """cache status should work (may show empty cache)."""
    monkeypatch.setenv("HOME", str(tmp_path))
    result = run_cli("cache", "status", expect_rc=None)
    # Should not crash — either shows cache info or no-cache message
    assert result.returncode in (0, 1)


def test_cache_clear(tmp_path, monkeypatch):
    """cache clear should work even with no cache."""
    monkeypatch.setenv("HOME", str(tmp_path))
    result = run_cli("cache", "clear", expect_rc=None)
    assert result.returncode in (0, 1)
