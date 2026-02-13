#!/usr/bin/env python3
"""
Integration tests for AIP CLI messaging commands.

Tests `aip message` and `aip reply` against a real local service instance.
These tests verify the FULL flow: CLI → HTTP → server → database → response.

Run with: python3 -m pytest tests/test_cli_messaging_integration.py -x -v
"""

import sys
import os
import json
import base64
import tempfile
import subprocess
from pathlib import Path

import pytest
import requests

# Add paths for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


@pytest.fixture
def temp_creds_dir(tmp_path):
    """Create a temporary directory for credentials."""
    creds_dir = tmp_path / "aip_creds"
    creds_dir.mkdir()
    return creds_dir


@pytest.fixture
def agent_a(local_service, temp_creds_dir):
    """Register agent A and return credentials dict."""
    import uuid
    unique_name = f"agent_a_{uuid.uuid4().hex[:8]}"
    
    # Register via API
    resp = requests.post(
        f"{local_service}/register/easy",
        json={"platform": "test", "username": unique_name},
        timeout=10,
    )
    assert resp.status_code == 200, f"Failed to register agent A: {resp.text}"
    data = resp.json()
    
    # Save credentials to temp file
    creds = {
        "did": data["did"],
        "public_key": data["public_key"],
        "private_key": data["private_key"],
        "platform": "test",
        "username": unique_name,
        "service": local_service,
    }
    creds_path = temp_creds_dir / "agent_a_credentials.json"
    with open(creds_path, "w") as f:
        json.dump(creds, f)
    os.chmod(creds_path, 0o600)
    
    return {"creds": creds, "path": creds_path}


@pytest.fixture
def agent_b(local_service, temp_creds_dir):
    """Register agent B and return credentials dict."""
    import uuid
    unique_name = f"agent_b_{uuid.uuid4().hex[:8]}"
    
    # Register via API
    resp = requests.post(
        f"{local_service}/register/easy",
        json={"platform": "test", "username": unique_name},
        timeout=10,
    )
    assert resp.status_code == 200, f"Failed to register agent B: {resp.text}"
    data = resp.json()
    
    # Save credentials to temp file
    creds = {
        "did": data["did"],
        "public_key": data["public_key"],
        "private_key": data["private_key"],
        "platform": "test",
        "username": unique_name,
        "service": local_service,
    }
    creds_path = temp_creds_dir / "agent_b_credentials.json"
    with open(creds_path, "w") as f:
        json.dump(creds, f)
    os.chmod(creds_path, 0o600)
    
    return {"creds": creds, "path": creds_path}


def run_cli_direct(creds_path, service_url, command_args):
    """
    Run CLI command directly by calling the CLI module functions.
    
    This approach is faster and more reliable than subprocess.
    Returns (returncode, stdout_capture, stderr_capture).
    """
    # Import CLI after setting environment
    os.environ["AIP_SERVICE_URL"] = service_url
    
    # Temporarily override credentials path
    from aip_identity import cli
    original_paths = cli.CREDENTIALS_PATHS
    cli.CREDENTIALS_PATHS = [creds_path]
    
    # Capture stdout/stderr
    from io import StringIO
    old_stdout = sys.stdout
    old_stderr = sys.stderr
    stdout_capture = StringIO()
    stderr_capture = StringIO()
    
    try:
        sys.stdout = stdout_capture
        sys.stderr = stderr_capture
        
        # Parse args and call the appropriate command
        import argparse
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        
        # Add message subcommand
        msg_parser = subparsers.add_parser("message")
        msg_parser.add_argument("recipient")
        msg_parser.add_argument("content")
        msg_parser.add_argument("--service", default=service_url)
        
        # Add messages subcommand
        msgs_parser = subparsers.add_parser("messages")
        msgs_parser.add_argument("--decrypt", action="store_true")
        msgs_parser.add_argument("--unread", action="store_true")
        msgs_parser.add_argument("--mark-read", action="store_true")
        msgs_parser.add_argument("--service", default=service_url)
        
        # Add reply subcommand
        reply_parser = subparsers.add_parser("reply")
        reply_parser.add_argument("message_id")
        reply_parser.add_argument("content")
        reply_parser.add_argument("--service", default=service_url)
        
        parsed_args = parser.parse_args(command_args)
        
        # Call the command
        if parsed_args.command == "message":
            cli.cmd_message(parsed_args)
        elif parsed_args.command == "messages":
            cli.cmd_messages(parsed_args)
        elif parsed_args.command == "reply":
            cli.cmd_reply(parsed_args)
        else:
            raise ValueError(f"Unknown command: {parsed_args.command}")
            
        return_code = 0  # Success
    except SystemExit as e:
        return_code = e.code if e.code is not None else 1
    except Exception as e:
        sys.stderr.write(f"CLI error: {e}\n")
        import traceback
        traceback.print_exc(file=sys.stderr)
        return_code = 1
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr
        cli.CREDENTIALS_PATHS = original_paths
        
    # Create a result object similar to subprocess.CompletedProcess
    class Result:
        def __init__(self, returncode, stdout, stderr):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = stderr
    
    return Result(return_code, stdout_capture.getvalue(), stderr_capture.getvalue())


def run_cli_subprocess(creds_path, service_url, *args):
    """
    Run CLI command via subprocess (alternative method).
    """
    env = os.environ.copy()
    env["AIP_SERVICE_URL"] = service_url
    env["HOME"] = str(creds_path.parent)
    # Ensure PYTHONPATH includes the src directory
    aip_root = Path(__file__).parent.parent
    env["PYTHONPATH"] = f"{aip_root / 'src'}:{env.get('PYTHONPATH', '')}"
    
    # Copy credentials to expected location
    home_aip = Path(env["HOME"]) / ".aip"
    home_aip.mkdir(exist_ok=True)
    import shutil
    shutil.copy(creds_path, home_aip / "credentials.json")
    
    result = subprocess.run(
        [sys.executable, "-m", "aip_identity.cli"] + list(args),
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
        cwd=str(aip_root),  # Run from AIP root directory
    )
    return result


class TestMessageSendIntegration:
    """Test `aip message` command end-to-end."""
    
    def test_send_message_success(self, local_service, agent_a, agent_b):
        """Agent A can send encrypted message to agent B, B can retrieve and decrypt it."""
        # Send message from A to B
        result = run_cli_direct(
            agent_a["path"],
            local_service,
            ["message", agent_b["creds"]["did"], "Hello from Agent A!"],
        )
        
        assert result.returncode == 0, f"Failed to send message:\nstdout: {result.stdout}\nstderr: {result.stderr}"
        assert "Message sent" in result.stdout
        
        # Verify B can retrieve the message
        result = run_cli_direct(
            agent_b["path"],
            local_service,
            ["messages", "--decrypt"],
        )
        
        assert result.returncode == 0, f"Failed to retrieve messages:\nstdout: {result.stdout}\nstderr: {result.stderr}"
        assert "Hello from Agent A!" in result.stdout
        assert agent_a["creds"]["did"] in result.stdout
        assert "decrypted" in result.stdout.lower()
    
    def test_message_content_is_encrypted(self, local_service, agent_a, agent_b):
        """Verify the stored message content is actually encrypted (not plaintext)."""
        plaintext = "This should be encrypted in storage"
        
        # Send message
        result = run_cli_direct(
            agent_a["path"],
            local_service,
            ["message", agent_b["creds"]["did"], plaintext],
        )
        assert result.returncode == 0
        
        # Query the database directly to verify encryption
        # We'll use the admin endpoint to check
        resp = requests.post(
            f"{local_service}/challenge",
            json={"did": agent_b["creds"]["did"]},
            timeout=10,
        )
        challenge = resp.json()["challenge"]
        
        # Sign challenge
        import nacl.signing
        priv_bytes = base64.b64decode(agent_b["creds"]["private_key"])
        signing_key = nacl.signing.SigningKey(priv_bytes)
        signature = base64.b64encode(signing_key.sign(challenge.encode()).signature).decode()
        
        # Get messages
        resp = requests.post(
            f"{local_service}/messages",
            json={
                "did": agent_b["creds"]["did"],
                "challenge": challenge,
                "signature": signature,
                "unread_only": False,
            },
            timeout=10,
        )
        assert resp.status_code == 200
        messages = resp.json()["messages"]
        
        # Find our message
        found = False
        for msg in messages:
            encrypted_content = msg.get("encrypted_content", "")
            # The encrypted content should NOT be the plaintext
            assert plaintext not in encrypted_content, "Message is stored as plaintext!"
            # Encrypted content should be base64
            try:
                base64.b64decode(encrypted_content)
                found = True
            except Exception:
                pass
        
        assert found, "Could not find encrypted message in inbox"
    
    def test_send_to_nonexistent_recipient_fails(self, local_service, agent_a):
        """Sending to a non-existent DID should fail gracefully."""
        fake_did = "did:aip:nonexistent12345678901234567890"
        
        result = run_cli_direct(
            agent_a["path"],
            local_service,
            ["message", fake_did, "This should fail"],
        )
        
        assert result.returncode != 0, "Should fail when sending to non-existent DID"
        assert "not found" in result.stderr.lower() or "not registered" in result.stderr.lower() or \
               "not found" in result.stdout.lower() or "not registered" in result.stdout.lower()
    
    def test_signature_verification_works(self, local_service, agent_a, agent_b):
        """Verify that signature verification works end-to-end."""
        # Send a message (this will only succeed if signature is valid)
        result = run_cli_direct(
            agent_a["path"],
            local_service,
            ["message", agent_b["creds"]["did"], "Testing signature verification"],
        )
        
        # If this succeeds, signature was verified correctly
        assert result.returncode == 0, f"Signature verification failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
        assert "Message sent" in result.stdout
        
        # Verify the message was actually stored
        resp = requests.post(
            f"{local_service}/challenge",
            json={"did": agent_b["creds"]["did"]},
            timeout=10,
        )
        challenge = resp.json()["challenge"]
        
        import nacl.signing
        priv_bytes = base64.b64decode(agent_b["creds"]["private_key"])
        signing_key = nacl.signing.SigningKey(priv_bytes)
        signature = base64.b64encode(signing_key.sign(challenge.encode()).signature).decode()
        
        resp = requests.post(
            f"{local_service}/messages",
            json={
                "did": agent_b["creds"]["did"],
                "challenge": challenge,
                "signature": signature,
                "unread_only": False,
            },
            timeout=10,
        )
        assert resp.status_code == 200
        messages = resp.json()["messages"]
        assert len(messages) > 0, "Message was not stored after successful send"


class TestReplyIntegration:
    """Test `aip reply` command end-to-end."""
    
    def test_reply_to_message(self, local_service, agent_a, agent_b):
        """Agent A sends to B, B retrieves messages, B replies, A can retrieve the reply."""
        # Step 1: A sends to B
        result = run_cli_direct(
            agent_a["path"],
            local_service,
            ["message", agent_b["creds"]["did"], "Original message from A"],
        )
        assert result.returncode == 0
        
        # Step 2: B retrieves messages to get message ID
        result = run_cli_direct(
            agent_b["path"],
            local_service,
            ["messages", "--decrypt"],
        )
        assert result.returncode == 0
        
        # Extract message ID from output (format: "ID: msg_xxxxxxxxxxxx")
        import re
        match = re.search(r"ID:\s+(msg_[a-f0-9]+)", result.stdout)
        assert match, f"Could not find message ID in output:\n{result.stdout}"
        message_id = match.group(1)
        
        # Step 3: B replies to the message
        result = run_cli_direct(
            agent_b["path"],
            local_service,
            ["reply", message_id, "This is my reply from B"],
        )
        assert result.returncode == 0, f"Reply failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
        assert "Reply sent" in result.stdout
        
        # Step 4: A retrieves messages and sees the reply
        result = run_cli_direct(
            agent_a["path"],
            local_service,
            ["messages", "--decrypt"],
        )
        assert result.returncode == 0
        assert "This is my reply from B" in result.stdout
        assert "[Re:" in result.stdout  # Reply prefix
    
    def test_reply_to_nonexistent_message_fails(self, local_service, agent_a):
        """Replying to a non-existent message ID should fail."""
        fake_message_id = "msg_nonexistent123"
        
        result = run_cli_direct(
            agent_a["path"],
            local_service,
            ["reply", fake_message_id, "This should fail"],
        )
        
        assert result.returncode != 0, "Should fail when replying to non-existent message"
        assert "not found" in result.stderr.lower() or "not found" in result.stdout.lower()


class TestMessageEncryption:
    """Test encryption and decryption flow."""
    
    def test_encryption_uses_sealedbox(self, local_service, agent_a, agent_b):
        """Verify that SealedBox encryption is being used."""
        # Send a message
        result = run_cli_direct(
            agent_a["path"],
            local_service,
            ["message", agent_b["creds"]["did"], "Testing SealedBox encryption"],
        )
        assert result.returncode == 0
        
        # Retrieve encrypted content from server
        resp = requests.post(
            f"{local_service}/challenge",
            json={"did": agent_b["creds"]["did"]},
            timeout=10,
        )
        challenge = resp.json()["challenge"]
        
        import nacl.signing
        import nacl.public
        priv_bytes = base64.b64decode(agent_b["creds"]["private_key"])
        signing_key = nacl.signing.SigningKey(priv_bytes)
        signature = base64.b64encode(signing_key.sign(challenge.encode()).signature).decode()
        
        resp = requests.post(
            f"{local_service}/messages",
            json={
                "did": agent_b["creds"]["did"],
                "challenge": challenge,
                "signature": signature,
                "unread_only": False,
            },
            timeout=10,
        )
        messages = resp.json()["messages"]
        assert len(messages) > 0
        
        encrypted_content_b64 = messages[0]["encrypted_content"]
        encrypted_bytes = base64.b64decode(encrypted_content_b64)
        
        # Try to decrypt with SealedBox
        curve_priv = signing_key.to_curve25519_private_key()
        sealed_box = nacl.public.SealedBox(curve_priv)
        decrypted = sealed_box.decrypt(encrypted_bytes)
        
        assert b"Testing SealedBox encryption" in decrypted


class TestEndToEndFlow:
    """Test complete conversation flow."""
    
    def test_full_conversation(self, local_service, agent_a, agent_b):
        """Test a complete back-and-forth conversation."""
        # A → B: Initial message
        result = run_cli_direct(
            agent_a["path"],
            local_service,
            ["message", agent_b["creds"]["did"], "Hey B, how are you?"],
        )
        assert result.returncode == 0
        
        # B retrieves and replies
        result = run_cli_direct(
            agent_b["path"],
            local_service,
            ["messages", "--decrypt"],
        )
        assert result.returncode == 0
        import re
        match = re.search(r"ID:\s+(msg_[a-f0-9]+)", result.stdout)
        msg_id_1 = match.group(1)
        
        result = run_cli_direct(
            agent_b["path"],
            local_service,
            ["reply", msg_id_1, "I'm good, thanks for asking!"],
        )
        assert result.returncode == 0
        
        # A retrieves B's reply and replies back
        result = run_cli_direct(
            agent_a["path"],
            local_service,
            ["messages", "--decrypt"],
        )
        assert result.returncode == 0
        assert "I'm good, thanks for asking!" in result.stdout
        match = re.search(r"ID:\s+(msg_[a-f0-9]+)", result.stdout)
        msg_id_2 = match.group(1)
        
        result = run_cli_direct(
            agent_a["path"],
            local_service,
            ["reply", msg_id_2, "Awesome! Let's catch up soon."],
        )
        assert result.returncode == 0
        
        # B retrieves final message
        result = run_cli_direct(
            agent_b["path"],
            local_service,
            ["messages", "--decrypt"],
        )
        assert result.returncode == 0
        assert "Awesome! Let's catch up soon." in result.stdout
        
        # Both should have multiple messages
        assert result.stdout.count("Message") >= 2


class TestMessageCounts:
    """Test message count tracking."""
    
    def test_unread_count(self, local_service, agent_a, agent_b):
        """Verify unread message counting."""
        # Send 3 messages from A to B
        for i in range(3):
            result = run_cli_direct(
                agent_a["path"],
                local_service,
                ["message", agent_b["creds"]["did"], f"Message {i+1}"],
            )
            assert result.returncode == 0
        
        # Check unread count
        resp = requests.get(
            f"{local_service}/messages/count",
            params={"did": agent_b["creds"]["did"]},
            timeout=10,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["unread"] == 3
        
        # Retrieve messages (should mark as read)
        result = run_cli_direct(
            agent_b["path"],
            local_service,
            ["messages", "--decrypt", "--mark-read"],
        )
        assert result.returncode == 0
        
        # Check unread count again (should be 0)
        resp = requests.get(
            f"{local_service}/messages/count",
            params={"did": agent_b["creds"]["did"]},
            timeout=10,
        )
        data = resp.json()
        assert data["unread"] == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
