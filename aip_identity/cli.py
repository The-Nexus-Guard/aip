#!/usr/bin/env python3
"""
aip — Unified CLI for the Agent Identity Protocol.

Commands:
  register   Register a new agent DID
  verify     Verify a signed artifact
  vouch      Vouch for another agent
  sign       Sign a skill directory or file
  message    Send an encrypted message
  rotate-key Rotate your signing key
  badge      Show trust badge for a DID
  whoami     Show your current identity
"""

import argparse
import base64
import hashlib
import json
import os
import sys
import time
from pathlib import Path

AIP_SERVICE = os.environ.get("AIP_SERVICE_URL", "https://aip-service.fly.dev")
CREDENTIALS_PATHS = [
    Path.home() / ".aip" / "credentials.json",
    Path.home() / ".openclaw" / "workspace" / "credentials" / "aip_credentials.json",
]
SIGNATURE_FILE = ".aip-signature.json"
IGNORE_PATTERNS = {
    ".git", "__pycache__", ".aip-signature.json", ".DS_Store",
    "node_modules", ".env", "*.pyc", "*.pyo",
}


# ── Helpers ──────────────────────────────────────────────────────────

def find_credentials():
    """Find AIP credentials from known locations."""
    for path in CREDENTIALS_PATHS:
        if path.exists():
            try:
                with open(path) as f:
                    creds = json.load(f)
                if "did" in creds and "private_key" in creds:
                    return creds
            except (json.JSONDecodeError, KeyError):
                continue
    return None


def save_credentials(creds, path=None):
    """Save credentials to disk."""
    if path is None:
        path = CREDENTIALS_PATHS[0]
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(creds, f, indent=2)
    os.chmod(path, 0o600)
    print(f"Credentials saved to {path}")


def require_credentials():
    """Return credentials or exit with an error."""
    creds = find_credentials()
    if not creds:
        print("No AIP credentials found. Run: aip register")
        sys.exit(1)
    return creds


def get_client(creds=None, service_url=None):
    """Build an AIPClient from stored credentials."""
    from aip_identity.client import AIPClient
    if creds is None:
        creds = require_credentials()
    return AIPClient(
        did=creds["did"],
        public_key=creds.get("public_key", ""),
        private_key=creds.get("private_key", ""),
        service_url=service_url or creds.get("service", AIP_SERVICE),
    )


def hash_file(filepath):
    """SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def should_ignore(path, base):
    rel = os.path.relpath(path, base)
    parts = Path(rel).parts
    for part in parts:
        if part in IGNORE_PATTERNS:
            return True
        for pattern in IGNORE_PATTERNS:
            if pattern.startswith("*") and part.endswith(pattern[1:]):
                return True
    return os.path.basename(path) == SIGNATURE_FILE


def collect_files(target_path):
    target = Path(target_path)
    if target.is_file():
        return {str(target.name): str(target)}
    files = {}
    for root, dirs, filenames in os.walk(target):
        dirs[:] = [d for d in dirs if d not in IGNORE_PATTERNS]
        for fname in sorted(filenames):
            fpath = os.path.join(root, fname)
            if not should_ignore(fpath, target):
                rel_path = os.path.relpath(fpath, target)
                files[rel_path] = fpath
    return dict(sorted(files.items()))


def decode_key(key_str):
    """Decode a key from hex or base64."""
    try:
        return bytes.fromhex(key_str)
    except ValueError:
        return base64.b64decode(key_str)


# ── Commands ─────────────────────────────────────────────────────────

def cmd_register(args):
    """Register a new agent DID."""
    try:
        import nacl.signing
    except ImportError:
        print("Error: PyNaCl required. pip install pynacl")
        sys.exit(1)
    try:
        import requests
    except ImportError:
        print("Error: requests required. pip install requests")
        sys.exit(1)

    service_url = args.service or AIP_SERVICE

    if args.secure:
        # Local key generation (private key never leaves machine)
        signing_key = nacl.signing.SigningKey.generate()
        pub_bytes = bytes(signing_key.verify_key)
        priv_bytes = bytes(signing_key)

        pub_hex = pub_bytes.hex()
        priv_hex = priv_bytes.hex()
        did = "did:aip:" + hashlib.sha256(pub_bytes).hexdigest()[:32]

        resp = requests.post(
            f"{service_url}/register",
            json={
                "public_key": pub_hex,
                "platform": args.platform,
                "username": args.username,
            },
            timeout=10,
        )
        if not resp.ok:
            print(f"Registration failed: {resp.text}")
            sys.exit(1)

        data = resp.json()
        if "did" in data:
            did = data["did"]

        creds = {
            "did": did,
            "public_key": pub_hex,
            "private_key": priv_hex,
            "platform": args.platform,
            "username": args.username,
            "service": service_url,
            "registered_at": int(time.time()),
        }
        save_credentials(creds)
        print(f"\n✅ Registered (secure)!")
        print(f"   DID: {did}")
        print(f"   Private key never left your machine.")
    else:
        from aip_identity.client import AIPClient
        client = AIPClient.register(
            platform=args.platform,
            platform_id=args.username,
            service_url=service_url,
        )
        creds = {
            "did": client.did,
            "public_key": client.public_key,
            "private_key": client.private_key,
            "platform": args.platform,
            "username": args.username,
            "service": service_url,
            "registered_at": int(time.time()),
        }
        save_credentials(creds)
        print(f"\n✅ Registered!")
        print(f"   DID: {client.did}")

    if args.output:
        save_credentials(creds, Path(args.output))


def cmd_verify(args):
    """Verify a signed artifact."""
    try:
        import nacl.signing
        import nacl.exceptions
    except ImportError:
        print("Error: PyNaCl required. pip install pynacl")
        sys.exit(1)

    target = Path(args.path)
    sig_path = (target.parent if target.is_file() else target) / SIGNATURE_FILE

    if not sig_path.exists():
        print(f"No signature found at {sig_path}")
        sys.exit(1)

    with open(sig_path) as f:
        signed = json.load(f)

    signature = signed.pop("signature")
    manifest = signed

    # Verify cryptographic signature
    verify_key = nacl.signing.VerifyKey(decode_key(manifest["public_key"]))
    payload = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    try:
        verify_key.verify(payload, bytes.fromhex(signature))
    except nacl.exceptions.BadSignatureError:
        print("❌ SIGNATURE INVALID — files may have been tampered with!")
        sys.exit(1)

    # Verify file hashes
    files = collect_files(args.path)
    mismatches = [f for f in manifest["files"] if f in files and hash_file(files[f]) != manifest["files"][f]]
    missing = [f for f in manifest["files"] if f not in files]

    if mismatches or missing:
        print("❌ VERIFICATION FAILED")
        for f in mismatches:
            print(f"   Modified: {f}")
        for f in missing:
            print(f"   Missing: {f}")
        sys.exit(1)

    new_files = [f for f in files if f not in manifest["files"]]
    print(f"✅ Signature valid!")
    print(f"   Signer: {manifest['did']}")
    print(f"   Signed: {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(manifest['timestamp']))}")
    print(f"   Files: {len(manifest['files'])} verified")
    if new_files:
        print(f"   ⚠️  {len(new_files)} new file(s) not in original signature")


def cmd_vouch(args):
    """Vouch for another agent."""
    creds = require_credentials()
    client = get_client(creds, args.service)

    vouch_id = client.vouch(
        target_did=args.target_did,
        scope=args.scope or "GENERAL",
        statement=args.statement,
        ttl_days=args.ttl_days,
    )
    print(f"✅ Vouched for {args.target_did}")
    print(f"   Vouch ID: {vouch_id}")
    print(f"   Scope: {args.scope or 'GENERAL'}")


def cmd_sign(args):
    """Sign a skill directory or file."""
    try:
        import nacl.signing
    except ImportError:
        print("Error: PyNaCl required. pip install pynacl")
        sys.exit(1)

    creds = require_credentials()
    files = collect_files(args.path)
    if not files:
        print(f"No files found in {args.path}")
        sys.exit(1)

    print(f"Signing {len(files)} file(s) as {creds['did']}...")

    file_hashes = {rel: hash_file(abs_p) for rel, abs_p in files.items()}
    manifest = {
        "version": "1.0",
        "did": creds["did"],
        "public_key": creds.get("public_key", ""),
        "timestamp": int(time.time()),
        "files": file_hashes,
    }

    signing_key = nacl.signing.SigningKey(decode_key(creds["private_key"]))
    payload = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    sig = signing_key.sign(payload).signature.hex()

    output = {**manifest, "signature": sig}
    target = Path(args.path)
    sig_path = (target.parent if target.is_file() else target) / SIGNATURE_FILE
    with open(sig_path, "w") as f:
        json.dump(output, f, indent=2)

    print(f"✅ Signed! Manifest written to {sig_path}")
    print(f"   DID: {creds['did']}")
    print(f"   Files: {len(files)}")


def cmd_message(args):
    """Send an encrypted message to another agent."""
    creds = require_credentials()
    client = get_client(creds, args.service)

    import requests as req
    resp = req.post(
        f"{client.service_url}/messages/send",
        json={
            "sender_did": client.did,
            "recipient_did": args.recipient,
            "content": args.content,
            "signature": client.sign(f"{client.did}|{args.recipient}|{args.content}".encode()),
        },
        timeout=10,
    )
    if resp.ok:
        print(f"✅ Message sent to {args.recipient}")
    else:
        print(f"❌ Failed: {resp.text}")
        sys.exit(1)


def cmd_messages(args):
    """Retrieve and optionally decrypt your messages."""
    creds = require_credentials()
    service = args.service or creds.get("service", AIP_SERVICE)

    import requests as req

    # Step 1: Get challenge
    ch_resp = req.post(f"{service}/challenge", json={"did": creds["did"]}, timeout=10)
    if not ch_resp.ok:
        print(f"❌ Challenge failed: {ch_resp.text}")
        sys.exit(1)
    challenge = ch_resp.json().get("challenge")

    # Step 2: Sign challenge
    client = get_client(creds, service)
    signature = client.sign(challenge.encode())

    # Step 3: Retrieve messages
    msg_resp = req.post(
        f"{service}/messages",
        json={
            "did": creds["did"],
            "challenge": challenge,
            "signature": signature,
            "unread_only": args.unread,
        },
        timeout=15,
    )
    if not msg_resp.ok:
        print(f"❌ Failed to retrieve messages: {msg_resp.text}")
        sys.exit(1)

    data = msg_resp.json()
    messages = data.get("messages", [])
    count = data.get("count", len(messages))

    if count == 0:
        print("📭 No messages.")
        return

    print(f"📬 {count} message(s):\n")

    for i, msg in enumerate(messages, 1):
        sender = msg.get("sender_did", "unknown")
        ts = msg.get("created_at", msg.get("timestamp", "?"))
        content = msg.get("encrypted_content", msg.get("content", ""))
        encrypted = bool(msg.get("encrypted_content")) or msg.get("encrypted", False)
        msg_id = msg.get("id", "?")

        print(f"── Message {i} ──")
        print(f"  From:    {sender}")
        print(f"  Date:    {ts}")
        print(f"  ID:      {msg_id}")

        if encrypted and args.decrypt:
            try:
                import nacl.public
                import nacl.signing
                priv_bytes = base64.b64decode(creds["private_key"])
                # Ed25519 signing key → Curve25519 for decryption
                signing_key = nacl.signing.SigningKey(priv_bytes)
                curve_priv = signing_key.to_curve25519_private_key()
                sealed_box = nacl.public.SealedBox(curve_priv)
                plaintext = sealed_box.decrypt(base64.b64decode(content))
                print(f"  Content: {plaintext.decode()}")
                print(f"  🔓 (decrypted)")
            except ImportError:
                print(f"  Content: [encrypted — pip install pynacl to decrypt]")
            except Exception as e:
                print(f"  Content: [decryption failed: {e}]")
                print(f"  Raw:     {content[:80]}...")
        elif encrypted:
            print(f"  Content: [encrypted — use --decrypt to read]")
        else:
            print(f"  Content: {content}")
        print()

    # Step 4: Mark as read if requested
    if args.mark_read and messages:
        for msg in messages:
            msg_id = msg.get("id")
            if msg_id:
                try:
                    req.delete(
                        f"{service}/message/{msg_id}",
                        json={"did": creds["did"], "challenge": challenge, "signature": signature},
                        timeout=5,
                    )
                except Exception:
                    pass
        print(f"✅ Marked {len(messages)} message(s) as read.")


def cmd_rotate_key(args):
    """Rotate your signing key."""
    try:
        import nacl.signing
    except ImportError:
        print("Error: PyNaCl required. pip install pynacl")
        sys.exit(1)

    creds = require_credentials()
    client = get_client(creds, args.service)

    # Generate new keypair
    new_key = nacl.signing.SigningKey.generate()
    new_pub = base64.b64encode(bytes(new_key.verify_key)).decode()
    new_priv = base64.b64encode(bytes(new_key)).decode()

    # Sign rotation request with old key
    rotation_payload = f"rotate|{creds['did']}|{new_pub}|{int(time.time())}"
    old_sig = client.sign(rotation_payload.encode())

    import requests as req
    resp = req.post(
        f"{client.service_url}/rotate-key",
        json={
            "did": creds["did"],
            "new_public_key": new_pub,
            "old_signature": old_sig,
        },
        timeout=10,
    )
    if resp.ok:
        creds["public_key"] = new_pub
        creds["private_key"] = new_priv
        save_credentials(creds)
        print(f"✅ Key rotated for {creds['did']}")
    else:
        print(f"❌ Rotation failed: {resp.text}")
        sys.exit(1)


def cmd_badge(args):
    """Show trust badge for a DID."""
    creds = find_credentials()
    client = get_client(creds or {"did": "did:aip:anon", "public_key": "", "private_key": ""}, args.service)

    try:
        info = client.lookup(args.did)
        trust = client.get_trust(args.did)
        print(f"🪪  {args.did}")
        print(f"   Platform: {info.get('platform', '?')}/{info.get('username', '?')}")
        print(f"   Vouches: {trust.get('vouch_count', 0)}")
        print(f"   Scopes: {', '.join(trust.get('scopes', [])) or 'none'}")
        if trust.get("vouched_by"):
            print(f"   Vouched by: {', '.join(trust['vouched_by'][:5])}")
    except Exception as e:
        print(f"❌ Could not fetch badge: {e}")
        sys.exit(1)


def cmd_list(args):
    """List all registered agents on the AIP service."""
    import requests
    service = getattr(args, "service", None) or AIP_SERVICE
    url = f"{service}/admin/registrations"
    params = {"limit": args.limit, "offset": args.offset}
    try:
        resp = requests.get(url, params=params, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        regs = data.get("registrations", [])
        if not regs:
            print("No registrations found.")
            return
        print(f"{'DID':<45} {'Platform':<12} {'Username':<25} {'Created'}")
        print("-" * 100)
        for r in regs:
            platforms = r.get("platforms", [])
            if platforms:
                for p in platforms:
                    print(f"{r['did']:<45} {p.get('platform','?'):<12} {p.get('username','?'):<25} {r.get('created_at','?')}")
            else:
                print(f"{r['did']:<45} {'—':<12} {'—':<25} {r.get('created_at','?')}")
        print(f"\nShowing {data['count']} of {data['limit']} (offset {data['offset']})")
    except requests.RequestException as e:
        print(f"Error: {e}")
        sys.exit(1)


def cmd_whoami(args):
    """Show your current identity."""
    creds = require_credentials()
    print(f"DID: {creds['did']}")
    print(f"Platform: {creds.get('platform', '?')}/{creds.get('username', '?')}")
    pub = creds.get("public_key", "")
    print(f"Public key: {pub[:16]}..." if len(pub) > 16 else f"Public key: {pub}")

    try:
        import requests as req
        service = creds.get("service", AIP_SERVICE)
        resp = req.get(f"{service}/identity/{creds['did']}", timeout=5)
        if resp.ok:
            info = resp.json()
            print(f"Vouches: {info.get('vouches_received', 0)}")
            print(f"Trust score: {info.get('trust_score', 0):.2f}")
    except Exception:
        print("(Could not reach AIP service for trust info)")


# ── Main ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="aip",
        description="Agent Identity Protocol — cryptographic identity, trust, and messaging for AI agents",
    )
    parser.add_argument("--service", default=None, help=f"AIP service URL (default: {AIP_SERVICE})")
    sub = parser.add_subparsers(dest="command")

    # register
    p_reg = sub.add_parser("register", help="Register a new agent DID")
    p_reg.add_argument("platform", help="Platform name (e.g. moltbook, github)")
    p_reg.add_argument("username", help="Your username on that platform")
    p_reg.add_argument("--secure", action="store_true", help="Generate key locally (private key never leaves machine)")
    p_reg.add_argument("--output", "-o", help="Save credentials to this path")

    # verify
    p_ver = sub.add_parser("verify", help="Verify a signed artifact")
    p_ver.add_argument("path", help="Path to signed directory or file")

    # vouch
    p_vouch = sub.add_parser("vouch", help="Vouch for another agent")
    p_vouch.add_argument("target_did", help="DID to vouch for")
    p_vouch.add_argument("--scope", default="GENERAL", help="Trust scope (default: GENERAL)")
    p_vouch.add_argument("--statement", help="Trust statement")
    p_vouch.add_argument("--ttl-days", type=int, help="Expiration in days")

    # sign
    p_sign = sub.add_parser("sign", help="Sign a skill directory or file")
    p_sign.add_argument("path", help="Path to sign")

    # message (send)
    p_msg = sub.add_parser("message", help="Send a message to another agent")
    p_msg.add_argument("recipient", help="Recipient DID")
    p_msg.add_argument("content", help="Message content")

    # messages (inbox)
    p_msgs = sub.add_parser("messages", help="Retrieve your messages")
    p_msgs.add_argument("--unread", action="store_true", default=False, help="Only show unread messages")
    p_msgs.add_argument("--decrypt", action="store_true", default=True, help="Decrypt encrypted messages (default: yes)")
    p_msgs.add_argument("--no-decrypt", dest="decrypt", action="store_false", help="Don't decrypt messages")
    p_msgs.add_argument("--mark-read", action="store_true", default=False, help="Mark retrieved messages as read")

    # rotate-key
    p_rot = sub.add_parser("rotate-key", help="Rotate your signing key")

    # badge
    p_badge = sub.add_parser("badge", help="Show trust badge for a DID")
    p_badge.add_argument("did", help="DID to look up")

    # list
    p_list = sub.add_parser("list", help="List registered agents on the AIP service")
    p_list.add_argument("--limit", type=int, default=50, help="Max results (default: 50)")
    p_list.add_argument("--offset", type=int, default=0, help="Pagination offset")

    # whoami
    sub.add_parser("whoami", help="Show your current identity")

    args = parser.parse_args()

    commands = {
        "register": cmd_register,
        "verify": cmd_verify,
        "vouch": cmd_vouch,
        "sign": cmd_sign,
        "message": cmd_message,
        "messages": cmd_messages,
        "rotate-key": cmd_rotate_key,
        "badge": cmd_badge,
        "whoami": cmd_whoami,
        "list": cmd_list,
    }

    if args.command in commands:
        commands[args.command](args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
