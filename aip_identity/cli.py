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

from aip_identity import __version__

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
    """Find AIP credentials from known locations.
    
    Checks AIP_CREDENTIALS_PATH env var first, then standard locations.
    """
    # Check env var override first
    env_path = os.environ.get("AIP_CREDENTIALS_PATH")
    if env_path:
        p = Path(env_path)
        if p.exists():
            try:
                with open(p) as f:
                    creds = json.load(f)
                if "did" in creds and "private_key" in creds:
                    return creds
            except (json.JSONDecodeError, KeyError):
                pass
        # If env var is set but file doesn't exist/is invalid, don't fall through
        return None

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
    print(f"  ⚠️  Private key stored in plaintext (file permissions set to 600).")


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

        pub_b64 = base64.b64encode(pub_bytes).decode()
        priv_b64 = base64.b64encode(priv_bytes).decode()
        did = "did:aip:" + hashlib.sha256(pub_bytes).hexdigest()[:32]

        resp = requests.post(
            f"{service_url}/register",
            json={
                "did": did,
                "public_key": pub_b64,
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
            "public_key": pub_b64,
            "private_key": priv_b64,
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


def cmd_revoke(args):
    """Revoke a vouch you previously issued."""
    creds = require_credentials()
    client = get_client(creds, args.service)

    result = client.revoke(vouch_id=args.vouch_id)
    print(f"✅ Vouch revoked: {args.vouch_id}")
    if result.get("message"):
        print(f"   {result['message']}")


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
    import base64 as b64
    from datetime import datetime, timezone

    # Fetch recipient's public key for encryption
    admin_resp = req.get(f"{client.service_url}/admin/registrations/{args.recipient}", timeout=10)
    if not admin_resp.ok:
        print(f"❌ Could not find recipient: {admin_resp.text}")
        sys.exit(1)
    pub_key_b64 = admin_resp.json()["registration"]["public_key"]

    # Encrypt with SealedBox
    from nacl.signing import VerifyKey
    from nacl.public import SealedBox
    vk = VerifyKey(b64.b64decode(pub_key_b64))
    box = SealedBox(vk.to_curve25519_public_key())
    encrypted_b64 = b64.b64encode(box.encrypt(args.content.encode())).decode()

    # Sign with timestamp (domain-separated)
    timestamp = datetime.now(timezone.utc).isoformat()
    sig_payload = f"{client.did}|{args.recipient}|{timestamp}|{encrypted_b64}"
    signature = client.sign(sig_payload.encode())

    resp = req.post(
        f"{client.service_url}/message",
        json={
            "sender_did": client.did,
            "recipient_did": args.recipient,
            "encrypted_content": encrypted_b64,
            "signature": signature,
            "timestamp": timestamp,
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
        import nacl.signing as _ns
        priv_bytes = base64.b64decode(creds["private_key"])
        sk = _ns.SigningKey(priv_bytes)
        marked = 0
        for msg in messages:
            msg_id = msg.get("id")
            if msg_id:
                try:
                    sig = base64.b64encode(sk.sign(msg_id.encode()).signature).decode()
                    resp = req.patch(
                        f"{service}/message/{msg_id}/read",
                        params={"did": creds["did"], "signature": sig},
                        timeout=5,
                    )
                    if resp.ok:
                        marked += 1
                except Exception as e:
                    print(f"  ⚠️ Failed to mark {msg_id}: {e}")
        print(f"✅ Marked {marked}/{len(messages)} message(s) as read.")


def cmd_reply(args):
    """Reply to a received message by ID."""
    creds = require_credentials()
    service = args.service or creds.get("service", AIP_SERVICE)
    client = get_client(creds, service)

    import requests as req

    # Step 1: Retrieve the original message to get sender DID
    ch_resp = req.post(f"{service}/challenge", json={"did": creds["did"]}, timeout=10)
    if not ch_resp.ok:
        print(f"❌ Challenge failed: {ch_resp.text}")
        sys.exit(1)
    challenge = ch_resp.json().get("challenge")
    signature = client.sign(challenge.encode())

    msg_resp = req.post(
        f"{service}/messages",
        json={
            "did": creds["did"],
            "challenge": challenge,
            "signature": signature,
            "unread_only": False,
        },
        timeout=15,
    )
    if not msg_resp.ok:
        print(f"❌ Failed to retrieve messages: {msg_resp.text}")
        sys.exit(1)

    messages = msg_resp.json().get("messages", [])
    original = None
    for msg in messages:
        if msg.get("id") == args.message_id:
            original = msg
            break

    if not original:
        print(f"❌ Message {args.message_id} not found in your inbox.")
        sys.exit(1)

    recipient_did = original.get("sender_did")
    if not recipient_did:
        print("❌ Could not determine sender DID from original message.")
        sys.exit(1)

    # Step 2: Send the reply
    content = args.content
    reply_prefix = f"[Re: {args.message_id[:8]}] "
    full_content = reply_prefix + content

    import base64 as b64
    from datetime import datetime, timezone

    # Encrypt with recipient's public key
    admin_resp = req.get(f"{service}/admin/registrations/{recipient_did}", timeout=10)
    if not admin_resp.ok:
        print(f"❌ Could not find recipient: {admin_resp.text}")
        sys.exit(1)
    pub_key_b64 = admin_resp.json()["registration"]["public_key"]

    from nacl.signing import VerifyKey
    from nacl.public import SealedBox
    vk = VerifyKey(b64.b64decode(pub_key_b64))
    box = SealedBox(vk.to_curve25519_public_key())
    encrypted_b64 = b64.b64encode(box.encrypt(full_content.encode())).decode()

    timestamp = datetime.now(timezone.utc).isoformat()
    sig_payload = f"{client.did}|{recipient_did}|{timestamp}|{encrypted_b64}"
    signature_reply = client.sign(sig_payload.encode())

    resp = req.post(
        f"{service}/message",
        json={
            "sender_did": client.did,
            "recipient_did": recipient_did,
            "encrypted_content": encrypted_b64,
            "signature": signature_reply,
            "timestamp": timestamp,
        },
        timeout=10,
    )
    if resp.ok:
        print(f"✅ Reply sent to {recipient_did}")
        print(f"   In reply to: {args.message_id[:12]}...")
    else:
        print(f"❌ Failed: {resp.text}")
        sys.exit(1)


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


def cmd_trust_score(args):
    """Calculate transitive trust score between two agents."""
    import requests
    service = getattr(args, "service", None) or AIP_SERVICE

    source = args.source
    target = args.target
    scope = getattr(args, "scope", None)

    params = {"source_did": source, "target_did": target}
    if scope:
        params["scope"] = scope

    try:
        resp = requests.get(f"{service}/trust-path", params=params, timeout=15)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as e:
        print(f"❌ Error querying trust path: {e}")
        sys.exit(1)

    if not data.get("path_exists"):
        print(f"❌ No trust path found between:")
        print(f"   Source: {source}")
        print(f"   Target: {target}")
        print(f"   Trust score: 0.0")
        return

    score = data.get("trust_score", 0.0)
    path = data.get("path", [])
    chain = data.get("trust_chain", [])
    length = data.get("path_length", 0)

    # Score bar
    bar_len = 20
    filled = int(score * bar_len)
    bar = "█" * filled + "░" * (bar_len - filled)

    print(f"🔗 Trust Path Found")
    print(f"   Score: {score:.4f} [{bar}]")
    print(f"   Hops:  {length}")
    print()

    if path:
        print("   Path:")
        for i, did in enumerate(path):
            prefix = "   → " if i > 0 else "     "
            print(f"{prefix}{did}")

    if chain:
        print()
        print("   Trust Chain:")
        for v in chain:
            voucher = v.get("voucher_did", "?")[:20]
            target_d = v.get("target_did", "?")[:20]
            vscope = v.get("scope", "GENERAL")
            print(f"     {voucher}… → {target_d}… [{vscope}]")


def cmd_trust_graph(args):
    """Visualize the AIP trust graph as ASCII art, DOT, or JSON."""
    import requests
    service = getattr(args, "service", None) or AIP_SERVICE

    # Fetch all registrations
    try:
        resp = requests.get(f"{service}/admin/registrations", params={"limit": 100}, timeout=15)
        resp.raise_for_status()
        regs = resp.json().get("registrations", [])
    except requests.RequestException as e:
        print(f"Error fetching registrations: {e}")
        sys.exit(1)

    # Build DID→name map and collect all edges
    did_name = {}
    for r in regs:
        platforms = r.get("platforms", [])
        name = platforms[0].get("username", r["did"][:20]) if platforms else r["did"][:20]
        did_name[r["did"]] = name

    edges = []  # (voucher_name, target_name, scope)
    for r in regs:
        try:
            g = requests.get(f"{service}/trust-graph", params={"did": r["did"]}, timeout=10)
            if g.ok:
                data = g.json()
                for v in data.get("vouches_for", []):
                    src = did_name.get(v["voucher_did"], v["voucher_did"][:16])
                    tgt = did_name.get(v["target_did"], v["target_did"][:16])
                    edges.append((src, tgt, v.get("scope", "GENERAL")))
        except requests.RequestException:
            continue

    all_names = set(did_name.values())
    fmt = getattr(args, "format", "ascii")

    if fmt == "json":
        out = {"nodes": sorted(all_names), "edges": [{"from": s, "to": t, "scope": sc} for s, t, sc in edges]}
        print(json.dumps(out, indent=2))
        return

    if fmt == "dot":
        print("digraph trust {")
        print('  rankdir=LR;')
        print('  node [shape=box, style=rounded];')
        for s, t, sc in edges:
            label = f' [label="{sc}"]' if sc != "GENERAL" else ""
            print(f'  "{s}" -> "{t}"{label};')
        for name in all_names:
            if not any(name == s or name == t for s, t, _ in edges):
                print(f'  "{name}";')
        print("}")
        return

    # ASCII art (default)
    if not edges and not all_names:
        print("No agents registered yet.")
        return

    print("AIP Trust Graph")
    print("=" * 50)
    print()

    # Group by voucher
    from collections import defaultdict
    voucher_targets = defaultdict(list)
    received_vouches = defaultdict(list)
    for s, t, sc in edges:
        voucher_targets[s].append((t, sc))
        received_vouches[t].append((s, sc))

    if edges:
        for voucher in sorted(voucher_targets):
            targets = voucher_targets[voucher]
            print(f"  {voucher}")
            for i, (tgt, sc) in enumerate(targets):
                prefix = "└──" if i == len(targets) - 1 else "├──"
                scope_str = f" [{sc}]" if sc != "GENERAL" else ""
                print(f"    {prefix} vouches for → {tgt}{scope_str}")
            print()

    # Show isolated nodes (no vouches given or received)
    connected = set()
    for s, t, _ in edges:
        connected.add(s)
        connected.add(t)
    isolated = all_names - connected
    if isolated:
        print("  Unconnected agents:")
        for name in sorted(isolated):
            print(f"    ○ {name}")
        print()

    print(f"  Total: {len(all_names)} agents, {len(edges)} vouches")


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


def cmd_search(args):
    """Search agents by platform or username."""
    import requests
    service = getattr(args, "service", None) or AIP_SERVICE
    url = f"{service}/admin/registrations"
    params = {"limit": args.limit}
    if args.platform:
        params["platform"] = args.platform
    try:
        resp = requests.get(url, params=params, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        regs = data.get("registrations", [])
        query = args.query.lower()
        # Filter by query matching platform or username
        matches = []
        for r in regs:
            platforms = r.get("platforms", [])
            for p in platforms:
                if query in p.get("platform", "").lower() or query in p.get("username", "").lower():
                    matches.append((r, p))
                    break
            else:
                if query in r.get("did", "").lower():
                    matches.append((r, {"platform": "—", "username": "—"}))
        if not matches:
            print(f"No agents matching '{args.query}' found.")
            return
        print(f"{'DID':<45} {'Platform':<12} {'Username':<25} {'Created'}")
        print("-" * 100)
        for r, p in matches:
            print(f"{r['did']:<45} {p.get('platform','?'):<12} {p.get('username','?'):<25} {r.get('created_at','?')}")
        print(f"\n{len(matches)} result(s)")
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


# ── Status (dashboard) ───────────────────────────────────────────────


def cmd_status(args):
    """Show a dashboard: your identity + network health + unread messages."""
    import urllib.request

    service = args.service or AIP_SERVICE

    # 1. Service health
    print("═══ AIP Status ═══\n")
    try:
        with urllib.request.urlopen(f"{service}/health", timeout=5) as resp:
            health = json.loads(resp.read().decode())
        ver = health.get("version", "?")
        regs = health.get("metrics", {}).get("registrations", "?")
        vouches = health.get("metrics", {}).get("active_vouches", "?")
        db_ok = health.get("checks", {}).get("database", {}).get("ok", False)
        print(f"  Service: {service}")
        print(f"  Version: {ver}  |  DB: {'✅' if db_ok else '❌'}")
        print(f"  Network: {regs} agents, {vouches} active vouches")
    except Exception as e:
        print(f"  Service: ❌ unreachable ({e})")
        print()
        return

    # 2. Identity (if credentials exist)
    creds_path = Path.home() / ".aip" / "credentials.json"
    alt_path = Path("aip_credentials.json")
    creds = None
    for p in [creds_path, alt_path, Path("credentials/aip_credentials.json")]:
        if p.exists():
            with open(p) as f:
                creds = json.load(f)
            break

    if creds:
        did = creds.get("did", "?")
        plat = creds.get("platform", creds.get("platform_id", "?"))
        user = creds.get("username", creds.get("platform_username", "?"))
        print(f"\n  Identity: {plat}/{user}")
        print(f"  DID: {did}")

        # Fetch trust info
        try:
            with urllib.request.urlopen(f"{service}/identity/{did}", timeout=5) as resp:
                info = json.loads(resp.read().decode())
            score = info.get("trust_score", 0)
            v_recv = info.get("vouches_received", 0)
            print(f"  Trust: {score:.2f}  |  Vouches received: {v_recv}")
        except Exception:
            pass

        # Unread messages
        try:
            with urllib.request.urlopen(f"{service}/messages/count?did={did}", timeout=5) as resp:
                msg_data = json.loads(resp.read().decode())
            unread = msg_data.get("unread", 0)
            sent = msg_data.get("sent", 0)
            print(f"  Messages: {unread} unread, {sent} sent")
        except Exception:
            pass
    else:
        print("\n  Identity: not configured (run `aip register` first)")

    print()


def cmd_stats(args):
    """Show public network statistics with growth data."""
    import urllib.request

    service = args.service or AIP_SERVICE

    print("═══ AIP Network Stats ═══\n")
    try:
        with urllib.request.urlopen(f"{service}/stats", timeout=10) as resp:
            data = json.loads(resp.read().decode())
    except Exception as e:
        print(f"  ❌ Could not fetch stats: {e}")
        return

    stats = data.get("stats", {})
    print(f"  Agents:      {stats.get('registrations', '?')}")
    print(f"  Vouches:     {stats.get('active_vouches', '?')}")
    print(f"  Messages:    {stats.get('messages', '?')}")
    print(f"  Signatures:  {stats.get('skill_signatures', '?')}")
    print(f"  Verified:    {stats.get('verifications_completed', '?')}")

    by_plat = stats.get("by_platform", {})
    if by_plat:
        print(f"\n  By platform:")
        for plat, count in by_plat.items():
            print(f"    {plat}: {count}")

    growth = stats.get("growth", {})
    daily = growth.get("daily_registrations", [])
    if daily:
        print(f"\n  Registration growth (last 30 days):")
        for entry in daily:
            bar = "█" * entry["count"]
            print(f"    {entry['date']}: {bar} {entry['count']}")

    print()


# ── Webhook ──────────────────────────────────────────────────────────

def cmd_webhook(args):
    """Manage webhook subscriptions."""
    import urllib.request

    creds = require_credentials()
    service = args.service or creds.get("service", AIP_SERVICE)
    sub = args.webhook_action

    if sub == "list":
        url = f"{service}/webhooks/{creds['did']}"
        try:
            with urllib.request.urlopen(url, timeout=10) as resp:
                data = json.loads(resp.read())
        except Exception as e:
            print(f"❌ Failed to list webhooks: {e}")
            return
        hooks = data.get("webhooks", [])
        if not hooks:
            print("No webhooks registered.")
            return
        for h in hooks:
            status = "✅ active" if h["active"] else "❌ inactive"
            events = ", ".join(h["events"])
            print(f"  {h['id']}  {status}  events=[{events}]  failures={h['failure_count']}")
            print(f"    → {h['url']}")

    elif sub == "add":
        import nacl.signing
        priv = decode_key(creds["private_key"])
        signing_key = nacl.signing.SigningKey(priv)
        url = args.url
        msg = f"webhook:{url}"
        sig = base64.b64encode(signing_key.sign(msg.encode()).signature).decode()
        events = args.events.split(",") if args.events else ["registration"]
        payload = json.dumps({
            "owner_did": creds["did"],
            "url": url,
            "events": events,
            "signature": sig,
        }).encode()
        req = urllib.request.Request(
            f"{service}/webhooks",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
            print(f"✅ Webhook created: {data['id']}")
            print(f"   URL: {url}")
            print(f"   Events: {', '.join(events)}")
        except urllib.error.HTTPError as e:
            body = e.read().decode()
            print(f"❌ Failed ({e.code}): {body}")
        except Exception as e:
            print(f"❌ Failed: {e}")

    elif sub == "delete":
        import nacl.signing
        priv = decode_key(creds["private_key"])
        signing_key = nacl.signing.SigningKey(priv)
        wh_id = args.webhook_id
        msg = f"delete-webhook:{wh_id}"
        sig = base64.b64encode(signing_key.sign(msg.encode()).signature).decode()
        payload = json.dumps({
            "owner_did": creds["did"],
            "signature": sig,
        }).encode()
        req = urllib.request.Request(
            f"{service}/webhooks/{wh_id}",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="DELETE",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                print(f"✅ Webhook {wh_id} deleted.")
        except urllib.error.HTTPError as e:
            body = e.read().decode()
            print(f"❌ Failed ({e.code}): {body}")
        except Exception as e:
            print(f"❌ Failed: {e}")

    else:
        print("Usage: aip webhook {list|add|delete}")
        print("  list                    List your webhooks")
        print("  add <url> [--events ..]  Register a webhook")
        print("  delete <id>             Delete a webhook")


# ── Audit ─────────────────────────────────────────────────────────────

def cmd_audit(args):
    """Comprehensive self-audit: trust, vouches, messages, profile completeness."""
    import urllib.request

    service = args.service or AIP_SERVICE
    creds = find_credentials()
    if not creds:
        print("No AIP credentials found. Run: aip register")
        return

    did = creds["did"]
    plat = creds.get("platform", creds.get("platform_id", "?"))
    user = creds.get("username", creds.get("platform_username", "?"))

    print("═══ AIP Self-Audit ═══\n")
    print(f"  DID:      {did}")
    print(f"  Platform: {plat}/{user}")

    issues = []
    score = 0
    max_score = 0

    # 1. Identity registration
    max_score += 1
    try:
        with urllib.request.urlopen(f"{service}/identity/{did}", timeout=5) as resp:
            identity = json.loads(resp.read().decode())
        trust = identity.get("trust_score", 0)
        verified = identity.get("verified", False)
        v_recv = identity.get("vouches_received", 0)
        v_given = identity.get("vouches_given", 0)
        score += 1
        print(f"\n  ✅ Registered on network")
        print(f"     Trust score: {trust:.2f}")
        print(f"     Verified:    {'✅ yes' if verified else '❌ no'}")
        print(f"     Vouches:     {v_recv} received, {v_given} given")
        if not verified:
            issues.append("Not verified — complete platform verification")
    except Exception as e:
        print(f"\n  ❌ Could not fetch identity: {e}")
        issues.append("Identity not found on network")

    # 2. Trust score
    max_score += 1
    if trust >= 0.5:
        score += 1
        print(f"  ✅ Trust score healthy ({trust:.2f})")
    elif trust > 0:
        score += 0.5
        print(f"  ⚠️  Trust score low ({trust:.2f}) — get more vouches")
        issues.append("Low trust score — seek vouches from established agents")
    else:
        print(f"  ❌ No trust score — you need vouches")
        issues.append("Zero trust — register and get vouched")

    # 3. Vouches received
    max_score += 1
    if v_recv >= 3:
        score += 1
        print(f"  ✅ Good vouch coverage ({v_recv} vouches)")
    elif v_recv >= 1:
        score += 0.5
        print(f"  ⚠️  Only {v_recv} vouch(es) — aim for 3+")
        issues.append(f"Only {v_recv} vouch(es) received — seek more")
    else:
        print(f"  ❌ No vouches received")
        issues.append("No vouches — ask trusted agents to vouch for you")

    # 4. Vouches given (contributing to network)
    max_score += 1
    if v_given >= 1:
        score += 1
        print(f"  ✅ Contributing vouches ({v_given} given)")
    else:
        print(f"  ⚠️  No vouches given — help grow the trust network")
        issues.append("No vouches given — vouch for agents you trust")

    # 5. Messages
    max_score += 1
    try:
        with urllib.request.urlopen(f"{service}/messages/count?did={did}", timeout=5) as resp:
            msg_data = json.loads(resp.read().decode())
        unread = msg_data.get("unread", 0)
        sent = msg_data.get("sent", 0)
        score += 1
        print(f"  ✅ Messaging active ({unread} unread, {sent} sent)")
        if unread > 0:
            issues.append(f"{unread} unread message(s) — check with `aip messages`")
    except Exception:
        print(f"  ⚠️  Could not check messages")

    # 6. Profile completeness
    max_score += 1
    try:
        with urllib.request.urlopen(f"{service}/agent/{did}/profile", timeout=5) as resp:
            profile = json.loads(resp.read().decode())
        filled = sum(1 for k in ["display_name", "bio", "website", "avatar_url"] if profile.get(k))
        tags = profile.get("tags", [])
        if tags:
            filled += 1
        total_fields = 5
        if filled >= 4:
            score += 1
            print(f"  ✅ Profile well-filled ({filled}/{total_fields} fields)")
        elif filled >= 2:
            score += 0.5
            print(f"  ⚠️  Profile partially filled ({filled}/{total_fields})")
            missing = [k for k in ["display_name", "bio", "website", "avatar_url"] if not profile.get(k)]
            if not tags:
                missing.append("tags")
            issues.append(f"Profile incomplete — missing: {', '.join(missing)}")
        else:
            print(f"  ❌ Profile mostly empty ({filled}/{total_fields})")
            issues.append("Profile nearly empty — run `aip profile set`")
    except Exception:
        print(f"  ⚠️  Could not fetch profile")
        issues.append("Set up your profile with `aip profile set`")

    # Summary
    pct = int((score / max_score) * 100) if max_score > 0 else 0
    bar_len = 20
    filled_bar = int(bar_len * score / max_score)
    bar = "█" * filled_bar + "░" * (bar_len - filled_bar)
    print(f"\n  Score: [{bar}] {pct}% ({score:.1f}/{max_score})")

    if issues:
        print(f"\n  📋 Recommendations ({len(issues)}):")
        for i, issue in enumerate(issues, 1):
            print(f"     {i}. {issue}")
    else:
        print(f"\n  🎉 Perfect score! Your identity is fully set up.")

    print()


# ── Changelog ────────────────────────────────────────────────────────

def cmd_changelog(args):
    """Show recent AIP changes and version history."""
    import urllib.request

    url = "https://raw.githubusercontent.com/The-Nexus-Guard/aip/main/CHANGELOG.md"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            text = resp.read().decode()
    except Exception as e:
        print(f"❌ Could not fetch changelog: {e}")
        return

    lines = text.split("\n")
    n = args.entries
    count = 0
    output = []
    for line in lines:
        if line.startswith("## ") and count > 0:
            count += 1
            if count > n:
                break
        elif line.startswith("## "):
            count = 1
        if count >= 1:
            output.append(line)

    print("\n".join(output) if output else text[:2000])


# ── Export / Import ──────────────────────────────────────────────────

def cmd_export(args):
    """Export your identity as portable JSON."""
    creds = require_credentials()
    export_data = {
        "aip_version": "1.0",
        "did": creds["did"],
        "public_key": creds.get("public_key", ""),
        "platform": creds.get("platform_id", creds.get("platform", "")),
        "username": creds.get("username", creds.get("platform_username", "")),
        "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if args.include_private:
        if "private_key" in creds:
            export_data["private_key"] = creds["private_key"]
            print("⚠️  WARNING: Private key included. Keep this file secret!", file=sys.stderr)
        else:
            print("No private key found in credentials.", file=sys.stderr)

    output = json.dumps(export_data, indent=2)
    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w") as f:
            f.write(output + "\n")
        if args.include_private:
            os.chmod(out_path, 0o600)
        print(f"✅ Identity exported to {out_path}", file=sys.stderr)
    else:
        print(output)


def cmd_import(args):
    """Import another agent's public key for offline verification."""
    import urllib.request

    keyring_dir = Path(args.keyring_dir) if args.keyring_dir else Path.home() / ".aip" / "keyring"
    keyring_dir.mkdir(parents=True, exist_ok=True)

    source = args.source

    # If it looks like a DID, fetch from service
    if source.startswith("did:aip:"):
        url = f"{AIP_SERVICE}/admin/registrations/{source}"
        try:
            with urllib.request.urlopen(url, timeout=10) as resp:
                data = json.loads(resp.read().decode())
        except Exception as e:
            print(f"❌ Failed to fetch DID from service: {e}", file=sys.stderr)
            sys.exit(1)
        # Handle nested response (admin endpoint wraps in "registration")
        reg = data.get("registration", data)
        agent_data = {
            "did": reg.get("did", source),
            "public_key": reg.get("public_key", ""),
            "fetched_from": AIP_SERVICE,
            "imported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
    elif Path(source).exists():
        # Read from JSON file
        with open(source) as f:
            agent_data = json.load(f)
        if "did" not in agent_data or "public_key" not in agent_data:
            print("❌ Invalid identity file: must contain 'did' and 'public_key'", file=sys.stderr)
            sys.exit(1)
        agent_data["imported_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    else:
        print(f"❌ Source not found: {source} (expected a file path or did:aip:... DID)", file=sys.stderr)
        sys.exit(1)

    # Save to keyring
    did_slug = agent_data["did"].replace(":", "_")
    out_path = keyring_dir / f"{did_slug}.json"
    with open(out_path, "w") as f:
        json.dump(agent_data, f, indent=2)

    name = agent_data.get("username", agent_data["did"])
    print(f"✅ Imported {name} ({agent_data['did']})")
    print(f"   Saved to {out_path}")


# ── Main ─────────────────────────────────────────────────────────────

def cmd_profile(args):
    """View or update agent profiles."""
    action = getattr(args, "profile_action", None)

    if action == "show":
        did = args.did
        if not did:
            creds = find_credentials()
            if not creds:
                print("No DID specified and no credentials found. Usage: aip profile show <did>")
                return
            did = creds["did"]

        try:
            import requests
            resp = requests.get(f"{AIP_SERVICE}/agent/{did}/profile")
            resp.raise_for_status()
            profile = resp.json()
            print(f"\n  Agent Profile: {did[:20]}...")
            print(f"  {'─' * 40}")
            print(f"  Name:    {profile.get('display_name') or '(not set)'}")
            print(f"  Bio:     {profile.get('bio') or '(not set)'}")
            print(f"  Avatar:  {profile.get('avatar_url') or '(not set)'}")
            print(f"  Website: {profile.get('website') or '(not set)'}")
            tags = profile.get("tags", [])
            print(f"  Tags:    {', '.join(tags) if tags else '(none)'}")
            if profile.get("updated_at"):
                print(f"  Updated: {profile['updated_at']}")
            print()
        except Exception as e:
            print(f"Error: {e}")

    elif action == "set":
        creds = require_credentials()
        client = get_client(creds)

        fields = {}
        if args.display_name:
            fields["display_name"] = args.display_name
        if args.bio:
            fields["bio"] = args.bio
        if args.avatar_url:
            fields["avatar_url"] = args.avatar_url
        if args.website:
            fields["website"] = args.website
        if args.tags:
            fields["tags"] = [t.strip() for t in args.tags.split(",")]

        if not fields:
            print("No fields specified. Use --name, --bio, --avatar, --website, or --tags")
            return

        try:
            result = client.update_profile(**fields)
            print("✅ Profile updated!")
            profile = result.get("profile", {})
            print(f"  Name:    {profile.get('display_name') or '(not set)'}")
            print(f"  Bio:     {profile.get('bio') or '(not set)'}")
            tags = profile.get("tags", [])
            print(f"  Tags:    {', '.join(tags) if tags else '(none)'}")
        except Exception as e:
            print(f"Error updating profile: {e}")
    else:
        print("Usage: aip profile show [did] | aip profile set --name '...' --bio '...'")


def cmd_init(args):
    """One-command setup: register + set profile."""
    # Check if already registered
    existing = find_credentials()
    if existing and not args.force:
        print(f"⚠️  Already registered as {existing['did']}")
        print(f"   Use --force to re-register with a new identity.")
        print(f"   Or use 'aip profile set' to update your profile.")
        return

    try:
        import nacl.signing
        import requests
    except ImportError:
        print("Error: Required packages missing. pip install pynacl requests")
        sys.exit(1)

    service_url = args.service or AIP_SERVICE

    # Step 1: Register (always secure — key never leaves machine)
    print("\n🚀 AIP Quick Setup")
    print("=" * 40)

    platform = args.platform
    username = args.username

    if not platform:
        platform = input("\n  Platform (e.g. github, moltbook): ").strip()
        if not platform:
            print("❌ Platform is required.")
            sys.exit(1)
    if not username:
        username = input(f"  Username on {platform}: ").strip()
        if not username:
            print("❌ Username is required.")
            sys.exit(1)

    print(f"\n📝 Registering on {platform} as {username}...")

    signing_key = nacl.signing.SigningKey.generate()
    pub_bytes = bytes(signing_key.verify_key)
    priv_bytes = bytes(signing_key)

    pub_b64 = base64.b64encode(pub_bytes).decode()
    priv_b64 = base64.b64encode(priv_bytes).decode()
    did = "did:aip:" + hashlib.sha256(pub_bytes).hexdigest()[:32]

    resp = requests.post(
        f"{service_url}/register",
        json={
            "did": did,
            "public_key": pub_b64,
            "platform": platform,
            "username": username,
        },
        timeout=10,
    )
    if not resp.ok:
        print(f"❌ Registration failed: {resp.text}")
        sys.exit(1)

    data = resp.json()
    if "did" in data:
        did = data["did"]

    creds = {
        "did": did,
        "public_key": pub_b64,
        "private_key": priv_b64,
        "platform": platform,
        "username": username,
        "service": service_url,
        "registered_at": int(time.time()),
    }
    save_credentials(creds)
    print(f"   ✅ DID: {did}")

    # Step 2: Set profile if provided
    profile_fields = {}
    if args.name:
        profile_fields["display_name"] = args.name
    if args.bio:
        profile_fields["bio"] = args.bio
    if args.tags:
        profile_fields["tags"] = [t.strip() for t in args.tags.split(",")]

    if profile_fields:
        print(f"\n👤 Setting profile...")
        try:
            client = get_client(creds)
            result = client.update_profile(**profile_fields)
            profile = result.get("profile", {})
            if profile.get("display_name"):
                print(f"   Name: {profile['display_name']}")
            if profile.get("bio"):
                print(f"   Bio:  {profile['bio']}")
            tags = profile.get("tags", [])
            if tags:
                print(f"   Tags: {', '.join(tags)}")
            print(f"   ✅ Profile set!")
        except Exception as e:
            print(f"   ⚠️  Profile update failed: {e}")
            print(f"   You can set it later with: aip profile set --name '...'")

    # Summary
    print(f"\n{'=' * 40}")
    print(f"🎉 You're on AIP!")
    print(f"   DID:      {did}")
    print(f"   Platform: {platform}/{username}")
    print(f"\n   Next steps:")
    print(f"   • aip whoami          — view your identity")
    print(f"   • aip sign <dir>      — sign a skill")
    print(f"   • aip message <did>   — send encrypted message")
    print(f"   • aip status          — full dashboard")
    print()


def cmd_demo(args):
    """Interactive demo: explore AIP features without registering."""
    import urllib.request

    service = getattr(args, "service", None) or AIP_SERVICE

    print("╔══════════════════════════════════════════════════════╗")
    print("║     🔐 AIP — Agent Identity Protocol Demo          ║")
    print("║     Interactive walkthrough (no registration needed) ║")
    print("╚══════════════════════════════════════════════════════╝")
    print()

    # Step 1: Network stats
    print("━━━ Step 1: Network Overview ━━━")
    print(f"Querying {service}/stats ...")
    try:
        req = urllib.request.Request(f"{service}/stats")
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        stats = data.get("stats", data)
        print(f"  📊 Agents registered:  {stats.get('registrations', stats.get('total_agents', '?'))}")
        print(f"  🤝 Active vouches:     {stats.get('active_vouches', '?')}")
        print(f"  📬 Messages exchanged: {stats.get('messages', stats.get('total_messages', '?'))}")
        print(f"  ✍️  Skills signed:      {stats.get('skill_signatures', '?')}")
    except Exception as e:
        print(f"  ⚠️  Could not reach service: {e}")
    print()

    # Step 2: Agent directory
    print("━━━ Step 2: Agent Directory ━━━")
    print("Fetching registered agents...")
    try:
        req = urllib.request.Request(f"{service}/admin/registrations?limit=10")
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        agents = data if isinstance(data, list) else data.get("registrations", data.get("agents", []))
        for agent in agents[:5]:
            did = agent.get("did", "?")
            platforms = agent.get("platforms", [])
            if platforms:
                platform = platforms[0].get("platform", "?")
                username = platforms[0].get("username", "?")
            else:
                platform = agent.get("platform", "?")
                username = agent.get("platform_id", agent.get("username", "?"))
            print(f"  🤖 {username} ({platform}) — {did[:30]}...")
        if len(agents) > 5:
            print(f"  ... and {len(agents) - 5} more")
    except Exception as e:
        print(f"  ⚠️  Could not fetch agents: {e}")
    print()

    # Step 3: Verify an agent
    print("━━━ Step 3: Trust Verification ━━━")
    sample_did = "did:aip:c1965a89866ecbfaad49803e6ced70fb"
    print(f"Checking trust for {sample_did[:40]}...")
    try:
        req = urllib.request.Request(f"{service}/trust/{sample_did}")
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read())
        registered = result.get("registered", False)
        status = "✅ Registered" if registered else "❌ Not found"
        vouches = result.get("vouch_count", len(result.get("vouched_by", [])))
        scopes = result.get("scopes", [])
        print(f"  Status: {status}")
        print(f"  Vouches received: {vouches}")
        if scopes:
            print(f"  Trust scopes: {', '.join(scopes)}")
    except Exception as e:
        print(f"  ⚠️  Could not verify: {e}")
    print()

    # Step 4: Badge
    print("━━━ Step 4: Trust Badge ━━━")
    print(f"Fetching badge for The_Nexus_Guard_001...")
    try:
        req = urllib.request.Request(f"{service}/badge/{sample_did}")
        with urllib.request.urlopen(req, timeout=10) as resp:
            content_type = resp.headers.get("Content-Type", "")
            if "svg" in content_type or "xml" in content_type:
                print(f"  🏅 Badge: {service}/badge/{sample_did}")
                print(f"  (SVG badge — embed in your README or profile)")
            else:
                badge = json.loads(resp.read())
                level = badge.get("level", badge.get("trust_level", "?"))
                score = badge.get("score", badge.get("trust_score", "?"))
                print(f"  🏅 Level: {level}")
                print(f"  📈 Score: {score}")
    except Exception as e:
        print(f"  ⚠️  Could not fetch badge: {e}")
    print()

    # Step 5: What's next
    print("━━━ Ready to join? ━━━")
    print()
    print("  Quick setup (one command):")
    print("    pip install aip-identity")
    print("    aip init <platform> <username>")
    print()
    print("  Or step by step:")
    print("    aip register <platform> <username> --secure")
    print("    aip profile set --name 'My Agent' --bio 'What I do'")
    print("    aip vouch <did> --scope GENERAL")
    print("    aip sign ./my-skill/")
    print("    aip message <did> 'Hello!'")
    print()
    print("  📖 Docs: https://the-nexus-guard.github.io/aip/")
    print("  🔍 Explorer: https://the-nexus-guard.github.io/aip/explorer.html")
    print("  📦 PyPI: https://pypi.org/project/aip-identity/")
    print()


def cmd_migrate(args):
    """Migrate credentials between locations or upgrade format."""
    print("═══ AIP Credential Migration ═══\n")

    # Find all credential files
    found = []
    for p in CREDENTIALS_PATHS:
        if p.exists():
            try:
                with open(p) as f:
                    data = json.load(f)
                found.append((p, data))
                print(f"  📄 Found: {p}")
                print(f"     DID: {data.get('did', '?')}")
                has_pk = "private_key" in data
                print(f"     Private key: {'✅ yes' if has_pk else '❌ no'}")
            except (json.JSONDecodeError, KeyError) as e:
                print(f"  ⚠️  Found but invalid: {p} ({e})")

    if not found:
        print("  ❌ No credentials found anywhere.")
        print(f"     Expected locations: {', '.join(str(p) for p in CREDENTIALS_PATHS)}")
        print("     Run: aip init")
        return

    # Determine the canonical (best) credentials
    best = None
    for p, data in found:
        if "did" in data and "private_key" in data:
            if best is None:
                best = (p, data)
            elif "public_key" in data and "public_key" not in best[1]:
                best = (p, data)

    if best is None:
        print("\n  ❌ No complete credentials (need did + private_key).")
        return

    best_path, best_data = best

    # Normalize field names (old format compatibility)
    normalized = dict(best_data)
    if "platform_id" in normalized and "platform" not in normalized:
        normalized["platform"] = normalized.pop("platform_id")
    if "platform_username" in normalized and "username" not in normalized:
        normalized["username"] = normalized.pop("platform_username")
    # Ensure public_key exists
    if "public_key" not in normalized and "private_key" in normalized:
        try:
            import nacl.signing
            pk_bytes = base64.b64decode(normalized["private_key"])
            signing_key = nacl.signing.SigningKey(pk_bytes)
            normalized["public_key"] = base64.b64encode(
                bytes(signing_key.verify_key)
            ).decode()
            print("\n  🔑 Derived public key from private key.")
        except Exception as e:
            print(f"\n  ⚠️  Could not derive public key: {e}")

    target = args.target
    if target:
        target_path = Path(target)
    else:
        target_path = CREDENTIALS_PATHS[0]  # default: ~/.aip/credentials.json

    if args.dry_run:
        print(f"\n  🔍 DRY RUN — would write to: {target_path}")
        print(f"     Fields: {', '.join(normalized.keys())}")
        return

    # Write normalized credentials to target
    target_path.parent.mkdir(parents=True, exist_ok=True)
    with open(target_path, "w") as f:
        json.dump(normalized, f, indent=2)
    os.chmod(target_path, 0o600)
    print(f"\n  ✅ Migrated to {target_path}")
    print(f"     DID: {normalized['did']}")
    print(f"     Fields: {', '.join(normalized.keys())}")

    # Clean up old locations if different from target
    if args.cleanup:
        for p, _ in found:
            if p != target_path and p.exists():
                p.unlink()
                print(f"  🗑️  Removed old: {p}")


def cmd_cache(args):
    """Cache agent directory locally for offline verification."""
    import urllib.request

    cache_dir = Path(args.cache_dir) if args.cache_dir else Path.home() / ".aip" / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)

    service = args.service or AIP_SERVICE

    if args.cache_action == "sync":
        print("═══ AIP Offline Cache Sync ═══\n")
        print(f"  Service: {service}")
        print(f"  Cache:   {cache_dir}\n")

        # Fetch all agents
        try:
            url = f"{service}/admin/registrations?limit=1000"
            with urllib.request.urlopen(url, timeout=15) as resp:
                data = json.loads(resp.read().decode())
        except Exception as e:
            print(f"  ❌ Failed to fetch directory: {e}")
            sys.exit(1)

        agents = data.get("registrations", data if isinstance(data, list) else [])
        print(f"  📡 Fetched {len(agents)} agents from service")

        # Save each agent's public key + metadata
        for agent in agents:
            did = agent.get("did", "")
            if not did:
                continue
            agent_file = cache_dir / f"{did.replace(':', '_')}.json"
            cache_entry = {
                "did": did,
                "public_key": agent.get("public_key", ""),
                "platform": agent.get("platform", ""),
                "username": agent.get("username", ""),
                "cached_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
            with open(agent_file, "w") as f:
                json.dump(cache_entry, f, indent=2)

        # Save directory index
        index = {
            "synced_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "agent_count": len(agents),
            "service": service,
        }
        with open(cache_dir / "index.json", "w") as f:
            json.dump(index, f, indent=2)

        print(f"  ✅ Cached {len(agents)} agents to {cache_dir}")
        print(f"     Use `aip cache lookup <DID>` for offline verification")

    elif args.cache_action == "lookup":
        did = args.did
        if not did:
            print("  ❌ Provide a DID: aip cache lookup <DID>")
            sys.exit(1)
        agent_file = cache_dir / f"{did.replace(':', '_')}.json"
        if not agent_file.exists():
            print(f"  ❌ Not in cache: {did}")
            print("     Run `aip cache sync` to update cache")
            sys.exit(1)
        with open(agent_file) as f:
            data = json.load(f)
        print(f"  DID:        {data['did']}")
        print(f"  Public Key: {data.get('public_key', '?')[:20]}...")
        print(f"  Platform:   {data.get('platform', '?')}")
        print(f"  Username:   {data.get('username', '?')}")
        print(f"  Cached:     {data.get('cached_at', '?')}")

    elif args.cache_action == "status":
        index_file = cache_dir / "index.json"
        if not index_file.exists():
            print("  No cache found. Run `aip cache sync`")
            return
        with open(index_file) as f:
            index = json.load(f)
        print(f"  Last sync:  {index.get('synced_at', '?')}")
        print(f"  Agents:     {index.get('agent_count', '?')}")
        print(f"  Cache dir:  {cache_dir}")

    elif args.cache_action == "clear":
        import shutil
        if cache_dir.exists():
            shutil.rmtree(cache_dir)
            print(f"  🗑️  Cache cleared: {cache_dir}")
        else:
            print("  No cache to clear.")

    else:
        print("  Usage: aip cache [sync|lookup|status|clear]")


def cmd_doctor(args):
    """Diagnose AIP setup: connectivity, credentials, service compatibility."""
    import urllib.request
    import platform as plat_mod

    service = args.service or AIP_SERVICE
    checks = []
    warnings = []

    def check(name, ok, detail=""):
        status = "✅" if ok else "❌"
        checks.append((name, ok))
        msg = f"  {status} {name}"
        if detail:
            msg += f" — {detail}"
        print(msg)
        return ok

    print("═══ AIP Doctor ═══\n")
    print(f"  Python: {plat_mod.python_version()}")
    print(f"  OS: {plat_mod.system()} {plat_mod.release()}")
    print(f"  Service: {service}")
    print()

    # 1. Check dependencies
    print("  📦 Dependencies")
    for dep in ["nacl", "requests"]:
        try:
            __import__(dep)
            check(f"  {dep}", True, "installed")
        except ImportError:
            check(f"  {dep}", False, "missing — pip install pynacl requests")
    print()

    # 2. Service connectivity
    print("  🌐 Connectivity")
    svc_ok = False
    svc_version = "?"
    try:
        with urllib.request.urlopen(f"{service}/health", timeout=10) as resp:
            health = json.loads(resp.read().decode())
        svc_ok = health.get("status") == "healthy"
        svc_version = health.get("version", "?")
        db_ok = health.get("checks", {}).get("database", {}).get("ok", False)
        check("  Service reachable", svc_ok, f"v{svc_version}")
        check("  Database", db_ok)
    except Exception as e:
        check("  Service reachable", False, str(e))
    print()

    # 3. Credentials
    print("  🔑 Credentials")
    # Use same logic as find_credentials() — respects AIP_CREDENTIALS_PATH env var
    env_creds_path = os.environ.get("AIP_CREDENTIALS_PATH")
    if env_creds_path:
        search_paths = [Path(env_creds_path)]
    else:
        search_paths = list(CREDENTIALS_PATHS) + [Path("aip_credentials.json"), Path("credentials/aip_credentials.json")]
    creds = None
    creds_file = None
    for p in search_paths:
        if p.exists():
            try:
                with open(p) as f:
                    creds = json.load(f)
                creds_file = p
                break
            except Exception:
                pass

    if creds:
        check("  Credentials file", True, str(creds_file))
        did = creds.get("did", "")
        has_did = bool(did and did.startswith("did:aip:"))
        check("  DID format", has_did, did[:40] if did else "missing")
        has_pk = bool(creds.get("private_key"))
        check("  Private key", has_pk, "present" if has_pk else "MISSING — cannot sign")
        has_pub = bool(creds.get("public_key"))
        check("  Public key", has_pub, "present" if has_pub else "MISSING")

        # 4. Registration check (online)
        if svc_ok and has_did:
            print()
            print("  📡 Registration")
            try:
                with urllib.request.urlopen(f"{service}/trust/{did}", timeout=5) as resp:
                    info = json.loads(resp.read().decode())
                registered = bool(info.get("registered") or info.get("did"))
                check("  Registered on service", registered)
                v_recv = info.get("vouch_count", 0)
                check("  Vouches received", v_recv > 0, f"{v_recv}")
                if v_recv == 0:
                    warnings.append("No vouches received — ask a trusted agent to vouch for you")
            except urllib.request.HTTPError as e:
                if e.code == 404:
                    check("  Registered on service", False, "DID not found — run `aip register`")
                else:
                    check("  Registered on service", False, f"HTTP {e.code}")
            except Exception as e:
                check("  Registered on service", False, str(e))
    else:
        check("  Credentials file", False, "not found — run `aip init` or `aip register`")
    print()

    # 5. Version check
    print("  🔄 Version")
    try:
        from aip_identity import __version__
        check("  CLI version", True, f"v{__version__}")
        if svc_ok and svc_version != "?":
            match = __version__ == svc_version
            if not match:
                warnings.append(f"Version mismatch: CLI v{__version__} ≠ service v{svc_version} — pip install --upgrade aip-identity")
            check("  CLI ↔ service version match", match, f"CLI v{__version__} vs service v{svc_version}")
    except ImportError:
        check("  CLI version", False, "could not determine")
    print()

    # Summary
    total = len(checks)
    passed = sum(1 for _, ok in checks if ok)
    failed = total - passed

    if warnings:
        print("  ⚠️  Warnings:")
        for w in warnings:
            print(f"    • {w}")
        print()

    if failed == 0:
        print(f"  🎉 All {total} checks passed — AIP is healthy!")
    else:
        print(f"  ⚠️  {passed}/{total} checks passed, {failed} failed")
        print("  Run `aip init <platform> <username>` to set up, or check the docs:")
        print("  https://the-nexus-guard.github.io/aip/")
    print()


def main():
    parser = argparse.ArgumentParser(
        prog="aip",
        description="Agent Identity Protocol — cryptographic identity, trust, and messaging for AI agents",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--service", default=None, help=f"AIP service URL (default: {AIP_SERVICE})")
    sub = parser.add_subparsers(dest="command")

    # init (quick setup)
    p_init = sub.add_parser("init", help="One-command setup: register + set profile")
    p_init.add_argument("platform", nargs="?", default=None, help="Platform name (e.g. github, moltbook)")
    p_init.add_argument("username", nargs="?", default=None, help="Your username on that platform")
    p_init.add_argument("--name", help="Display name for your profile")
    p_init.add_argument("--bio", help="Short bio (max 500 chars)")
    p_init.add_argument("--tags", help="Comma-separated tags (e.g. 'ai,security,builder')")
    p_init.add_argument("--force", action="store_true", help="Re-register even if credentials exist")

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

    # reply
    p_reply = sub.add_parser("reply", help="Reply to a received message")
    p_reply.add_argument("message_id", help="ID of the message to reply to")
    p_reply.add_argument("content", help="Reply content")

    # rotate-key
    p_rot = sub.add_parser("rotate-key", help="Rotate your signing key")

    # badge
    p_badge = sub.add_parser("badge", help="Show trust badge for a DID")
    p_badge.add_argument("did", help="DID to look up")

    # list
    p_list = sub.add_parser("list", help="List registered agents on the AIP service")
    p_list.add_argument("--limit", type=int, default=50, help="Max results (default: 50)")
    p_list.add_argument("--offset", type=int, default=0, help="Pagination offset")

    # trust-score
    p_ts = sub.add_parser("trust-score", help="Calculate transitive trust score between two agents")
    p_ts.add_argument("source", help="Source DID")
    p_ts.add_argument("target", help="Target DID")
    p_ts.add_argument("--scope", default=None, help="Trust scope filter (e.g. GENERAL, CODE_SIGNING)")

    # trust-graph
    p_tg = sub.add_parser("trust-graph", help="Visualize the AIP trust network")
    p_tg.add_argument("--format", choices=["ascii", "dot", "json"], default="ascii", help="Output format (default: ascii)")

    # whoami
    p_revoke = sub.add_parser("revoke", help="Revoke a vouch you previously issued")
    p_revoke.add_argument("vouch_id", help="ID of the vouch to revoke")
    p_revoke.add_argument("--service", default=None, help="AIP service URL")

    # search
    p_search = sub.add_parser("search", help="Search agents by platform or username")
    p_search.add_argument("query", help="Search term (matched against platform or username)")
    p_search.add_argument("--platform", default=None, help="Filter by platform (e.g. moltbook, github)")
    p_search.add_argument("--limit", type=int, default=50, help="Max results (default: 50)")

    sub.add_parser("whoami", help="Show your current identity")

    # status
    sub.add_parser("status", help="Dashboard: identity + network health + unread messages")

    # stats
    sub.add_parser("stats", help="Public network statistics with growth data")

    # webhook
    p_wh = sub.add_parser("webhook", help="Manage webhook subscriptions (list/add/delete)")
    p_wh_sub = p_wh.add_subparsers(dest="webhook_action")
    p_wh_sub.add_parser("list", help="List your webhooks")
    p_wh_add = p_wh_sub.add_parser("add", help="Register a new webhook")
    p_wh_add.add_argument("url", help="HTTPS URL to receive notifications")
    p_wh_add.add_argument("--events", default="registration", help="Comma-separated events (registration,vouch,message or *)")
    p_wh_del = p_wh_sub.add_parser("delete", help="Delete a webhook")
    p_wh_del.add_argument("webhook_id", help="Webhook ID to delete")

    # changelog
    p_cl = sub.add_parser("changelog", help="Show recent AIP changes and version history")
    p_cl.add_argument("-n", "--entries", type=int, default=5, help="Number of versions to show (default: 5)")

    # export
    p_export = sub.add_parser("export", help="Export your identity (DID + public key) as portable JSON")
    p_export.add_argument("-o", "--output", default=None, help="Output file (default: stdout)")
    p_export.add_argument("--include-private", action="store_true", help="Include private key (DANGEROUS — for backup only)")

    # import
    p_import = sub.add_parser("import", help="Import another agent's public key for offline verification")
    p_import.add_argument("source", help="JSON file path or DID to fetch from service")
    p_import.add_argument("--keyring-dir", default=None, help="Directory to store imported keys (default: ~/.aip/keyring/)")

    # migrate
    p_migrate = sub.add_parser("migrate", help="Migrate credentials between locations or upgrade format")
    p_migrate.add_argument("--target", default=None, help="Target path (default: ~/.aip/credentials.json)")
    p_migrate.add_argument("--cleanup", action="store_true", help="Remove old credential files after migration")
    p_migrate.add_argument("--dry-run", action="store_true", help="Show what would happen without changing anything")

    # cache (offline mode)
    p_cache = sub.add_parser("cache", help="Offline cache: sync agent directory for local verification")
    p_cache_sub = p_cache.add_subparsers(dest="cache_action")
    p_cache_sync = p_cache_sub.add_parser("sync", help="Download agent directory to local cache")
    p_cache_sync.add_argument("--service", default=None, help="AIP service URL")
    p_cache_lookup = p_cache_sub.add_parser("lookup", help="Look up an agent from cache")
    p_cache_lookup.add_argument("did", nargs="?", help="DID to look up")
    p_cache_sub.add_parser("status", help="Show cache status")
    p_cache_sub.add_parser("clear", help="Clear local cache")
    p_cache.add_argument("--cache-dir", default=None, help="Cache directory (default: ~/.aip/cache/)")

    # demo
    sub.add_parser("demo", help="Interactive walkthrough — explore AIP without registering")

    # audit
    sub.add_parser("audit", help="Self-audit: trust, vouches, messages, profile completeness")
    sub.add_parser("doctor", help="Diagnose AIP setup: connectivity, credentials, service version")

    p_profile = sub.add_parser("profile", help="View or update agent profiles")
    p_profile_sub = p_profile.add_subparsers(dest="profile_action")
    p_profile_get = p_profile_sub.add_parser("show", help="Show an agent's profile")
    p_profile_get.add_argument("did", nargs="?", help="DID to look up (default: your own)")
    p_profile_set = p_profile_sub.add_parser("set", help="Update your profile")
    p_profile_set.add_argument("--name", dest="display_name", help="Display name")
    p_profile_set.add_argument("--bio", help="Short bio (max 500 chars)")
    p_profile_set.add_argument("--avatar", dest="avatar_url", help="Avatar URL")
    p_profile_set.add_argument("--website", help="Website URL")
    p_profile_set.add_argument("--tags", help="Comma-separated tags (max 10)")

    args = parser.parse_args()

    commands = {
        "init": cmd_init,
        "demo": cmd_demo,
        "register": cmd_register,
        "profile": cmd_profile,
        "verify": cmd_verify,
        "vouch": cmd_vouch,
        "revoke": cmd_revoke,
        "sign": cmd_sign,
        "message": cmd_message,
        "messages": cmd_messages,
        "reply": cmd_reply,
        "rotate-key": cmd_rotate_key,
        "badge": cmd_badge,
        "whoami": cmd_whoami,
        "list": cmd_list,
        "trust-score": cmd_trust_score,
        "trust-graph": cmd_trust_graph,
        "search": cmd_search,
        "audit": cmd_audit,
        "doctor": cmd_doctor,
        "status": cmd_status,
        "stats": cmd_stats,
        "webhook": cmd_webhook,
        "changelog": cmd_changelog,
        "migrate": cmd_migrate,
        "cache": cmd_cache,
        "export": cmd_export,
        "import": cmd_import,
    }

    if args.command in commands:
        commands[args.command](args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
