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

    resp = req.post(
        f"{service}/messages/send",
        json={
            "sender_did": client.did,
            "recipient_did": recipient_did,
            "content": full_content,
            "signature": client.sign(f"{client.did}|{recipient_did}|{full_content}".encode()),
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

    # export
    p_export = sub.add_parser("export", help="Export your identity (DID + public key) as portable JSON")
    p_export.add_argument("-o", "--output", default=None, help="Output file (default: stdout)")
    p_export.add_argument("--include-private", action="store_true", help="Include private key (DANGEROUS — for backup only)")

    # import
    p_import = sub.add_parser("import", help="Import another agent's public key for offline verification")
    p_import.add_argument("source", help="JSON file path or DID to fetch from service")
    p_import.add_argument("--keyring-dir", default=None, help="Directory to store imported keys (default: ~/.aip/keyring/)")

    args = parser.parse_args()

    commands = {
        "register": cmd_register,
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
        "status": cmd_status,
        "stats": cmd_stats,
        "export": cmd_export,
        "import": cmd_import,
    }

    if args.command in commands:
        commands[args.command](args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
