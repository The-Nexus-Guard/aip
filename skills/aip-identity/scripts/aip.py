#!/usr/bin/env python3
"""
AIP Identity Tool — Register, verify, vouch, and sign with Agent Identity Protocol.
Usage: python3 aip.py <command> [options]
"""

import argparse, base64, hashlib, json, os, sys, time, urllib.request, urllib.error
from datetime import datetime, timezone

AIP_BASE = os.environ.get("AIP_SERVICE_URL", "https://aip-service.fly.dev")
DEFAULT_CREDS = "aip_credentials.json"


# --- Ed25519 helpers (try nacl, fall back to subprocess calling openssl) ---

def _generate_keypair_nacl():
    import nacl.signing
    sk = nacl.signing.SigningKey.generate()
    return (
        base64.b64encode(sk.encode()).decode(),
        base64.b64encode(sk.verify_key.encode()).decode(),
    )

def _sign_nacl(message: bytes, private_key_b64: str) -> str:
    import nacl.signing
    sk = nacl.signing.SigningKey(base64.b64decode(private_key_b64))
    signed = sk.sign(message)
    return base64.b64encode(signed.signature).decode()

def generate_keypair():
    try:
        return _generate_keypair_nacl()
    except ImportError:
        pass
    # Fallback: use hashlib-based Ed25519 via subprocess
    import subprocess, tempfile
    with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
        kf = f.name
    try:
        subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out", kf],
                       check=True, capture_output=True)
        raw = subprocess.run(["openssl", "pkey", "-in", kf, "-outform", "DER"],
                             check=True, capture_output=True).stdout
        # Ed25519 DER private key: last 32 bytes are the seed
        seed = raw[-32:]
        pub_raw = subprocess.run(
            ["openssl", "pkey", "-in", kf, "-pubout", "-outform", "DER"],
            check=True, capture_output=True).stdout
        pub = pub_raw[-32:]
        return base64.b64encode(seed).decode(), base64.b64encode(pub).decode()
    finally:
        os.unlink(kf)

def sign_message(message: bytes, private_key_b64: str) -> str:
    try:
        return _sign_nacl(message, private_key_b64)
    except ImportError:
        pass
    import subprocess, tempfile
    seed = base64.b64decode(private_key_b64)
    # Build DER-encoded Ed25519 private key
    der_prefix = bytes.fromhex("302e020100300506032b657004220420")
    der = der_prefix + seed
    with tempfile.NamedTemporaryFile(suffix=".der", delete=False) as f:
        f.write(der)
        kf = f.name
    try:
        result = subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-inkey", kf, "-keyform", "DER"],
            input=message, check=True, capture_output=True)
        return base64.b64encode(result.stdout).decode()
    finally:
        os.unlink(kf)


# --- API helpers ---

def api(method, path, data=None):
    url = f"{AIP_BASE}{path}"
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, method=method,
                                headers={"Content-Type": "application/json"} if body else {})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        err = e.read().decode()
        try:
            err = json.loads(err)
        except Exception:
            pass
        print(f"Error {e.code}: {json.dumps(err, indent=2) if isinstance(err, dict) else err}", file=sys.stderr)
        sys.exit(1)

def load_creds(path):
    p = path or DEFAULT_CREDS
    if not os.path.exists(p):
        print(f"Credentials not found: {p}\nRun 'aip.py register' first.", file=sys.stderr)
        sys.exit(1)
    with open(p) as f:
        return json.load(f)


# --- Commands ---

def cmd_register(args):
    if not args.platform or not args.username:
        print("--platform and --username required", file=sys.stderr)
        sys.exit(1)

    priv_b64, pub_b64 = generate_keypair()
    pub_bytes = base64.b64decode(pub_b64)
    did = "did:aip:" + hashlib.md5(pub_bytes).hexdigest()

    result = api("POST", "/register", {
        "did": did,
        "public_key": pub_b64,
        "platform": args.platform,
        "platform_id": args.username,
    })

    creds = {
        "did": did,
        "public_key": pub_b64,
        "private_key": priv_b64,
        "platform": args.platform,
        "username": args.username,
        "registered_at": datetime.now(timezone.utc).isoformat(),
    }
    out = args.credentials or DEFAULT_CREDS
    with open(out, "w") as f:
        json.dump(creds, f, indent=2)

    print(f"✅ Registered successfully!")
    print(f"   DID: {did}")
    print(f"   Credentials saved to: {out}")
    print(f"   ⚠️  Back up {out} — private key cannot be recovered!")


def cmd_verify(args):
    if args.did:
        result = api("GET", f"/identity/{args.did}")
    elif args.username:
        result = api("GET", f"/verify?platform=moltbook&username={args.username}")
    else:
        print("--username or --did required", file=sys.stderr)
        sys.exit(1)

    if not result or not result.get("verified"):
        print("❌ Agent not found in AIP registry.")
        return

    print(f"✅ Verified agent:")
    print(f"   DID: {result.get('did')}")
    platforms = result.get("platforms", [])
    for p in platforms:
        print(f"   Platform: {p.get('platform')} / {p.get('username')}")
        print(f"   Registered: {p.get('registered_at')}")

    # Fetch trust graph for vouches
    try:
        graph = api("GET", f"/trust-graph?did={result['did']}")
        received = graph.get("vouched_by", graph.get("vouches_received", []))
        if received:
            print(f"   Vouches ({len(received)}):")
            for v in received:
                cat = v.get('category') or v.get('scope', '?')
                print(f"     - {v.get('voucher_did', '?')} [{cat}]")
        else:
            print("   Vouches: none")
    except Exception:
        pass


def cmd_vouch(args):
    creds = load_creds(args.credentials)
    if not args.target_did:
        print("--target-did required", file=sys.stderr)
        sys.exit(1)

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    category = args.category or "GENERAL"
    msg = f"VOUCH:{creds['did']}:{args.target_did}:{category}:{ts}"
    sig = sign_message(msg.encode(), creds["private_key"])

    result = api("POST", f"/identity/{args.target_did}/vouch", {
        "voucher_did": creds["did"],
        "category": category,
        "signature": sig,
        "timestamp": ts,
    })

    print(f"✅ Vouched for {args.target_did} [{category}]")


def cmd_sign(args):
    creds = load_creds(args.credentials)
    content = args.content
    if args.file:
        with open(args.file, "rb") as f:
            content = hashlib.sha256(f.read()).hexdigest()
    if not content:
        print("--content or --file required", file=sys.stderr)
        sys.exit(1)

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    msg = f"SIGN:{creds['did']}:{content}:{ts}"
    sig = sign_message(msg.encode(), creds["private_key"])

    name = args.name or "unnamed"
    result = api("POST", "/skill/sign", {
        "did": creds["did"],
        "skill_name": name,
        "content_hash": content,
        "signature": sig,
        "timestamp": ts,
    })

    print(f"✅ Signed '{name}'")
    print(f"   Hash: {content}")
    print(f"   Signature: {sig[:40]}...")


def cmd_whoami(args):
    creds = load_creds(args.credentials)
    result = api("GET", f"/identity/{creds['did']}")
    if not result:
        print("❌ DID not found in registry (may have been removed).")
        return

    print(f"🆔 Your AIP Identity:")
    print(f"   DID: {creds['did']}")
    print(f"   Platform: {result.get('platform')} / {result.get('platform_id')}")
    print(f"   Registered: {result.get('registered_at')}")

    graph = api("GET", f"/trust-graph?did={creds['did']}")
    received = graph.get("vouched_by", graph.get("vouches_received", []))
    given = graph.get("vouches_for", graph.get("vouches_given", []))
    print(f"   Vouches received: {len(received)}")
    for v in received:
        cat = v.get('category') or v.get('scope', '?')
        print(f"     ← {v.get('voucher_did', '?')} [{cat}]")
    print(f"   Vouches given: {len(given)}")
    for v in given:
        cat = v.get('category') or v.get('scope', '?')
        print(f"     → {v.get('target_did', '?')} [{cat}]")


# --- CLI ---

def main():
    parser = argparse.ArgumentParser(description="AIP Identity Tool")
    sub = parser.add_subparsers(dest="command")

    p_reg = sub.add_parser("register", help="Register a new DID")
    p_reg.add_argument("--platform", default="moltbook")
    p_reg.add_argument("--username", required=True)
    p_reg.add_argument("--credentials", default=DEFAULT_CREDS)

    p_ver = sub.add_parser("verify", help="Verify an agent")
    p_ver.add_argument("--username")
    p_ver.add_argument("--did")

    p_vouch = sub.add_parser("vouch", help="Vouch for an agent")
    p_vouch.add_argument("--target-did", required=True)
    p_vouch.add_argument("--category", default="GENERAL", choices=["IDENTITY", "CODE_SIGNING", "COMMUNICATION", "GENERAL"])
    p_vouch.add_argument("--credentials", default=DEFAULT_CREDS)

    p_sign = sub.add_parser("sign", help="Sign content or a file")
    p_sign.add_argument("--content", help="Hash or content to sign")
    p_sign.add_argument("--file", help="File to hash and sign")
    p_sign.add_argument("--name", help="Skill/content name")
    p_sign.add_argument("--credentials", default=DEFAULT_CREDS)

    p_who = sub.add_parser("whoami", help="Show your identity")
    p_who.add_argument("--credentials", default=DEFAULT_CREDS)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    {"register": cmd_register, "verify": cmd_verify, "vouch": cmd_vouch,
     "sign": cmd_sign, "whoami": cmd_whoami}[args.command](args)


if __name__ == "__main__":
    main()
