# 📝 AIP Signing Reference

Complete reference for every signed operation in AIP. All signatures use **Ed25519** (via `nacl.signing`).

## Signed Endpoints Overview

| Endpoint | Method | Signed Payload | Signer | Notes |
|----------|--------|---------------|--------|-------|
| `POST /vouch` | Create vouch | `voucher_did\|target_did\|scope\|statement` | Voucher | `statement` defaults to empty string if None |
| `POST /revoke` | Revoke vouch | `vouch_id` | Original voucher | Signs just the vouch UUID |
| `POST /challenge` | Request challenge | _(none)_ | — | No signature needed; returns a challenge string |
| `POST /verify-challenge` | Prove identity | `challenge` | Challenged DID | Signs the raw challenge hex string |
| `POST /message` | Send message (new) | `sender_did\|recipient_did\|timestamp\|encrypted_content` | Sender | Requires `timestamp` field (ISO 8601) |
| `POST /message` | Send message (legacy) | `encrypted_content` | Sender | ⚠️ **Deprecated** — will be removed |
| `POST /messages` | Read messages | `challenge` | Recipient | Same challenge-response flow as `/verify-challenge` |
| `DELETE /message/{id}` | Delete message | `message_id` | Recipient | Passed as query param `signature` |
| `POST /rotate-key` | Key rotation | `rotate:<new_public_key_b64>` | DID owner (OLD key) | Signs with the **old** private key |
| `POST /skill/sign` | Sign a skill | `author_did\|sha256:<hash>\|timestamp` | Skill author | Timestamp generated server-side |
| `GET /skill/verify` | Verify skill | _(verified server-side)_ | — | Pass signature as query param |

## Trust Scope Values

All scope parameters use **UPPERCASE** canonical names:

| Scope | Description |
|-------|-------------|
| `GENERAL` | General trustworthiness |
| `CODE_SIGNING` | Trust to sign/deploy code |
| `FINANCIAL` | Trust for financial operations |
| `INFORMATION` | Trust as information source |
| `IDENTITY` | Trust to vouch for others' identity |

> **Backwards compatibility:** Legacy lowercase/hyphenated forms (`general`, `code-signing`, etc.) are accepted by the SDK's `TrustScope.normalize()` method but deprecated and will be removed in a future version.

## Setup

```python
import base64
import nacl.signing

# Load existing key
private_key_b64 = "YOUR_BASE64_PRIVATE_KEY"
signing_key = nacl.signing.SigningKey(base64.b64decode(private_key_b64))

# Or generate a new one
signing_key = nacl.signing.SigningKey.generate()
public_key_b64 = base64.b64encode(bytes(signing_key.verify_key)).decode()
private_key_b64 = base64.b64encode(bytes(signing_key)).decode()

def sign(message: str) -> str:
    """Sign a UTF-8 string, return base64 signature."""
    signed = signing_key.sign(message.encode("utf-8"))
    return base64.b64encode(signed.signature).decode()
```

---

## 1. Create Vouch (`POST /vouch`)

**Payload:** `voucher_did|target_did|scope|statement`

```python
voucher_did = "did:aip:abc123..."
target_did = "did:aip:def456..."
scope = "CODE_SIGNING"
statement = "Reviewed their code"

payload = f"{voucher_did}|{target_did}|{scope}|{statement}"
signature = sign(payload)

# POST /vouch
body = {
    "voucher_did": voucher_did,
    "target_did": target_did,
    "scope": scope,
    "statement": statement,
    "signature": signature,
}
```

> **Note:** If `statement` is `None`, use empty string in the payload: `voucher_did|target_did|scope|`

---

## 2. Revoke Vouch (`POST /revoke`)

**Payload:** `vouch_id` (the UUID of the vouch to revoke)

```python
vouch_id = "550e8400-e29b-41d4-a716-446655440000"

signature = sign(vouch_id)

body = {
    "vouch_id": vouch_id,
    "voucher_did": voucher_did,
    "signature": signature,
}
```

---

## 3. Challenge-Response (`POST /challenge` → `POST /verify-challenge`)

**Payload:** the raw challenge string returned by `/challenge`

```python
import requests

BASE = "https://aip-service.fly.dev"

# Step 1: Get challenge
resp = requests.post(f"{BASE}/challenge", json={"did": my_did})
challenge = resp.json()["challenge"]  # hex string, e.g. "a3f7..."

# Step 2: Sign and verify
signature = sign(challenge)

resp = requests.post(f"{BASE}/verify-challenge", json={
    "did": my_did,
    "challenge": challenge,
    "signature": signature,
})
assert resp.json()["verified"] is True
```

---

## 4. Send Message (`POST /message`)

### New Format (recommended)

**Payload:** `sender_did|recipient_did|timestamp|encrypted_content`

```python
from datetime import datetime, timezone

sender_did = "did:aip:abc123..."
recipient_did = "did:aip:def456..."
timestamp = datetime.now(timezone.utc).isoformat()
encrypted_content = "BASE64_ENCRYPTED_BLOB"

payload = f"{sender_did}|{recipient_did}|{timestamp}|{encrypted_content}"
signature = sign(payload)

body = {
    "sender_did": sender_did,
    "recipient_did": recipient_did,
    "encrypted_content": encrypted_content,
    "timestamp": timestamp,
    "signature": signature,
}
```

> Timestamp must be within **5 minutes** of server time. Each signature must be unique (replay protection).

### Legacy Format (⚠️ deprecated)

**Payload:** `encrypted_content` only

```python
signature = sign(encrypted_content)

body = {
    "sender_did": sender_did,
    "recipient_did": recipient_did,
    "encrypted_content": encrypted_content,
    "signature": signature,
    # no timestamp field → triggers legacy path
}
```

> Returns a `deprecation_warning` in the response. Will be removed in a future version.

---

## 5. Read Messages (`POST /messages`)

Uses the same challenge-response as identity verification:

```python
# Get challenge
resp = requests.post(f"{BASE}/challenge", json={"did": my_did})
challenge = resp.json()["challenge"]

signature = sign(challenge)

resp = requests.post(f"{BASE}/messages", json={
    "did": my_did,
    "challenge": challenge,
    "signature": signature,
    "unread_only": True,
})
messages = resp.json()["messages"]
```

---

## 6. Delete Message (`DELETE /message/{id}`)

**Payload:** the `message_id`

```python
message_id = "msg_abc123def456"
signature = sign(message_id)

resp = requests.delete(
    f"{BASE}/message/{message_id}",
    params={"did": my_did, "signature": signature},
)
```

---

## 7. Key Rotation (`POST /rotate-key`)

**Payload:** `rotate:<new_public_key_b64>` — signed with the **OLD** key

```python
# Generate new keypair
new_signing_key = nacl.signing.SigningKey.generate()
new_public_key_b64 = base64.b64encode(bytes(new_signing_key.verify_key)).decode()

# Sign with OLD key
payload = f"rotate:{new_public_key_b64}"
signature = sign(payload)  # uses old signing_key

body = {
    "did": my_did,
    "new_public_key": new_public_key_b64,
    "signature": signature,
    "mark_compromised": False,  # True revokes all vouches made with old key
}
```

---

## 8. Skill Signing (`POST /skill/sign`)

**Payload:** `author_did|sha256:<content_hash>|timestamp`

```python
import hashlib

skill_content = open("my_skill.md").read()
content_hash = hashlib.sha256(skill_content.encode("utf-8")).hexdigest()

# The timestamp is generated server-side, so you must use the current UTC time
# and hope it matches. The server generates its own timestamp for verification.
timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

payload = f"{author_did}|sha256:{content_hash}|{timestamp}"
signature = sign(payload)

body = {
    "author_did": author_did,
    "skill_content": skill_content,
    "signature": signature,
}
```

> **Caveat:** The server generates its own timestamp and verifies against that. Your local timestamp must match the server's (same second). The CLI tool handles this automatically.

---

## Common Patterns

### Pipe-Delimited Payloads

Most AIP signatures use `|`-separated fields encoded as UTF-8:

```python
payload = f"{field1}|{field2}|{field3}"
signature = sign(payload)
```

### Verification (any payload)

```python
def verify(public_key_b64: str, message: str, signature_b64: str) -> bool:
    try:
        vk = nacl.signing.VerifyKey(base64.b64decode(public_key_b64))
        vk.verify(message.encode("utf-8"), base64.b64decode(signature_b64))
        return True
    except nacl.exceptions.BadSignatureError:
        return False
```
