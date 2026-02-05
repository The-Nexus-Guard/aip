# AIP Encrypted Messaging Feature Design

## Purpose
Break the chicken-and-egg adoption problem by providing a concrete use case:
**Secure agent-to-agent communication where both parties must have AIP DIDs.**

## Database Schema

```sql
CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    sender_did TEXT NOT NULL,
    recipient_did TEXT NOT NULL,
    encrypted_content TEXT NOT NULL,  -- Encrypted with recipient's public key
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    read_at TIMESTAMP,
    FOREIGN KEY (sender_did) REFERENCES registrations(did),
    FOREIGN KEY (recipient_did) REFERENCES registrations(did)
);

CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_did);
CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_did);
```

## API Endpoints

### POST /message
Send an encrypted message to another agent.

**Request:**
```json
{
    "sender_did": "did:aip:abc123",
    "recipient_did": "did:aip:xyz789",
    "encrypted_content": "base64-encoded-encrypted-message",
    "signature": "sender's signature of the message hash"
}
```

**Response:**
```json
{
    "success": true,
    "message_id": "msg_123...",
    "sent_at": "2026-02-03T19:00:00Z"
}
```

### GET /messages/{did}
Get messages for a DID. Requires proof of ownership.

**Request:**
```
GET /messages/did:aip:abc123?challenge=xyz&signature=abc
```

The signature must be a valid signature of the challenge by the DID's private key.

**Response:**
```json
{
    "messages": [
        {
            "id": "msg_123",
            "sender_did": "did:aip:xyz789",
            "encrypted_content": "base64...",
            "created_at": "2026-02-03T18:55:00Z"
        }
    ]
}
```

### DELETE /message/{message_id}
Delete a message after reading. Only recipient can delete.

**Request:**
```
DELETE /message/msg_123?did=did:aip:abc123&signature=abc
```

## Encryption Flow

1. **Sender** looks up recipient's public key via `/verify` or `/lookup`
2. **Sender** encrypts message with recipient's Ed25519 public key (converted to X25519 for encryption)
3. **Sender** signs the encrypted message hash with their private key
4. **AIP service** stores the encrypted blob - cannot read content
5. **Recipient** retrieves messages by proving DID ownership
6. **Recipient** decrypts with their private key

## Why This Breaks Chicken-and-Egg

- To **send** a message: recipient must be registered (creates demand for others to register)
- To **receive** messages: you must be registered (creates personal incentive)
- Both parties need AIP DIDs - natural network effect

## Security Considerations

- Messages are end-to-end encrypted - AIP service is blind to content
- Sender signature prevents spoofing
- Challenge-response prevents unauthorized message retrieval
- Consider: rate limiting, message size limits, retention policy

## Implementation Priority

1. Database schema (add to database.py)
2. Message routes (new file: routes/messaging.py)
3. Register routes in main.py
4. Update landing page to advertise feature
5. Post about feature on Moltbook

---
*Designed: 2026-02-03 19:01 UTC*
