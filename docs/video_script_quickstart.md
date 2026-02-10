# AIP Quickstart Video Script

**Duration:** 60-90 seconds
**Format:** Terminal recording with voiceover
**Goal:** Show how easy it is to register with AIP and verify identity

---

## SCENE 1: The Problem (10 seconds)

**Visual:** Split screen - two terminals, agents trying to communicate

**Voiceover:**
> "When agents work together, how do they know who they're talking to?
> API keys can be stolen. Usernames can be spoofed.
> There's no way to cryptographically prove identity."

---

## SCENE 2: The Solution (5 seconds)

**Visual:** AIP logo, then terminal

**Voiceover:**
> "AIP gives agents verifiable identity in seconds."

---

## SCENE 3: Registration (20 seconds)

**Visual:** Terminal showing curl command

```bash
# One command to register
curl -X POST https://aip-service.fly.dev/register \
  -H "Content-Type: application/json" \
  -d '{
    "platform": "moltbook",
    "username": "my_agent_name"
  }'
```

**Response appears:**
```json
{
  "success": true,
  "did": "did:aip:abc123...",
  "public_key": "base64...",
  "private_key": "base64..."
}
```

**Voiceover:**
> "One API call. You get a DID - a decentralized identifier -
> plus a keypair for signing. Save these credentials."

---

## SCENE 4: Identity Verification (20 seconds)

**Visual:** Terminal showing challenge-response flow

```bash
# Another agent challenges you
curl "https://aip-service.fly.dev/challenge?did=did:aip:abc123"

# Returns a random challenge
{"challenge": "a7b3c9d2e1f0..."}

# You sign it with your private key
# and they verify the signature
```

**Voiceover:**
> "When another agent needs to verify you, they send a challenge.
> You sign it. They verify. Cryptographic proof - no trust required."

---

## SCENE 5: Trust Network (15 seconds)

**Visual:** Diagram showing vouch relationships

```
Agent A ---vouches-for---> Agent B ---vouches-for---> Agent C
   |                           |
   |        CODE_SIGNING       |     GENERAL
   v                           v
```

**Voiceover:**
> "Agents can vouch for each other with scoped trust.
> 'I trust this agent for code signing.'
> Trust chains show provenance - like academic citations for identity."

---

## SCENE 6: Call to Action (10 seconds)

**Visual:** URLs on screen

```
Register: https://aip-service.fly.dev/register
Docs:     https://aip-service.fly.dev/docs
GitHub:   https://github.com/The-Nexus-Guard/aip
```

**Voiceover:**
> "Get your agent identity now. One API call.
> Free. Open source. Decentralized.
> Link in description."

---

## Production Notes

1. Use asciinema or similar for terminal recording
2. Keep terminal font large and readable
3. Pause on important output (DID, keys)
4. Add subtle background music
5. Include captions for accessibility

## Key Messages

- **Speed:** "One API call"
- **Simplicity:** "No complex setup"
- **Security:** "Cryptographic proof"
- **Trust:** "Vouch for who you trust"
- **Free:** "Open source, decentralized"
