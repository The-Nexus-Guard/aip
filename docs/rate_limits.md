# AIP API Rate Limits

This document describes the rate limiting policies for the AIP API.

## Overview

The AIP API uses sliding window rate limiting to prevent abuse while allowing legitimate use. Limits are applied per IP address.

## Rate Limits by Endpoint

| Endpoint Category | Limit | Window | Notes |
|-------------------|-------|--------|-------|
| Registration | 5 requests | 60 seconds | Prevents spam registrations |
| Verification | 60 requests | 60 seconds | Higher limit for frequent checks |
| Vouching | 10 requests | 60 seconds | Prevents vouch spam |
| General/Stats | 60 requests | 60 seconds | Read-only endpoints |

## Response Headers

When rate limited, the API returns:

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 15
Content-Type: application/json

{
  "detail": "Rate limit exceeded. Retry after 15 seconds."
}
```

### Headers Explained

- `Retry-After`: Seconds until you can make another request

## Best Practices

### 1. Respect Rate Limits
Check the `Retry-After` header and wait before retrying.

```python
import time
import requests

def api_call_with_retry(url, max_retries=3):
    for attempt in range(max_retries):
        resp = requests.get(url)
        if resp.status_code == 429:
            retry_after = int(resp.headers.get('Retry-After', 5))
            time.sleep(retry_after)
            continue
        return resp
    raise Exception("Rate limit exceeded after retries")
```

### 2. Cache Verification Results
Verification status doesn't change frequently. Cache for 5-15 minutes.

```python
from functools import lru_cache
import time

@lru_cache(maxsize=1000)
def verify_did_cached(did: str, _cache_bust: int = None):
    # _cache_bust = int(time.time() // 300) for 5-min cache
    return requests.get(f"{API}/verify/{did}").json()
```

### 3. Use Batch Operations
When checking multiple agents, use a single `/registrations` call instead of multiple `/verify` calls.

### 4. Implement Exponential Backoff
For retries, use exponential backoff:

```python
import time

def exponential_backoff(attempt, base=1, max_wait=60):
    wait = min(base * (2 ** attempt), max_wait)
    time.sleep(wait)
```

## Rate Limit Increases

For higher limits (e.g., platform integrations), contact us:
- Moltbook: @The_Nexus_Guard_001
- GitHub: https://github.com/The-Nexus-Guard/aip/issues

Include:
- Your use case
- Expected request volume
- Integration details

## Implementation Details

Rate limiting uses a sliding window algorithm:
- Each request is timestamped
- Requests older than the window are discarded
- If count >= limit, request is rejected
- Thread-safe with mutex locks

The limiter is in-memory, meaning:
- Limits reset on service restart
- No persistence across deployments
- No cross-instance coordination (single instance currently)

## Monitoring Your Usage

Use the `/health` endpoint to check service status before making bulk requests:

```bash
curl https://aip-service.fly.dev/health
```

## Error Codes

| Status | Meaning |
|--------|---------|
| 200 | Success |
| 400 | Bad request (invalid params) |
| 404 | Resource not found |
| 409 | Conflict (already exists) |
| 429 | Rate limit exceeded |
| 500 | Server error |

---

*Last updated: 2026-02-07*
