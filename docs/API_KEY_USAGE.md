# CyberGuard AI — API Key Usage Guide

This guide explains how external customers and integrations authenticate with
CyberGuard AI using **API Keys**, without requiring a user account or JWT token.

---

## How to Generate an API Key

API keys are generated from the CyberGuard dashboard under **Settings → API Keys**,
or programmatically via the management API (requires JWT authentication).

```http
POST /api-keys/create
Authorization: Bearer <YOUR_JWT_TOKEN>
Content-Type: application/json

{
  "label": "my-integration",
  "expires_in_days": 365
}
```

**Response (shown only once):**
```json
{
  "id": "3f6a1b2c-...",
  "label": "my-integration",
  "api_key": "cg_live_4a9f3e...",
  "expires_at": "2027-07-14T19:00:00+00:00",
  "message": "Store this key securely — it will NOT be shown again."
}
```

> [!CAUTION]
> The **plaintext API key is returned exactly once**. It is never stored.
> Copy it immediately and store it in a secrets manager (e.g., AWS Secrets Manager,
> HashiCorp Vault, environment variable).

---

## Authentication Methods

CyberGuard AI accepts API keys via **two interchangeable headers**.
You only need to use one.

### Method 1 — X-API-Key header (recommended)

```
X-API-Key: cg_live_4a9f3e...
```

### Method 2 — Authorization Bearer header

```
Authorization: Bearer cg_live_4a9f3e...
```

The server automatically distinguishes API keys (prefix `cg_live_`) from
JWT tokens.

---

## API Key Format

```
cg_live_<64 hex characters>
```

- **Prefix**: `cg_live_` — identifies CyberGuard live keys
- **Entropy**: 32 bytes (256 bits) via `secrets.token_hex(32)` — CSPRNG
- **Storage**: Only the SHA-256 hash is stored in the database
- **Comparison**: Constant-time hash comparison (timing-attack resistant)

---

## Example: Run a Threat Detection

### cURL

```bash
curl -X POST https://cyberguard.example.com/api/v1/agent/analyze \
  -H "X-API-Key: cg_live_4a9f3e..." \
  -H "Content-Type: application/json" \
  -d '{"type": "url", "data": "https://suspicious-domain.com"}'
```

### Python (requests)

```python
import requests

API_KEY = "cg_live_4a9f3e..."
BASE_URL = "https://cyberguard.example.com"

response = requests.post(
    f"{BASE_URL}/api/v1/agent/analyze",
    headers={
        "X-API-Key": API_KEY,
        "Content-Type": "application/json",
    },
    json={
        "type": "url",
        "data": "https://suspicious-domain.com",
    },
    timeout=30,
)
response.raise_for_status()
result = response.json()
print(result["agent_verdict"])
```

### JavaScript (fetch)

```javascript
const API_KEY = "cg_live_4a9f3e...";
const BASE_URL = "https://cyberguard.example.com";

const response = await fetch(`${BASE_URL}/api/v1/agent/analyze`, {
  method: "POST",
  headers: {
    "X-API-Key": API_KEY,
    "Content-Type": "application/json",
  },
  body: JSON.stringify({
    type: "url",
    data: "https://suspicious-domain.com",
  }),
});

if (!response.ok) throw new Error(`HTTP ${response.status}`);
const result = await response.json();
console.log(result.agent_verdict);
```

---

## Example Response

```json
{
  "agent_verdict": {
    "score": 87,
    "label": "MALICIOUS",
    "confidence": 0.91
  },
  "attack_type": "PHISHING",
  "severity": "high",
  "vector_details": [...],
  "entities": ["suspicious-domain.com"],
  "intelligence": {
    "threat_intel": { "found": true, "risk_level": "high" }
  },
  "explanation": { ... },
  "mitre_mappings": ["T1566.002"]
}
```

---

## Key Management API

All management endpoints require JWT authentication (dashboard users).

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api-keys/create` | Generate a new API key |
| `GET` | `/api-keys/` | List all keys (metadata only) |
| `GET` | `/api-keys/{id}/stats` | Usage stats + recent audit logs |
| `DELETE` | `/api-keys/{id}` | Revoke a key |
| `POST` | `/api-keys/{id}/rotate` | Rotate (replace hash, return new key once) |

---

## Rotation

When a key is compromised or its rotation period expires, rotate it:

```bash
curl -X POST https://cyberguard.example.com/api-keys/<KEY_ID>/rotate \
  -H "Authorization: Bearer <YOUR_JWT_TOKEN>"
```

The old key hash is **atomically replaced** with a new one in a single DB
transaction. Usage counters and expiry settings are preserved.

---

## Expiration

Keys can optionally expire. Expired keys return HTTP **401** immediately.

```json
{ "detail": "API key has expired." }
```

To set an expiry, pass `expires_in_days` during creation. Omit the field for
a non-expiring key.

---

## Usage Analytics

Every request increments:
- `usage_count` — total requests made with this key
- `successful_requests` — requests that completed without error
- `failed_requests` — requests that returned 4xx/5xx
- `last_used` — ISO-8601 timestamp of last request
- `last_used_ip` — client IP of last request

View these in the dashboard or via the stats endpoint:

```bash
curl https://cyberguard.example.com/api-keys/<KEY_ID>/stats \
  -H "Authorization: Bearer <YOUR_JWT_TOKEN>"
```

---

## Security Model

| Property | Implementation |
|----------|----------------|
| Entropy | 32 bytes (256-bit) CSPRNG |
| Storage | SHA-256 hash only (never plaintext) |
| Comparison | `hmac.compare_digest` (constant-time) |
| Expiration | Enforced at auth time, UTC-aware |
| Revocation | Soft-delete (`is_active = False`) |
| Workspace isolation | Every key is bound to exactly one workspace |
| Audit trail | `api_key_audit_logs` table (append-only) |
| IP logging | `last_used_ip` + per-request audit log |

---

## Error Responses

| HTTP Status | Reason |
|-------------|--------|
| `401` | Missing key, invalid key, revoked key, or expired key |
| `403` | Key is valid but endpoint requires user (JWT) auth |
| `429` | Rate limit exceeded (workspace RPM exceeded) |
| `402` | Monthly quota exhausted |
