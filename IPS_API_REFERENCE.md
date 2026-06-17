# Intrusion Prevention System: API Reference & Integration Guide

## Quick Start: Integrating Prevention into Your Workflow

### Step 1: Understanding the Workflow

```
Detection → Risk Scoring → Alert Generation → Prevention Evaluation → Entity Blocking
    ↓            ↓              ↓                      ↓                  ↓
  Models     ScoringEngine   AlertService      PreventionEngine    Middleware
```

### Step 2: Enable Prevention (Automatic)

Prevention is **automatically enabled** when your application starts:

1. Application initializes (`src/main.py`)
2. PreventionMiddleware is registered
3. PreventionScheduler starts background cleanup task
4. Ready to block entities

### Step 3: Check If Your System Is Protected

```bash
# Verify IPS is running
curl -X GET http://localhost:8000/api/v1/prevention/stats \
  -H "X-API-KEY: your_api_key"

# Should return statistics with active_blocks_count
```

## Detailed API Reference

### 1. List Blocked Entities

**Endpoint:** `GET /api/v1/prevention/blocked`

**Query Parameters:**
- `skip` (int, default: 0) - Offset for pagination
- `limit` (int, default: 50, max: 500) - Number of results
- `active_only` (bool, default: true) - Only show non-expired blocks
- `entity_type` (string, optional) - Filter: `IP`, `URL`, or `DOMAIN`
- `severity` (string, optional) - Filter: `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`

**Request:**
```bash
curl -X GET "http://localhost:8000/api/v1/prevention/blocked?skip=0&limit=50&severity=CRITICAL" \
  -H "X-API-KEY: your_api_key"
```

**Response (200 OK):**
```json
{
  "total": 150,
  "skip": 0,
  "limit": 50,
  "items": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "entity": "192.168.1.100",
      "entity_type": "IP",
      "severity": "CRITICAL",
      "reason": "High risk score (>= 90)",
      "blocked_until": "2026-05-18T14:30:00Z",
      "auto_generated": true,
      "resolved_status": false,
      "prevention_reason": "This IP was detected with high malicious confidence",
      "blocked_request_count": 127,
      "created_at": "2026-05-11T14:30:00Z"
    },
    {
      "id": "660e8400-e29b-41d4-a716-446655440001",
      "entity": "malicious.com",
      "entity_type": "DOMAIN",
      "severity": "HIGH",
      "reason": "Known malicious entity detected",
      "blocked_until": "2026-05-12T14:30:00Z",
      "auto_generated": true,
      "resolved_status": false,
      "prevention_reason": "ThreatIntel match for known phishing domain",
      "blocked_request_count": 34,
      "created_at": "2026-05-11T13:45:00Z"
    }
  ]
}
```

**Error (401 Unauthorized):**
```json
{
  "detail": "Not authenticated"
}
```

### 2. Get Prevention Statistics

**Endpoint:** `GET /api/v1/prevention/stats`

**Request:**
```bash
curl -X GET http://localhost:8000/api/v1/prevention/stats \
  -H "X-API-KEY: your_api_key"
```

**Response (200 OK):**
```json
{
  "active_blocks_count": 42,
  "total_blocked_requests_24h": 3847,
  "blocks_by_severity": {
    "LOW": 5,
    "MEDIUM": 8,
    "HIGH": 20,
    "CRITICAL": 9
  },
  "blocks_by_entity_type": {
    "IP": 28,
    "URL": 10,
    "DOMAIN": 4
  },
  "auto_generated_blocks": 38,
  "manual_blocks": 4,
  "auto_unblock_scheduled": 42
}
```

**Use Case:** Display on SOC dashboard for real-time monitoring

### 3. Unblock Entity (Manual Override)

**Endpoint:** `POST /api/v1/prevention/unblock/{blocked_entity_id}`

**Parameters:**
- `blocked_entity_id` (path, required) - UUID of the blocked entity

**Request Body:**
```json
{
  "reason": "False positive - this is a trusted partner IP"
}
```

**Full Request:**
```bash
curl -X POST http://localhost:8000/api/v1/prevention/unblock/550e8400-e29b-41d4-a716-446655440000 \
  -H "X-API-KEY: your_api_key" \
  -H "Content-Type: application/json" \
  -d '{
    "reason": "Whitelisted organization"
  }'
```

**Response (200 OK):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "entity": "192.168.1.100",
  "entity_type": "IP",
  "severity": "CRITICAL",
  "reason": "High risk score (>= 90)",
  "blocked_until": "2026-05-18T14:30:00Z",
  "auto_generated": true,
  "resolved_status": true,
  "prevention_reason": "...",
  "blocked_request_count": 127,
  "created_at": "2026-05-11T14:30:00Z"
}
```

**Errors:**
- 403 Forbidden - User lacks permission (requires admin/developer role)
- 404 Not Found - Entity not found
- 400 Bad Request - Invalid entity ID format

### 4. Get Prevention Reasoning

**Endpoint:** `GET /api/v1/prevention/reasoning/{blocked_entity_id}`

**Request:**
```bash
curl -X GET http://localhost:8000/api/v1/prevention/reasoning/550e8400-e29b-41d4-a716-446655440000 \
  -H "X-API-KEY: your_api_key"
```

**Response (200 OK):**
```json
{
  "blocked_entity_id": "550e8400-e29b-41d4-a716-446655440000",
  "reasoning": "\nThis IP (192.168.1.100) was automatically blocked because:\n\n1. **Reason**: High risk score (>= 90)\n2. **Severity Level**: CRITICAL\n3. **Prevention Policy**: Automatic response to critical threats\n\nBlock Duration:\n- Created: 2026-05-11 14:30:00 UTC\n- Expires: 2026-05-18 14:30:00 UTC\n\nStatistics:\n- Blocked Requests: 127\n- Auto-Generated: Yes\n\nRelated Investigation:\n- Alert ID: alert-uuid\n- Scan ID: scan-uuid\n\nThis entity poses a significant threat and has been automatically quarantined\nuntil the configured prevention duration expires or manual intervention occurs."
}
```

### 5. Get Prevention History

**Endpoint:** `GET /api/v1/prevention/history`

**Query Parameters:**
- `skip` (int, default: 0) - Offset for pagination
- `limit` (int, default: 50, max: 500) - Number of results
- `hours` (int, default: 24, max: 720) - Look back period in hours

**Request:**
```bash
curl -X GET "http://localhost:8000/api/v1/prevention/history?hours=48&skip=0&limit=50" \
  -H "X-API-KEY: your_api_key"
```

**Response (200 OK):**
```json
{
  "total": 237,
  "skip": 0,
  "limit": 50,
  "items": [
    {
      "id": "uuid-1",
      "entity": "evil.phishing.com",
      "entity_type": "DOMAIN",
      "severity": "CRITICAL",
      "reason": "Known malicious entity detected",
      "blocked_until": "2026-05-18T15:22:00Z",
      "blocked_request_count": 89,
      "created_at": "2026-05-11T15:22:00Z"
    },
    {
      "id": "uuid-2",
      "entity": "10.0.0.50",
      "entity_type": "IP",
      "severity": "HIGH",
      "reason": "Multiple attacks from same entity within time window",
      "blocked_until": "2026-05-12T08:15:00Z",
      "blocked_request_count": 45,
      "created_at": "2026-05-11T08:15:00Z"
    }
  ]
}
```

### 6. Trigger Cleanup (Admin Only)

**Endpoint:** `POST /api/v1/prevention/cleanup`

**Request:**
```bash
curl -X POST http://localhost:8000/api/v1/prevention/cleanup \
  -H "X-API-KEY: your_api_key"
```

**Response (200 OK):**
```json
{
  "status": "success",
  "expired_blocks_cleaned": 15
}
```

**Note:** Cleanup runs automatically every 5 minutes. Manual trigger is optional.

## Integration Scenarios

### Scenario 1: SOC Dashboard Display

Build a real-time SOC dashboard showing prevention metrics:

```python
import requests

API_KEY = "your_api_key"
BASE_URL = "http://localhost:8000/api/v1/prevention"

# Get current statistics
response = requests.get(
    f"{BASE_URL}/stats",
    headers={"X-API-KEY": API_KEY}
)

stats = response.json()

print(f"🚨 Active Blocks: {stats['active_blocks_count']}")
print(f"⛔ Blocked Today: {stats['total_blocked_requests_24h']}")
print(f"🔴 Critical Blocks: {stats['blocks_by_severity']['CRITICAL']}")

# Alert if threshold exceeded
if stats['active_blocks_count'] > 100:
    print("⚠️  WARNING: Block count exceeding threshold")
```

### Scenario 2: Automated False Positive Detection

```python
# Monitor unblock requests
import requests

BASE_URL = "http://localhost:8000/api/v1/prevention"

# Get recent history
history_response = requests.get(
    f"{BASE_URL}/history?hours=1&limit=100",
    headers={"X-API-KEY": API_KEY}
)

# Analyze for patterns
blocks = history_response.json()['items']

# If same entity blocked/unblocked frequently, it's likely a FP
entity_counts = {}
for block in blocks:
    entity = block['entity']
    entity_counts[entity] = entity_counts.get(entity, 0) + 1

fp_candidates = [e for e, count in entity_counts.items() if count > 3]
print(f"Suspected false positives: {fp_candidates}")
```

### Scenario 3: Integration with External SIEM

```bash
#!/bin/bash

# Send prevention data to Splunk every 5 minutes
while true; do
  curl -X GET "http://localhost:8000/api/v1/prevention/stats" \
    -H "X-API-KEY: your_api_key" | \
  curl -X POST "https://splunk.company.com/services/collector" \
    -H "Authorization: Splunk your_splunk_token" \
    -d @-

  sleep 300
done
```

### Scenario 4: Custom Whitelist Management

```python
# Maintain whitelist of trusted entities
WHITELIST = {
    "office.company.com": "Corporate office",
    "192.168.1.1": "Gateway router",
    "api.partner.com": "Partner API"
}

# Check before blocking
def should_block(entity):
    if entity in WHITELIST:
        print(f"⚪ Skipping whitelist entry: {entity}")
        return False
    return True
```

## Error Codes & Handling

| Code | Error | Meaning | Action |
|------|-------|---------|--------|
| 200 | Success | Request completed successfully | Continue |
| 400 | Bad Request | Invalid parameters or UUID format | Check parameters |
| 401 | Unauthorized | Missing or invalid API key | Provide valid API key |
| 403 | Forbidden | User lacks required permissions | Use admin account |
| 404 | Not Found | Entity not found | Check entity ID exists |
| 500 | Server Error | Backend error | Check server logs |

## Rate Limiting

Prevention API endpoints are subject to workspace rate limits:
- Default: 10 requests per minute per API key
- Configurable in workspace settings
- Implement exponential backoff for retries

## Pagination Guidelines

For large result sets, use pagination:

```python
# Fetch all blocked entities in chunks
skip = 0
limit = 50
all_entities = []

while True:
    response = requests.get(
        f"{BASE_URL}/blocked?skip={skip}&limit={limit}",
        headers={"X-API-KEY": API_KEY}
    )
    
    data = response.json()
    all_entities.extend(data['items'])
    
    if len(all_entities) >= data['total']:
        break
    
    skip += limit

print(f"Total blocked entities: {len(all_entities)}")
```

## Best Practices

1. **Always provide error handling**
   ```python
   try:
       response = requests.get(...)
       response.raise_for_status()
   except requests.exceptions.RequestException as e:
       logger.error(f"API error: {e}")
   ```

2. **Implement retry logic**
   ```python
   from requests.adapters import HTTPAdapter
   from urllib3.util.retry import Retry
   
   session = requests.Session()
   retry = Retry(total=3, backoff_factor=0.5)
   adapter = HTTPAdapter(max_retries=retry)
   session.mount('http://', adapter)
   ```

3. **Cache statistics for performance**
   ```python
   from functools import lru_cache
   from time import time
   
   @lru_cache(maxsize=1)
   def get_cached_stats():
       return requests.get(...).json()
   ```

4. **Log all prevention actions**
   ```python
   logger.info(f"Unblocked entity: {entity_id}, reason: {reason}")
   ```

## Webhook Integration (Future)

Configure webhooks to receive real-time prevention alerts:

```json
{
  "webhook_url": "https://your-soc.com/webhooks/prevention",
  "events": ["entity_blocked", "entity_unblocked"],
  "retry_policy": "exponential"
}
```

---

For more information, see [IPS_SYSTEM_DOCUMENTATION.md](IPS_SYSTEM_DOCUMENTATION.md)
