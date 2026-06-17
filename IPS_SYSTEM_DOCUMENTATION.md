# CyberGuard AI: Intrusion Prevention System (IPS) Documentation

## Overview

CyberGuard AI now includes an **enterprise-grade Intrusion Prevention System (IPS)** that automatically responds to detected threats in real-time. The system transforms the platform from a passive Intrusion Detection System (IDS) into an active, automated threat response platform capable of blocking malicious entities before they cause damage.

## Architecture

### Core Components

#### 1. **PreventionEngine Service** (`src/services/prevention_engine.py`)
The heart of the IPS system. Handles:
- Automatic threat evaluation based on configurable rules
- Entity blocking with expiration policies
- Prevention statistics and analytics
- Intelligent reasoning generation for blocked entities

#### 2. **BlockedEntity Database Model** (`src/models/models.py`)
Stores all blocked entities with:
- Entity information (IP, URL, Domain)
- Severity levels (LOW, MEDIUM, HIGH, CRITICAL)
- Block duration with automatic expiration
- Prevention reason and detailed reasoning
- Blocked request counter for analytics

#### 3. **Prevention API Endpoints** (`src/api/v1/prevention.py`)
RESTful endpoints for IPS management:
- GET `/prevention/blocked` - List blocked entities
- GET `/prevention/stats` - Prevention statistics
- POST `/prevention/unblock/{id}` - Manual unblock
- GET `/prevention/history` - Prevention action history
- GET `/prevention/reasoning/{id}` - Detailed blocking reason

#### 4. **Prevention Middleware** (`src/api/middleware.py`)
Middleware layer that:
- Intercepts incoming requests before application logic
- Extracts client IP (considering proxy headers)
- Checks against blocked entities
- Returns 403 Forbidden for blocked entities
- Increments blocked request counter

#### 5. **Prevention Scheduler** (`src/utils/prevention_scheduler.py`)
Background task scheduler that:
- Runs cleanup task every 5 minutes
- Automatically expires old blocks
- Maintains database hygiene

#### 6. **Threat Prevention Center** (React Dashboard)
User interface for:
- Viewing active blocked entities
- Real-time prevention statistics
- Prevention action timeline
- Manual unblock capabilities
- Intelligent prevention reasoning

## Prevention Rules & Thresholds

### Automatic Blocking Rules

1. **High Risk Score Rule**
   - Trigger: `risk_score >= 90`
   - Duration: 7 days (CRITICAL)
   - Applies to: All entity types

2. **Repeated Attacks Rule**
   - Trigger: ≥ 3 attacks within 1 hour
   - Duration: 24 hours (HIGH)
   - Applies to: IP addresses and domains

3. **Known Malicious Entity Rule**
   - Trigger: Entity matches ThreatIntel blacklist
   - Duration: 7 days (CRITICAL)
   - Applies to: All entity types

4. **Critical Network Anomaly Rule**
   - Trigger: Severity = CRITICAL
   - Duration: 24 hours (HIGH)
   - Applies to: Network traffic

5. **Phishing Detection Rule**
   - Trigger: Entity type = URL AND risk_score >= 70
   - Duration: 24 hours (HIGH)
   - Applies to: URLs only

### Prevention Duration Policies

| Severity | Duration |
|----------|----------|
| MEDIUM   | 1 hour   |
| HIGH     | 24 hours |
| CRITICAL | 7 days   |

### Configurable Thresholds

```python
PreventionEngine.RISK_SCORE_AUTO_BLOCK = 90          # Auto-block threshold
PreventionEngine.REPEATED_ATTACK_THRESHOLD = 3       # Num attacks before ban
PreventionEngine.REPEATED_ATTACK_WINDOW = 3600       # Time window (seconds)
```

## Integration Points

### 1. SecurityAgent Orchestrator
When a threat is analyzed:
1. Detection models generate risk score
2. Alert is created (if risk_score >= 70)
3. PreventionEngine.evaluate_threat() is called
4. If prevention is triggered, entity is blocked
5. Response includes prevention action status

### 2. Alert System
Every prevention action:
- Generates an alert entry
- Links to related scan/alert
- Triggers notifications
- Updates dashboard in real-time

### 3. Threat Intelligence Pipeline
- Blocks are cross-referenced with ThreatIntel
- Intelligence hits auto-escalate severity
- Known malicious entities get maximum duration blocks

### 4. Correlation Engine
- Patterns across multiple vectors trigger prevention
- Cross-vector correlations inform severity levels
- Repeated entity detections escalate responses

## API Endpoints Reference

### Get Blocked Entities
```bash
GET /api/v1/prevention/blocked?skip=0&limit=50&active_only=true&entity_type=IP&severity=CRITICAL
```

**Response:**
```json
{
  "total": 150,
  "skip": 0,
  "limit": 50,
  "items": [
    {
      "id": "uuid",
      "entity": "192.168.1.100",
      "entity_type": "IP",
      "severity": "CRITICAL",
      "reason": "High risk score (>= 90)",
      "blocked_until": "2026-05-18T10:30:00",
      "auto_generated": true,
      "resolved_status": false,
      "prevention_reason": "...",
      "blocked_request_count": 45,
      "created_at": "2026-05-11T10:30:00"
    }
  ]
}
```

### Get Prevention Statistics
```bash
GET /api/v1/prevention/stats
```

**Response:**
```json
{
  "active_blocks_count": 42,
  "total_blocked_requests_24h": 1023,
  "blocks_by_severity": {
    "LOW": 5,
    "MEDIUM": 8,
    "HIGH": 20,
    "CRITICAL": 9
  },
  "blocks_by_entity_type": {
    "IP": 25,
    "URL": 12,
    "DOMAIN": 5
  },
  "auto_generated_blocks": 38,
  "manual_blocks": 4,
  "auto_unblock_scheduled": 42
}
```

### Unblock Entity
```bash
POST /api/v1/prevention/unblock/{blocked_entity_id}
Content-Type: application/json

{
  "reason": "False positive - entity is trusted"
}
```

### Get Prevention Reasoning
```bash
GET /api/v1/prevention/reasoning/{blocked_entity_id}
```

**Response:**
```json
{
  "blocked_entity_id": "uuid",
  "reasoning": "This IP (192.168.1.100) was automatically blocked because:\n\n1. **Reason**: High risk score (>= 90)\n2. **Severity Level**: CRITICAL\n3. **Prevention Policy**: Entity was detected as highly malicious..."
}
```

### Get Prevention History
```bash
GET /api/v1/prevention/history?hours=24&skip=0&limit=50
```

## Request Blocking Flow

```
Incoming Request
    ↓
PreventionMiddleware (Intercepts)
    ↓
Extract Client IP (with proxy headers)
    ↓
Query BlockedEntity table
    ↓
Is entity blocked AND not expired? 
    ├─ YES → Return 403 Forbidden + Increment counter
    └─ NO → Continue to next middleware
    ↓
AuditMiddleware (Log request)
    ↓
Application Logic
```

## Response Example (Blocked Request)

```json
{
  "status": "blocked",
  "reason": "Your IP address has been blocked due to suspicious activity",
  "entity": "192.168.1.100",
  "blocked_until": "2026-05-18T10:30:00"
}
```

HTTP Status: **403 Forbidden**

## Automatic Cleanup & Expiration

The Prevention Scheduler runs every 5 minutes to:

1. Query for expired blocks (`blocked_until < now`)
2. Mark them as `resolved_status = True`
3. Set `unblocked_at` timestamp
4. Log cleanup action

**Example:**
```python
# Runs in background
cleaned_count = PreventionEngine.cleanup_expired_blocks(db)
# Returns: 15 (15 entities were auto-unblocked)
```

## Dashboard: Threat Prevention Center

### Features

#### Real-Time Statistics
- Active block count
- Blocked requests (24h)
- Auto-generated vs manual blocks
- Distribution by severity and type

#### Blocked Entities Table
- Entity display with type indicators
- Severity color-coding
- Blocked request counter
- Expiration timestamp
- Quick action buttons

#### Prevention Timeline
- Chronological view of recent blocks
- Entity and reason display
- Timestamp information

#### Detailed Views
- Entity details modal with full information
- Prevention reasoning modal with intelligent explanation
- Manual unblock capability

#### Filtering & Search
- Search by entity name/IP/URL
- Filter by entity type (IP, URL, DOMAIN)
- Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)

## Usage Examples

### Detecting & Blocking a Malicious IP

```python
# 1. Scan incoming network traffic
result = DetectionService.analyze_network(flow_data)
# Returns: { "confidence": 95, "verdict": "malicious", "severity": "CRITICAL", ... }

# 2. Orchestrator calculates risk score
final_score = 95  # High risk score

# 3. PreventionEngine evaluates threat
should_block, blocked_entity = PreventionEngine.evaluate_threat(
    db=db,
    workspace_id=workspace_id,
    entity="192.168.1.100",
    entity_type="IP",
    risk_score=95,
    threat_context={"severity": "CRITICAL", "intelligence_hit": True}
)
# Returns: (True, BlockedEntity)

# 4. Entity is automatically blocked for 7 days
# 5. Dashboard shows new block in real-time
# 6. Any request from that IP gets 403 Forbidden
```

### Manual Unblocking

```python
# User clicks "Unblock" in dashboard
POST /api/v1/prevention/unblock/entity-uuid
{
  "reason": "Whitelisted organization"
}

# Result:
# - Entity marked as resolved
# - Unblocked timestamp recorded
# - Unblocked_by user ID logged
# - Audit log entry created
```

### Configuring Custom Thresholds

```python
# In PreventionEngine class, modify these values:

PreventionEngine.RISK_SCORE_AUTO_BLOCK = 85  # Lower threshold
PreventionEngine.REPEATED_ATTACK_THRESHOLD = 2  # More aggressive
PreventionEngine.REPEATED_ATTACK_WINDOW = 1800  # 30 minutes

# Rebuild and restart application
```

## Monitoring & Analytics

### Key Metrics to Monitor

1. **Active Blocks Count** - Current number of blocked entities
2. **Blocked Requests (24h)** - Traffic volume from blocked IPs
3. **Auto-Generation Rate** - Percentage of automatic vs manual blocks
4. **Average Block Duration** - How long entities stay blocked
5. **Unblock Rate** - Percentage requiring manual intervention

### Example Analytics Query

```python
stats = PreventionEngine.get_prevention_stats(db, workspace_id)

print(f"Active blocks: {stats['active_blocks_count']}")
print(f"Critical blocks: {stats['blocks_by_severity']['CRITICAL']}")
print(f"Requests blocked today: {stats['total_blocked_requests_24h']}")
```

## Security Best Practices

1. **False Positive Management**
   - Review unblocking logs regularly
   - Monitor manual unblock patterns
   - Adjust thresholds if needed

2. **Audit Trail**
   - All prevention actions are logged
   - Track who unblocked entities
   - Maintain compliance records

3. **Whitelist Management**
   - Maintain list of trusted entities
   - Override automatic blocks for partners/integrations
   - Document whitelist decisions

4. **Performance Optimization**
   - Cleanup runs every 5 minutes (non-blocking)
   - Middleware caching can be added for high-traffic
   - Consider load balancing for scalability

5. **Multi-Tenant Isolation**
   - Blocks are workspace-isolated
   - Each tenant has independent blocklists
   - No cross-tenant interference

## Troubleshooting

### Issue: Legitimate traffic being blocked

**Solution:**
1. Check blocking reason in detail modal
2. Review entity in Prevention Center
3. Click "Unblock Entity" button
4. Add to whitelist if needed
5. Monitor for false positives

### Issue: Performance degradation

**Solution:**
1. Check database size of BlockedEntity table
2. Verify cleanup task is running
3. Consider archiving old blocks
4. Add index on entity + workspace_id

### Issue: Blocks not expiring

**Solution:**
1. Verify scheduler is running (`app.on_event("startup")`)
2. Check if cleanup task is active
3. Manually trigger: `POST /api/v1/prevention/cleanup`
4. Review error logs

## Future Enhancements

1. **Machine Learning Integration**
   - ML model to predict false positives
   - Adaptive threshold tuning
   - Behavioral analysis

2. **Advanced Blocking Strategies**
   - Rate limiting for blocked entities
   - Graduated response escalation
   - Honeypot detection

3. **Integration Capabilities**
   - SIEM system integration (splunk, elastic)
   - Threat feed integration
   - Third-party block list subscriptions

4. **Advanced Analytics**
   - Predictive blocking suggestions
   - Anomaly detection dashboards
   - Threat pattern analysis

## References

- [PreventionEngine Service](src/services/prevention_engine.py)
- [Prevention API](src/api/v1/prevention.py)
- [Prevention Middleware](src/api/middleware.py)
- [Prevention Scheduler](src/utils/prevention_scheduler.py)
- [Dashboard Component](dashboard/src/pages/PreventionCenter.jsx)
