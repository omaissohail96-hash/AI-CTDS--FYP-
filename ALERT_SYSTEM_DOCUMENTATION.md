# CyberGuard AI - Enterprise Alert & Notification System Documentation

## Overview

This release adds a production-ready notification and monitoring layer to the existing alert system, including email delivery, structured logging, and monitoring endpoints while preserving the original alert workflow.

## New Production Features

- SMTP-based notification delivery for critical and high severity alerts
- HTML email templates and branding support
- Structured JSON logging to logs/cyberguard.log
- Monitoring snapshot API at /api/v1/monitoring
- Versioned API support under /api/v1 and /api/v2

The Alert & Notification System is an enterprise-grade real-time threat alerting platform integrated with CyberGuard's multi-vector threat detection engine. It automatically generates, manages, and distributes alerts when security threats are detected.

## Architecture

### System Components

```
┌─────────────────────────────────────────────────────────────┐
│                    Security Agent Orchestrator              │
│           (URL, Email, Network, Web Attack Analysis)        │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│              Risk Scoring Engine                            │
│    (Multi-vector correlation & threat intelligence)        │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│              Alert Service                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ Generation   │  │ Severity     │  │ Correlation  │     │
│  │ (Score>=70)  │  │ Calculation  │  │ Detection    │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ Repeated     │  │ Blacklist    │  │ Escalation   │     │
│  │ Entity Check │  │ Matching     │  │ Logic        │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└────────────────────────┬────────────────────────────────────┘
                         │
        ┌────────────────┼────────────────┐
        │                │                │
        ▼                ▼                ▼
    Database         Notifications    API Endpoints
    (Alerts)         (Email/Webhook)   (REST/WebSocket)
        │                │                │
        └────────────────┼────────────────┘
                         │
                         ▼
                    React Dashboard
                  (Real-time Visualization)
```

### Database Schema

#### Alert Model
```
Alert
├── id (UUID) - Primary key
├── workspace_id (FK) - Multi-tenant isolation
├── scan_history_id (FK) - Linked scan
├── alert_type - Classification (phishing, malware, network_anomaly, sql_injection, xss, etc.)
├── severity - Level (LOW, MEDIUM, HIGH, CRITICAL)
├── title - Alert title
├── description - Detailed description
├── entity - Affected entity (domain, IP, email, URL)
├── entity_type - Type of entity (domain, ip, email, web_payload)
├── source_vector - Detection vector (URL, EMAIL, NETWORK, WEB)
├── risk_score - 0-100 threat score
├── ml_confidence - ML model confidence percentage
├── indicators - JSON array of attack indicators
├── correlated_events - Number of related events
├── recommended_action - Suggested remediation
├── resolved_status - Resolution flag
├── resolved_at - Resolution timestamp
├── resolved_by (FK) - User who resolved
├── resolution_notes - Resolution details
├── notification_sent - Flag for in-dashboard notification
├── email_sent - Flag for email notification
├── webhook_sent - Flag for webhook notification
├── created_at - Alert creation timestamp
├── updated_at - Last update timestamp
├── Indexes: (workspace_id, created_at), (workspace_id, severity), (workspace_id, resolved_status)
```

#### AlertHistory Model
```
AlertHistory
├── id (UUID) - Primary key
├── alert_id (FK) - Related alert
├── workspace_id (FK) - Workspace context
├── user_id (FK) - User performing action
├── action - Event type (created, resolved, escalated)
├── previous_severity - Severity before change
├── new_severity - Severity after change
├── notes - Action notes
├── created_at - Event timestamp
```

### Alert Generation Pipeline

#### 1. **Trigger Conditions**
Alerts are generated when ANY of these conditions are met:

```python
# Condition 1: Risk Score Threshold
if risk_score >= 70:
    generate_alert()

# Condition 2: Blacklist Match
if intelligence_result.hit == True:
    generate_alert()

# Condition 3: Repeated Suspicious Entity (24-hour window)
if entity_occurrences >= 3 in 24_hours:
    escalate_alert()
    generate_alert()

# Condition 4: Network Anomaly Severity
if network_anomaly.severity > 70:
    generate_alert()

# Condition 5: Correlated Indicators
if correlation_engine.detected and rule_count >= 2:
    escalate_severity()
    generate_alert()
```

#### 2. **Severity Calculation**

```
Base Severity:
  0-30    → LOW
  31-60   → MEDIUM
  61-85   → HIGH
  86-100  → CRITICAL

Escalation Factors:
  + Blacklist Match        → Escalate 1 level
  + Correlated Indicators  → Escalate to HIGH (if not CRITICAL)
  + High ML Confidence (>=90%) on HIGH/CRITICAL → Escalate to CRITICAL
  + Repeated Entity (3+ in 24h) → Add +10 to risk score (max +20)
  + Timezone-aware Time Window → Escalate during business hours
```

#### 3. **Duplicate Prevention**

```
cooldown_period = 60 minutes

If alert_exists(
    workspace_id=workspace_id,
    entity=entity,
    alert_type=alert_type,
    created_at > now - 60_minutes,
    resolved_status=False
):
    skip_alert_generation()
else:
    generate_alert()
```

## Alert Severity Levels

| Level    | Score | Color     | Icon | Response Time | Priority |
|----------|-------|-----------|------|----------------|----------|
| LOW      | 0-30  | Green     | ℹ️   | 72 hours      | Low      |
| MEDIUM   | 31-60 | Orange    | ⚡   | 24 hours      | Medium   |
| HIGH     | 61-85 | Orange-R  | ⚠️   | 4 hours       | High     |
| CRITICAL | 86-100| Red       | 🚨   | 1 hour        | Critical |

## API Endpoints

### Alert Retrieval

#### GET `/api/v1/alerts`
**Get paginated alerts with filtering**

```bash
curl -X GET "http://localhost:8000/api/v1/alerts?severity=CRITICAL&resolved=false&limit=50&offset=0" \
  -H "Authorization: Bearer ${TOKEN}"
```

Query Parameters:
- `severity`: Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)
- `resolved`: Filter by status (true/false)
- `limit`: Results per page (1-200, default 50)
- `offset`: Pagination offset (default 0)

Response:
```json
{
  "alerts": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "workspace_id": "550e8400-e29b-41d4-a716-446655440001",
      "alert_type": "phishing",
      "severity": "CRITICAL",
      "title": "🚨 CRITICAL: Phishing Threat Detected",
      "description": "Entity 'secure-login-paypal.com' detected as phishing...",
      "entity": "secure-login-paypal.com",
      "entity_type": "domain",
      "source_vector": "URL",
      "risk_score": 94,
      "ml_confidence": 98,
      "recommended_action": "Block domain immediately...",
      "indicators": [
        {
          "type": "attack_type",
          "value": "PHISHING",
          "source": "ml_detection"
        },
        {
          "type": "threat_type",
          "value": "credential_harvest",
          "source": "threat_intel"
        }
      ],
      "correlated_events": 3,
      "resolved_status": false,
      "notification_sent": true,
      "email_sent": true,
      "created_at": "2025-05-10T14:30:00Z"
    }
  ],
  "total": 127,
  "limit": 50,
  "offset": 0
}
```

#### GET `/api/v1/alerts/recent`
**Get recent alerts from last N hours**

```bash
curl -X GET "http://localhost:8000/api/v1/alerts/recent?hours=24&limit=20" \
  -H "Authorization: Bearer ${TOKEN}"
```

Query Parameters:
- `hours`: Time period (1-168, default 24)
- `limit`: Max results (1-100, default 20)

#### GET `/api/v1/alerts/critical`
**Get all unresolved critical alerts**

```bash
curl -X GET "http://localhost:8000/api/v1/alerts/critical?limit=10" \
  -H "Authorization: Bearer ${TOKEN}"
```

#### GET `/api/v1/alerts/{alert_id}`
**Get detailed alert information**

```bash
curl -X GET "http://localhost:8000/api/v1/alerts/550e8400-e29b-41d4-a716-446655440000" \
  -H "Authorization: Bearer ${TOKEN}"
```

### Alert Management

#### POST `/api/v1/alerts/{alert_id}/resolve`
**Mark alert as resolved**

```bash
curl -X POST "http://localhost:8000/api/v1/alerts/550e8400-e29b-41d4-a716-446655440000/resolve" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "resolution_notes": "Domain already blocked by IT team"
  }'
```

Request Body:
```json
{
  "resolution_notes": "Optional resolution notes"
}
```

#### POST `/api/v1/alerts/{alert_id}/escalate`
**Escalate alert severity**

```bash
curl -X POST "http://localhost:8000/api/v1/alerts/550e8400-e29b-41d4-a716-446655440000/escalate" \
  -H "Authorization: Bearer ${TOKEN}"
```

### Statistics & Analytics

#### GET `/api/v1/alerts/stats`
**Get alert statistics**

```bash
curl -X GET "http://localhost:8000/api/v1/alerts/stats?hours=24" \
  -H "Authorization: Bearer ${TOKEN}"
```

Response:
```json
{
  "total_alerts": 234,
  "resolved_alerts": 189,
  "unresolved_alerts": 45,
  "unresolved_by_severity": {
    "CRITICAL": 3,
    "HIGH": 12,
    "MEDIUM": 18,
    "LOW": 12
  },
  "top_alert_types": [
    {
      "type": "phishing",
      "count": 56
    },
    {
      "type": "network_anomaly",
      "count": 34
    }
  ],
  "top_entities": [
    {
      "entity": "malicious-domain.com",
      "count": 8
    }
  ]
}
```

#### GET `/api/v1/alerts/unresolved-count`
**Get unresolved alert count by severity**

```bash
curl -X GET "http://localhost:8000/api/v1/alerts/unresolved-count" \
  -H "Authorization: Bearer ${TOKEN}"
```

Response:
```json
{
  "total": 45,
  "by_severity": {
    "CRITICAL": 3,
    "HIGH": 12,
    "MEDIUM": 18,
    "LOW": 12
  }
}
```

#### GET `/api/v1/alerts/search`
**Search alerts**

```bash
curl -X GET "http://localhost:8000/api/v1/alerts/search?query=paypal&severity=CRITICAL&limit=20" \
  -H "Authorization: Bearer ${TOKEN}"
```

## React Components

### AlertsPanel
**Full-featured alert management interface**

```jsx
import { AlertsPanel } from '../components';

<AlertsPanel />
```

Features:
- Real-time alert list with auto-refresh
- Filtering by severity and resolution status
- Pagination support
- Statistics dashboard
- Alert detail modal
- Resolution interface

### CriticalAlertsWidget
**Dashboard widget for critical alerts**

```jsx
import { CriticalAlertsWidget } from '../components';

<CriticalAlertsWidget />
```

### AlertTimeline
**Chronological alert visualization**

```jsx
import { AlertTimeline } from '../components';

<AlertTimeline limit={10} />
```

### AlertCard
**Individual alert display**

```jsx
import { AlertCard } from '../components';

<AlertCard 
  alert={alertObject}
  onResolve={handleResolve}
  onSelect={handleSelect}
  onEscalate={handleEscalate}
/>
```

### AlertDetailModal
**Comprehensive alert detail view**

```jsx
import { AlertDetailModal } from '../components';

<AlertDetailModal 
  alert={alertObject}
  onClose={handleClose}
  onResolve={handleResolve}
/>
```

### SeverityBadge
**Severity indicator**

```jsx
import { SeverityBadge } from '../components';

<SeverityBadge severity="CRITICAL" />
```

### AlertToast
**Toast notification**

```jsx
import { AlertToast } from '../components';

<AlertToast 
  alert={alertObject}
  onClose={handleClose}
/>
```

## Frontend Integration

### Dashboard Page Integration

The dashboard now includes:

1. **Alert Widget Grid** (below stats)
   - Critical alerts widget
   - Alert timeline

2. **Sidebar Navigation**
   - New "Alerts" menu item
   - Links to full alerts panel

3. **Alert Bell Icon** (for future navbar integration)
   - Unresolved alert counter
   - Critical alert indicator

### Usage Example

```jsx
// In DashboardPage.jsx
import { CriticalAlertsWidget, AlertTimeline } from '../components';

export default function DashboardPage() {
  return (
    <>
      {/* Stats cards */}
      <div className="stats-grid">...</div>
      
      {/* Alert widgets */}
      <div className="alerts-widget-grid">
        <CriticalAlertsWidget />
        <AlertTimeline limit={8} />
      </div>
      
      {/* Analytics */}
      <div className="analytics-grid">...</div>
    </>
  );
}
```

## Backend Integration

### Alert Generation in Orchestrator

```python
# In SecurityAgent.analyze_payload()
if final_score >= 70 and workspace:
    generated_alert = AlertService.generate_alert(
        db=db,
        workspace_id=workspace.id,
        user_id=None,
        scan_history_id=None,
        scan_result=top_result,
        entity=primary_entity,
        entity_type=entity_type,
        risk_score=int(final_score),
        intelligence_result=intel_result,
        correlation_result=correlation,
    )
```

### Notification Integration

```python
# Send notifications
from src.services.notification_service import NotificationService

await NotificationService.send_notifications(
    db=db,
    alert=alert,
    recipient_emails=['security-team@company.com'],
    webhook_urls=['https://siem.company.com/webhook'],
)
```

## Notification System

### Email Alerts

```python
# Generate professional HTML email
content = NotificationService.prepare_email_content(alert)

# Send to recipients
await NotificationService.send_email_notification(
    recipient_emails=['team@company.com'],
    alert=alert,
)
```

### Webhook Payload

```json
{
  "alert_id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2025-05-10T14:30:00Z",
  "severity": "CRITICAL",
  "alert_type": "phishing",
  "title": "🚨 CRITICAL: Phishing Threat Detected",
  "description": "Entity 'secure-login-paypal.com' detected as phishing...",
  "entity": "secure-login-paypal.com",
  "entity_type": "domain",
  "source_vector": "URL",
  "risk_score": 94,
  "ml_confidence": 98,
  "recommended_action": "Block domain immediately at firewall and email gateway",
  "indicators": [
    {
      "type": "attack_type",
      "value": "PHISHING",
      "source": "ml_detection"
    }
  ],
  "correlated_events": 3,
  "workspace_id": "550e8400-e29b-41d4-a716-446655440001"
}
```

## Configuration

### Environment Variables

```bash
# Email Configuration
ALERT_EMAIL_ENABLED=false  # Enable email notifications
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=alerts@cyberguard.ai
SMTP_PASSWORD=your-password

# Webhook Configuration
ALERT_WEBHOOK_TIMEOUT=5

# Alert Thresholds
ALERT_RISK_SCORE_THRESHOLD=70
ALERT_COOLDOWN_MINUTES=60
ALERT_REPEATED_ENTITY_WINDOW_HOURS=24
ALERT_NETWORK_ANOMALY_THRESHOLD=70
```

### Database Initialization

```bash
# Create alert tables
python -c "from src.core.database import initialize_database; initialize_database()"

# Or manually run migrations
# The SQLAlchemy models handle table creation automatically
```

## Audit Logging

All alert operations are logged to `audit_logs` table:

```json
{
  "workspace_id": "550e8400-e29b-41d4-a716-446655440001",
  "user_id": "550e8400-e29b-41d4-a716-446655440002",
  "action": "alert_generated",
  "module": "alert_service",
  "status": "success",
  "event_metadata": {
    "alert_id": "550e8400-e29b-41d4-a716-446655440000",
    "severity": "CRITICAL",
    "risk_score": 94,
    "entity": "secure-login-paypal.com",
    "alert_type": "phishing",
    "has_blacklist_match": true,
    "has_correlation": true
  },
  "created_at": "2025-05-10T14:30:00Z"
}
```

## Performance & Scalability

### Indexing Strategy
- `(workspace_id, created_at)` - For recent alert queries
- `(workspace_id, severity)` - For severity filtering
- `(workspace_id, resolved_status)` - For status queries
- `(entity, workspace_id)` - For entity deduplication

### Query Optimization
```python
# Use indexed queries
alerts = db.query(Alert).filter(
    and_(
        Alert.workspace_id == workspace_id,
        Alert.created_at > cutoff_time,  # Indexed
        Alert.severity == 'CRITICAL',     # Indexed
    )
).limit(50)
```

### Batch Operations
```python
# For bulk alert operations
db.bulk_insert_mappings(Alert, alert_list)
db.bulk_update_mappings(Alert, updates)
```

## Testing

### Sample Alert Scenarios

```python
from src.services.notification_service import EmailAlertSimulator

# Generate test alert emails
email = EmailAlertSimulator.generate_sample_alert_email("phishing")
print(email)  # Email content for testing
```

### Test Endpoints

```bash
# Create test alert
curl -X POST http://localhost:8000/api/v1/agent/analyze \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "url",
    "data": "http://evil-phishing.com/login"
  }'

# View generated alert
curl -X GET http://localhost:8000/api/v1/alerts/recent?hours=1 \
  -H "Authorization: Bearer ${TOKEN}"

# Resolve alert
curl -X POST http://localhost:8000/api/v1/alerts/{alert_id}/resolve \
  -H "Authorization: Bearer ${TOKEN}" \
  -d '{"resolution_notes": "Test resolution"}'
```

## Best Practices

1. **Alert Thresholds**: Don't lower risk_score threshold below 70 to avoid alert fatigue
2. **Cooldown Period**: Maintain 60+ minute cooldown for duplicate prevention
3. **Escalation**: Review and adjust escalation multipliers based on your threat model
4. **Retention**: Archive resolved alerts older than 90 days
5. **Notifications**: Use webhook URLs for SIEM integration, emails for admin alerts
6. **Resolution**: Always add resolution notes for compliance tracking

## Troubleshooting

### Alerts Not Generating
1. Check risk_score calculation in scoring engine
2. Verify workspace_id is set in context
3. Review duplicate alert cooldown window
4. Check alert service logs for errors

### Missing Indicators
1. Verify correlation engine is enabled
2. Check threat intelligence database
3. Review scan_result structure from detection services

### Performance Issues
1. Check database indexes on `workspace_id` and `created_at`
2. Implement alert archival for old alerts
3. Use pagination for large result sets
4. Monitor query execution times

## Support & Roadmap

### Planned Enhancements
- [ ] Alert suppression rules
- [ ] Scheduled alert digest emails
- [ ] Slack integration
- [ ] PagerDuty integration
- [ ] Custom alert templates
- [ ] Alert correlation groups
- [ ] Machine learning for false positive reduction

### Current Version
- Version: 1.0.0
- Released: May 2025
- Status: Production-Ready
