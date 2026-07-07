# CyberGuard AI — Enterprise Upgrade Guide (v2.2.0)

## Overview
This document covers operations for the new enterprise stack, including Redis, Celery, and the False Positive framework.

## Infrastructure Additions
The `docker-compose.yml` has been updated with:
1. **Redis**: Cache layer and task broker
2. **Celery Worker**: Background task execution (`high_priority`, `default`, `low_priority`)
3. **Celery Beat**: Scheduled tasks (Threat Intel sync, cache warming)
4. **Flower**: Task monitoring UI (Port `5555`)

## Zero-Config Local Development
If you don't want to run Redis or Celery during local development, the system is designed to **degrade gracefully**:
- `REDIS_ENABLED=False`: All cache lookups hit the database directly.
- `CELERY_ENABLED=False`: All background tasks run synchronously in the request thread.

## Database Migrations
We have added a custom idempotent migration script to upgrade the database schema without data loss:
```bash
python migrations/001_enterprise_upgrade.py upgrade
```

## Security & Auth
- **JWT Cookies**: Browsers now receive HttpOnly cookies for `access_token` and `refresh_token`. LocalStorage is no longer used for session persistence.
- **API Keys**: Scripts/Postman can still use the `Authorization: Bearer <token>` or `X-API-Key: <key>` headers.
- **Trusted Proxies**: Configure `TRUSTED_PROXIES` in your `.env` (comma-separated IPs) to prevent IP spoofing via `X-Forwarded-For`.

## False Positive Framework
Entities are no longer auto-blocked on a single ML signal.
- If an entity reaches a high risk score but lacks a secondary corroborating signal, it goes into the **Human Review Queue**.
- Admins can override false positives via `/api/v1/fp/reports/{id}/approve`, which removes active blocks.
