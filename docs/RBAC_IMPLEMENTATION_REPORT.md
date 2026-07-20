# Workspace RBAC Implementation Report

## Architecture

CyberGuard now authorizes dashboard users through an authoritative `WorkspaceUser` membership record. The policy is centralized in `src/core/rbac.py`; legacy `users.role` values are normalized during authorization to preserve existing JWT, Google/Supabase, API-key, and older database compatibility.

## Roles and Policy

| Role | Access summary |
| --- | --- |
| Owner | Full workspace control, ownership transfer, API keys, configuration, auditing, and member administration. |
| Admin | Member administration for Analyst/Operator/Viewer, API keys, IDS/IPS, alerts, hunting, reports, and audit logs. |
| Analyst | Scans, investigations, alert resolution, UBA, MITRE, explainability, report export, and audit read access. |
| Operator | Scans, dashboards, alerts, alert acknowledgement, reports, and scan-history reads. |
| Viewer | Read-only dashboards, reports, analytics, threat summaries, and scan history. |

The full machine-readable permission matrix is exposed at `GET /api/v1/workspace/permissions`.

## API Endpoints

| Method | Path | Authorization |
| --- | --- | --- |
| GET | `/api/v1/workspace/members` | `workspace:members:read` |
| POST | `/api/v1/workspace/invite` | `workspace:members:manage` |
| PATCH | `/api/v1/workspace/member/{id}/role` | `workspace:members:manage` |
| DELETE | `/api/v1/workspace/member/{id}` | `workspace:members:manage` |
| POST | `/api/v1/workspace/transfer-ownership` | Owner only |
| GET | `/api/v1/workspace/roles` | Authenticated workspace user |
| GET | `/api/v1/workspace/permissions` | Authenticated workspace user |

Example invitation:

```http
POST /api/v1/workspace/invite
Authorization: Bearer <access-token>
Content-Type: application/json

{"email":"analyst@example.com","role":"analyst"}
```

```json
{"id":"membership-id","email":"analyst@example.com","role":"analyst","status":"active"}
```

## Security Controls

- Workspace creator becomes the initial Owner for password and Google registration.
- Existing users are backfilled into `workspace_users` on startup without losing legacy access.
- Only Owners can transfer ownership or manage Admin memberships.
- Admins can assign and remove only Analyst, Operator, and Viewer roles.
- Users cannot change their own role, remove themselves, remove an Owner, or assign Owner through normal role edits.
- All member invitation, role-change, removal, ownership-transfer, and permission-denial events are written to the audit log.
- API keys retain their existing scan-only authentication path and cannot call user membership APIs.

## Database Migration

`alembic/versions/003_workspace_rbac.py` adds `workspace_users` with unique `(workspace_id, user_id)` membership and a workspace/role index. `initialize_database()` also creates and backfills the table for non-Alembic deployments.

## Frontend

The **Workspace Members** sidebar page provides a member table, role dropdowns, invitation form, removal confirmation, status, and joined date. Controls are hidden unless the current user has `workspace:members:manage`; the active role appears in the header.

## Verification

`pytest -q tests/test_workspace_rbac.py` passes: invitation/listing, admin privilege-escalation prevention, self/owner protection, and ownership transfer.
