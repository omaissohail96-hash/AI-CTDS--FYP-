# Production Upgrade Summary

## What changed
- Added environment-driven database configuration for SQLite and PostgreSQL.
- Added Alembic scaffolding and an initial migration for core tables.
- Added a threat explanation service that generates structured threat reasoning and MITRE context.
- Added SMTP-backed email notifications with HTML templates.
- Added structured logging, monitoring endpoints, and a monitoring dashboard page.
- Added versioned API routers for /api/v1 and /api/v2.
- Added CI workflow and tests for the upgraded backend.

## How to run
1. Copy .env.example to .env.
2. Set DATABASE_URL to your desired backend.
3. Run `alembic upgrade head`.
4. Start the backend with `uvicorn src.main:app --reload --host 0.0.0.0 --port 8000`.
5. Start the frontend with `cd dashboard && npm run dev`.
