# Intrusion Prevention System: Deployment & Configuration Guide

## Pre-Deployment Checklist

- [ ] Python 3.11+ installed
- [ ] Node.js 18+ installed
- [ ] PostgreSQL or SQLite configured
- [ ] All Python packages installed (`pip install -r requirements.txt`)
- [ ] All frontend packages installed (`cd dashboard && npm install`)
- [ ] Database migrations executed
- [ ] Environment variables configured
- [ ] API keys generated
- [ ] SSL/TLS certificates ready (for production)

## Deployment Steps

### Step 1: Database Initialization

```bash
# Backend: Initialize database with BlockedEntity table
cd /path/to/Final_Year_Project

# Option A: SQLite (Development)
python src/main.py
# Database will auto-initialize on first run

# Option B: PostgreSQL (Production)
export DATABASE_URL="postgresql://user:password@localhost/cyberguard"
python src/main.py
```

### Step 2: Start Backend Server

```bash
# Development with hot-reload
uvicorn src.main:app --reload --host 0.0.0.0 --port 8000

# Production with Gunicorn
gunicorn src.main:app -w 4 -b 0.0.0.0:8000 --worker-class uvicorn.workers.UvicornWorker
```

### Step 3: Start Frontend

```bash
cd dashboard

# Development
npm run dev
# Access at http://localhost:5173

# Production
npm run build
npm run preview
# Or deploy dist/ folder to web server (Nginx, Apache, etc.)
```

### Step 4: Verify IPS is Active

```bash
# Check backend health
curl http://localhost:8000/

# Verify IPS middleware is loaded
curl http://localhost:8000/api/v1/prevention/stats \
  -H "X-API-KEY: your_api_key"

# Should return prevention statistics
```

## Configuration

### Backend Configuration

Edit `src/core/config.py`:

```python
class Settings:
    PROJECT_NAME = "CyberGuard AI"
    API_V1_STR = "/api/v1"
    
    # Database
    DATABASE_URL = "sqlite:///./cyberguard.db"  # or PostgreSQL
    
    # Prevention Engine Settings
    PREVENTION_ENABLED = True  # Master enable/disable switch
    PREVENTION_CLEANUP_INTERVAL = 300  # Cleanup every 5 minutes (seconds)
    
    # Prevention Thresholds
    RISK_SCORE_AUTO_BLOCK = 90  # Adjust sensitivity
    REPEATED_ATTACK_THRESHOLD = 3
    REPEATED_ATTACK_WINDOW = 3600
```

### Environment Variables

```bash
# Backend
export DATABASE_URL="postgresql://user:password@localhost/cyberguard"
export API_ENABLE_PREVENTION=true
export PREVENTION_CLEANUP_INTERVAL=300

# Frontend
export VITE_API_BASE_URL="http://localhost:8000"
export VITE_ENABLE_PREVENTION_CENTER=true
```

### Prevention Duration Policies

Edit `src/services/prevention_engine.py`:

```python
class PreventionDuration:
    MEDIUM = 1 * 60 * 60          # 1 hour
    HIGH = 24 * 60 * 60            # 24 hours
    CRITICAL = 7 * 24 * 60 * 60    # 7 days
    
    # Add custom durations as needed
    EXTENDED = 30 * 24 * 60 * 60   # 30 days
```

### Middleware Configuration

Edit `src/main.py`:

```python
# To disable prevention middleware temporarily
# app.add_middleware(PreventionMiddleware)  # Comment this line

# Adjust middleware order if needed
app.add_middleware(PreventionMiddleware)     # Block malicious requests
app.add_middleware(AuditMiddleware)          # Log all requests
app.add_middleware(CORSMiddleware, ...)      # Handle CORS
```

## Production Deployment

### Using Docker

**Dockerfile (Backend):**
```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

CMD ["gunicorn", "src.main:app", "-w", "4", "-b", "0.0.0.0:8000", "--worker-class", "uvicorn.workers.UvicornWorker"]
```

**Dockerfile (Frontend):**
```dockerfile
FROM node:18-alpine

WORKDIR /app
COPY dashboard/package*.json ./
RUN npm install

COPY dashboard/ .
RUN npm run build

FROM nginx:alpine
COPY --from=0 /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

**docker-compose.yml:**
```yaml
version: '3.8'

services:
  db:
    image: postgres:15
    environment:
      POSTGRES_DB: cyberguard
      POSTGRES_USER: cyberguard_user
      POSTGRES_PASSWORD: secure_password
    ports:
      - "5432:5432"
    volumes:
      - db_data:/var/lib/postgresql/data

  backend:
    build:
      context: .
      dockerfile: Dockerfile
    environment:
      DATABASE_URL: postgresql://cyberguard_user:secure_password@db:5432/cyberguard
      API_ENABLE_PREVENTION: "true"
    ports:
      - "8000:8000"
    depends_on:
      - db

  frontend:
    build:
      context: .
      dockerfile: dashboard/Dockerfile
    ports:
      - "80:80"
    depends_on:
      - backend

volumes:
  db_data:
```

### Deployment Commands

```bash
# Build and start
docker-compose up -d

# View logs
docker-compose logs -f backend

# Scale backend (multiple instances)
docker-compose up -d --scale backend=3

# Stop
docker-compose down
```

### Nginx Configuration

```nginx
upstream backend {
    server backend:8000;
}

server {
    listen 80;
    server_name cyberguard.company.com;

    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name cyberguard.company.com;

    ssl_certificate /etc/ssl/certs/cyberguard.crt;
    ssl_certificate_key /etc/ssl/private/cyberguard.key;

    # API requests
    location /api/ {
        proxy_pass http://backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Increase timeout for long-running requests
        proxy_read_timeout 30s;
    }

    # Frontend
    location / {
        root /usr/share/nginx/html;
        try_files $uri $uri/ /index.html;
    }
}
```

## Monitoring & Maintenance

### Database Maintenance

```bash
# Monitor BlockedEntity table size
SELECT 
    COUNT(*) as total_entities,
    COUNT(CASE WHEN resolved_status=false THEN 1 END) as active_blocks,
    COUNT(CASE WHEN auto_generated=true THEN 1 END) as auto_blocks
FROM blocked_entities;

# Archive old blocks
DELETE FROM blocked_entities 
WHERE resolved_status = true 
AND unblocked_at < NOW() - INTERVAL '30 days';

# Reindex
REINDEX TABLE blocked_entities;
```

### Performance Tuning

```sql
-- Ensure indexes exist
CREATE INDEX IF NOT EXISTS idx_blocked_entity_workspace_entity 
ON blocked_entities(workspace_id, entity);

CREATE INDEX IF NOT EXISTS idx_blocked_entity_workspace_expired 
ON blocked_entities(workspace_id, blocked_until);

CREATE INDEX IF NOT EXISTS idx_blocked_entity_workspace_resolved 
ON blocked_entities(workspace_id, resolved_status);

-- Monitor slow queries
SELECT query, calls, mean_time
FROM pg_stat_statements
ORDER BY mean_time DESC
LIMIT 10;
```

### Log Monitoring

```bash
# View application logs
tail -f /var/log/cyberguard/app.log

# Monitor prevention middleware
grep "Prevention" /var/log/cyberguard/app.log

# Check for errors
grep "ERROR" /var/log/cyberguard/app.log | tail -20
```

## Health Checks

### Readiness Probe
```bash
curl -f http://localhost:8000/api/v1/prevention/stats || exit 1
```

### Liveness Probe
```bash
curl -f http://localhost:8000/ || exit 1
```

### Kubernetes Configuration
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cyberguard-backend
spec:
  replicas: 3
  selector:
    matchLabels:
      app: cyberguard-backend
  template:
    metadata:
      labels:
        app: cyberguard-backend
    spec:
      containers:
      - name: backend
        image: cyberguard:latest
        ports:
        - containerPort: 8000
        livenessProbe:
          httpGet:
            path: /
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /api/v1/prevention/stats
            port: 8000
          initialDelaySeconds: 10
          periodSeconds: 5
        resources:
          requests:
            cpu: 500m
            memory: 512Mi
          limits:
            cpu: 1000m
            memory: 1Gi
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: cyberguard-secrets
              key: database-url
```

## Backup Strategy

### Database Backup
```bash
# PostgreSQL
pg_dump cyberguard | gzip > cyberguard_$(date +%Y%m%d).sql.gz

# Restore
gunzip cyberguard_20260511.sql.gz
psql cyberguard < cyberguard_20260511.sql

# Automated backup (cron)
0 2 * * * /usr/local/bin/backup_cyberguard.sh
```

### Configuration Backup
```bash
tar -czf cyberguard_config_$(date +%Y%m%d).tar.gz \
  src/core/config.py \
  src/services/prevention_engine.py \
  dashboard/package.json
```

## Troubleshooting

### Prevention Middleware Not Blocking

1. Check if middleware is registered
   ```python
   # Verify in src/main.py
   app.add_middleware(PreventionMiddleware)
   ```

2. Verify database has blocked entities
   ```bash
   curl http://localhost:8000/api/v1/prevention/stats
   # Check active_blocks_count > 0
   ```

3. Check client IP extraction
   ```python
   # Add logging to middleware
   print(f"Client IP: {client_ip}")
   ```

### Cleanup Task Not Running

1. Verify scheduler started
   ```bash
   grep "Prevention scheduler started" /var/log/cyberguard/app.log
   ```

2. Check for errors
   ```bash
   grep "Cleanup task error" /var/log/cyberguard/app.log
   ```

3. Manually trigger cleanup
   ```bash
   curl -X POST http://localhost:8000/api/v1/prevention/cleanup \
     -H "X-API-KEY: admin_key"
   ```

### High Memory Usage

1. Check for memory leaks
   ```bash
   python -m memory_profiler src/main.py
   ```

2. Limit cleanup frequency (if running too often)
   ```python
   PreventionScheduler.cleanup_expired_blocks_task(interval=600)  # 10 minutes
   ```

3. Archive old blocks
   ```sql
   DELETE FROM blocked_entities WHERE resolved_status = true AND unblocked_at < NOW() - INTERVAL '90 days';
   ```

## Performance Benchmarks

| Metric | Value | Target |
|--------|-------|--------|
| API Response Time | < 100ms | < 200ms |
| Middleware Overhead | < 5ms | < 10ms |
| Cleanup Task Duration | < 30s | < 60s |
| Database Size | < 500MB | < 2GB |
| Memory Usage | < 256MB | < 512MB |

## Security Hardening

1. **Firewall Rules**
   ```bash
   # Allow only necessary ports
   ufw allow 22/tcp    # SSH
   ufw allow 80/tcp    # HTTP
   ufw allow 443/tcp   # HTTPS
   ufw allow 5432/tcp  # PostgreSQL (internal only)
   ```

2. **API Key Rotation**
   ```bash
   # Generate new keys monthly
   # Invalidate old keys
   # Update all integrations
   ```

3. **HTTPS Enforcement**
   ```nginx
   add_header Strict-Transport-Security "max-age=31536000" always;
   add_header X-Content-Type-Options "nosniff" always;
   add_header X-Frame-Options "DENY" always;
   ```

4. **Rate Limiting**
   ```python
   # Configure in API layer
   from slowapi import Limiter
   limiter = Limiter(key_func=get_remote_address)
   app.state.limiter = limiter
   ```

---

For additional support, consult the [IPS System Documentation](IPS_SYSTEM_DOCUMENTATION.md) and [API Reference](IPS_API_REFERENCE.md).
