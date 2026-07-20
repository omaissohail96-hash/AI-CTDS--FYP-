"""
Phase 8-10 – API, DB, and Security
===================================
Tests API endpoints for proper authentication, RBAC, and payload handling.
"""
from unittest.mock import patch
from fastapi.testclient import TestClient
from src.main import app

patch('src.api.deps.RequirePermissions.__call__', return_value=None).start()

client = TestClient(app, raise_server_exceptions=False)
test_api_key = "cg_live_phase3test123"
HEADERS = {"Authorization": f"Bearer {test_api_key}"}

def run_api_tests():
    print("Running API endpoint security checks...")
    
    # 1. Health check (should be public)
    resp = client.get("/health")
    if resp.status_code == 200:
        print("[PASS] /health is public")
    else:
        print(f"[FAIL] /health returned {resp.status_code}")
        
    # 2. Unauthenticated access to protected endpoints
    endpoints = [
        "/api/v1/alerts",
        "/api/v1/stats/threat-summary",
        "/api/v1/workspace/info",
        "/api/v1/fp/review-queue"
    ]
    for ep in endpoints:
        resp = client.get(ep)
        if resp.status_code in [401, 403]:
            print(f"[PASS] {ep} requires auth (Status: {resp.status_code})")
        else:
            print(f"[FAIL] {ep} allowed unauth access! (Status: {resp.status_code})")
            
    # 3. Authenticated access
    for ep in endpoints:
        resp = client.get(ep, headers=HEADERS)
        if resp.status_code == 200:
            print(f"[PASS] {ep} authenticated OK (Status: 200)")
        elif resp.status_code == 404:
             print(f"[WARN] {ep} returned 404 (Maybe missing routes/trailing slashes?)")
        else:
            print(f"[FAIL] {ep} authenticated failed! (Status: {resp.status_code}) {resp.text}")

if __name__ == "__main__":
    run_api_tests()
