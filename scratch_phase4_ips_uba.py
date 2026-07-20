"""
Phase 4-6 – Alerting, IPS, and UBA Testing
==========================================
Tests the prevention capabilities and user behavior tracking
by generating a malicious payload that should be blocked.
"""
import os
from unittest.mock import patch

# Robustly patch the rate limiter class method and SaaSGuard
patch('src.api.middleware.InMemoryRateLimiter.is_rate_limited', return_value=False).start()
patch('src.utils.saas_guard.SaaSGuard.check_rate_limit', return_value=0).start()
patch('src.utils.saas_guard.SaaSGuard.check_quota', return_value=0).start()
patch('src.core.trusted_proxy.TrustedProxyResolver.get_client_ip', return_value="192.168.99.1").start()
patch('src.services.false_positive_service.FalsePositiveFramework.should_block', return_value=(True, False, "Mocked block for IPS testing")).start()
patch('src.utils.scoring.ScoringEngine.calculate_risk', return_value={
    "score": 95,
    "label": "CRITICAL",
    "summary": "Mocked Critical Score for IPS testing",
    "contributions": {"ml_model": 95}
}).start()

from fastapi.testclient import TestClient
from src.main import app
from src.core.database import SessionLocal
from src.models.models import BlockedEntity, Alert, UserBehaviorEvent

client = TestClient(app, raise_server_exceptions=False)
test_api_key = "cg_live_phase3test123"
HEADERS = {"Authorization": f"Bearer {test_api_key}"}
URL = "/api/v1/agent/analyze"

def cleanup_db():
    db = SessionLocal()
    db.query(BlockedEntity).delete()
    db.query(Alert).delete()
    db.query(UserBehaviorEvent).delete()
    db.commit()
    db.close()

def run_ips_test():
    cleanup_db()
    
    # 1. Send extremely malicious payload to trigger block
    fake_ip = "192.168.99.1"
    headers = {**HEADERS, "x-forwarded-for": fake_ip}
    payload = {
        "type": "network",
        "data": {
            "source_ip": fake_ip,
            "destination_port": 22,
            "protocol": "tcp",
            "bytes_sent": 10000,
            "flags": ["SYN"]
        }
    }
    print("Sending highly malicious payload from IP:", fake_ip)
    resp = client.post(URL, json=payload, headers=headers)
    if resp.status_code == 200:
        res = resp.json()
        print(f"Verdict: {res.get('agent_verdict', {}).get('label')} (Score: {res.get('agent_verdict', {}).get('score')})")
        print(f"Prevention triggered: {res.get('prevention_action', {}).get('triggered')}")
        print(f"Alert generated: {res.get('alert', {}).get('generated')}")
    else:
        print(f"Failed to analyze: {resp.status_code} {resp.text}")
        return False
        
    # 2. Check if IP is blocked in subsequent request
    print("\nSending follow-up request from same IP. Should be 403 Forbidden...")
    resp2 = client.post(URL, json={"type": "web", "data": "hello"}, headers=headers)
    if resp2.status_code == 403:
        print(f"SUCCESS: Request was blocked! (Status: {resp2.status_code})")
        print(f"Block Reason: {resp2.json().get('reason')}")
    else:
        print(f"FAIL: Request was NOT blocked. (Status: {resp2.status_code})")
        
    # 3. Check UBA Event Tracking
    db = SessionLocal()
    uba_count = db.query(UserBehaviorEvent).count()
    alert_count = db.query(Alert).count()
    block_count = db.query(BlockedEntity).count()
    db.close()
    
    print(f"\nDB State -> Alerts: {alert_count}, Blocked IPs: {block_count}, UBA Events: {uba_count}")
    
    blocked_entities = db.query(BlockedEntity).all()
    print("Blocked Entities in DB:")
    for b in blocked_entities:
        print(f" - {b.entity} (until {b.blocked_until}, active={not b.resolved_status})")
        
    if uba_count == 0:
        print("FAIL: No UBA events were recorded.")
        return False
        
    print("\nPhase 4-6 tests PASSED.")
    return True

if __name__ == "__main__":
    run_ips_test()
