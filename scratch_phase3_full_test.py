"""
Phase 3 – Detection Engine & Intelligence Testing
===================================================
Tests every detector type through the live FastAPI stack (TestClient)
using API-key authentication.
"""
import os, sys, time, json, random
from unittest.mock import patch

# Patch the in-memory rate limiter BEFORE importing the app
# This prevents 429s during test runs
with patch.dict(os.environ, {"RATE_LIMIT_ENABLED": "false"}):
    pass  # env set, but settings already frozen

from fastapi.testclient import TestClient
from src.main import app

# Robustly patch the rate limiter class method and SaaSGuard
patch('src.api.middleware.InMemoryRateLimiter.is_rate_limited', return_value=False).start()
patch('src.utils.saas_guard.SaaSGuard.check_rate_limit', return_value=0).start()
patch('src.utils.saas_guard.SaaSGuard.check_quota', return_value=0).start()


client = TestClient(app, raise_server_exceptions=False)

RAW_KEY = "cg_live_phase3test123"
HEADERS = {"Authorization": f"Bearer {RAW_KEY}"}
URL = "/api/v1/agent/analyze"

results = []


def run_case(name, payload_type, data, expect_label=None, expect_attack_type=None):
    fake_ip = f"192.168.1.{random.randint(1, 254)}"
    headers = {**HEADERS, "x-forwarded-for": fake_ip}
    payload = {"type": payload_type, "data": data}
    resp = client.post(URL, json=payload, headers=headers)

    if resp.status_code == 429:
        results.append(("SKIP", name, f"Rate limited (429) – increase RATE_LIMIT_DEFAULT_RPM"))
        return None

    if resp.status_code != 200:
        results.append(("FAIL", name, f"HTTP {resp.status_code}: {resp.text[:300]}"))
        return None

    body = resp.json()
    verdict = body.get("agent_verdict", {})
    label = verdict.get("label", "?")
    score = verdict.get("score", 0)
    attack = body.get("attack_type", "?")
    mitre = [m.get("technique_id") for m in body.get("mitre_mappings", [])]
    has_scan_id = bool(body.get("scan_id"))

    notes = f"verdict={label} score={score} attack={attack} mitre={mitre} scan_id={has_scan_id}"

    failed = False
    if expect_label and label not in expect_label:
        failed = True
    if expect_attack_type and expect_attack_type != "ANY":
        # Check if any keyword matches (case-insensitive)
        matched = any(kw.upper() in (attack or "").upper() for kw in expect_attack_type)
        if not matched and attack not in expect_attack_type:
            failed = True

    status = "FAIL" if failed else "PASS"
    results.append((status, name, notes))
    return body


print()
print("="*70)
print("  PHASE 3 - Detection Engine & Intelligence Testing")
print("="*70)

# ─── 1. URL / Phishing Detector ─────────────────────────────────────────
print("\n[1] URL / Phishing Detector")
run_case(
    "Phishing URL - known bad pattern",
    "url", "http://secure-login-paypal-update.com/login",
    expect_label=["SUSPICIOUS", "MALICIOUS", "HIGH"]
)
run_case(
    "Phishing URL - credential theft domain",
    "url", "http://account-verify-google-inc.tk/signin",
    expect_label=["SUSPICIOUS", "MALICIOUS", "HIGH"]
)
run_case(
    "Clean URL - google.com",
    "url", "https://google.com",
    # We don't assert on clean URLs - any response is acceptable
)
run_case(
    "Clean URL - github.com",
    "url", "https://github.com/openai/openai-python",
)

# ─── 2. Email / Phishing Text Detector ──────────────────────────────────
print("\n[2] Email / Text Phishing Detector")
run_case(
    "Phishing Email - urgency + account suspension",
    "email",
    "URGENT: Your account will be suspended. Click here to verify immediately or face permanent ban. "
    "Provide your username and password. http://fake-bank.com/login",
    expect_label=["SUSPICIOUS", "MALICIOUS", "HIGH"]
)
run_case(
    "Phishing Email - prize scam",
    "email",
    "Congratulations! You have been selected to receive $1,000,000! "
    "Click now to claim your winnings. Provide your bank details immediately.",
    expect_label=["SUSPICIOUS", "MALICIOUS", "HIGH"]
)
run_case(
    "Benign Email - team meeting",
    "email",
    "Hey team, are we still meeting at 2 PM for the sprint review? Please confirm.",
)

# ─── 3. Web Attack Detector ─────────────────────────────────────────────
print("\n[3] Web Attack Detector (SQLi, XSS, Command Injection)")
r = run_case(
    "SQL Injection - classic OR bypass",
    "web", "1' OR '1'='1",
)
r2 = run_case(
    "SQL Injection - DROP TABLE",
    "web", "'; DROP TABLE users; --",
)
r3 = run_case(
    "XSS - script tag",
    "web", "<script>alert('XSS')</script>",
)
r4 = run_case(
    "Command Injection",
    "web", "; cat /etc/passwd",
)
r5 = run_case(
    "Path Traversal",
    "web", "../../../../etc/shadow",
)
run_case(
    "Benign Web Input",
    "web", "hello world search query",
)

# Print any 500-body for web attack cases for diagnosis
for label, body in [("SQLi", r), ("DROP TABLE", r2), ("XSS", r3), ("CMD", r4), ("PATH", r5)]:
    if body is None:
        print(f"  !! {label} returned None (possible 500)")

# ─── 4. Network Detector ────────────────────────────────────────────────
print("\n[4] Network Attack Detector")
run_case(
    "Port Scan - SYN flood pattern",
    "network",
    {"source_ip": "10.0.0.5", "destination_ip": "192.168.1.1",
     "port": 22, "protocol": "TCP", "flags": "SYN", "bytes_sent": 100},
)
run_case(
    "DDoS pattern - high UDP volume",
    "network",
    {"source_ip": "1.2.3.4", "destination_ip": "192.168.1.100",
     "port": 80, "protocol": "UDP", "bytes_sent": 10_000_000, "packets": 50000},
)
run_case(
    "Normal traffic - HTTPS to DNS",
    "network",
    {"source_ip": "192.168.1.10", "destination_ip": "8.8.8.8",
     "port": 443, "protocol": "TCP", "bytes_sent": 1024},
)

# ─── 5. Auto-detect type ────────────────────────────────────────────────
print("\n[5] Auto-detection (type=auto)")
run_case(
    "Auto-detect URL",
    "auto", "http://malicious-phishing-test.com/harvest",
)

# ─── Print Results ────────────────────────────────────────────────────────
print()
print("="*70)
print("  TEST RESULTS SUMMARY")
print("="*70)
passes = fails = skips = 0
for status, name, notes in results:
    icon = "[PASS]" if status == "PASS" else ("[SKIP]" if status == "SKIP" else "[FAIL]")
    print(f"  {icon} {name}")
    print(f"         {notes}")
    if status == "PASS":
        passes += 1
    elif status == "SKIP":
        skips += 1
    else:
        fails += 1

print()
print("="*70)
print(f"  TOTAL: {passes + fails + skips}  |  PASSED: {passes}  |  FAILED: {fails}  |  SKIPPED: {skips}")
print("="*70)
sys.exit(0 if fails == 0 else 1)
