import requests
import json
import time

BASE_URL = "http://localhost:8000/api/v1"

def test_enterprise_intelligence():
    # 1. Login
    print("--- Authenticating ---")
    login_data = {"username": "test@cyberguard.ai", "password": "TestPassword123!"}
    r = requests.post(f"{BASE_URL}/login/access-token", data=login_data)
    token = r.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    print("Logged in successfully.\n")

    # 2. First Scan (Threat Intel Enrichment)
    print("--- Scan 1: Threat Intelligence Enrichment ---")
    payload = {"type": "url", "data": "http://evil-phishing.com"}
    r = requests.post(f"{BASE_URL}/agent/analyze", json=payload, headers=headers)
    res1 = r.json()
    print(f"Risk Score: {res1['agent_verdict']['score']}")
    print(f"Verdict: {res1['agent_verdict']['label']}")
    print(f"Intelligence: {json.dumps(res1['intelligence']['threat_intel'], indent=2)}")
    print("\n")

    # Small delay for timestamp difference
    time.sleep(1)

    # 3. Second Scan (Cross-Vector Correlation)
    print("--- Scan 2: Cross-Vector Threat Correlation ---")
    r = requests.post(f"{BASE_URL}/agent/analyze", json=payload, headers=headers)
    res2 = r.json()
    print(f"Risk Score (Adjusted): {res2['agent_verdict']['score']}")
    print(f"Correlation Detected: {res2['intelligence']['correlation']['detected']}")
    if res2['intelligence']['correlation']['detected']:
        print(f"Pattern: {res2['intelligence']['correlation']['pattern']}")
        print(f"Evidence Count: {res2['intelligence']['correlation']['evidence_count']}")
    print("\n")

if __name__ == "__main__":
    test_enterprise_intelligence()
