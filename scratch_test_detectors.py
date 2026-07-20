import requests
import sqlite3
import json

# Connect to dev DB and get an API key
conn = sqlite3.connect("cyberguard.db")
cursor = conn.cursor()

# Get a workspace_id
cursor.execute("SELECT id FROM workspaces LIMIT 1")
ws = cursor.fetchone()
if not ws:
    print("No workspace found. Creating one...")
    import uuid
    ws_id = str(uuid.uuid4())
    cursor.execute("INSERT INTO workspaces (id, name, created_at) VALUES (?, 'Dev WS', datetime('now'))", (ws_id,))
    conn.commit()
    ws = (ws_id,)

ws_id = ws[0]

# Let's just create an API Key bypassing hash for testing, OR we can just use the super admin token.
# Actually, since we need to send the API key hash to DB, we can just hash it.
import hashlib
raw_key = "cg_live_phase3test123"
key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

cursor.execute("SELECT id FROM api_keys WHERE key_hash=?", (key_hash,))
if not cursor.fetchone():
    import uuid
    cursor.execute(
        "INSERT INTO api_keys (id, workspace_id, label, key_hash, is_active, created_at, usage_count) VALUES (?, ?, 'Phase 3 Test', ?, 1, datetime('now'), 0)",
        (str(uuid.uuid4()), ws_id, key_hash)
    )
    conn.commit()

conn.close()

# Now we have our valid API key
headers = {
    "Authorization": f"Bearer {raw_key}"
}
url = "http://localhost:8000/api/v1/agent/analyze"

def test_detector(name, payload_type, data):
    print(f"\n--- Testing {name} ---")
    payload = {
        "type": payload_type,
        "data": data
    }
    try:
        resp = requests.post(url, json=payload, headers=headers)
        print(f"Status: {resp.status_code}")
        if resp.status_code == 500:
            print(resp.text)
        else:
            print(json.dumps(resp.json(), indent=2))
    except Exception as e:
        print(f"Error: {e}")

# 1. URL Phishing Detector
test_detector("URL Phishing (Malicious)", "url", "http://secure-login-paypal-update.com/login")
test_detector("URL Phishing (Benign)", "url", "https://google.com")

# 2. Email Detector
malicious_email = "URGENT: Your account will be suspended. Click here to verify your identity immediately or face permanent ban."
test_detector("Email Analysis (Malicious)", "email", malicious_email)

benign_email = "Hey team, just wanted to check if we are still on for the meeting at 2 PM?"
test_detector("Email Analysis (Benign)", "email", benign_email)

# 3. Web Attack
sql_injection = "1' OR '1'='1"
test_detector("Web Attack (SQLi)", "web", sql_injection)

# 4. Network Attack (JSON data)
network_payload = {
    "source_ip": "192.168.1.100",
    "destination_ip": "10.0.0.5",
    "port": 22,
    "bytes_sent": 5000000,
    "protocol": "TCP",
    "flags": "SYN"
}
test_detector("Network Attack", "network", network_payload)
