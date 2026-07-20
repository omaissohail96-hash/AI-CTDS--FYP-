import sys
from fastapi.testclient import TestClient
from src.main import app

client = TestClient(app)

# We need a valid API key
import sqlite3
import hashlib
conn = sqlite3.connect("cyberguard.db")
cursor = conn.cursor()
# Find an active api key
cursor.execute("SELECT key_hash FROM api_keys WHERE is_active=1 LIMIT 1")
key = cursor.fetchone()
conn.close()

if not key:
    print("No active key found!")
    sys.exit(1)

# Wait, we only have the HASH in the DB! We don't have the raw key!
# That's why I created "cg_live_phase3test123" earlier.
raw_key = "cg_live_phase3test123"

headers = {
    "Authorization": f"Bearer {raw_key}"
}
url = "/api/v1/agent/analyze"

payload = {
    "type": "url",
    "data": "http://secure-login-paypal-update.com/login"
}

try:
    response = client.post(url, json=payload, headers=headers)
    print("Status:", response.status_code)
    print("Response:", response.text)
except Exception as e:
    import traceback
    traceback.print_exc()
