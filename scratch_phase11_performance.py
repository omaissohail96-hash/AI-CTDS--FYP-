import time
from fastapi.testclient import TestClient
from src.main import app

client = TestClient(app, raise_server_exceptions=False)

def measure_time(endpoint, method="GET", json_data=None, iterations=10):
    start = time.time()
    for _ in range(iterations):
        if method == "GET":
            client.get(endpoint)
        else:
            client.post(endpoint, json=json_data)
    end = time.time()
    avg_ms = ((end - start) / iterations) * 1000
    print(f"{method} {endpoint}: avg {avg_ms:.2f} ms over {iterations} iterations")

if __name__ == "__main__":
    print("Gathering performance metrics...")
    measure_time("/health")
    
    payload = {
        "type": "network",
        "data": {
            "source_ip": "10.0.0.5",
            "destination_ip": "192.168.1.10",
            "protocol": "TCP",
            "payload": "GET / HTTP/1.1",
            "flags": ["SYN"]
        }
    }
    
    # We bypass auth for this perf test
    from unittest.mock import patch
    with patch('src.api.middleware.InMemoryRateLimiter.is_rate_limited', return_value=False), \
         patch('src.utils.saas_guard.SaaSGuard.check_rate_limit', return_value=0), \
         patch('src.utils.saas_guard.SaaSGuard.check_quota', return_value=0), \
         patch('src.core.trusted_proxy.TrustedProxyResolver.get_client_ip', return_value="127.0.0.1"), \
         patch('src.api.deps.RequirePermissions.__call__', return_value=None):
         
        # Need API key in headers to bypass the get_api_key check? 
        # Actually /api/v1/agent/analyze uses `RequirePermissions("scans:create")`
        HEADERS = {"Authorization": "Bearer cg_live_perf_test"}
        
        start = time.time()
        for _ in range(10):
             client.post("/api/v1/agent/analyze", json=payload, headers=HEADERS)
        end = time.time()
        avg_ms = ((end - start) / 10) * 1000
        print(f"POST /api/v1/agent/analyze: avg {avg_ms:.2f} ms over 10 iterations")
