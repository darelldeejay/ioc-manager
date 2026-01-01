
import requests
import json
import time

BASE_URL = "http://127.0.0.1:5000"
# WARNING: We need a valid token. If auth is enabled in app.py, this will fail without it.
# Let's try to grab a token from the config or use a known one if hardcoded.
# If manual auth is required, I'll try to simulate a session login first.

s = requests.Session()

def login_and_test():
    print("--- START DEBUG ---")
    
    # 1. Login to get session cookie (if using session auth for UI actions)
    # Adjust credentials if known, or try to act as API client with token.
    # App seems to check `require_api_token` for /api/ routes.
    # Let's try to assume there is a token "123456" or similar from previous context?
    # Or, let's try to read the API tokens file first? No, I can't easily.
    # Let's try "admin" / "admin" login first to get session.
    
    login_payload = {"username": "admin", "password": "password"} # Hypothesis
    # Actually, let's just try the API with a likely token or check if I can bypass.
    
    # Let's try to hit the health check
    try:
        r = s.get(f"{BASE_URL}/api/", headers={"Authorization": "Bearer 123456"}, timeout=2)
        print(f"Health Check (Bearer 123456): {r.status_code} - {r.text}")
    except Exception as e:
        print(f"Health Check Failed: {e}")
        return

    # 2. Test History Endpoint
    test_ip = "1.1.1.1" # Dummy
    print(f"\nTesting History for {test_ip}...")
    try:
        r = s.get(f"{BASE_URL}/api/estado/{test_ip}", headers={"Authorization": "Bearer 123456"})
        print(f"GET /api/estado/{test_ip}: {r.status_code}")
        print(f"Response: {r.text[:200]}...") # Truncate
    except Exception as e:
        print(f"History Request Error: {e}")

    # 3. Test TTL Edit (POST)
    print(f"\nTesting TTL Edit for {test_ip}...")
    payload = {
        "origen": "debug_script",
        "force": True,
        "items": [{
            "ip": test_ip,
            "tags": ["debug"],
            "ttl": "30"
        }]
    }
    try:
        r = s.post(f"{BASE_URL}/api/bloquear-ip", json=payload, headers={"Authorization": "Bearer 123456"})
        print(f"POST /api/bloquear-ip: {r.status_code}")
        print(f"Response: {r.text}")
    except Exception as e:
        print(f"TTL Edit Request Error: {e}")

if __name__ == "__main__":
    login_and_test()
