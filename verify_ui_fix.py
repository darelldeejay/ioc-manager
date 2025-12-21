
import requests
import json
import time

URL = "http://127.0.0.1:5000/api/bloquear-ip"
TOKEN = "token-secreto-prueba-api"

payload = {
    "ip": "44.44.44.44",
    "tags": ["Test"],
    "ttl": "1h",
    "alert_id": "TEST-UI-FIX"
}

print(f" sending POST to {URL}...")
try:
    # Retry logic because server might be starting
    for i in range(5):
        try:
            resp = requests.post(URL, json=payload, headers={"Authorization": f"Bearer {TOKEN}"})
            print(f" Status: {resp.status_code}")
            print(f" Body: {resp.text}")
            break
        except requests.exceptions.ConnectionError:
            print(" Server not ready, retrying...")
            time.sleep(2)
except Exception as e:
    print(f" EXCEPTION: {e}")
