
import requests
import json
import time

URL = "http://127.0.0.1:5000/api/bloquear-ip"
TOKEN = "token-secreto-prueba-api"

payload = {
    "ip": "55.55.55.55",
    "tags": ["Test"],
    "ttl": "1h",
    "alert_id": "FINAL-TEST"
}

print(f" sending POST to {URL}...")
try:
    resp = requests.post(URL, json=payload, headers={"Authorization": f"Bearer {TOKEN}"})
    print(f" Status: {resp.status_code}")
    print(f" Body: {resp.text}")
except Exception as e:
    print(f" EXCEPTION: {e}")
