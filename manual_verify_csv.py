
import requests
import os
import json

URL = "http://127.0.0.1:5000/"
LOGIN_URL = "http://127.0.0.1:5000/login"

s = requests.Session()
# Intentar login con admin/admin por si acaso (password default suele ser admin o password)
print("Logging in...")
# Bypass login using debug route
print("Getting session via /debug-dashboard...")
s.get("http://127.0.0.1:5000/debug-dashboard")
# Now s has session cookie 

try:
    files = {'file': open('test_upload.csv', 'rb')}
    data = {'ttl_csv': 'permanente'}

    print("Uploading CSV...")
    resp = s.post(URL, files=files, data=data)
    print(f"Status: {resp.status_code}")
except Exception as e:
    print(f"Exception during request: {e}")

# Validar persistencia en JSON
print("Checking ioc-meta.json...")
if os.path.exists("ioc-meta.json"):
    with open("ioc-meta.json", "r") as f:
        meta = json.load(f)
    details = meta.get("ip_details", {})
    
    # 55.55.55.1 -> Alert: ALERT-MULTI-01
    d1 = details.get("55.55.55.1", {})
    alert_ids = d1.get('alert_ids')
    print(f"55.55.55.1 Alert: {alert_ids} (Expected: ['ALERT-MULTI-01'])") 
    
    # 55.55.55.4 -> Tags: Multi, Test
    d4 = details.get("55.55.55.4", {})
    tags = d4.get('tags')
    print(f"55.55.55.4 Tags: {tags} (Expected: ['Multicliente', 'Test'])")

# Validar Feeds
for f_name in ["ioc-feed.txt", "ioc-feed-bpe.txt", "ioc-feed-test.txt"]:
    if os.path.exists(f_name):
        with open(f_name, "r") as f:
            cnt = f.read().count("55.55.55.")
            print(f"{f_name}: {cnt} entries")
