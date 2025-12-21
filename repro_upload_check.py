
import requests
import os
import json

URL = "http://127.0.0.1:5000/"

s = requests.Session()
# Auth bypass
s.get("http://127.0.0.1:5000/debug-dashboard")

def test_csv(content, name):
    print(f"\n--- Testing {name} ---")
    filename = f"test_{name}.csv"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(content)
    
    files = {'file': open(filename, 'rb')}
    data = {'ttl_csv': 'permanente'}
    
    try:
        resp = s.post(URL, files=files, data=data)
        print(f"Status: {resp.status_code}")
        if resp.status_code != 200:
            print("Response:", resp.text[:200])
    except Exception as e:
        print(f"Error: {e}")
        
    if os.path.exists(filename):
        try:
            os.remove(filename)
        except:
            pass

# Case 1: Semicolon valid
content1 = """IP;Tags;AlertID
8.8.4.4;Multicliente;TEST-CSV-1
"""
test_csv(content1, "semicolon")

# Case 2: Comma valid
content2 = """IP,Tags,AlertID
8.8.8.8,Multicliente,TEST-CSV-2
"""
test_csv(content2, "comma")

# Case 3: No header
content3 = """1.0.0.1;BPE;TEST-NOHEADER"""
test_csv(content3, "noheader")

# Case 4: Missing tags (should fail/reject)
content4 = """1.0.0.2;;TEST-FAIL"""
test_csv(content4, "missing_tags")

# Verify results
print("\n--- Verification ---")
if os.path.exists("ioc-meta.json"):
    with open("ioc-meta.json", "r") as f:
        meta = json.load(f)
    print("8.8.4.4 Meta:", meta.get("ip_details", {}).get("8.8.4.4"))
    print("8.8.8.8 Meta:", meta.get("ip_details", {}).get("8.8.8.8"))
    print("1.0.0.1 Meta:", meta.get("ip_details", {}).get("1.0.0.1"))
    print("1.0.0.2 Meta (Should be None):", meta.get("ip_details", {}).get("1.0.0.2"))

print("\n--- Testing plantilla.csv content ---")
plantilla_content = """IP;Tags;AlertID
1.1.1.1;Multicliente;TICKET-001
2.2.2.2;BPE;TICKET-002
3.3.3.3;Multicliente,Test;MANUAL-ALERT
"""
test_csv(plantilla_content, "plantilla_real")
