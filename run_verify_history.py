import requests
import sys
import json
import time

BASE_URL = "http://127.0.0.1:5000"
LOGIN_URL = f"{BASE_URL}/login"
INDEX_URL = f"{BASE_URL}/"
API_URL = f"{BASE_URL}/api/counters/history"

# Credentials from previous context
USERNAME = "admin"
PASSWORD = "password"

s = requests.Session()

def verify():
    # Wait for server to start
    time.sleep(2)
    
    print(f"[*] Logging in as {USERNAME}...")
    r = s.post(LOGIN_URL, data={"username": USERNAME, "password": PASSWORD}, allow_redirects=True)
    print(f"    Login Status: {r.status_code}")
    if "Gestor" in r.text or "Logout" in r.text or "logout" in r.text:
        print("    [+] Login OK")
    else:
        print("    [!] Login seemed to fail (No dashboard text found)")
    
    print(f"[*] Accessing Index to trigger snapshot...")
    # This triggers the snapshot in app.py
    r = s.get(INDEX_URL)
    print(f"    Index Status: {r.status_code}")
    
    print(f"[*] Fetching History API: {API_URL}")
    r = s.get(API_URL)
    print(f"    API Status: {r.status_code}")
    
    if r.status_code == 200:
        if "login" in r.url:
            print("[!] API redirected to login page!")
            sys.exit(1)
            
        try:
            data = r.json()
            print(f"[*] Data received: {len(data)} entries")
            if data:
                print(f"[*] Latest Snapshot: {data[-1]}")
                print("[OK] Verification Success")
            else:
                print("[!] Empty data list (Snapshot might not have run)")
                sys.exit(1)
        except Exception as e:
            print(f"[!] Failed to parse JSON: {e}")
            print(f"    Response text: {r.text[:200]}")
            sys.exit(1)
    else:
        print(f"[!] API Error: {r.status_code}")
        sys.exit(1)

if __name__ == "__main__":
    verify()
