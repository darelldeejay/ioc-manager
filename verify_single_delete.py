
import requests
import os

FEED_TEST = "ioc-feed-test.txt"
IP_TO_DELETE = "66.66.66.66"

# 1. Ensure IP exists in Test Feed (it should from previous step, if not write it)
# We can just check content first.
content = ""
if os.path.exists(FEED_TEST):
    with open(FEED_TEST, "r") as f:
        content = f.read()

if IP_TO_DELETE not in content:
    print(f"IP {IP_TO_DELETE} not found in test feed initially. Writing it...")
    with open(FEED_TEST, "a", encoding="utf-8") as f:
        f.write(f"{IP_TO_DELETE}|2025-01-01|0\n")
else:
    print(f"IP {IP_TO_DELETE} found in test feed. Proceeding to delete.")

# 2. Trigger Delete IP via POST /
from app import app

with app.test_client() as client:
    with client.session_transaction() as sess:
        sess["username"] = "admin"
        sess["role"] = "admin"
    
    print(f"Sending POST delete-ip={IP_TO_DELETE}...")
    resp = client.post("/", data={"delete_ip": IP_TO_DELETE}, follow_redirects=True)
    print(f"Response: {resp.status_code}")

# 3. Verify
print("Verifying Test Feed content...")
if os.path.exists(FEED_TEST):
    with open(FEED_TEST, "r") as f:
        new_content = f.read()
    
    if IP_TO_DELETE not in new_content:
        print("SUCCESS: IP removed from Test Feed.")
    else:
        print("FAILURE: IP still in Test Feed!")
else:
    print("SUCCESS: Feed file gone (empty/deleted).")
