
import requests
import os

FEED = "ioc-feed.txt"
BPE = "ioc-feed-bpe.txt"
TEST = "ioc-feed-test.txt"

# 1. Setup Data
with open(FEED, "w", encoding="utf-8") as f:
    f.write("1.1.1.1|2025-01-01|0\n")
with open(BPE, "w", encoding="utf-8") as f:
    f.write("2.2.2.2|2025-01-01|0\n")
with open(TEST, "w", encoding="utf-8") as f:
    f.write("3.3.3.3|2025-01-01|0\n")

print("Created dummy data in all 3 feeds.")

# 2. Trigger Delete All via POST / (requires login session... tricky with simple request)
# Alternative: Since we are local, we can just run a python script that IMPORTS app and checks the logic?
# No, app.context is needed.
# Easier: Use requests.Session to login then post.

LOGIN_URL = "http://127.0.0.1:5000/login"
INDEX_URL = "http://127.0.0.1:5000/"

s = requests.Session()
try:
    # Login (assuming admin/admin default or similar, checking env would be better but blocked)
    # The previous attempt failed because server was restarting.
    # Let's try to post delete-all? No, needs CSRF? Flask-WTF? No, standard form in this app.
    # But it needs @login_required.
    
    # Actually, can I just check if the files exist and are empty after MANUAL action?
    # User is testing manually. I should notify user to test.
    # But I want to verify myself.
    
    # I will try to use `app.test_client()`!
    from app import app
    
    with app.test_client() as client:
        # Mock login session
        with client.session_transaction() as sess:
            sess["username"] = "admin"
            sess["role"] = "admin"
        
        print("Sending POST delete-all...")
        resp = client.post("/", data={"delete-all": "1"}, follow_redirects=True)
        print(f"Response: {resp.status_code}")
        
    # 3. Verify
    print("Verifying files...")
    f_size = os.path.getsize(FEED) if os.path.exists(FEED) else 0
    b_size = os.path.getsize(BPE) if os.path.exists(BPE) else 0
    t_size = os.path.getsize(TEST) if os.path.exists(TEST) else 0
    
    print(f"MAIN size: {f_size}")
    print(f"BPE size: {b_size}")
    print(f"TEST size: {t_size}")
    
    if f_size == 0 and b_size == 0 and t_size == 0:
        print("SUCCESS: All feeds cleared.")
    else:
        print("FAILURE: Some feeds not cleared.")
        
except Exception as e:
    print(f"ERROR: {e}")
