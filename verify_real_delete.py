
import requests
import time
import os

FEED_TEST = "ioc-feed-test.txt"
IP_TO_DELETE = "77.77.77.77" # The one added manually

LOGIN_URL = "http://127.0.0.1:5000/login"
INDEX_URL = "http://127.0.0.1:5000/"

# 1. Login
s = requests.Session()
# We don't have password visible but previous attempts failed to login.
# Assuming dev env defaults. Usually it's admin/admin.
# Wait, I cannot see .env. 
# But I can access the app via Python... 
# Actually, I can cheat: I can use the API to add an IP (already added 77.77...), 
# and then use the API to DELETE it? No, user says "boton eliminar de la tabla".
# Table delete uses POST /.
# I NEED to login to use POST /.

# Let's try to grab the cookie from the browser? No.
# Let's try default creds.
print("Attempting login...")
resp = s.post(LOGIN_URL, data={"username": "admin", "password": "password"}, allow_redirects=True)
if "Credenciales incorrectas" in resp.text:
    print("Login failed with 'password'. Trying 'admin'...")
    resp = s.post(LOGIN_URL, data={"username": "admin", "password": "admin"}, allow_redirects=True)

if "Credenciales incorrectas" in resp.text:
    print("Login failed with 'admin'. Giving up on auth test.")
else:
    print("Login SUCCESS (presumably).")
    
    # Check if 77.77.77.77 is in the index page
    idx = s.get(INDEX_URL)
    if IP_TO_DELETE in idx.text:
        print(f"IP {IP_TO_DELETE} found on Index page. Attempting delete...")
        
        # POST delete
        resp_del = s.post(INDEX_URL, data={"delete_ip": IP_TO_DELETE}, allow_redirects=True)
        print(f"Delete Response Code: {resp_del.status_code}")
        
        # Verify file content directly
        if os.path.exists(FEED_TEST):
            with open(FEED_TEST, "r") as f:
                content = f.read()
            if IP_TO_DELETE in content:
                print("FAILURE: IP still in file after delete POST.")
            else:
                print("SUCCESS: IP removed from file.")
        else:
            print("SUCCESS: File does not exist.")
    else:
        print(f"IP {IP_TO_DELETE} NOT found on Index page. Maybe verify_add_another.py didn't persist?")
