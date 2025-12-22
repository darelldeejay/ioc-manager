from werkzeug.security import generate_password_hash
import json
import os

META_FILE = "users.json"
ADMIN_USER = "admin"
NEW_PASS = "password"

if not os.path.exists(META_FILE):
    print("users.json not found")
    exit(1)

with open(META_FILE, "r") as f:
    users = json.load(f)

print(f"Resetting password for {ADMIN_USER}...")
users[ADMIN_USER]["password_hash"] = generate_password_hash(NEW_PASS)

with open(META_FILE, "w") as f:
    json.dump(users, f, indent=2)

print("Done. New password is 'password'")
