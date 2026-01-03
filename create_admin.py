
import db
from werkzeug.security import generate_password_hash

def create():
    username = "debug_admin"
    password = "password123"
    role = "admin"
    
    print(f"Creating user {username}...")
    pwd_hash = generate_password_hash(password)
    
    # Try to create
    if db.create_user(username, pwd_hash, role):
        print("Success.")
    else:
        # If exists, update password
        print("User exists, updating...")
        db.update_user(username, password_hash=pwd_hash, role=role)
        print("Updated.")

if __name__ == "__main__":
    create()
