import db
import secrets
from werkzeug.security import generate_password_hash

def create_temp_env():
    db.init_db()
    
    # 1. API Key
    token = "dk_temp_verify_420607e8" # Reuse same token
    db.create_api_key("VerifyScript", token, "READ,WRITE")
    print(f"TOKEN={token}")
    
    # 2. Dummy User (to pass setup check)
    if db.get_user_count() == 0:
        print("Creating dummy admin for verification...")
        db.create_user("admin", generate_password_hash("admin"), role="admin")
    else:
        print("Users already exist. Skipping user creation.")

if __name__ == "__main__":
    create_temp_env()
