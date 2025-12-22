from app import load_users, save_users, generate_password_hash, _iso, _now_utc

def add_restricted_user():
    print("Loading users...")
    users = load_users()
    
    username = "bpe_client"
    password = "bpe.12345"
    
    print(f"Adding user {username}...")
    users[username] = {
        "password_hash": generate_password_hash(password),
        "role": "view_only",
        "allowed_feeds": ["bpe"],
        "created_at": _iso(_now_utc())
    }
    
    save_users(users)
    print("User saved!")

if __name__ == "__main__":
    add_restricted_user()
