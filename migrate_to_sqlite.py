import sqlite3
import json
import os
from datetime import datetime
from db import init_db, get_db

USERS_FILE = "users.json"
META_FILE = "ioc-meta.json"
AUDIT_FILE = "audit-log.jsonl"
DB_FILE = "ioc_manager.db"

def migrate_users():
    if not os.path.exists(USERS_FILE):
        print("No users.json found.")
        return

    print("Migrating users...")
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        users = json.load(f)

    conn = get_db()
    c = conn.cursor()
    
    count = 0
    for u in users:
        # Check if exists
        c.execute("SELECT 1 FROM users WHERE username = ?", (u["username"],))
        if c.fetchone():
            continue
            
        c.execute('''
            INSERT INTO users (username, password_hash, role, created_at, allowed_feeds)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            u["username"],
            u["password_hash"],
            u.get("role", "editor"),
            u.get("created_at"),
            json.dumps(u.get("allowed_feeds", []))
        ))
        count += 1
    
    conn.commit()
    conn.close()
    print(f"Migrated {count} users.")

def migrate_meta():
    if not os.path.exists(META_FILE):
        print("No ioc-meta.json found.")
        return

    print("Migrating IP metadata...")
    with open(META_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    details = data.get("ip_details", {})
    by_ip = data.get("by_ip", {}) # Helper map

    conn = get_db()
    c = conn.cursor()
    
    count = 0
    for ip, info in details.items():
        # Check if exists
        c.execute("SELECT 1 FROM ip_metadata WHERE ip = ?", (ip,))
        if c.fetchone():
            continue

        # Extract fields
        source = info.get("source") or by_ip.get(ip, "manual")
        tags = json.dumps(info.get("tags", []))
        alert_ids = json.dumps(info.get("alert_ids", []))
        history = json.dumps(info.get("history", []))
        
        # Calculate TTL/Expiry based on active feeds logic if possible
        # For now, store what's in meta, which relies on 'expires_at'
        expires_at = info.get("expires_at")
        # Estimate 'ttl' from expires_at logic? Or default 0?
        # We'll store what we have.
        
        c.execute('''
            INSERT INTO ip_metadata (ip, source, tags, added_at, ttl, expiration_date, alert_ids, history)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            ip,
            source,
            tags,
            info.get("last_update"), # Using last_update as added_at proxy if creation not verified
            '0', # Default, hard to infer specific int TTL from just meta without feed parsing
            expires_at,
            alert_ids,
            history
        ))
        count += 1

    conn.commit()
    conn.close()
    print(f"Migrated {count} IP metadata records.")

def migrate_audit():
    if not os.path.exists(AUDIT_FILE):
        print("No audit-log.jsonl found.")
        return

    print("Migrating Audit Log...")
    conn = get_db()
    c = conn.cursor()
    
    count = 0
    with open(AUDIT_FILE, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip(): continue
            try:
                entry = json.loads(line)
                c.execute('''
                    INSERT INTO audit_log (ts, event, actor, scope, details)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    entry.get("ts"),
                    entry.get("event"),
                    entry.get("actor"),
                    entry.get("scope"),
                    json.dumps(entry.get("details", {}))
                ))
                count += 1
            except Exception as e:
                print(f"Skipping bad audit line: {e}")

    conn.commit()
    conn.close()
    print(f"Migrated {count} audit logs.")

if __name__ == "__main__":
    init_db()
    migrate_users()
    migrate_meta()
    migrate_audit()
    print("Migration Complete.")
