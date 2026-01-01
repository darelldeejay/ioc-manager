
import sqlite3
import json
from datetime import datetime
import os

DB_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), "ioc_manager.db")

def days_remaining(added_at_arg, ttl_arg):
    try:
        ttl = int(ttl_arg)
    except:
        return f"Error TTL: {ttl_arg}" 

    if ttl <= 0:
        return "Permanent"

    if not added_at_arg:
        return "No Date"

    try:
        # Try Parsing ISO
        dt = datetime.fromisoformat(str(added_at_arg).replace("Z", "+00:00"))
        if dt.tzinfo:
            dt = dt.replace(tzinfo=None)
    except:
        try:
            dt = datetime.strptime(str(added_at_arg), "%Y-%m-%d")
        except:
            return f"Error Date Parse: {added_at_arg}"

    delta = (datetime.now() - dt).days
    left = ttl - delta
    return left if left >= 0 else 0

def check_db():
    if not os.path.exists(DB_PATH):
        print(f"DB not found at {DB_PATH}")
        return

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    try:
        c.execute("SELECT ip, ttl, added_at FROM ip_metadata LIMIT 10")
        rows = c.fetchall()
        print(f"Checking {len(rows)} IPs...")
        for r in rows:
            ip = r['ip']
            ttl = r['ttl']
            added = r['added_at']
            
            res = days_remaining(added, ttl)
            print(f"IP: {ip} | TTL: {ttl} | Added: {added} | -> Remaining: {res}")
            
    except Exception as e:
        print(f"DB Error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    check_db()
