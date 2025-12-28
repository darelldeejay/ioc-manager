
import sqlite3
import os
import json
from datetime import datetime, timezone

DB_FILE = os.path.join(os.path.dirname(os.path.realpath(__file__)), "ioc_manager.db")

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    
    # Tabla: Usuarios
    c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'editor',
        created_at TEXT,
        last_login TEXT,
        allowed_feeds TEXT -- JSON list
    )
    ''')
    
    # Tabla: Metadata IPv4 (Estado actual)
    # Stores tags, source, ttl, and misc details.
    # The actual "feed" is still generated from this state + flat files, or we move to full DB?
    # Requirement: "Pasar ip_details + audit a SQLite".
    c.execute('''
    CREATE TABLE IF NOT EXISTS ip_metadata (
        ip TEXT PRIMARY KEY,
        source TEXT DEFAULT 'manual', -- manual, csv, api
        tags TEXT, -- JSON list ["Multicliente", "BPE"]
        added_at TEXT,
        ttl TEXT DEFAULT '0', -- 0=permanent, or days
        expiration_date TEXT,
        alert_ids TEXT, -- JSON list of tickets
        history TEXT -- JSON list of changes
    )
    ''')

    # Tabla: Auditoría
    c.execute('''
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        event TEXT NOT NULL,
        actor TEXT,
        scope TEXT,
        details TEXT -- JSON
    )
    ''')

    # Indices
    c.execute('CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_audit_event ON audit_log(event)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_meta_source ON ip_metadata(source)')

    conn.commit()
    conn.close()

def _iso(dt: datetime) -> str:
    if dt is None: return None
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

# --- Helpers de acceso (CRUD basico) ---

def get_user_count():
    try:
        conn = get_db()
        row = conn.execute("SELECT COUNT(*) as count FROM users").fetchone()
        conn.close()
        return row['count']
    except Exception:
        return 0

def get_user_by_username(username):
    try:
        conn = get_db()
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()
        if row:
            return dict(row)
        return None
    except Exception:
        return None

def create_user(username, password_hash, role="editor"):
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (username, password_hash, role, _iso(datetime.now(timezone.utc)))
        )
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"DB Create User Error: {e}")
        return False

def db_audit(event, actor, scope, details=None):
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO audit_log (ts, event, actor, scope, details) VALUES (?, ?, ?, ?, ?)",
            (
                _iso(datetime.now(timezone.utc)), 
                str(event), 
                str(actor), 
                str(scope), # Ensure scope is string, even if dict passed by mistake
                json.dumps(details or {}, ensure_ascii=False)
            )
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"DB Log Error: {e}")

# --- Helpers de acceso (CRUD basico) ---

# ... User Helpers ...

# --- IP Metadata Helpers ---

def get_ip(ip):
    try:
        conn = get_db()
        row = conn.execute("SELECT * FROM ip_metadata WHERE ip = ?", (ip,)).fetchone()
        conn.close()
        return dict(row) if row else None
    except Exception:
        return None

def get_all_ips():
    try:
        conn = get_db()
        rows = conn.execute("SELECT * FROM ip_metadata").fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []

def upsert_ip(ip, source, tags, ttl, expiration_date, alert_ids, history):
    """
    Inserta o actualiza una IP completa.
    tags, alert_ids, history deben ser listas/dicts pasados como objetos Python (se convierten a JSON aquí).
    """
    try:
        conn = get_db()
        conn.execute("""
            INSERT INTO ip_metadata (ip, source, tags, added_at, ttl, expiration_date, alert_ids, history)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                source=excluded.source,
                tags=excluded.tags,
                ttl=excluded.ttl,
                expiration_date=excluded.expiration_date,
                alert_ids=excluded.alert_ids,
                history=excluded.history
        """, (
            ip, 
            source, 
            json.dumps(tags, ensure_ascii=False), 
            _iso(datetime.now(timezone.utc)), # updated/added at
            str(ttl), 
            _iso(expiration_date) if isinstance(expiration_date, datetime) else expiration_date,
            json.dumps(alert_ids or [], ensure_ascii=False),
            json.dumps(history or [], ensure_ascii=False)
        ))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"DB Upsert IP Error: {e}")
        return False

def delete_ip(ip):
    try:
        conn = get_db()
        conn.execute("DELETE FROM ip_metadata WHERE ip = ?", (ip,))
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False

def delete_all_ips():
    try:
        conn = get_db()
        conn.execute("DELETE FROM ip_metadata")
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False
