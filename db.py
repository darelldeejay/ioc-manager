import sqlite3
import os
import json
from datetime import datetime, timezone

def _iso(dt: datetime) -> str:
    """Formatea una fecha a ISO 8601 con sufijo Z (UTC)."""
    if dt is None: return None
    if isinstance(dt, str): return dt
    # Asegurar que tenga timezone, si no, asumir UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

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
    
    # Tabla: Metadata IPv4
    c.execute('''
    CREATE TABLE IF NOT EXISTS ip_metadata (
        ip TEXT PRIMARY KEY,
        source TEXT DEFAULT 'manual',
        tags TEXT, 
        added_at TEXT,
        ttl TEXT DEFAULT '0',
        expiration_date TEXT,
        alert_ids TEXT, 
        history TEXT 
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

    # Tabla: Configuración
    c.execute('''
    CREATE TABLE IF NOT EXISTS config (
        key TEXT PRIMARY KEY,
        value TEXT
    )
    ''')

    # Tabla: Métricas Históricas
    c.execute('''
    CREATE TABLE IF NOT EXISTS history_metrics (
        date TEXT PRIMARY KEY,
        total INTEGER DEFAULT 0,
        manual INTEGER DEFAULT 0,
        csv INTEGER DEFAULT 0,
        api INTEGER DEFAULT 0,
        tags_json TEXT
    )
    ''')

    # Tabla: API Keys
    c.execute('''
    CREATE TABLE IF NOT EXISTS api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        token TEXT UNIQUE NOT NULL,
        scopes TEXT NOT NULL,
        created_at TEXT
    )
    ''')

    # Tabla: Historial de Tests
    c.execute('''
    CREATE TABLE IF NOT EXISTS test_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        success INTEGER,
        output TEXT,
        actor TEXT
    )
    ''')

    # Tabla: Logs de Acceso al Feed
    c.execute('''
    CREATE TABLE IF NOT EXISTS feed_access_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        remote_ip TEXT,
        user_agent TEXT,
        status_code INTEGER,
        details TEXT -- JSON
    )
    ''')

    # Índices
    c.execute('CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_audit_event ON audit_log(event)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_meta_source ON ip_metadata(source)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_feed_ts ON feed_access_log(ts)')

    conn.commit()
    conn.close()

# --- Config Helpers ---
def get_config(key, default=None):
    try:
        conn = get_db()
        row = conn.execute("SELECT value FROM config WHERE key = ?", (key,)).fetchone()
        conn.close()
        return row['value'] if row else default
    except Exception:
        return default

def set_config(key, value):
    try:
        conn = get_db()
        conn.execute("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", (key, str(value)))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"DB Set Config Error: {e}")
        return False

# --- API Key Helpers ---
def create_api_key(name, token, scopes):
    try:
        conn = get_db()
        created_at = _iso(datetime.now(timezone.utc))
        conn.execute(
            "INSERT INTO api_keys (name, token, scopes, created_at) VALUES (?, ?, ?, ?)",
            (name, token, scopes, created_at)
        )
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"DB Create API Key Error: {e}")
        return False

def list_api_keys():
    try:
        conn = get_db()
        rows = conn.execute("SELECT * FROM api_keys ORDER BY created_at DESC").fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []

def delete_api_key(key_id):
    try:
        conn = get_db()
        conn.execute("DELETE FROM api_keys WHERE id = ?", (key_id,))
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False

def get_api_key(token):
    try:
        conn = get_db()
        row = conn.execute("SELECT * FROM api_keys WHERE token = ?", (token,)).fetchone()
        conn.close()
        return dict(row) if row else None
    except Exception:
        return None

# --- User Helpers ---
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
        return dict(row) if row else None
    except Exception:
        return None

def create_user(username, password_hash, role="editor", allowed_feeds=None):
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO users (username, password_hash, role, created_at, allowed_feeds) VALUES (?, ?, ?, ?, ?)",
            (username, password_hash, role, _iso(datetime.now(timezone.utc)), json.dumps(allowed_feeds or []))
        )
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"DB Create User Error: {e}")
        return False

def update_user(username, role=None, allowed_feeds=None, password_hash=None):
    try:
        conn = get_db()
        fields, params = [], []
        if role is not None:
            fields.append("role = ?"); params.append(role)
        if allowed_feeds is not None:
            fields.append("allowed_feeds = ?"); params.append(json.dumps(allowed_feeds))
        if password_hash is not None:
            fields.append("password_hash = ?"); params.append(password_hash)
        if not fields: return True
        params.append(username)
        conn.execute(f"UPDATE users SET {', '.join(fields)} WHERE username = ?", tuple(params))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"DB Update User Error: {e}")
        return False

def delete_user(username):
    try:
        conn = get_db()
        conn.execute("DELETE FROM users WHERE username = ?", (username,))
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False

# --- Audit & Feed Logs ---
def db_audit(event, actor, scope, details=None):
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO audit_log (ts, event, actor, scope, details) VALUES (?, ?, ?, ?, ?)",
            (_iso(datetime.now(timezone.utc)), str(event), str(actor), str(scope), json.dumps(details or {}))
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"DB Audit Error: {e}")

def get_audit_log(limit=500):
    try:
        conn = get_db()
        rows = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        conn.close()
        result = []
        for r in rows:
            d = dict(r)
            try: d['details'] = json.loads(d['details']) if d['details'] else {}
            except: d['details'] = {}
            result.append(d)
        return result
    except Exception:
        return []

def log_feed_access(remote_ip, user_agent, status_code, details=None):
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO feed_access_log (ts, remote_ip, user_agent, status_code, details) VALUES (?, ?, ?, ?, ?)",
            (_iso(datetime.now(timezone.utc)), remote_ip, user_agent, status_code, json.dumps(details or {}))
        )
        conn.execute("DELETE FROM feed_access_log WHERE id NOT IN (SELECT id FROM feed_access_log ORDER BY id DESC LIMIT 1000)")
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"DB Log Feed Error: {e}")

def get_feed_access_logs(limit=10):
    try:
        conn = get_db()
        rows = conn.execute("SELECT * FROM feed_access_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        conn.close()
        result = []
        for r in rows:
            d = dict(r)
            try: d['details'] = json.loads(d['details']) if d['details'] else {}
            except: d['details'] = {}
            result.append(d)
        return result
    except Exception:
        return []

# --- IP Management ---
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
    try:
        conn = get_db()
        conn.execute("""
            INSERT INTO ip_metadata (ip, source, tags, added_at, ttl, expiration_date, alert_ids, history)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                source=excluded.source, tags=excluded.tags, ttl=excluded.ttl,
                expiration_date=excluded.expiration_date, alert_ids=excluded.alert_ids, history=excluded.history
        """, (ip, source, json.dumps(tags), _iso(datetime.now(timezone.utc)), str(ttl), 
              _iso(expiration_date) if isinstance(expiration_date, datetime) else expiration_date,
              json.dumps(alert_ids or []), json.dumps(history or [])))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"DB Upsert IP Error: {e}")
        return False

def bulk_upsert_ips(ip_list):
    if not ip_list: return True
    try:
        conn = get_db()
        params = []
        for it in ip_list:
            params.append((it['ip'], it['source'], json.dumps(it.get('tags', [])), _iso(datetime.now(timezone.utc)),
                           str(it.get('ttl', 0)), _iso(it.get('expiration_date')) if isinstance(it.get('expiration_date'), datetime) else it.get('expiration_date'),
                           json.dumps(it.get('alert_ids', [])), json.dumps(it.get('history', []))))
        conn.executemany("""
            INSERT INTO ip_metadata (ip, source, tags, added_at, ttl, expiration_date, alert_ids, history)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                source=excluded.source, tags=excluded.tags, ttl=excluded.ttl,
                expiration_date=excluded.expiration_date, alert_ids=excluded.alert_ids, history=excluded.history
        """, params)
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"DB Bulk Upsert Error: {e}")
        return False

def delete_ip(ip):
    try:
        conn = get_db()
        conn.execute("DELETE FROM ip_metadata WHERE ip = ?", (ip,))
        conn.commit()
        conn.close()
        return True
    except Exception: return False

def delete_all_ips():
    try:
        conn = get_db()
        conn.execute("DELETE FROM ip_metadata")
        conn.commit()
        conn.close()
        return True
    except Exception: return False

def update_ip_ttl(ip, new_ttl):
    try:
        conn = get_db()
        conn.execute("UPDATE ip_metadata SET ttl = ? WHERE ip = ?", (str(new_ttl), ip))
        conn.commit()
        conn.close()
        return True
    except Exception: return False

# --- Tags ---
def add_tag(ip, tag):
    try:
        data = get_ip(ip)
        if not data: return False
        tags = json.loads(data['tags']) if data['tags'] else []
        if tag not in tags:
            tags.append(tag)
            conn = get_db()
            conn.execute("UPDATE ip_metadata SET tags = ? WHERE ip = ?", (json.dumps(tags), ip))
            conn.commit()
            conn.close()
            return True
        return False
    except Exception: return False

def remove_tag(ip, tag):
    try:
        data = get_ip(ip)
        if not data: return False
        tags = json.loads(data['tags']) if data['tags'] else []
        if tag in tags:
            tags.remove(tag)
            conn = get_db()
            conn.execute("UPDATE ip_metadata SET tags = ? WHERE ip = ?", (json.dumps(tags), ip))
            conn.commit()
            conn.close()
            return True
        return True
    except Exception: return False

def bulk_add_tag(ip_list, tag):
    modified = False
    try:
        conn = get_db()
        for ip in ip_list:
            row = conn.execute("SELECT tags FROM ip_metadata WHERE ip = ?", (ip,)).fetchone()
            if not row: continue
            tags = json.loads(row['tags']) if row['tags'] else []
            if tag not in tags:
                tags.append(tag)
                conn.execute("UPDATE ip_metadata SET tags = ? WHERE ip = ?", (json.dumps(tags), ip))
                modified = True
        conn.commit()
        conn.close()
    except Exception: pass
    return modified

def bulk_remove_tag(ip_list, tag):
    modified = False
    try:
        conn = get_db()
        for ip in ip_list:
            row = conn.execute("SELECT tags FROM ip_metadata WHERE ip = ?", (ip,)).fetchone()
            if not row: continue
            tags = json.loads(row['tags']) if row['tags'] else []
            if tag in tags:
                tags.remove(tag)
                conn.execute("UPDATE ip_metadata SET tags = ? WHERE ip = ?", (json.dumps(tags), ip))
                modified = True
        conn.commit()
        conn.close()
    except Exception: pass
    return modified

# --- Metrics ---
def save_daily_snapshot(counters):
    try:
        today = datetime.now().strftime('%Y-%m-%d')
        conn = get_db()
        conn.execute('''
            INSERT OR REPLACE INTO history_metrics (date, total, manual, csv, api, tags_json)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (today, counters.get('total', 0), counters.get('manual', 0), counters.get('csv', 0), counters.get('api', 0), json.dumps(counters.get('tags', {}))))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"DB Metrics Error: {e}")

def get_metrics_history(limit=30):
    try:
        conn = get_db()
        rows = conn.execute('SELECT * FROM history_metrics ORDER BY date DESC LIMIT ?', (limit,)).fetchall()
        conn.close()
        history = []
        for r in rows:
            history.append({'date': r['date'], 'total': r['total'], 'sources': {'manual': r['manual'], 'csv': r['csv'], 'api': r['api']}, 'tags': json.loads(r['tags_json']) if r['tags_json'] else {}})
        return sorted(history, key=lambda x: x['date'])
    except Exception: return []

# --- Test History ---
def save_test_run(success, output, actor="system"):
    try:
        conn = get_db()
        conn.execute('INSERT INTO test_runs (ts, success, output, actor) VALUES (?, ?, ?, ?)', (datetime.now().isoformat(), 1 if success else 0, output, actor))
        conn.commit()
        conn.close()
    except Exception: pass

def get_test_history(limit=10):
    try:
        conn = get_db()
        rows = conn.execute('SELECT * FROM test_runs ORDER BY ts DESC LIMIT ?', (limit,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception: return []
