
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

    # Tabla: Configuración (Llave-Valor)
    c.execute('''
    CREATE TABLE IF NOT EXISTS config (
        key TEXT PRIMARY KEY,
        value TEXT
    )
    ''')

    # Tabla: Métricas Históricas (Dashboard)
    c.execute('''
    CREATE TABLE IF NOT EXISTS history_metrics (
        date TEXT PRIMARY KEY,  -- YYYY-MM-DD
        total INTEGER DEFAULT 0,
        manual INTEGER DEFAULT 0,
        csv INTEGER DEFAULT 0,
        api INTEGER DEFAULT 0,
        tags_json TEXT          -- JSON con desglose de tags
    )
    ''')


    # Tabla: API Keys (Nombre, Token, Scopes)
    c.execute('''
    CREATE TABLE IF NOT EXISTS api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        token TEXT UNIQUE NOT NULL,
        scopes TEXT NOT NULL, -- "READ,WRITE,ALL"
        created_at TEXT
    )
    ''')

    # Tabla: Historial de Tests
    c.execute('''
    CREATE TABLE IF NOT EXISTS test_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        success INTEGER, -- 1=OK, 0=Fail
        output TEXT,
        actor TEXT
    )
    ''')

    # Indices
    c.execute('CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_audit_event ON audit_log(event)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_meta_source ON ip_metadata(source)')

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

def create_user(username, password_hash, role="editor", allowed_feeds=None):
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO users (username, password_hash, role, created_at, allowed_feeds) VALUES (?, ?, ?, ?, ?)",
            (
                username, 
                password_hash, 
                role, 
                _iso(datetime.now(timezone.utc)),
                json.dumps(allowed_feeds or [], ensure_ascii=False)
            )
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
        # Build dynamic update
        fields = []
        params = []
        if role is not None:
            fields.append("role = ?")
            params.append(role)
        if allowed_feeds is not None:
            fields.append("allowed_feeds = ?")
            params.append(json.dumps(allowed_feeds, ensure_ascii=False))
        if password_hash is not None:
            fields.append("password_hash = ?")
            params.append(password_hash)
            
        if not fields:
            return True # Nothing to update
            
        params.append(username)
        query = f"UPDATE users SET {', '.join(fields)} WHERE username = ?"
        
        conn.execute(query, tuple(params))
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
    except Exception as e:
        print(f"DB Delete User Error: {e}")
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

def get_audit_log(limit=500):
    """
    Recupera los últimos registros de auditoría de la base de datos.
    """
    try:
        conn = get_db()
        # Orden descendente por ID o TS para ver lo más reciente arriba
        rows = conn.execute(
            "SELECT ts, event, actor, scope, details FROM audit_log ORDER BY id DESC LIMIT ?",
            (limit,)
        ).fetchall()
        conn.close()
        
        result = []
        for r in rows:
            d = dict(r)
            try:
                d['details'] = json.loads(d['details']) if d['details'] else {}
            except:
                d['details'] = {}
            result.append(d)
        return result
    except Exception as e:
        print(f"Error fetching audit log: {e}")
        return []

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

def bulk_upsert_ips(ip_list):
    """
    Inserta o actualiza multiples IPs en una sola transaccion.
    ip_list: Lista de diccionarios con keys: ip, source, tags, ttl, expiration_date, alert_ids, history
    """
    if not ip_list:
        return True
        
    try:
        conn = get_db()
        # Usamos executemany para maxima velocidad
        # Preparamos los datos
        params = []
        for item in ip_list:
            params.append((
                item['ip'],
                item['source'],
                json.dumps(item.get('tags', []), ensure_ascii=False),
                _iso(datetime.now(timezone.utc)), # added_at (always update?)
                str(item.get('ttl', 0)),
                _iso(item['expiration_date']) if isinstance(item.get('expiration_date'), datetime) else item.get('expiration_date'),
                json.dumps(item.get('alert_ids', []), ensure_ascii=False),
                json.dumps(item.get('history', []), ensure_ascii=False)
            ))

        conn.executemany("""
            INSERT INTO ip_metadata (ip, source, tags, added_at, ttl, expiration_date, alert_ids, history)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                source=excluded.source,
                tags=excluded.tags,
                ttl=excluded.ttl,
                expiration_date=excluded.expiration_date,
                alert_ids=excluded.alert_ids,
                history=excluded.history
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

def remove_tag(ip, tag):
    """
    Elimina un tag específico de una IP.
    """
    try:
        ip_data = get_ip(ip)
        if not ip_data:
            return False
            
        tags = []
        if ip_data['tags']:
            try:
                tags = json.loads(ip_data['tags'])
            except:
                pass
                
        if tag in tags:
            tags.remove(tag)
            # Update DB (partial update of tags)
            conn = get_db()
            conn.execute("UPDATE ip_metadata SET tags = ? WHERE ip = ?", (json.dumps(tags, ensure_ascii=False), ip))
            conn.commit()
            conn.close()
            return True
        return True # Tag no estaba, éxito

    except Exception as e:
        print(f"DB Remove Tag Error: {e}")
        return False

def update_ip_ttl(ip, new_ttl):
    """
    Actualiza solo el TTL de una IP.
    """
    try:
        conn = get_db()
        conn.execute("UPDATE ip_metadata SET ttl = ? WHERE ip = ?", (str(new_ttl), ip))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"DB Update TTL Error: {e}")
        return False


# --- Tag Management Helpers ---
def add_tag(ip, tag):
    """
    Añade un tag específico a una IP si no lo tiene ya.
    """
    try:
        ip_data = get_ip(ip)
        if not ip_data:
            return False
            
        tags = []
        if ip_data['tags']:
            try:
                tags = json.loads(ip_data['tags'])
            except:
                pass
                
        if tag not in tags:
            tags.append(tag)
            conn = get_db()
            conn.execute("UPDATE ip_metadata SET tags = ? WHERE ip = ?", (json.dumps(tags, ensure_ascii=False), ip))
            conn.commit()
            conn.close()
            return True
        return False # Tag ya existía
    except Exception as e:
        print(f"DB Add Tag Error: {e}")
        return False

def bulk_add_tag(ip_list, tag):
    """
    Añade el tag a todas las IPs de la lista.
    Retorna True si al menos una IP fue modificada.
    """
    modified = False
    try:
        conn = get_db()
        for ip in ip_list:
            # Check existing tags
            row = conn.execute("SELECT tags FROM ip_metadata WHERE ip = ?", (ip,)).fetchone()
            if not row: continue
            
            curr_tags = []
            if row['tags']:
                try: curr_tags = json.loads(row['tags'])
                except: pass
            
            if tag not in curr_tags:
                curr_tags.append(tag)
                conn.execute("UPDATE ip_metadata SET tags = ? WHERE ip = ?", (json.dumps(curr_tags, ensure_ascii=False), ip))
                modified = True
        
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"DB Bulk Add Error: {e}")
    return modified

def bulk_remove_tag(ip_list, tag):
    """
    Elimina el tag de todas las IPs de la lista.
    Retorna True si al menos una IP fue modificada.
    """
    modified = False
    try:
        conn = get_db()
        for ip in ip_list:
            row = conn.execute("SELECT tags FROM ip_metadata WHERE ip = ?", (ip,)).fetchone()
            if not row: continue
            
            curr_tags = []
            if row['tags']:
                try: curr_tags = json.loads(row['tags'])
                except: pass
            
            if tag in curr_tags:
                curr_tags.remove(tag)
                conn.execute("UPDATE ip_metadata SET tags = ? WHERE ip = ?", (json.dumps(curr_tags, ensure_ascii=False), ip))
                modified = True
        
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"DB Bulk Remove Error: {e}")
    return modified


def save_daily_snapshot(counters):
    """
    Guarda o actualiza la foto de contadores para el día de hoy.
    counters: dict con {total, manual, csv, api, tags: dict}
    """
    try:
        today = datetime.now().strftime('%Y-%m-%d')
        conn = get_db()
        
        tags_json = json.dumps(counters.get('tags', {}))
        
        # INSERT OR REPLACE para mantener actualizado el día actual
        conn.execute('''
            INSERT OR REPLACE INTO history_metrics (date, total, manual, csv, api, tags_json)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            today, 
            counters.get('total', 0), 
            counters.get('manual', 0), 
            counters.get('csv', 0), 
            counters.get('api', 0), 
            tags_json
        ))
        
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"⚠️ Error saving daily snapshot: {e}")

def get_metrics_history(limit=30):
    """
    Devuelve lista de objetos históricos ordenados por fecha asc.
    """
    try:
        conn = get_db()
        rows = conn.execute('SELECT * FROM history_metrics ORDER BY date DESC LIMIT ?', (limit,)).fetchall()
        conn.close()
        
        # Convertir a lista y ordenar cronológicamente para Chart.js
        history = []
        for r in rows:
            history.append({
                'date': r['date'],
                'total': r['total'],
                'sources': {
                    'manual': r['manual'],
                    'csv': r['csv'],
                    'api': r['api']
                },
                'tags': json.loads(r['tags_json']) if r['tags_json'] else {}
            })
        
        return sorted(history, key=lambda x: x['date']) # Retornar ASC para la gráfica
    except Exception as e:
        print(f"⚠️ Error fetching history: {e}")
        return []

# --- Test History Helpers ---
def save_test_run(success, output, actor="system"):
    try:
        conn = get_db()
        conn.execute('INSERT INTO test_runs (ts, success, output, actor) VALUES (?, ?, ?, ?)',
                     (datetime.now().isoformat(), 1 if success else 0, output, actor))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"⚠️ Error saving test run: {e}")

def get_test_history(limit=10):
    try:
        conn = get_db()
        rows = conn.execute('SELECT * FROM test_runs ORDER BY ts DESC LIMIT ?', (limit,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception as e:
        print(f"⚠️ Error fetching test history: {e}")
        return []

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
        conn.execute("INSERT INTO config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error setting config {key}: {e}")
        return False
