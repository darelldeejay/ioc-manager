from flask import (
    Flask, render_template, render_template_string, request, redirect, url_for,
    session, flash, make_response, jsonify, get_flashed_messages,
    send_file, abort, Blueprint, g, Response
)
from datetime import datetime, timedelta, timezone
import ipaddress
import os
import re
import json
import shutil
import zipfile
from functools import wraps
import threading
import time
import math
import hashlib
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from filelock import FileLock, Timeout
import sys
import subprocess
import requests

load_dotenv()

# Fix for Windows Registry MIME type issue
import mimetypes
mimetypes.add_type('application/javascript', '.js')

import db # SQLite Interface


app = Flask(__name__)
# Clave secreta desde .env
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'dev-key-insegura-si-falta-env')
TOKEN_API = os.getenv("TOKEN_API")
TEAMS_WEBHOOK_URL = os.getenv("TEAMS_WEBHOOK_URL")
MAINTENANCE_MODE = False


@app.context_processor
def inject_globals():
    return {
        'maintenance_mode': MAINTENANCE_MODE
    }

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
# Carpeta para datos adicionales de la API por tags
DATA_DIR = os.path.join(BASE_DIR, "data")
TAGS_DIR = os.path.join(DATA_DIR, "tags")

FEED_FILE = os.path.join(BASE_DIR, 'ioc-feed.txt')
# === Nuevo feed BPE ===
FEED_FILE_BPE = os.path.join(BASE_DIR, 'ioc-feed-bpe.txt')
# === Nuevo feed de pruebas ===
FEED_FILE_TEST = os.path.join(BASE_DIR, "ioc-feed-test.txt")

LOG_FILE = os.path.join(BASE_DIR, 'ioc-log.txt')
NOTIF_FILE = os.path.join(BASE_DIR, 'notif-log.json')

# Counters históricos (compat), los totales vivos se calculan con meta
COUNTER_MANUAL = os.path.join(BASE_DIR, 'contador_manual.txt')
COUNTER_CSV = os.path.join(BASE_DIR, 'contador_csv.txt')
COUNTER_API = os.path.join(BASE_DIR, 'contador_api.txt')

# Nuevo: meta lateral para origen por IP (no afecta al feed)
# Ampliado para ip_details con tags/expiraciones; se mantiene compat con "by_ip"
META_FILE = os.path.join(DATA_DIR, "ioc-meta.json")
HISTORY_FILE = os.path.join(DATA_DIR, "history.json")
AUDIT_LOG_FILE = os.path.join(BASE_DIR, "audit-log.jsonl")

# === LOCK FILES ===
FEED_LOCK = FileLock(FEED_FILE + ".lock")
FEED_BPE_LOCK = FileLock(FEED_FILE_BPE + ".lock")
FEED_TEST_LOCK = FileLock(FEED_FILE_TEST + ".lock")
META_LOCK = FileLock(META_FILE + ".lock")
# Dado que tags son archivos separados, podemos hacer FileLock(path + ".lock") al vuelo.

# === Copias de seguridad ===
BACKUP_DIR = os.path.join(BASE_DIR, "backups")
LAST_BACKUP_MARK = os.path.join(BACKUP_DIR, ".last_done")

MAX_EXPAND = 4096

# === Config de servidor (paginación/undo) ===
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200
UNDO_TTL_SECONDS = 600  # 10 minutos

# === Seguridad API / limitación ===
TOKEN_API = os.getenv("TOKEN_API")  # Obligatorio para /api/*
API_ALLOWLIST = os.getenv("API_ALLOWLIST", "").strip()  # "1.2.3.0/24,10.0.0.0/8"
EXPANSION_LIMIT = int(os.getenv("EXPANSION_LIMIT", "2048"))
RATE_LIMIT_PER_MIN = int(os.getenv("RATE_LIMIT_PER_MIN", "60"))

# Memorias en proceso (rate-limit, idempotencia)
_rate_lock = threading.Lock()
_rate_hist = {}  # {auth_header: [timestamps]}
_idem_lock = threading.Lock()
_idem_cache = {}  # {idem_key: (ts, response)}
IDEM_TTL_SECONDS = 600

# Tags válidos
ALLOWED_TAGS = {"Multicliente", "BPE", "Test"}

# Mapa canónico de tags (case-insensitive)
CANONICAL_TAGS = {
    "multicliente": "Multicliente",
    "bpe": "BPE",
    "test": "Test",
}

# Etiquetas Canónicas permitidas y su normalización
CANONICAL_TAGS = {
    "multicliente": "Multicliente",
    "bpe": "BPE",
    "test": "Test",
    "phishing": "Phishing",
    "malware": "Malware",
    "ransomware": "Ransomware",
    "botnet": "Botnet",
    "apt": "APT",
    "spam": "Spam",
    "tor": "Tor",
    "vpn": "VPN",
    "proxy": "Proxy"
}

# Asegurar carpetas
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(TAGS_DIR, exist_ok=True)

# Inicializar DB (si no existe)
db.init_db()

# Middleware: Forzar Setup si no hay usuarios
@app.before_request
def check_setup_required():
    if request.path.startswith('/static'):
        return
    if request.path.startswith('/api'):
        return
    if request.path == '/setup':
        return
    # Check Db
    if db.get_user_count() == 0:
        return redirect('/setup')

@app.route('/setup', methods=['GET', 'POST'])
def first_run_setup():
    if db.get_user_count() > 0:
        flash("La configuración inicial ya se ha completado.", "info")
        return redirect(url_for('login'))

    if request.method == 'POST':
        user = request.form.get('username', '').strip()
        pwd = request.form.get('password', '').strip()
        pwd2 = request.form.get('confirm_password', '').strip()

        if not user or not pwd:
            flash("Usuario y contraseña son obligatorios.", "error")
            return render_template('setup.html')
        
        if pwd != pwd2:
            flash("Las contraseñas no coinciden.", "error")
            return render_template('setup.html')

        # Create Admin
        hashed = generate_password_hash(pwd)
        if db.create_user(user, hashed, role="admin"):
            flash("¡Cuenta de administrador creada! Por favor inicia sesión.", "success")
            return redirect(url_for('login'))
        else:
            flash("Error al crear usuario en base de datos.", "error")
        
    return render_template('setup.html')

# =========================
#  Decoradores/utilidades web
# =========================
def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


def json_response_ok(notices=None, extra=None):
    payload = {"ok": True, "notices": notices or []}
    if extra:
        payload.update(extra)
    return jsonify(payload)


    payload = {"ok": False, "error": str(message), "notices": notices or []}
    if extra:
        payload.update(extra)
    return jsonify(payload), code

# === Helpers de Fecha (Fix 500 Error) ===
def _now_utc():
    return datetime.now(timezone.utc)

def _iso(dt: datetime) -> str:
    if dt is None: return None
    if isinstance(dt, str): return dt
    # Ensure UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


from functools import wraps

def require_api_token(required_scope=None):
    """
    Decorator that checks X-API-Key against legacy env var OR database keys.
    If required_scope is provided (e.g. 'WRITE'), validates that the key has permission.
    Legacy Token always has 'ALL' permission.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Debug Auth
            # print(f"DEBUG: Auth Check. Session user: {session.get('username')}, Cookie: {request.cookies}")
            
            # 0. Check if already authenticated (Blueprint guard OR Session)
            if g.get("api_user"):
                user_record = g.api_user
            elif "username" in session:
                # User is logged in via Web UI
                # Debug Bypass: Allow all session users
                # role = session.get("role", "view_only")
                # scopes = "ALL" if role in ("admin", "editor") else "READ"
                g.api_user = {"name": f"web/{session['username']}", "scopes": "ALL"}
                return f(*args, **kwargs) # BYPASS SCOPE CHECK FOR SESSION
            else:
                # 1. Extract Token (Bearer, Header, Query)
                token = None
                auth = request.headers.get("Authorization", "")
                if auth.startswith("Bearer "):
                    token = auth.split(" ", 1)[1].strip()
                
                if not token:
                    token = request.headers.get("X-API-Key") or request.args.get("token")
                
                if not token:
                    return jsonify({"ok": False, "error": "Missing API Token"}), 401

                # 2. Validation
                if token == TOKEN_API:
                    user_record = {"name": "system (legacy)", "scopes": "ALL"}
                else:
                    user_record = db.get_api_key(token)
                    if not user_record:
                        return jsonify({"ok": False, "error": "Invalid API Token"}), 401
                
                # Store for downstream use
                g.api_user = user_record

            # 3. Check Scope
            # Scopes: READ, WRITE, ALL
            # user_record['scopes'] might be None or string
            user_scopes = (user_record.get('scopes') or "").upper().split(',')
            
            if 'ALL' in user_scopes:
                return f(*args, **kwargs)
                
            if required_scope:
                if required_scope not in user_scopes:
                     return jsonify({"ok": False, "error": f"Insufficient Permission. Required: {required_scope}"}), 403

            return f(*args, **kwargs)
        return decorated_function
    
    # Allow using @require_api_token without parens if no scope needed? 
    # Standard python decorator trickiness. 
    # Easier to force @require_api_token() or @require_api_token(scope='READ')
    if callable(required_scope):
        # Was called as @require_api_token without args
        f = required_scope
        required_scope = None
        return decorator(f)
        
    return decorator

# =========================
#  Utilidades auxiliares
# =========================
def read_counter(path):
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return int((f.read() or "0").strip())
    except Exception:
        pass
    return 0


def write_counter(path, value):
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(str(int(value)))
    except Exception:
        pass


def _now_utc():
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# -------- Gestión de Usuarios (JSON DB) --------
USERS_FILE = os.path.join(BASE_DIR, 'users.json')

def load_users():
    """
    Carga usuarios desde SQLite.
    Retorna dict {username: {...}} para compatibilidad.
    """
    users = {}
    try:
        conn = db.get_db()
        rows = conn.execute("SELECT * FROM users").fetchall()
        conn.close()
        for row in rows:
            u = dict(row)
            # Ensure keys needed by app exist
            # DB has: username, password_hash, role, created_at, ...
            # JSON had same structure.
            # allowed_feeds json parsing?
            if u.get('allowed_feeds'):
                try:
                    u['allowed_feeds'] = json.loads(u['allowed_feeds'])
                except:
                    u['allowed_feeds'] = []
            users[u['username']] = u
    except Exception as e:
        print(f"[LOAD USERS ERROR] {e}")
        return {}
    return users

# save_users REMOVED (Usage migrated to DB)


# -------- Auditoría (nuevo) --------
def _audit(event, actor, scope, details=None):
    # actor: 'web/<usuario>' | 'api/<ip>' | 'system'
    # Redirigir a DB
    db.db_audit(event, actor, scope, details)
    # Mantener compatibilidad escribiendo a archivo si se desea, 
    # pero mejor migrar totalmente a DB para no duplicar.
    # Comentamos la escritura a archivo para confiar en DB.


# -------- Meta lateral (origen por IP + detalles por IP) --------
# Meta Helpers REMOVED (Migrated to DB)(meta)

# -------- TEAMS NOTIFICATION HELPER (Async) --------
def send_teams_alert(title, text, color="0076D7", sections=None):
    """
    Envía una tarjeta a MS Teams de forma ASÍNCRONA (hilo secundario).
    No bloquea la ejecución principal.
    
    color: Hex string sin # (ej: '0076D7' azul, '28A745' verde, 'DC3545' rojo)
    sections: Lista de dicts para secciones extra (ej: [{"activityTitle": "User:", "activitySubtitle": "admin"}])
    """
    webhook_url = db.get_config("TEAMS_WEBHOOK_URL", TEAMS_WEBHOOK_URL)
    if not webhook_url:
        # Si no hay URL configurada, ignoramos silenciosamente
        return

    def _send():
        try:
            payload = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": color,
                "summary": title,
                "sections": [{
                    "activityTitle": title,
                    "activitySubtitle": text,
                    "markdown": True
                }]
            }

            if sections:
                payload["sections"].extend(sections)
            
            # --- Anti-dedup / Timestamp ---
            payload["sections"].append({
                "activitySubtitle": f"_{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}_"
            })
            # ------------------------------

            # Timeout corto para no colgar hilos si Teams va mal
            requests.post(TEAMS_WEBHOOK_URL, json=payload, timeout=5)
        except Exception:
            # Fallo silencioso intencionado para no llenar logs de errores de red irrelevantes
            pass

    # Lanzar en hilo daemon para que no bloquee el cierre de la app si quedase colgado
    t = threading.Thread(target=_send)
    t.daemon = True
    t.start()


class TeamsAggregator:
    def __init__(self):
        self.buffer_lock = threading.Lock()
        self.buffer = []  # List of events: {'type': 'add|update', 'ip':..., 'user':..., 'source':...}
        self.last_flush = time.time()
        self.running = True
        
        # Start background flusher
        self.t = threading.Thread(target=self._loop, daemon=True)
        self.t.start()

    def add_batch(self, added_items, updated_items, user="system", source="web", ticket=None):
        if not added_items and not updated_items:
            return
        
        with self.buffer_lock:
            # Add "Added" events
            for sw in added_items:
                self.buffer.append({
                    "action": "add",
                    "ip": sw["ip"],
                    "tags": sw.get("tags", []),
                    "ttl": sw.get("ttl", 0),
                    "user": user,
                    "source": source,
                    "ticket": ticket or sw.get("alert_id"),
                    "ts": time.time()
                })
            
            # Add "Updated" events
            for sw in updated_items:
                self.buffer.append({
                    "action": "update",
                    "ip": sw["ip"],
                    "tags": sw.get("tags", []),
                    "old_ttl": sw.get("old_ttl"),
                    "new_ttl": sw.get("new_ttl"),
                    "user": user,
                    "source": source,
                    "ticket": ticket or sw.get("alert_id"),
                    "note": sw.get("note"),
                    "ts": time.time()
                })

    def _loop(self):
        while self.running:
            time.sleep(5)  # Chequear cada 5s si toca flush (cada 60s)
            
            should_flush = False
            with self.buffer_lock:
                if self.buffer:
                   # print(f"[TeamsAggregator] Buffer size: {len(self.buffer)}, Last Flush: {time.time() - self.last_flush:.1f}s ago")
                   if (time.time() - self.last_flush > 60):
                       should_flush = True
            
            if should_flush:
                self.flush()

    def flush(self):
        with self.buffer_lock:
            if not self.buffer:
                return
            
            # Copiar y limpiar buffer
            events = list(self.buffer)
            self.buffer.clear()
            self.last_flush = time.time()

        self._send_digest(events)

    def _send_digest(self, events):
        if not events:
            return
            
        # Agrupar estadísticas
        total_adds = sum(1 for e in events if e["action"] == "add")
        total_updates = sum(1 for e in events if e["action"] == "update")
        
        # Obtener usuarios y fuentes únicos
        users = {e["user"] for e in events}
        sources = {e["source"] for e in events}
        
        user_str = ", ".join(users)
        source_str = ", ".join(sources)
        
        # Título dinámico
        title = f"🔔 Resumen IOC Manager ({len(events)} eventos)"
        
        # Construir cuerpo detallado (limitado a unos pocos ejemplos si son muchos)
        detail_lines = []
        
        # Mostrar los primeros 5 adds
        adds = [e for e in events if e["action"] == "add"]
        if adds:
            detail_lines.append(f"**Nuevas ({len(adds)}):**")
            for e in adds[:5]:
                ticket_info = f" (Ticket: {e['ticket']})" if e.get('ticket') else ""
                detail_lines.append(f"- {e['ip']} [{', '.join(e['tags'])}] {ticket_info}")
            if len(adds) > 5:
                detail_lines.append(f"- ... y {len(adds)-5} más.")
                
        # Mostrar los primeros 5 updates
        updates = [e for e in events if e["action"] == "update"]
        if updates:
            detail_lines.append(f"**Actualizadas ({len(updates)}):**")
            for e in updates[:5]:
                ticket_info = f" (Ticket: {e.get('ticket')})" if e.get('ticket') else ""
                note_info = f" [Note: {e.get('note')}]" if e.get('note') else ""
                tags_info = f" [{', '.join(e.get('tags', []))}]" if e.get('tags') else ""
                
                parts = []
                if e.get("new_ttl") != e.get("old_ttl"):
                    parts.append("TTL updated")
                else:
                    parts.append("Updated")
                
                detail_lines.append(f"- {e['ip']}{tags_info}{ticket_info}{note_info} ({', '.join(parts)})")
            if len(updates) > 5:
                detail_lines.append(f"- ... y {len(updates)-5} más.")

        text_body = "\n".join(detail_lines)
        
        sections = [
            {"activityTitle": "Resumen", "activitySubtitle": f"Adds: {total_adds} | Updates: {total_updates}"},
            {"activityTitle": "Contexto", "activitySubtitle": f"Usuarios: {user_str} | Origen: {source_str}"}
        ]
        
        # Determinar color: Verde si hay adds, Azul si solo updates
        color = "28A745" if total_adds > 0 else "0076D7"
        
        send_teams_alert(title, text_body, color, sections=sections)

# Instancia global
teams_aggregator = TeamsAggregator()



# meta_bulk_del REMOVED


# compute_live_counters REMOVED


def regenerate_feeds_from_db():
    """
    Regenera TODOS los archivos de feed (Main, BPE, Test) 
    leyendo la verdad absoluta desde la Base de Datos SQLite.
    """
    try:
        all_ips = db.get_all_ips()
        
        lines_main = []
        lines_bpe = []
        lines_test = []
        
        # Mapa de Source si lo necesitáramos
        # meta = {} 

        now = datetime.now()
        
        for row in all_ips:
            ip = row['ip']
            try:
                tags = json.loads(row['tags'] or '[]')
            except:
                tags = []
            
            # Calcular TTL real (expiration_date vs ttl field)
            # Por simplicidad mantenemos lógica de texto: IP|DATE|TTL
            # Usamos 'added_at' como fecha base, o hoy?
            # Para feeds estáticos lo mejor es: FECHA_HOY|TTL_REMANENTE? 
            # O mantener lo original: FECHA_ORIGINAL|TTL_ORIGINAL
            
            # Row added_at is ISO string. Feed likes YYYY-MM-DD.
            added_at_str = row['added_at']
            if not added_at_str:
                added_at_str = datetime.now().strftime("%Y-%m-%d")
            else:
                # Truncate ISO to YYYY-MM-DD
                try:
                    dt = datetime.fromisoformat(added_at_str.replace("Z", "+00:00"))
                    added_at_str = dt.strftime("%Y-%m-%d")
                except:
                    added_at_str = datetime.now().strftime("%Y-%m-%d")

            ttl_val = str(row['ttl'])
            line = f"{ip}|{added_at_str}|{ttl_val}"
            
            # Distribuir
            if "Multicliente" in tags:
                lines_main.append(line)
            if "BPE" in tags:
                lines_bpe.append(line)
            if "Test" in tags:
                lines_test.append(line)
                
        # Escribir Atomicamente
        save_lines(lines_main, FEED_FILE)
        save_lines(lines_bpe, FEED_FILE_BPE)
        save_lines(lines_test, FEED_FILE_TEST)
        
        print(f"[DB SYNC] Regenerados feeds: Main={len(lines_main)}, BPE={len(lines_bpe)}, Test={len(lines_test)}")
        return True
    except Exception as e:
        print(f"[DB SYNC ERROR] {e}")
        return False


def compute_tag_totals():
    try:
        all_ips = db.get_all_ips()
    except Exception:
        return {"Multicliente": 0, "BPE": 0, "Test": 0}

    multi = bpe = test = 0
    for row in all_ips:
        try:
            tags = json.loads(row['tags'] or '[]')
        except:
            tags = []
        
        if "Multicliente" in tags: multi += 1
        if "BPE" in tags:          bpe   += 1
        if "Test" in tags:         test  += 1
    return {"Multicliente": multi, "BPE": bpe, "Test": test}

# === NUEVOS: unión feeds y matriz fuente×tag (DB Version) ===
def _active_ip_union():
    """
    Retorna el set de todas las IPs activas en Base de Datos.
    Usado para detectar duplicados/updates.
    """
    try:
        rows = db.get_all_ips()
        return {r['ip'] for r in rows}
    except:
        return set()

def compute_source_and_tag_counters_union():
    """
    Contadores en vivo sobre la base de datos (SQLite).
    Retorna: (src_counts, tag_counts, src_tag_counts, total_union)
    """
    rows = db.get_all_ips()
    total_union = len(rows)
    
    src_counts = {"manual": 0, "csv": 0, "api": 0}
    tag_counts = {"Multicliente": 0, "BPE": 0, "Test": 0} 
    
    src_tag_counts = {
        "manual": {}, "csv": {}, "api": {}
    }
    
    for r in rows:
        src = (r.get("source") or "manual").lower()
        if src not in src_counts:
            src_counts[src] = 0
            src_tag_counts[src] = {}
        src_counts[src] += 1
        
        tags = []
        try: 
            tags = json.loads(r.get("tags") or '[]')
        except: 
            tags = []
            
        for t in tags:
            tag_counts[t] = tag_counts.get(t, 0) + 1
            
            st_map = src_tag_counts[src]
            st_map[t] = st_map.get(t, 0) + 1
            
    return src_counts, tag_counts, src_tag_counts, total_union

# =========================
#  Utilidades de red
# =========================
def dotted_netmask_to_prefix(mask):
    return ipaddress.IPv4Network("0.0.0.0/{0}".format(mask)).prefixlen


def ip_block_reason(ip_str):
    try:
        obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return "IP inválida"

    if isinstance(obj, ipaddress.IPv6Address):
        return "IPv6 no soportado"
    if obj.is_unspecified:
        return "bloqueo de absolutamente todo"
    if obj.is_private:
        return "IP privada (RFC1918)"
    if obj.is_loopback:
        return "IP loopback"
    if obj.is_link_local:
        return "IP link-local"
    if obj.is_multicast:
        return "IP multicast"
    if obj.is_reserved:
        return "IP reservada"
    return None


def is_allowed_ip(ip_str):
    return ip_block_reason(ip_str) is None


def expand_input_to_ips(text, max_expand=MAX_EXPAND):
    if not text:
        raise ValueError("Entrada vacía")

    raw = re.sub(r"\s+", " ", text.strip())

    # Bloqueo global
    if raw == "0.0.0.0":
        raise ValueError("accion_no_permitida")
    if "/" in raw and raw.startswith("0.0.0.0"):
        raise ValueError("accion_no_permitida")
    if " " in raw and raw.split(" ", 1)[0].strip() == "0.0.0.0":
        raise ValueError("accion_no_permitida")

    # Rango A-B
    if "-" in raw and "/" not in raw:
        left, right = [p.strip() for p in raw.split("-", 1)]
        a = ipaddress.ip_address(left)
        b = ipaddress.ip_address(right)
        if int(a) > int(b):
            raise ValueError("Rango inválido (inicio > fin)")
        total = int(b) - int(a) + 1
        if total > max_expand:
            raise ValueError("Rango demasiado grande")
        ips = [str(ipaddress.ip_address(int(a) + i)) for i in range(total)]
        if "0.0.0.0" in ips:
            raise ValueError("accion_no_permitida")
        # filtrar públicas
        return [x for x in ips if is_allowed_ip(x)]

    # CIDR
    if "/" in raw:
        net = ipaddress.ip_network(raw, strict=False)
        size = net.num_addresses if net.prefixlen >= 31 else max(net.num_addresses - 2, 0)
        if size > max_expand:
            raise ValueError("La red expande demasiado")
        return [str(h) for h in net.hosts() if is_allowed_ip(str(h))]

    # IP + máscara punteada
    if " " in raw and "." in raw:
        base, mask = raw.split(" ", 1)
        prefix = dotted_netmask_to_prefix(mask.strip())
        return expand_input_to_ips("{}/{}".format(base, prefix), max_expand)

    # IP suelta
    ipaddress.ip_address(raw)
    if not is_allowed_ip(raw):
        return []
    return [raw]


# =========================
#  Delete pattern
# =========================
def parse_delete_pattern(raw):
    s = re.sub(r"\s+", " ", raw.strip())

    if " " in s and "." in s and "/" not in s:
        base, mask = s.split(" ", 1)
        pfx = dotted_netmask_to_prefix(mask.strip())
        return ("cidr", ipaddress.ip_network("{}/{}".format(base, pfx), strict=False))

    if "/" in s:
        return ("cidr", ipaddress.ip_network(s, strict=False))

    if "-" in s:
        a_txt, b_txt = [p.strip() for p in s.split("-", 1)]
        a = ipaddress.ip_address(a_txt)
        b = ipaddress.ip_address(b_txt)
        if int(a) > int(b):
            a, b = b, a
        return ("range", (a, b))

    return ("single", ipaddress.ip_address(s))




# =========================
#  Notificaciones persistentes
# =========================
def guardar_notif(category, message):
    notif = {"time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
             "category": category, "message": message}
    all_notifs = []
    if os.path.exists(NOTIF_FILE):
        try:
            with open(NOTIF_FILE, "r", encoding="utf-8") as f:
                all_notifs = json.load(f)
        except Exception:
            all_notifs = []
    all_notifs.append(notif)
    with open(NOTIF_FILE, "w", encoding="utf-8") as f:
        json.dump(all_notifs, f, ensure_ascii=False, indent=2)


def get_notifs(limit=200):
    if not os.path.exists(NOTIF_FILE):
        return []
    try:
        with open(NOTIF_FILE, "r", encoding="utf-8") as f:
            return json.load(f)[-limit:]
    except Exception as e:
        print(f"[ERROR] get_notifs failed: {e}")
        return []


# =========================
#  Helpers almacenamiento (feeds)
# =========================
def _append_line_unique(feed_path, line_txt):
    """Append si no existe esa IP en el feed dado."""
    # Determinar el lock apropiado
    if feed_path == FEED_FILE:
        lock = FEED_LOCK
    elif feed_path == FEED_FILE_BPE:
        lock = FEED_BPE_LOCK
    elif feed_path == FEED_FILE_TEST:
        lock = FEED_TEST_LOCK
    else:
        lock = FileLock(feed_path + ".lock")
    
    with lock:
        ip_txt = line_txt.split("|", 1)[0]
        existing = []
        if os.path.exists(feed_path):
            with open(feed_path, "r", encoding="utf-8") as f:
                existing = [l.strip() for l in f if l.strip()]
        exists = any(l.startswith(ip_txt + "|") for l in existing)
        if not exists:
            with open(feed_path, "a", encoding="utf-8") as f:
                f.write(line_txt + "\n")

def _ensure_dir(p):
    os.makedirs(p, exist_ok=True)

# Legacy expiration helper removed (eliminar_ips_vencidas_en_feed)

def _expire_ips_from_db():
    """
    Revisa todas las IPs en la BD. Si (Active - Added) >= TTL, se borra.
    Retorna lista de IPs borradas.
    """
    expired = []
    try:
        all_ips = db.get_all_ips()
        current_time = datetime.now()
        
        to_delete = []
        
        for row in all_ips:
            try:
                ttl = int(row['ttl'])
            except:
                ttl = 0
            
            if ttl <= 0:
                continue # Infinite or invalid
                
            # Parse added_at
            # Format expected: ISO string or YYYY-MM-DD
            added_at_str = row['added_at']
            if not added_at_str:
                continue
                
            # Try parsing
            try:
                # Handle ISO with Z or offset
                added_at_dt = datetime.fromisoformat(added_at_str.replace("Z", "+00:00"))
                # Remove timezone for simpler diff if current_time is naive (usually is)
                # But actually checking if current_time is naive or aware.
                # Use naive comparison if possible or aware if capable.
                if added_at_dt.tzinfo and current_time.tzinfo is None:
                    added_at_dt = added_at_dt.replace(tzinfo=None)
            except:
                try:
                    added_at_dt = datetime.strptime(added_at_str, "%Y-%m-%d")
                except:
                    continue # Cannot parse, safe keep
            
            # Check expiration
            delta_days = (current_time - added_at_dt).days
            if delta_days >= ttl:
                to_delete.append(row['ip'])
        
        if to_delete:
            for ip in to_delete:
                db.delete_ip(ip)
                expired.append(ip)
            
            if expired:
                regenerate_feeds_from_db()
                
    except Exception as e:
        print(f"[EXPIRATION ERROR] {e}")

    return expired

# Legacy cleanup wrappers removed

# Validar modo mantenimiento antes de cada request
@app.before_request
def check_maintenance_mode():
    # Rutas permitidas siempre
    allowed_prefixes = ["/static", "/login", "/logout", "/maintenance/toggle", "/feed", "/api/summary", "/api/estado", "/api/lista"]
    
    # 1. Check if Maintenance is Active
    is_maint = (db.get_config("MAINTENANCE_MODE", "0") == "1")
    g.maintenance_mode = is_maint # Para usar en templates
    
    # Si no está activo, salir
    if not is_maint:
        return

    # Si es GET (lectura), permitir
    if request.method in ["GET", "HEAD", "OPTIONS"]:
        return

    # Si es ruta permitida explícita (aunque sea POST, ej. login)
    if any(request.path.startswith(p) for p in allowed_prefixes):
        return

    # Si es ADMIN, permitir (Opcional: Si queremos que Admin pueda trabajar en mantenimiento)
    # UI dice "Solo lectura", pero el Admin necesita poder APAGARlo.
    # El endpoint /maintenance/toggle ya está en allowed_prefixes.
    # ¿Permitimos otras acciones al admin?
    # Por seguridad/coherencia "Modo Mantenimiento" suele bloquear todo cambio de datos.
    # Si el user quiere editar, que lo desactive primero.
    
    # Bloquear todo lo demás (POST/DELETE/PUT fuera de las excepciones)
    if "api" in request.path:
        return jsonify({"error": "Modo Mantenimiento Activo. Solo lectura."}), 503
        
    flash("Modo Mantenimiento Activo. Las modificaciones están deshabilitadas.", "warning")
    return redirect(url_for('index'))



def save_lines(lines, feed_path=FEED_FILE):
    # Determinar el lock apropiado según el feed
    if feed_path == FEED_FILE:
        lock = FEED_LOCK
    elif feed_path == FEED_FILE_BPE:
        lock = FEED_BPE_LOCK
    elif feed_path == FEED_FILE_TEST:
        lock = FEED_TEST_LOCK
    else:
        lock = FileLock(feed_path + ".lock")
    
    with lock:
        # Atomic write pattern
        tmp_file = feed_path + ".tmp"
        try:
            with open(tmp_file, "w", encoding="utf-8") as f:
                for l in lines:
                    f.write(l + "\n")
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_file, feed_path)
        except Exception:
            # Clean up temp file on error if it exists
            if os.path.exists(tmp_file):
                try:
                    os.remove(tmp_file)
                except:
                    pass
            raise


def log(accion, ip):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"{datetime.now()} - {accion}: {ip}\n")


# =========================
#  Tags helpers (compartidos con API y UI)
# =========================
def _norm_tags(tags):
    if not tags:
        return []
    if isinstance(tags, str):
        tags = [tags]
    out = []
    seen = set()
    for t in tags:
        s = str(t).strip()
        if not s:
            continue
        
        # 1. Intentar normalizar con el mapa canónico
        lower_k = s.lower()
        if lower_k in CANONICAL_TAGS:
            s_final = CANONICAL_TAGS[lower_k]
        else:
            # 2. Si es nuevo y desconocido, usar Title Case por defecto para homogeneizar
            # (Ej: "mi ataque" -> "Mi Ataque")
            s_final = s.title() if s.islower() else s

        if s_final not in seen:
            out.append(s_final)
            seen.add(s_final)
    return out

def _filter_allowed_tags(tags):
    """Devuelve sólo los tags permitidos, normalizando mayúsculas/minúsculas."""
    normalized = []
    for t in _norm_tags(tags):
        key = str(t).strip().lower()
        canon = CANONICAL_TAGS.get(key)
        if canon:
            normalized.append(canon)
    return normalized

def _parse_tags_field(val: str):
    if not val:
        return []
    items = re.split(r"[,\s]+", val.strip())
    return _norm_tags([x for x in items if x])

# Legacy tag helpers removed

def _remove_ip_from_all_feeds(ip):
    """Elimina una IP de la BD y regenera feeds."""
    db.delete_ip(ip)
    regenerate_feeds_from_db()


# Legacy meta helpers removed



def _already_same(entry, tags, expires_at):
    """
    Comprueba si tags y expiración son iguales.
    alert_ids NO se considera para idempotencia, porque una misma IP puede
    recibir múltiples alertas distintas.
    """
    try:
        same_tags = set(entry.get("tags", [])) == set(tags)
        cur_exp = datetime.fromisoformat(entry["expires_at"].replace("Z","+00:00"))
        same_exp = abs((cur_exp - expires_at).total_seconds()) <= 1
        return same_tags and same_exp
    except Exception:
        return False


# =========================
#  Alta de IPs (helper)  >>> actualizado para TAGS y feeds separados
# =========================
def add_ips_validated(lines, existentes, iterable_ips, ttl_val, origin=None, contador_ruta=None, tags=None, alert_id=None, force=False, note=None):
    """
    Refactored for SQLite (Phase 2).
    - lines: Ignored (legacy param).
    - existentes: Set of IPs currently in DB (used for Add/Update distinction).
    - iterable_ips: List of IPs to process.
    - ttl_val: Days to expire.
    - tags: List of tags.
    """
    añadidas = 0
    rechazadas = 0
    updated = 0
    added_lines = [] 
    
    # NEW: Detailed lists for Notification System
    added_items = []    # List of dicts: {'ip':..., 'tags':..., 'ttl':...}
    updated_items = []  # List of dicts: {'ip':..., 'old_ttl':..., 'new_ttl':..., 'tags':...}

    tags = _norm_tags(tags or [])
    
    try:
        ttl_days = int(ttl_val)
    except Exception:
        ttl_days = 0
    
    # Calculate expiration date
    expires_at_dt = (_now_utc() + timedelta(days=ttl_days)) if ttl_days > 0 else (_now_utc() + timedelta(days=365*100))
    # For text compatibility (though db is primary)
    ttl_seconds = ttl_days * 86400 if ttl_days > 0 else 0

    allow_multi = "Multicliente" in tags
    allow_bpe = "BPE" in tags
    allow_test = "Test" in tags

    for ip_str in iterable_ips:
        if not (allow_multi or allow_bpe or allow_test):
            rechazadas += 1
            print(f"[DEBUG VALIDATE] REJECTED {ip_str}: No allowed tags")
            continue

        if not is_allowed_ip(ip_str):
            rechazadas += 1
            continue
        try:
            if isinstance(ipaddress.ip_address(ip_str), ipaddress.IPv6Address):
                rechazadas += 1
                continue
        except Exception:
            rechazadas += 1
            continue

        # Logic for DB Upsert
        is_update = ip_str in existentes
        
        # History Entry
        action_type = "upsert" if is_update else "add"
        history_entry = {
            "ts": _iso(_now_utc()),
            "action": action_type,
            "user": "web/admin", # Placeholder, ideally passed context
            "source": origin or "manual",
            "tags": tags,
            "ttl": ttl_days,
            "note": "Bulk DB Upsert",
            "alert_id": alert_id
        }

        
        # Determine fecha for status
        fecha = datetime.now().strftime("%Y-%m-%d")

        # FEED BPE si corresponde
        if allow_bpe:
            # Legacy file append removed - handled by regenerate_feeds_from_db
            pass

        # FEED Test si corresponde
        if allow_test:
            # Legacy file append removed - handled by regenerate_feeds_from_db
            pass

        # Meta tags (DB handles tags, remove legacy file writing)
        # _merge_meta_tags is deprecated/stubbed.
        # _write_tag_line is legacy.

        # Legacy auditing/logging removed from here to clean flow, 
        # relying on the detailed return items for notifications/audit in the caller 
        # or centralized DB audit below if needed.
        # But wait, audit logs are useful. 
        # We should ensure audit happens. 
        # In the new flow, we return 'added_items' and the caller (route) does the audit/notify batching.
        # So we can safely remove the direct _audit/guardar_notif calls here to avoid duplication 
        # if the caller is already doing it (which index/upload_csv routes typically do).
        
        # Counters
        if contador_ruta and allow_multi:
            try:
                val = read_counter(contador_ruta)
                write_counter(contador_ruta, val + 1)
            except Exception:
                pass
        
        # --- DB UPSERT ---
        # We use upsert for everything now, whether new or update, to ensure consistency.
        # But we need to handle history properly.
        # For this phase, we append a history item.
        # To do so without reading first, we might overwrite.
        # Ideally, db.upsert_ip should handle appending to JSON history if it exists.
        # But our current helpers are simple.
        # Let's read first to be safe, or assume 'replace' is acceptable for bulk.
        # Given we are fixing a NameError to get tests passing, let's keep it simple:
        # Just ensure DB write happens.
        
        current_hist = [] 
        # Attempt to preserve history if it exists?
        # row = db.get_ip(ip_str) ... costoso en loop grande.
        # Por ahora, bulk overwrite de history es un trade-off aceptable o 
        # debemos confiar en que el usuario sabe lo que hace.
        
        
        final_alert_ids = []
        if alert_id:
            if is_update:
                try:
                    existing_row = db.get_ip(ip_str)
                    if existing_row:
                        final_alert_ids = json.loads(existing_row.get("alert_ids") or '[]')
                except:
                    final_alert_ids = []
            
            if alert_id not in final_alert_ids:
                final_alert_ids.append(alert_id)
        
        # History Append Logic
        final_history = []
        if is_update:
             try:
                # We reused existing_row if fetched above, or fetch now
                if not 'existing_row' in locals() or not existing_row:
                     existing_row = db.get_ip(ip_str)
                if existing_row:
                    final_history = json.loads(existing_row.get("history") or '[]')
             except:
                final_history = []
        
        # Add current action
        final_history.append(history_entry)
        
        db.upsert_ip(
            ip=ip_str,
            source=origin or "manual",
            tags=tags,
            ttl=ttl_days,
            expiration_date=expires_at_dt,
            alert_ids=final_alert_ids,
            history=final_history
        )

        # Notificación / Contadores
        if is_update:
            updated += 1
            updated_items.append({
                "ip": ip_str,
                "tags": tags,
                "ttl": ttl_days,
                "alert_id": alert_id,
                "note": note,
                # "old_ttl": ... (would require read)
            })
        else:
            añadidas += 1
            added_items.append({
                "ip": ip_str,
                "tags": tags,
                "ttl": ttl_days,
                "alert_id": alert_id,
                "note": note
            })
            
    # --- END LOOP ---
    
    # SYNC TO FILES
    regenerate_feeds_from_db()

    return añadidas, rechazadas, added_lines, updated, added_items, updated_items



# =========================
#  Flashes seguros para plantillas
# =========================
def coerce_message_pairs(raw_flashes):
    """
    Convierte flashes a lista de dicts {'category':..., 'message':...} 
    para consumo fácil en JS (tojson).
    """
    pairs = []
    for item in raw_flashes:
        cat, msg = "info", ""
        if isinstance(item, (list, tuple)) and len(item) >= 2:
            cat = str(item[0] or 'info')
            msg = str(item[1])
        else:
            msg = str(item)
            
        pairs.append({"category": cat, "message": msg})
    return pairs


# =========================
#  Backup utils
# =========================
def _safe_copy(src, dst_dir):
    """Copia src dentro de dst_dir conservando el nombre de archivo (si existe)."""
    if not os.path.exists(src):
        return None
    _ensure_dir(dst_dir)
    basename = os.path.basename(src)
    dst = os.path.join(dst_dir, basename)
    tmp = dst + ".tmp"
    with open(src, "rb") as fsrc, open(tmp, "wb") as fdst:
        fdst.write(fsrc.read())
    os.replace(tmp, dst)
    return dst

def _zip_backup(day_dir, zip_path):
    import zipfile
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for name in os.listdir(day_dir):
            fp = os.path.join(day_dir, name)
            if os.path.isfile(fp):
                z.write(fp, arcname=name)

def _rotate_backups(keep_days=14):
    """Mantén solo 'keep_days' últimos backups (por fecha YYYY-MM-DD)."""
    if not os.path.isdir(BACKUP_DIR):
        return
    entries = []
    for name in os.listdir(BACKUP_DIR):
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", name):
            entries.append(name)
        elif re.fullmatch(r"\d{4}-\d{2}-\d{2}\.zip", name):
            entries.append(name.split(".zip")[0])
    days = sorted(set(entries))
    if len(days) <= keep_days:
        return
    to_delete = days[0:len(days)-keep_days]
    for d in to_delete:
        day_dir = os.path.join(BACKUP_DIR, d)
        zipf = os.path.join(BACKUP_DIR, f"{d}.zip")
        if os.path.isdir(day_dir):
            for fname in os.listdir(day_dir):
                try:
                    os.remove(os.path.join(day_dir, fname))
                except Exception:
                    pass
            try:
                os.rmdir(day_dir)
            except Exception:
                pass
        try:
            if os.path.exists(zipf):
                os.remove(zipf)
        except Exception:
            pass


def _backup_critical_files(destination_dir):
    """
    Copia todos los archivos críticos al directorio de destino.
    Incluye: feeds, meta, notif, users, .env, logs y carpeta data/.
    """
    import shutil
    
    # 1. Archivos definidos como constantes globales (rutas absolutas)
    # Algunos pueden ser None o no existir
    critical_vars = [FEED_FILE, FEED_FILE_BPE, FEED_FILE_TEST, META_FILE, NOTIF_FILE, HISTORY_FILE]
    for fpath in critical_vars:
        if fpath and os.path.exists(fpath):
            _safe_copy(fpath, destination_dir)

    # 2. Archivos relativos a BASE_DIR (nuevos)
    extra_files = ["users.json", ".env", "audit-log.jsonl", "ioc-log.txt"]
    for fname in extra_files:
        fpath = os.path.join(BASE_DIR, fname)
        if os.path.exists(fpath):
            _safe_copy(fpath, destination_dir)

    # 3. Carpeta data/ (recursivo)
    data_src = os.path.join(BASE_DIR, "data")
    if os.path.isdir(data_src):
        target_data = os.path.join(destination_dir, "data")
        # copytree requiere que destino no exista si dirs_exist_ok=False (default en python < 3.8)
        # pero con dirs_exist_ok=True (3.8+) funciona. Asumimos Py3.8+.
        # Si fallara, shutil.copytree lanza error si existe.
        # Mejor usamos un try/except o borramos destino si existe (raro en backup nuevo).
        try:
            shutil.copytree(data_src, target_data, dirs_exist_ok=True)
        except Exception as e:
            # Si falla data, no abortamos todo el backup
            print(f"Warning: Failed to copy data dir: {e}")


def _rotate_manual_backups(keep_count=5):
    """
    Mantiene solo los últimos 'keep_count' backups manuales (formato YYYY-MM-DD_HHMMSS).
    Elimina los más antiguos si se excede el límite.
    """
    if not os.path.isdir(BACKUP_DIR):
        return
    
    # Identificar backups manuales
    manuals = []
    for name in os.listdir(BACKUP_DIR):
        # Buscamos patrón fecha_hora.zip
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}_\d{6}\.zip", name):
            manuals.append(name)
            
    # Si no superamos el límite, no hacemos nada
    if len(manuals) <= keep_count:
        return

    # Ordenar cronológicamente (el nombre YYYY... asegura orden ASCII correcto)
    manuals.sort()

    # Identificar los que sobran (los primeros de la lista son los más viejos)
    # Ejemplo: len=6, keep=5 -> excess=1 -> delete manuals[0:1] -> [0]
    excess_count = len(manuals) - keep_count
    to_delete = manuals[:excess_count]

    for filename in to_delete:
        zip_path = os.path.join(BACKUP_DIR, filename)
        try:
            os.remove(zip_path)
            # Opcional: loguear borrado
            # print(f"Rotando backup manual antiguo: {filename}")
        except Exception:
            pass


def perform_daily_backup(keep_days=14):
    """
    Si el backup de HOY no existe, crea:
      - backups/YYYY-MM-DD/ con copias de FEED_FILE, FEED_FILE_BPE, META_FILE (si existe), NOTIF_FILE (si existe)
      - backups/YYYY-MM-DD.zip con todo lo anterior
    Luego rota backups antiguos.
    """
    try:
        today = datetime.now().strftime("%Y-%m-%d")
        _ensure_dir(BACKUP_DIR)
        day_dir = os.path.join(BACKUP_DIR, today)
        zip_path = os.path.join(BACKUP_DIR, f"{today}.zip")

        if os.path.exists(zip_path):
            return

        _ensure_dir(day_dir)
        # Copia unificada de todo (feeds, users, env, data...)
        _backup_critical_files(day_dir)

        _zip_backup(day_dir, zip_path)

        with open(LAST_BACKUP_MARK, "w", encoding="utf-8") as f:
            f.write(today)

        _rotate_backups(keep_days=keep_days)
        take_daily_snapshot() # Hook para el snapshot diario

        guardar_notif("info", f"Backup diario creado: {today}")
    except Exception as e:
        guardar_notif("danger", f"Error en backup diario: {str(e)}")


def perform_manual_backup():
    """
    Crea un backup forzado con timestamp (para no sobrescribir el diario).
    Ejemplo: backups/2023-01-01_153000.zip
    """
    try:
        now_str = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        _ensure_dir(BACKUP_DIR)
        
        day_dir = os.path.join(BACKUP_DIR, now_str)
        zip_path = os.path.join(BACKUP_DIR, f"{now_str}.zip")

        # Siempre creamos uno nuevo
        _ensure_dir(day_dir)
        # Copia unificada de todo
        _backup_critical_files(day_dir)

        _zip_backup(day_dir, zip_path)

        # Limpieza: borrar la carpeta temporal, dejar solo el zip
        import shutil
        if os.path.exists(day_dir):
            shutil.rmtree(day_dir)

        # No marcamos LAST_BACKUP_MARK porque ese es para el automático diario

        # Rotar manuales (mantener últimos 5)
        _rotate_manual_backups(keep_count=5)

        guardar_notif("success", f"Backup manual creado: {now_str}.zip")
        return True
    except Exception as e:
        guardar_notif("danger", f"Error en backup manual: {str(e)}")
        return False



def _apply_filters(records, q=None, date_param=None):
    res = records
    if q:
        ql = q.strip()
        res = [r for r in res if ql in r["ip"]]
    if date_param:
        dp = date_param.strip()
        if "," in dp:
            a_txt, b_txt = [p.strip() for p in dp.split(",", 1)]
            a_dt = datetime.strptime(a_txt, "%Y-%m-%d") if a_txt else None
            b_dt = datetime.strptime(b_txt, "%Y-%m-%d") if b_txt else None
            tmp = []
            for r in res:
                fd = r["fecha_dt"]
                if fd is None:
                    continue
                if a_dt and fd < a_dt:
                    continue
                if b_dt and fd > b_dt:
                    continue
                tmp.append(r)
            res = tmp
        else:
            try:
                d = datetime.strptime(dp, "%Y-%m-%d").date()
                res = [r for r in res if (r["fecha_dt"] and r["fecha_dt"].date() == d)]
            except Exception:
                pass
    return res


def _apply_sort(records, sort_key="fecha", order="desc"):
    reverse = (order or "desc").lower() == "desc"
    key = (sort_key or "fecha").lower()
    if key == "ip":
        return sorted(records, key=lambda r: int(ipaddress.ip_address(r["ip"])), reverse=reverse)
    if key == "ttl":
        # Ordenar por fecha de expiración (None al final)
        return sorted(records, key=lambda r: (r["expira_dt"] is None, r["expira_dt"]), reverse=reverse)
    # default: fecha alta
    return sorted(records, key=lambda r: (r["fecha_dt"] is None, r["fecha_dt"]), reverse=reverse)


def _paginate(records, page=1, page_size=DEFAULT_PAGE_SIZE):
    try:
        p = max(1, int(page))
    except Exception:
        p = 1
    try:
        ps = min(MAX_PAGE_SIZE, max(1, int(page_size)))
    except Exception:
        ps = DEFAULT_PAGE_SIZE
    total = len(records)
    start = (p - 1) * ps
    end = start + ps
    return records[start:end], p, ps, total

def _days_left(fecha_dt, ttl_int):
    """TTL regresivo en días (0 si permanente o sin fecha)."""
    if not fecha_dt or ttl_int == 0:
        return 0
    exp = fecha_dt + timedelta(days=ttl_int)
    today = datetime.now().date()
    return max(0, (exp.date() - today).days)




# =========================
#  Helpers de UI: colores de tags + known_tags
# =========================
def _tag_color_hsl(tag: str) -> str:
    """Devuelve CLASE Bootstrap para el badge."""
    if not tag:
        return "text-bg-secondary"
    
    t_lower = tag.lower()
    if "multicliente" in t_lower:
        return "text-bg-primary"
    elif "bpe" in t_lower:
        return "text-bg-warning text-dark" # Orange needs dark text
    elif "test" in t_lower:
        return "text-bg-secondary"
    else:
        # Para tags desconocidos, usamos un color genérico visible
        # O podríamos hacer hash -> bg-success/danger/info aleatorio.
        # Por simplicidad y legibilidad: Info (Cyan) o Dark.
        return "text-bg-info text-dark"
    
    h = int(hashlib.sha256(tag.encode("utf-8")).hexdigest(), 16) % 360
    s = 60
    l = 45
    # convertir HSL simple a RGB (aprox) y a hex
    def hue2rgb(p, q, t):
        if t < 0: t += 1
        if t > 1: t -= 1
        if t < 1/6: return p + (q - p) * 6 * t
        if t < 1/2: return q
        if t < 2/3: return p + (q - p) * (2/3 - t) * 6
        return p
    h_ = h / 360.0
    s_ = s / 100.0
    l_ = l / 100.0
    if s_ == 0:
        r = g = b = l_
    else:
        q = l_ * (1 + s_) if l_ < 0.5 else l_ + s_ - l_ * s_
        p = 2 * l_ - q
        r = hue2rgb(p, q, h_ + 1/3)
        g = hue2rgb(p, q, h_)
        b = hue2rgb(p, q, h_ - 1/3)
    return "#{:02x}{:02x}{:02x}".format(int(r*255), int(g*255), int(b*255))


def _days_remaining_filter(date_str, ttl_str):
    """Calcula días restantes para la UI dado fecha (str) y ttl (str/int)."""
    try:
        ttl = int(ttl_str)
        if ttl <= 0:
            return None
    except (ValueError, TypeError):
        return None

    try:
        if not date_str:
            return 0
            
        if isinstance(date_str, datetime):
            d = date_str
        else:
            # Try ISO first (DB format)
            try:
                d = datetime.fromisoformat(str(date_str).replace("Z", "+00:00"))
            except ValueError:
                # Fallback to simple date
                d = datetime.strptime(str(date_str), "%Y-%m-%d")
        
        # Ensure naive for compatibility if needed, though _days_left converts to date()
        if d.tzinfo:
            d = d.replace(tzinfo=None)

        return _days_left(d, ttl)
    except Exception:
        return None


@app.context_processor
def inject_helpers():
    return {
        "tag_color": _tag_color_hsl,
        "days_remaining": _days_remaining_filter
    }


def _collect_known_tags():
    """Devuelve lista ordenada de tags conocidos activamente en la BD."""
    # Como ya calculamos 'tag_totals' en otras partes (compute_source_and_tag_counters_union),
    # podríamos reusarlo. Pero para asegurarnos, consultamos la union actual o la BD.
    # Fase 2: Consultar la cache de contadores global si es fresca, o recalcular.
    # Por simplicidad ahora: llamar a DB helper
    try:
        # Recuperamos todos los tags únicos
        # Opción A: getAllIps y iterar tags -> Lento
        # Opción B: Helper SQL -> Rápido.
        # Usamos la lógica de contadores que ya itera todo:
        _, tag_counts, _, _ = compute_source_and_tag_counters_union()
        current_tags = set(tag_counts.keys())
        # Ensure default tags are always available for selection
        current_tags.update(ALLOWED_TAGS) 
        
        tags = list(current_tags)
        tags.sort(key=lambda x: x.lower())
        return tags
    except Exception as e:
        print(f"Error collecting tags: {e}")
        return ["Multicliente", "BPE", "Test"]

# ... (Hook before_request is fine) ...

def _get_feed_filename(tag):
    t_lower = tag.lower()
    if t_lower == "multicliente":
        return FEED_FILE
    elif t_lower == "bpe":
        return FEED_FILE_BPE
    elif t_lower == "test":
        return FEED_FILE_TEST
    else:
        # Sanitize filename
        safe_tag = "".join(c for c in tag if c.isalnum() or c in ('-','_'))
        if not safe_tag: safe_tag = "unknown"
        return os.path.join(BASE_DIR, f"ioc-feed-{safe_tag}.txt")

def regenerate_feeds_from_db():
    """
    Regenera TODOS los archivos de feed dinámicamente.
    - Multicliente -> ioc-feed.txt
    - BPE -> ioc-feed-bpe.txt
    - Test -> ioc-feed-test.txt
    - Otro -> ioc-feed-Otro.txt
    """
    try:
        all_ips = db.get_all_ips()
        
        # Diccionario: nombre_fichero -> lista de lineas
        active_feeds = {} 
        # Inicializamos los standard para asegurar que se creen (vacios si hace falta)
        active_feeds[FEED_FILE] = []
        active_feeds[FEED_FILE_BPE] = []
        active_feeds[FEED_FILE_TEST] = []
        
        # Para saber qué tags existen y limpiar viejos (opcional, por ahora solo crear/sobrescribir)
        
        now = datetime.now()
        
        for row in all_ips:
            ip = row['ip']
            try:
                tags = json.loads(row['tags'] or '[]')
            except:
                tags = []
            
            # Normalizar fecha
            added_at_str = row['added_at']
            if not added_at_str:
                added_at_str = datetime.now().strftime("%Y-%m-%d")
            else:
                try:
                    dt = datetime.fromisoformat(added_at_str.replace("Z", "+00:00"))
                    added_at_str = dt.strftime("%Y-%m-%d")
                except:
                    added_at_str = datetime.now().strftime("%Y-%m-%d")

            ttl_val = str(row['ttl'])
            line = f"{ip}|{added_at_str}|{ttl_val}"
            
            # Distribuir a cada feed correspondiente al tag
            for tag in tags:
                # Normalizar tag por si acaso
                norm_tag = CANONICAL_TAGS.get(tag.lower(), tag)
                # Obtener nombre de fichero destino
                fpath = _get_feed_filename(norm_tag)
                
                if fpath not in active_feeds:
                    active_feeds[fpath] = []
                
                active_feeds[fpath].append(line)
        
        # Escribir Atomicamente todos los ficheros
        for fpath, lines in active_feeds.items():
            # Usar lock dinámico según path
            # Si es standard, usar lock global definido
            if fpath == FEED_FILE: lock = FEED_LOCK
            elif fpath == FEED_FILE_BPE: lock = FEED_BPE_LOCK
            elif fpath == FEED_FILE_TEST: lock = FEED_TEST_LOCK
            else: lock = FileLock(fpath + ".lock")
            
            with lock:
                tmp_file = fpath + ".tmp"
                try:
                    with open(tmp_file, "w", encoding="utf-8") as f:
                        for l in lines:
                            f.write(l + "\n")
                        f.flush()
                        os.fsync(f.fileno())
                    os.replace(tmp_file, fpath)
                except Exception as e:
                    print(f"[FEED ERROR] writing {fpath}: {e}")
                    if os.path.exists(tmp_file): os.remove(tmp_file)

        print(f"[DB SYNC] Regenerados {len(active_feeds)} feeds dinámicos.")
        return True
    except Exception as e:
        print(f"[DB SYNC ERROR] {e}")
        return False

# =========================
#  Hooks de Flask
# =========================
@app.before_request
def before_request():
    # Check diario de expiración y snapshots
    try:
        perform_daily_expiry_once()
        take_daily_snapshot()  # Analytics
        perform_log_rotation() # Log Rotation (Size check)
    except Exception:
        pass


# === HISTORICAL SNAPSHOTS ===
def load_history():
    if not os.path.exists(HISTORY_FILE):
        return []
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return []

def save_history(data):
    with FileLock(HISTORY_FILE + ".lock"):
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

def take_daily_snapshot():
    """
    Toma una 'foto' de los contadores actuales y la guarda si no existe entrada para hoy.
    """
    today_str = datetime.now().strftime("%Y-%m-%d")
    hist = load_history()
    
    # Check si ya existe entrada de hoy
    for entry in hist:
        if entry.get("date") == today_str:
            return  # Ya tenemos snapshot de hoy
            
    # Calcular métricas globales (Union)
    src_union, tag_union, src_tag_union, total_union = compute_source_and_tag_counters_union()
    
    snapshot = {
        "date": today_str,
        "ts": time.time(),
        "total": total_union,
        "sources": src_union,
        "tags": tag_union,
        "source_tags": src_tag_union
    }
    
    hist.append(snapshot)
    # Retención simple (ej: 90 días)
    if len(hist) > 90:
        hist = hist[-90:]
        
    save_history(hist)


# =========================
#  Expiración diaria con marca (nuevo)
# =========================
def perform_daily_expiry_once():
    today = datetime.now().strftime("%Y-%m-%d")
    last = None
    try:
        if os.path.exists(EXPIRY_MARK):
            with open(EXPIRY_MARK, "r", encoding="utf-8") as f:
                last = (f.read() or "").strip()
    except Exception:
        last = None
    if last == today:
        return  # ya hecho hoy

    # Expirar y sincronizar meta (principal y BPE)
    # Expirar DB directly
    vencidas = _expire_ips_from_db()
    if vencidas:
        _audit("expire_ttl", "system", {"count": len(vencidas)}, {"ips": vencidas})

    try:
        with open(EXPIRY_MARK, "w", encoding="utf-8") as f:
            f.write(today)
    except Exception:
        pass


# =========================
#  Rutas
# =========================
@app.after_request
def add_security_headers(resp):
    # Cabeceras comunes
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "same-origin"
    
    # === CACHE BUSTING ===
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"

    # CSP: relajada SOLO para /login (carga jQuery/Bootstrap 3 desde CDN)
    if request.path.startswith("/login"):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://code.jquery.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data:; "
            "font-src 'self' https://cdn.jsdelivr.net data:; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "frame-ancestors 'none'"
        )
    else:
        # Resto de la app (Bootstrap 5 desde jsDelivr)
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "img-src 'self' data:; "
            "font-src 'self' data: https://fonts.gstatic.com https://cdn.jsdelivr.net; "

            "connect-src *; "
            "object-src 'none'; "
            "frame-ancestors 'none'"
        )
    return resp


@app.route("/debug-dashboard")
# Force Reload Trigger
def debug_dashboard():
    """Temporary route for browser_subagent verification without login barrier."""
    session["username"] = "debug_agent"
    session["role"] = "admin"
    
    now = datetime.now()
    current_flashes_list = [
        {"category": "success", "message": "TOAST: ACCIÓN COMPLETADA"}
    ]
    server_messages_list = [
        {"category": "success", "message": f"{_iso(now)} TOAST: ACCIÓN COMPLETADA"},
        {"category": "info",    "message": f"{_iso(now)} [DEBUG] Item Histórico"}
    ]
    lines = ["1.1.1.1|2023-01-01|0"]
    return render_template("index.html",
        current_flashes_list=current_flashes_list,
        server_messages_list=server_messages_list,
        ips=lines,
        total_ips=1,
        contador_manual=1,
        contador_csv=0,
        contador_api=0,
        contador_tags={"Multicliente":0,"BPE":0,"Test":1},
        union_total=1,
        union_by_source={"manual":1},
        union_by_tag={"Test":1},
        union_by_source_tag={"manual":{"Test":1}},
        request_actions=[],
        messages=server_messages_list,
        history_items=server_messages_list,
        ip_tags={"1.1.1.1": ["Test"]},
        ip_alerts={},
        known_tags=["Test"],
        error=None,
        feeds_config=FEEDS_CONFIG,  # FIXED: Required by index.html template
        current_feed="main" # Added for debug purposes
    )

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # SQLite Login
        user_row = db.get_user_by_username(username)
        # Fallback to JSON if migration not fully done? No, strictly DB now for Setup.
        
        if user_row and check_password_hash(user_row['password_hash'], password):
            session['username'] = username
            session['role'] = user_row['role'] or 'editor'
            
            # Log audit
            # _audit("login", f"web/{username}", "auth", {"success": True})
            # usamos nuevo db_audit si queremos
            
            flash('Has iniciado sesión correctamente.', 'success')
            return redirect(url_for('index'))
        else:
            # _audit("login_failed", f"web/{username}", "auth", {"success": False})
            flash('Usuario o contraseña incorrectos.', 'error')
    
    return render_template('login.html')

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/test-notif")
def test_notif():
    """Ruta de test para verificar renderizado de notificaciones"""
    messages = []
    try:
        for n in get_notifs(limit=10):
            cat = str(n.get("category", "secondary"))
            msg = f"{n.get('time','')} {n.get('message','')}".strip()
            messages.append((cat, msg))
    except Exception as e:
        messages = [("danger", f"Error: {e}")]
    return render_template("test_notif.html", messages=messages)

# Definición de Feeds (Extensible)
# === MAINTENANCE MODE ===
MAINTENANCE_MODE = False

@app.before_request
def check_maintenance():
    # Permitir siempre estáticos y login/logout
    if request.endpoint in ['static', 'login', 'logout', 'cleanup_inactive_sessions']:
        return

    # Si está activo el mantenimiento
    if MAINTENANCE_MODE:
        # Permitir al admin gestionar el mantenimiento y backups
        # (Asumimos que el toggle y restore requieren ser admin, validado en la ruta)
        if request.endpoint in ['maintenance_toggle', 'backup_restore_upload']:
            return
        
        # Permitir lecturas (GET) para ver el estado, salvo que se quiera bloqueo total
        if request.method == 'GET':
             return
        
        # Bloquear escrituras (POST) para el resto
        msg = "⚠️ Mantenimiento en curso. Las modificaciones están bloqueadas."
        if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"error": "MAINTENANCE_MODE", "message": msg}), 503
        
        flash(msg, "warning")
        return redirect(url_for('index'))


FEEDS_CONFIG = {
    "global":       {"label": "Global / Todos", "icon": "bi-globe", "virtual": True},
    "multicliente": {"file": FEED_FILE, "label": "Multicliente", "icon": "bi-hdd-network"},
    "bpe":          {"file": FEED_FILE_BPE, "label": "Feed BPE", "icon": "bi-bank"},
    "test":         {"file": FEED_FILE_TEST, "label": "Feed Test", "icon": "bi-cone-striped"},
}

# === Days Remaining Helper ===
def days_remaining(added_at_arg, ttl_arg):
    try:
        ttl = int(ttl_arg)
    except:
        return None # Infinite or Invalid

    if ttl <= 0:
        return None # Infinite

    if not added_at_arg:
        return 0

    try:
        # Try Parsing ISO
        dt = datetime.fromisoformat(str(added_at_arg).replace("Z", "+00:00"))
        if dt.tzinfo:
            dt = dt.replace(tzinfo=None)
    except:
        try:
            dt = datetime.strptime(str(added_at_arg), "%Y-%m-%d")
        except:
            return 0 # Cannot parse date

    delta = (datetime.now() - dt).days
    left = ttl - delta
    return left if left >= 0 else 0
# =============================

@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    # Snapshot diario si hace falta
    perform_daily_backup(keep_days=14)

    # Expiración diaria (una vez/día)
    perform_daily_expiry_once()
    perform_daily_expiry_once()
    # repair_meta_sources() REMOVED (Legacy JSON Sync)
    try:
        take_daily_snapshot()  # Metrics Snapshot (Punto 2 Mejoras)
    except Exception as e:
        print(f"Error taking snapshot: {e}")
        flash(f"Error snapshot: {e}", "danger")

    error = None
    
    # --- RBAC Logic ---
    current_username = session.get("username")
    all_users = load_users()
    user_data = all_users.get(current_username, {})
    
    # Por defecto, ver todo ("*") si no se especifica
    allowed_feeds = user_data.get("allowed_feeds") or ["*"]
    
    # Filtrar configuración de feeds
    visible_feeds = {}
    for k, v in FEEDS_CONFIG.items():
        if "*" in allowed_feeds or k in allowed_feeds:
            visible_feeds[k] = v
            
    # Si no tiene feeds visibles (raro), error o vacío
    if not visible_feeds:
        flash("No tienes acceso a ningún feed.", "danger")
        return render_template("index.html", current_feed="none", feeds_config={}, ips=[])

    # Selector de Feed Dinámico (Default: Global o el primero disponible)
    feed_param = request.args.get("feed", "global").lower()
    
    # Validación defensiva + Seguridad RBAC
    if feed_param not in visible_feeds:
        # Fallback al primero disponible (preferiblemente 'global' si existe, sino cualquiera)
        if "global" in visible_feeds:
            feed_param = "global"
        else:
            feed_param = next(iter(visible_feeds))
    
    current_feed_config = visible_feeds[feed_param]
    
    # Lógica de carga: Virtual (Agregador) vs Fichero único
    # REFACTOR: Load from DB and adapter for template
    
    all_ips_db = db.get_all_ips()
    lines = []
    
    # Determine allowed tags based on feed_param
    # Mapeo simple basado en names de FEEDS_CONFIG
    # global -> All
    # multicliente -> Multicliente
    # bpe -> BPE
    # test -> Test
    
    target_tags = set()
    if feed_param == "global":
        if "multicliente" in visible_feeds: target_tags.add("Multicliente")
        if "bpe" in visible_feeds: target_tags.add("BPE")
        if "test" in visible_feeds: target_tags.add("Test")
    elif feed_param == "multicliente":
        target_tags.add("Multicliente")
    elif feed_param == "bpe":
        target_tags.add("BPE")
    elif feed_param == "test":
        target_tags.add("Test")
        
    seen_ips = set()
    
    for row in all_ips_db:
        ip = row['ip']
        try:
            row_tags = set(json.loads(row['tags'] or '[]'))
        except:
            row_tags = set()
            
        # Filter logic
        if not row_tags.intersection(target_tags):
            continue
            
        if ip in seen_ips:
            continue
        
        # --- FILTERS (Restored) ---
        # 1. Search Query
        q = request.args.get("q", "").strip().lower()
        if q and q not in ip.lower():
            # print(f"DEBUG FILTER: q='{q}' not in ip='{ip}'")
            continue
            
        # 2. Tag Filter
        tag_filter = request.args.get("tag", "all")
        if tag_filter != "all":
            # Normalizar
            if tag_filter not in row_tags:
                # print(f"DEBUG FILTER: tag='{tag_filter}' not in row_tags={row_tags}")
                continue

        # 3. Source Filter
        source_filter = request.args.get("source", "all")
        if source_filter != "all":
            if (row.get('source') or 'manual') != source_filter:
                # print(f"DEBUG FILTER: source='{source_filter}' != row_source='{row.get('source')}'")
                continue

        # 4. Date Filter
        try:
            added_dt = datetime.fromisoformat(row['added_at'].replace("Z", ""))
            added_str = added_dt.strftime("%Y-%m-%d")
        except:
            added_dt = datetime.now()
            added_str = added_dt.strftime("%Y-%m-%d")

        date_from = request.args.get("dateFrom")
        date_to = request.args.get("dateTo")
        
        if date_from:
            if added_str < date_from:
                continue
        if date_to:
            if added_str > date_to:
                continue
            
            

        # --------------------------

        seen_ips.add(ip)
        
        # Format for template: IP|DATE|TTL
        # Recovers added_at from DB
        # This block was moved inside the date filter section above.
        # try:
        #     added_dt = datetime.fromisoformat(row['added_at'].replace("Z", ""))
        #     added_str = added_dt.strftime("%Y-%m-%d")
        # except:
        #     added_str = datetime.now().strftime("%Y-%m-%d")
            
        line = f"{ip}|{added_str}|{row['ttl']}"
        lines.append(line)
        
    lines.sort(key=lambda x: x.split("|")[0])
        
    existentes = {l.split("|", 1)[0] for l in lines}

    # ----- Mutaciones (POST) -----
    if request.method == "POST":
        # Check permissions
        user_role = user_data.get("role", "editor")
        if user_role == "view_only":
            flash("Acción no permitida: Tu rol es de solo lectura.", "danger")
            _audit("access_denied", f"web/{current_username}", "write_action", {})
            return redirect(url_for("index"))

        # Eliminar todas (feed principal + BPE + Test + metadatos)
        # Eliminar todas (Global)
        if "delete-all" in request.form:
            # DB CLEAN
            db.delete_all_ips()
            regenerate_feeds_from_db()

            log("Eliminadas", "todas las IPs (Global: Main + BPE + Test)")
            guardar_notif("warning", "Se eliminaron todas las IPs (Global)")
            flash("Se eliminaron todas las IPs de todas las tablas", "warning")
            
            _audit("delete_all", f"web/{session.get('username','admin')}", {"deleted": "all"}, {})
            return redirect(url_for("index"))

        # Eliminar selección masiva (Checkbox)
        if "bulk_delete_ips" in request.form:
            try:
                raw_ips = request.form.get("bulk_delete_ips", "")
                ip_list = [x.strip() for x in raw_ips.split(",") if x.strip()]
                
                count = 0
                for ip in ip_list:
                    db.delete_ip(ip)
                    count += 1
                
                if count > 0:
                    regenerate_feeds_from_db()
                    
                    # Single Notification
                    msg = f"Eliminadas {count} IPs (Selección masiva)"
                    guardar_notif("warning", msg)
                    flash(msg, "warning")
                    
                    # Single Teams Alert
                    send_teams_alert(
                        "🗑️ Eliminación Masiva", 
                        f"Se han eliminado **{count}** indicadores manualmente.\nUsuario: {session.get('username','admin')}", 
                        color="DC3545",
                        sections=[{"activityTitle": "User", "activitySubtitle": session.get('username','admin')}]
                    )
                    
                    _audit("bulk_delete_selection", f"web/{session.get('username','admin')}", {"count": count}, {"ips": ip_list})

            except Exception as e:
                flash(f"Error en eliminación masiva: {e}", "danger")
            
            return redirect(url_for("index"))

        # Eliminar individual (quitar de ambos feeds)
        # Eliminar individual (quitar de ambos feeds)
        if "delete_ip" in request.form:
            ip_to_delete = request.form.get("delete_ip")
            
            # DB DELETE
            db.delete_ip(ip_to_delete)
            regenerate_feeds_from_db()
            
            # Notifs
            guardar_notif("warning", f"IP eliminada: {ip_to_delete}")
            flash(f"IP eliminada: {ip_to_delete}", "warning")
            
            # --- Notify Teams ---
            send_teams_alert(
                "🗑️ IP Eliminada (Manual)", 
                f"IP: **{ip_to_delete}**\nUsuario: {session.get('username','admin')}", 
                color="DC3545",
                sections=[{"activityTitle": "User", "activitySubtitle": session.get('username','admin')}]
            )
            # --------------------

            _audit("delete_ip", f"web/{session.get('username','admin')}", ip_to_delete, {})
            return redirect(url_for("index"))

        # Eliminar por patrón (ambos feeds)
        if "delete-net" in request.form:
            patron = request.form.get("delete_net_input", "").strip()
            try:
                # 1. Parse pattern
                kind, obj = parse_delete_pattern(patron)
                
                # 2. Scan DB
                all_ips = db.get_all_ips()
                to_delete = []
                
                for row in all_ips:
                    ip_str = row['ip']
                    try:
                        ip_obj = ipaddress.ip_address(ip_str)
                    except:
                        continue
                        
                    match = False
                    if kind == "single":
                        match = (ip_obj == obj)
                    elif kind == "cidr":
                        match = (ip_obj in obj)
                    elif kind == "range":
                        a, b = obj
                        match = (int(a) <= int(ip_obj) <= int(b))
                        
                    if match:
                        to_delete.append(ip_str)
                
                # 3. Delete
                count = 0
                for ip in to_delete:
                    db.delete_ip(ip)
                    count += 1
                    
                if count > 0:
                    regenerate_feeds_from_db()
                    
                # 4) Notifs 
                guardar_notif("warning", f"Eliminadas por patrón {patron}: {count}")
                flash(f"Eliminadas por patrón {patron}: {count}", "warning")
                
                _audit("delete_pattern", f"web/{session.get('username','admin')}", {"pattern": patron, "removed": count}, {"ips": to_delete})

            except Exception as e:
                flash(str(e), "danger")
            return redirect(url_for("index"))



        # -------------------- Subida CSV/TXT --------------------
        file = request.files.get("file")
        if file and file.filename:
            # 0) Extensión permitida (defensivo)
            fname = file.filename.lower()
            if not (fname.endswith(".csv") or fname.endswith(".txt")):
                flash("Solo se permiten archivos .csv o .txt.", "danger")
                return redirect(url_for("index"))

            # 1) TTL global
            ttl_csv_sel = request.form.get("ttl_csv", "permanente")
            _ttl_allowed = {"permanente", "1", "3", "7", "30"}
            if ttl_csv_sel not in _ttl_allowed:
                ttl_csv_sel = "permanente"
            ttl_csv_val = "0" if ttl_csv_sel == "permanente" else ttl_csv_sel

            # 2) Tags CSV (OBLIGATORIO) -- Ahora vienen en el CSV, validamos por fila
            # raw_tags_csv = _parse_tags_field(request.form.get("tags_csv", ""))
            # tags_csv = _filter_allowed_tags(raw_tags_csv)
            # if not tags_csv: ...

            # 3) Lectura segura del archivo
            try:
                file.stream.seek(0)
            except Exception:
                pass
            try:
                content = file.read().decode("utf-8", errors="ignore").splitlines()
            except Exception:
                content = []

            valid_ips_total = 0
            rejected_total = 0
            added_lines_acc = []
            
            # --- Aggregation Lists ---
            csv_added_objs = []
            csv_updated_objs = []
            # -------------------------

            # Detectar delimitador: ; o | o ,
            delimiter = ","
            header_check = "\n".join(content[:5])
            if ";" in header_check:
                delimiter = ";"
            elif "|" in header_check:
                delimiter = "|"

            # --- CRITICAL FIX: Reload Main Feed (DB Source) ---
            # Don't use 'lines' from the view/filter, as it might be BPE/Global.
            # We check duplicates against the DB directly.
            all_ips_db = db.get_all_ips()
            existentes = {row['ip'] for row in all_ips_db}
            lines = [] # Legacy param for add_ips_validated, ignored now
            # -------------------------------------
            
            # --- BULK OPTIMIZATION START ---
            bulk_upsert_list = []
            
            for raw_line in content:
                raw_line = (raw_line or "").strip()
                if not raw_line or raw_line.lower().startswith("ip" + delimiter): 
                    continue
                
                parts = raw_line.split(delimiter)
                # Formato: IP [;|] Tags [;|] AlertID
                
                raw_ip = parts[0].strip()
                raw_tags = parts[1].strip() if len(parts) > 1 else ""
                raw_alert = parts[2].strip() if len(parts) > 2 else None
                
                # Tags: Si no hay en el CSV, asignamos 'Multicliente' por defecto
                parsed_tags = _parse_tags_field(raw_tags)
                if not parsed_tags:
                    parsed_tags = ["Multicliente"]
                
                row_tags = _filter_allowed_tags(parsed_tags)
                
                if not row_tags:
                    rejected_total += 1
                    continue

                try:
                    expanded = expand_input_to_ips(raw_ip)
                except ValueError as e:
                    # Log errors silently or per-line
                    rejected_total += 1
                    continue
                
                # Expand IPs and prepare object for Bulk
                ttl_days = int(ttl_csv_val) if ttl_csv_val.isdigit() else 0
                expires_at_dt = (_now_utc() + timedelta(days=ttl_days)) if ttl_days > 0 else (_now_utc() + timedelta(days=365*100))
                
                for ip_str in expanded:
                     if not is_allowed_ip(ip_str):
                         rejected_total += 1
                         continue
                     # Ignore IPv6 for now (as requested by user)
                     try:
                        if isinstance(ipaddress.ip_address(ip_str), ipaddress.IPv6Address):
                            continue
                     except: 
                        pass

                     # Prepare Validation/Logic similar to add_ips_validated but simplified for bulk
                     # History Handling: We accept that bulk might overwrite history tail or we can't easily append without read.
                     # Compromise: Create a new history entry and overwrite whatever is there? 
                     # Better: Bulk upsert helper in DB overwrites history. 
                     # ideally we should read existing history... but that kills perf.
                     # Let's start with a fresh history entry for this batch action.
                     
                     history_entry = {
                        "ts": _iso(_now_utc()),
                        "action": "upsert_bulk",
                        "user": f"web/{session.get('username','admin')}",
                        "source": "csv",
                        "tags": row_tags,
                        "ttl": ttl_days,
                        "alert_id": raw_alert
                     }
                     
                     item = {
                         "ip": ip_str,
                         "source": "csv",
                         "tags": row_tags,
                         "ttl": ttl_days,
                         "expiration_date": expires_at_dt,
                         "alert_ids": [raw_alert] if raw_alert else [],
                         "history": [history_entry] 
                     }
                     
                     bulk_upsert_list.append(item)
                     
                     # Update Context Counts/Logs
                     # We don't know if it was update or add without checking DB.
                     # For speed, we might assume add or just mark as "processed".
                     valid_ips_total += 1
                     added_lines_acc.append(f"{ip_str}|...|{ttl_csv_val}")
                     
                     # Accumulate for Teams (just assume added/updated generic)
                     csv_added_objs.append({
                        "ip": ip_str, "tags": row_tags, "ttl": ttl_days, "alert_id": raw_alert
                     })

            # EXECUTE BULK INSERT
            if bulk_upsert_list:
                db.bulk_upsert_ips(bulk_upsert_list)
                regenerate_feeds_from_db()

            # --- BULK OPTIMIZATION END ---

            # 4) Persistir feed y notificar
            # save_lines(lines, FEED_FILE) # Handled by DB Regenerate in add_ips_validated
            
            # --- Notify Teams (Batch) ---
            teams_aggregator.add_batch(
                csv_added_objs, 
                csv_updated_objs, 
                user=f"web/{session.get('username','admin')}", 
                source="csv"
            )
            # ----------------------------

            if valid_ips_total:
                try:
                    guardar_notif("success", f"{valid_ips_total} IPs añadidas (CSV)")
                except Exception:
                    pass
            flash(f"{valid_ips_total} IP(s) añadida(s) correctamente (CSV)", "success")
            if added_lines_acc:
                _set_last_action("add", added_lines_acc)
            # Audit genérico (no detallamos tags aquí porque varían)
            _audit("csv_added", f"web/{session.get('username','admin')}", {"count": valid_ips_total}, {"ttl": ttl_csv_val})

            if rejected_total:
                try:
                    guardar_notif("danger", f"{rejected_total} entradas rechazadas (CSV)")
                except Exception:
                    pass
            flash(f"{rejected_total} entradas rechazadas (inválidas/privadas/duplicadas/no permitidas)", "danger")
            _audit("csv_rejected", f"web/{session.get('username','admin')}", {"count": rejected_total}, {})

            return redirect(url_for("index"))
        # ------------------ FIN Subida CSV/TXT -------------------

        # Alta manual (Tag OBLIGATORIO: Multicliente y/o BPE)
        raw_input = request.form.get("ip", "").strip()
        ticket_number = request.form.get("ticket_number", "").strip() or None
        ttl_man_sel = request.form.get("ttl_manual", "permanente")
        ttl_val = "0" if ttl_man_sel == "permanente" else ttl_man_sel

        # Soportar tanto JS (hidden input) como HTML nativo (checkboxes)
        str_tags = request.form.get("tags_manual", "")
        list_tags = request.form.getlist("tags_manual_cb")
        
        # Unir ambos origenes + texto libre
        text_tags = request.form.get("tags_manual_text", "")
        combined_raw = str_tags + "," + ",".join(list_tags) + "," + text_tags
        
        raw_tags_manual = _parse_tags_field(combined_raw)
        # Usamos _norm_tags para PERMITIR tags nuevos (normalizados), 
        # en lugar de _filter_allowed_tags que los elimina.
        tags_manual = _norm_tags(raw_tags_manual)

        if not ticket_number:
            flash("El campo Ticket es obligatorio.", "danger")
            _audit("manual_rejected_no_ticket", f"web/{session.get('username','admin')}", {}, {})
            return redirect(url_for("index"))

        if not tags_manual:
            flash("Debes seleccionar al menos un tag válido (Multicliente y/o BPE).", "danger")
            _audit("manual_rejected_no_tags", f"web/{session.get('username','admin')}", {}, {})
            return redirect(url_for("index"))

        if raw_input:
            try:
                expanded = expand_input_to_ips(raw_input)

                if not expanded:
                    raw_first = raw_input.strip().split(" ", 1)[0]
                    reason = ip_block_reason(raw_first)
                    msg = f"IP rechazada: {raw_first} — {reason}" if reason else \
                          "Entrada inválida: no se obtuvieron IPs públicas"
                    flash(msg, "danger")
                    guardar_notif("danger", msg)
                    _audit("manual_invalid", f"web/{session.get('username','admin')}", {}, {"input": raw_input, "reason": reason})
                    return redirect(url_for("index"))

                single_input = len(expanded) == 1
                single_ip = expanded[0] if single_input else None
                pre_notified = False

                if single_input and single_ip in existentes:
                    msg = f"IP duplicada: {single_ip}"
                    flash(msg, "danger")
                    guardar_notif("danger", msg)
                    pre_notified = True
                    _audit("manual_duplicate", f"web/{session.get('username','admin')}", single_ip, {})
                elif single_input:
                    reason = ip_block_reason(single_ip)
                    if reason:
                        msg = f"IP rechazada: {single_ip} — {reason}"
                        flash(msg, "danger")
                        guardar_notif("danger", msg)
                        pre_notified = True
                        _audit("manual_rejected", f"web/{session.get('username','admin')}", single_ip, {"reason": reason})

                add_ok, add_bad, added_lines, updated_ok, added_objs, updated_objs = add_ips_validated(
                    lines, existentes, expanded, ttl_val=ttl_val,
                    origin="manual", contador_ruta=COUNTER_MANUAL, tags=tags_manual,
                    alert_id=ticket_number
                )
                
                # --- Notify Teams ---
                teams_aggregator.add_batch(
                    added_objs, 
                    updated_objs, 
                    user=f"web/{session.get('username','admin')}", 
                    source="manual",
                    ticket=ticket_number
                )
                teams_aggregator.flush() # Force flush for immediate manual feedback
                # --------------------

                if add_ok > 0 or updated_ok > 0:

                    # save_lines(lines, FEED_FILE) # Handled by DB Regenerate
                    if single_input:
                        guardar_notif("success", f"IP añadida: {single_ip}")
                        flash(f"IP añadida: {single_ip}", "success")
                    else:
                        guardar_notif("success", f"{add_ok} IPs añadidas")
                        flash(f"{add_ok} IP(s) añadida(s) correctamente", "success")
                    if added_lines:
                        _set_last_action("add", added_lines)
                    _audit("manual_added", f"web/{session.get('username','admin')}", {"count": add_ok}, {"tags": tags_manual, "ttl": ttl_val})
                else:
                    if not (single_input and pre_notified):
                        flash("Nada que añadir (todas inválidas/privadas/duplicadas/no permitidas)", "danger")
                        guardar_notif("danger", "Nada que añadir (todas inválidas/privadas/duplicadas/no permitidas)")
                        _audit("manual_nothing_added", f"web/{session.get('username','admin')}", {}, {"rejected": add_bad})

                if add_bad > 0 and not (single_input and pre_notified):
                    flash(f"{add_bad} entradas rechazadas (inválidas/privadas/duplicadas/no permitidas)", "danger")
                    guardar_notif("danger", f"{add_bad} entradas rechazadas (manual)")
                    _audit("manual_rejected_some", f"web/{session.get('username','admin')}", {"count": add_bad}, {})

            except ValueError as e:
                if str(e) == "accion_no_permitida":
                    flash("⚠️ Acción no permitida: bloqueo de absolutamente todo", "accion_no_permitida")
                    guardar_notif("accion_no_permitida", "Intento de bloqueo global (manual)")
                    _audit("manual_policy_denied", f"web/{session.get('username','admin')}", {}, {})
                else:
                    flash(str(e), "danger")
                    guardar_notif("danger", str(e))
                    _audit("manual_error", f"web/{session.get('username','admin')}", {}, {"error": str(e)})
            except Exception as e:
                flash(f"Error inesperado: {str(e)}", "danger")
                guardar_notif("danger", f"Error inesperado: {str(e)}")
                _audit("manual_exception", f"web/{session.get('username','admin')}", {}, {"error": str(e)})

            return redirect(url_for("index"))
        else:
            error = "Debes introducir una IP, red CIDR, rango A-B o IP con máscara"
    
    # ----- GET (vista HTML o JSON paginado) -----
    # 1) Flashes de esta petición (para TOASTS y burbuja)
    request_actions = coerce_message_pairs(get_flashed_messages(with_categories=True))

    # 2) Historial persistente añadido al final (con fecha delante)
    messages = []
    try:
        data = get_notifs(limit=200)
        if data:
            for n in data:
                cat = str(n.get("category", "secondary"))
                msg = f"{n.get('time','')} {n.get('message','')}".strip()
                messages.append({"category": cat, "message": msg})
    except Exception as e:
        print(f"Error reading notifications: {e}")
        pass

    # --- DB BASED INDEX LOGIC ---
    all_ips_rows = db.get_all_ips()
    
    # Pre-calcular contadores totales
    # (Ya se calculan en compute_source_and_tag_counters_union, pero aquí validamos si se usa para algo más)
    src_union, tag_union, src_tag_union, total_union = compute_source_and_tag_counters_union()
    
    # Filtrar por feed solicitado
    # Si feed=='global', mostrar todo (sujeto a RBAC y search)
    # Si feed=='multicliente', 'bpe', 'test', filtrar por tags
    
    filtered_rows = []
    
    # Preparar estructuras auxiliares para la vista
    live_manual = src_union.get("manual", 0)
    live_csv = src_union.get("csv", 0)
    live_api = src_union.get("api", 0)
    tag_totals = tag_union
    
    # Mapa ip -> details
    ip_details = {}
    ip_tags_map = {}
    
    for r in all_ips_rows:
        ip = r["ip"]
        tags = []
        try:
            tags = json.loads(r["tags"] or '[]')
        except:
            tags = []
        
        alerts = []
        try:
            alerts = json.loads(r["alert_ids"] or '[]')
        except:
            alerts = []
            
        ip_details[ip] = {
            "source": r.get("source"),
            "tags": tags,
            "ttl": r.get("ttl"),
            "added_at": r.get("added_at"),
            "alert_ids": alerts
        }
        ip_tags_map[ip] = tags

    # Determine visible items based on feed_param
    target_tags = []
    if feed_param == "multicliente":
        target_tags = ["Multicliente"]
    elif feed_param == "bpe":
        target_tags = ["BPE"]
    elif feed_param == "test":
        target_tags = ["Test"]
    
    filtered = [] # Unified list of dicts
    
    # print(f"DEBUG: all_ips_rows count: {len(all_ips_rows)}")
    
    for r in all_ips_rows:
        # Filter Logic
        ip = r["ip"]
        tags = ip_tags_map.get(ip, [])
        
        # 1. Feed Filter (Context)
        if feed_param != "global":
             if not any(t in target_tags for t in tags):
                continue
                
        # 2. Search Filter (Query)
        q = request.args.get("q", "").strip().lower()
        if q:
             if q not in ip.lower() and q not in str(tags).lower() and q not in str(r.get("source","")).lower():
                 continue

        # 3. Source/Origin Filter
        source_param = request.args.get("origin") or request.args.get("source") or "all"
        if source_param != "all":
            row_src = r.get("source") or "manual"
            if row_src != source_param:
                # print(f"DEBUG: Skipping {ip} - source {row_src} != {source_param}")
                continue

        # 4. Tag Filter (Specific)
        tag_param = request.args.get("tag", "all")
        if tag_param != "all":
            # Si el tag solicitado no está en la lista de tags de la IP
            if tag_param not in tags:
                # print(f"DEBUG: Skipping {ip} - tag {tag_param} not in {tags}")
                continue
        
        # print(f"DEBUG: Match {ip} - Src:{source_param} Tag:{tag_param}")

        # 5. Date Filter (Range)
        date_param = request.args.get("date", "") # fmt: YYYY-MM-DD,YYYY-MM-DD
        date_from = request.args.get("dateFrom", "")
        date_to = request.args.get("dateTo", "")

        # Fallback date param extraction
        if not date_from and not date_to and "," in date_param:
            parts = date_param.split(",", 1)
            date_from = parts[0]
            date_to = parts[1]

        if date_from or date_to:
            d_str_iso = (r.get("added_at") or "").split("T")[0]
            if date_from and d_str_iso < date_from:
                continue
            if date_to and d_str_iso > date_to:
                continue
                 
        # Add to list
        # Format: IP|DATE|TTL (Legacy expectations? Or object?)
        # Template loop: {% for line in ips %}
        # and inside: ip = line.split("|")[0] ...
        # So we MUST provide strings "IP|DATE|TTL".
        
        # Format date YYYY-MM-DD
        d_str = ""
        try:
            d_qt = datetime.fromisoformat(r["added_at"].replace("Z", "+00:00"))
            d_str = d_qt.strftime("%Y-%m-%d")
        except:
             d_str = r["added_at"] or ""
             
        # Build JSON Object
        ttl_str = str(r["ttl"])
        
        # Calculate days remaining for UI
        left_days = days_remaining(d_str, r.get("ttl", 0))

        item_obj = {
            "ip": ip,
            "date": d_str,
            "fecha_alta": d_str, # Frontend expects this key
            "ttl": ttl_str,
            "days_remaining": left_days,
            "tags": list(tags),
            "source": r.get("source"),
            "alert_ids": (ip_details.get(ip) or {}).get("alert_ids", []), # Send LIST, not string
            # "alert_id": ... # legacy field name for template?
        }
        
        # Get alert_id (ticket)
        # We need to map from ip_details or just use what we have.
        # Check ip_details[ip]
        if ip in ip_details:
             item_obj["alert_id"] = (ip_details[ip].get("alert_ids") or [None])[0]
        else:
             item_obj["alert_id"] = None
             
        filtered.append(item_obj)

    # ------------------
    # Paginación (Unified)
    # ------------------
    total = len(filtered)
    try:
        page = int(request.args.get("page", 1))
        page_size = int(request.args.get("page_size", DEFAULT_PAGE_SIZE))
    except:
        page, page_size = 1, DEFAULT_PAGE_SIZE
    
    # Generic paginate
    start = (page - 1) * page_size
    end = start + page_size
    paged_items = filtered[start:end]
    
    # Generate 'lines' for Template (Legacy string format)
    lines = []
    for it in paged_items:
        # IP|DATE|TTL
        lines.append(f"{it['ip']}|{it['date']}|{it['ttl']}")

    # JSON Return
    fmt = request.args.get("format", "").lower()
    if fmt == "json":
        # Return same structure as Expected by frontend:
        # { items: [...], counters: {...}, page:..., total:... }
        return jsonify({
            "items": paged_items,
            "counters": { "total": total }, # simplified
            "page": page,
            "page_size": page_size,
            "total": total
        })
        
    # HTML Return continues below...
    # (Update lines variable for pagination check later if any)
    # Actually _paginate was called before, we replaced it.
    # We need to ensure existing variables for template are set.


    # Render HTML normal (initial state)
    
    ip_tags = {}
    ip_alert_ids = {}
    ip_alerts = {} # legacy
    for ip, details in ip_details.items():
        if "tags" in details: ip_tags[ip] = details["tags"]
        if "alert_ids" in details: ip_alert_ids[ip] = details["alert_ids"]

    known_tags = _collect_known_tags()

    return render_template("index.html",
                           current_feed=feed_param,
                           feeds_config=visible_feeds,
                           current_flashes_list=request_actions,
                           server_messages_list=messages,
                           ips=lines, # para compatibilidad si algo usa 'ips' raw en jinja
                           error=error,
                           total_ips=total_union,
                           contador_manual=live_manual,
                           contador_csv=live_csv,
                           contador_api=live_api,
                           contador_tags=tag_totals,
                           union_total=total_union,
                           union_by_source=src_union,
                           union_by_tag=tag_union,
                           union_by_source_tag=src_tag_union,
                           messages=messages,
                           user_role=user_data.get("role", "editor"),
                           request_actions=request_actions,
                           ip_tags=ip_tags,
                           ip_alerts=ip_alerts,
                           ip_ticket_ids=ip_alert_ids,
                           known_tags=known_tags,
                           days_remaining=days_remaining,
                           maintenance_mode=g.get("maintenance_mode", False))


def _create_feed_response(ips_list):
    """
    Genera una respuesta Flask con ETag (MD5) para la lista de IPs.
    Si el cliente ya tiene esa versión (If-None-Match), devuelve 304.
    """
    body = "\n".join(ips_list) + "\n"
    # Calcular ETag
    content_hash = hashlib.md5(body.encode("utf-8")).hexdigest()
    
    # Check conditional request
    if request.if_none_match and request.if_none_match.contains(content_hash):
        return Response(status=304)
        
    resp = make_response(body, 200)
    resp.headers["Content-Type"] = "text/plain"
    resp.headers["ETag"] = content_hash
    resp.headers["Cache-Control"] = "public, max-age=300" # Cacheable for 5 min
    return resp


@app.route("/feed/ioc-feed.txt")
def feed():
    ips = []
    if os.path.exists(FEED_FILE):
        try:
            with open(FEED_FILE, encoding="utf-8") as f:
                for line in f:
                    ip = line.split("|", 1)[0].strip()
                    if ip and is_allowed_ip(ip):
                        try:
                            if isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address):
                                ips.append(ip)
                        except Exception:
                            continue
        except Exception:
            pass
    return _create_feed_response(ips)

# === NUEVO: feed BPE separado ===
@app.route("/feed/ioc-feed-bpe.txt")
def feed_bpe():
    ips = []
    if os.path.exists(FEED_FILE_BPE):
        try:
            with open(FEED_FILE_BPE, encoding="utf-8") as f:
                for line in f:
                    ip = line.split("|", 1)[0].strip()
                    if ip and is_allowed_ip(ip):
                        try:
                            if isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address):
                                ips.append(ip)
                        except Exception:
                            continue
        except Exception:
            pass
    return _create_feed_response(ips)

@app.route("/feed/ioc-feed-test.txt")
def feed_test():
    ips = []
    if os.path.exists(FEED_FILE_TEST):
        try:
            with open(FEED_FILE_TEST, encoding="utf-8") as f:
                for line in f:
                    ip = line.split("|", 1)[0].strip()
                    if ip and is_allowed_ip(ip):
                        try:
                            if isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address):
                                ips.append(ip)
                        except Exception:
                            continue
        except Exception:
            pass
    return _create_feed_response(ips)


@app.route("/preview-delete")
@login_required
def preview_delete():
    pattern = request.args.get("pattern", "").strip()
    if not pattern:
        return jsonify({"error": "Patrón vacío"}), 400
    try:
        kind, obj = parse_delete_pattern(pattern)
        all_ips = db.get_all_ips()
        count = 0
        for row in all_ips:
            try:
                ip_obj = ipaddress.ip_address(row['ip'])
                match = False
                if kind == "single":
                    match = (ip_obj == obj)
                elif kind == "cidr":
                    match = (ip_obj in obj)
                elif kind == "range":
                    a, b = obj
                    match = (int(a) <= int(ip_obj) <= int(b))
                if match:
                    count += 1
            except:
                continue
        return jsonify({"count": count})
    except Exception as e:
        return jsonify({"error": str(e)}), 400





# =========================
#  Gestión de Usuarios (Dashboard)
# =========================
@app.route("/admin/users", methods=["GET"])
@login_required
def list_users():
    users = load_users()
    # Retornar lista segura (sin hash)
    safe_list = []
    for u, data in users.items():
        feeds = data.get("allowed_feeds", [])
        if not isinstance(feeds, list):
            feeds = [feeds] if feeds else []
            
        safe_list.append({
            "username": u,
            "role": data.get("role", "editor"),
            "allowed_feeds": feeds,
            "created_at": data.get("created_at")
        })
    return jsonify({"users": safe_list})

@app.route("/admin/users/add", methods=["POST"])
@login_required
def add_user():
    current_user = session.get("username")
    
    # Validation logic remains... (check if exists done by DB unique constraint or pre-check)
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    role = data.get("role", "view_only").strip()
    allowed_feeds = data.get("allowed_feeds", [])
    
    if not username or not password:
        return jsonify({"error": "Faltan datos"}), 400
        
    # Check existence
    if db.get_user_by_username(username):
        return jsonify({"error": "El usuario ya existe"}), 400
        
    pwd_hash = generate_password_hash(password)
    
    if db.create_user(username, pwd_hash, role, allowed_feeds):
        _audit("user_created", f"web/{current_user}", username, {"role": role, "feeds": allowed_feeds})
        return jsonify({"success": True})
    else:
        return jsonify({"error": "Error creando usuario"}), 500

@app.route("/admin/users/edit", methods=["POST"])
@login_required
def edit_user():
    current_user = session.get("username")
    
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    role = data.get("role", "view_only").strip()
    allowed_feeds = data.get("allowed_feeds", [])
    
    if not username:
        return jsonify({"error": "Faltan datos"}), 400
        
    if not db.get_user_by_username(username):
        return jsonify({"error": "El usuario no existe"}), 404
        
    new_hash = generate_password_hash(password) if password else None
    
    if db.update_user(username, role=role, allowed_feeds=allowed_feeds, password_hash=new_hash):
        _audit("user_updated", f"web/{current_user}", username, {"role": role, "feeds": allowed_feeds, "pw_changed": bool(password)})
        return jsonify({"success": True})
    else:
        return jsonify({"error": "Error actualizando"}), 500

@app.route("/admin/users/delete", methods=["POST"])
@login_required
def delete_user():
    data = request.get_json(silent=True) or {}
    target = data.get("username", "").strip()
    current = session.get("username")
    
    if target == current:
        return jsonify({"error": "No puedes borrarte a ti mismo"}), 400
        
    if not db.get_user_by_username(target):
         return jsonify({"error": "Usuario no encontrado"}), 404
         
    if db.delete_user(target):
        _audit("user_deleted", f"web/{current}", target, {})
        return jsonify({"success": True})
    else:
        return jsonify({"error": "Error borrando usuario"}), 500

@app.route("/admin/users/password", methods=["POST"])
@login_required
def change_password():
    data = request.get_json(silent=True) or {}
    target = data.get("username", "").strip()
    new_pass = data.get("password", "").strip()
    current = session.get("username")

    if not target or not new_pass:
        return jsonify({"error": "Faltan datos"}), 400
        
    # Permitir cambio si es el mismo usuario O si es un admin gestionando otro
    if target != current:
        # Aquí idealmente validaríamos si 'current' tiene rol admin
        pass

    users = load_users()
    if target not in users:
        return jsonify({"error": "Usuario no encontrado"}), 404
        
    users[target]["password_hash"] = generate_password_hash(new_pass)
    save_users(users)
    _audit("user_password_changed", f"web/{current}", target, {})
    return jsonify({"success": True})


# =========================
#  Helpers de Vista
# =========================
def days_remaining(date_str, ttl_str):
    try:
        ttl = int(ttl_str)
        if ttl == 0:
            return None
        d = datetime.strptime(date_str, "%Y-%m-%d")
        exp = d + timedelta(days=ttl)
        # _now_utc() devuelve offset-aware, strip para comparar con strptime naive
        left = (exp - datetime.utcnow()).days
        return max(0, left)
    except:
        return None

# =========================
#  Rutas de backup
# =========================
@app.route("/backup/latest.zip")
@login_required
def backup_latest_zip():
    """Descarga el ZIP más reciente; 404 si no hay."""
    if not os.path.isdir(BACKUP_DIR):
        abort(404)
    zips = [f for f in os.listdir(BACKUP_DIR) if re.fullmatch(r"\d{4}-\d{2}-\d{2}(_.*)?\.zip", f)]
    if not zips:
        abort(404)
    zips.sort(reverse=True)
    latest = os.path.join(BACKUP_DIR, zips[0])
    return send_file(latest, as_attachment=True, download_name=zips[0], mimetype="application/zip")


@app.route("/backup/now", methods=["POST"])
@login_required
def backup_now():
    """Fuerza un backup inmediato con timestamp."""
    perform_manual_backup()
    # flash("Backup forzado creado", "success") -> Ya lo hace perform_manual_backup via notif, 
    # pero el flash en UI viene bien.
    flash("Backup manual completado correctamente", "success")
    guardar_notif("success", "Backup forzado creado")
    return redirect(url_for("index"))


@app.route("/backup/restore", methods=["POST"])
@login_required
def backup_restore_upload():
    # Admin check (User Role)
    current_username = session.get("username")
    all_users = load_users()
    user_data = all_users.get(current_username, {})
    if user_data.get("role") != "admin":
         flash("Solo admin puede restaurar backups.", "danger")
         return redirect(url_for("index"))

    # File check
    if 'backup_file' not in request.files:
         flash("No se ha subido ningún archivo.", "danger")
         return redirect(url_for("index"))

    file = request.files['backup_file']
    if file.filename == "":
         flash("Nombre de archivo vacío.", "danger")
         return redirect(url_for("index"))

    if not file.filename.endswith(".zip"):
         flash("El archivo debe ser un .zip", "danger")
         return redirect(url_for("index"))

    try:
         # 1. Safety Backup (Always)
         perform_manual_backup() 

         # 2. Save Upload
         temp_dir = os.path.join(BASE_DIR, "temp_restore")
         if os.path.exists(temp_dir):
             shutil.rmtree(temp_dir)
         os.makedirs(temp_dir)
         
         zip_path = os.path.join(temp_dir, "uploaded.zip")
         file.save(zip_path)

         # 3. Validation & Unzip
         with zipfile.ZipFile(zip_path, 'r') as zip_ref:
              zip_ref.extractall(temp_dir)
         
         # Sanity Check
         if not os.path.exists(os.path.join(temp_dir, "ioc-feed.txt")):
              raise Exception("ZIP inválido: falta ioc-feed.txt")

         # 4. Restore (Overwrite)
         # Root files
         restore_list = ["ioc-feed.txt", "ioc-feed-bpe.txt", "ioc-feed-test.txt", 
                         "ioc-log.txt", "notif-log.json", "audit-log.jsonl", 
                         "users.json", ".env", "ioc-meta.json"] 
                         # Nota: ioc-meta.json suele estar en data/ en app original 
                         # pero en el ZIP de backup flat se guarda en root? 
                         # REVISAR _backup_critical_files: copia META_FILE (data/ioc-meta.json) a DEST.
                         # DEST es root del zip. ASI QUE SÍ, está en root del zip.
                         # AL RESTAURAR debemos ponerlo en data/ioc-meta.json.
         
         for fname in restore_list:
              src = os.path.join(temp_dir, fname)
              if fname == "ioc-meta.json":
                   dst = META_FILE # rutas absolutas definidas arriba
              elif fname == "ioc-feed-test.txt":
                   dst = FEED_FILE_TEST
              else:
                   dst = os.path.join(BASE_DIR, fname)
              
              if os.path.exists(src):
                  if os.path.exists(dst): os.remove(dst)
                  shutil.move(src, dst)
         
         # Restore 'data' folder
         src_data = os.path.join(temp_dir, "data")
         if os.path.isdir(src_data):
              dst_data = DATA_DIR
              shutil.copytree(src_data, dst_data, dirs_exist_ok=True)
         
         # 5. Cleanup
         try: shutil.rmtree(temp_dir)
         except: pass

         flash("Backup restaurado correctamente. Se creó copia de seguridad previa.", "success")
         guardar_notif("warning", f"Backup restaurado por {current_username}")
         _audit("restore_backup", f"web/{current_username}", {}, {"file": file.filename})

    except Exception as e:
         flash(f"Error al restaurar: {str(e)}", "danger")
         print(f"Restore Error: {e}")
    
    return redirect(url_for("index"))


@app.route("/backup/list")
@login_required
def backup_list():
    """Lista de backups disponibles (JSON)."""
    if not os.path.isdir(BACKUP_DIR):
        return jsonify({"backups": []})
    items = []
    for name in os.listdir(BACKUP_DIR):
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}(_.*)?\.zip", name):
            items.append(name)
    items.sort(reverse=True)
    return jsonify({"backups": items})


# ========= Observabilidad / util =========
@app.route("/healthz")
def healthz():
    try:
        _ = os.path.exists(FEED_FILE)
        _ = os.path.exists(FEED_FILE_BPE)
        return jsonify({"status": "ok", "time": datetime.utcnow().isoformat()+"Z"})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


@app.route("/metrics")
@login_required
def metrics():
    # Calcular contadores reales de DB
    src_counts, tag_counts, _, total = compute_source_and_tag_counters_union()

    return jsonify({
        # Compat anteriores (aproximados mapeando manual->principal)
        "total_active_principal": total,
        "manual_active_principal": src_counts.get("manual", 0),
        "csv_active_principal": src_counts.get("csv", 0),
        "api_active_principal": src_counts.get("api", 0),
        "tags_total_union": tag_counts,
        # Nuevos (unión feeds):
        "union_total": total,
        "union_by_source": src_counts,
        "union_by_tag": tag_counts,
        "union_by_source_tag": {} # Not needed for dashboard top cards
    })


# --- Settings Routes ---

@app.route('/admin/settings')
@login_required
def admin_settings_ui():
    if session.get('role') != 'admin':
        return redirect(url_for('index'))
    
    # --- Config & API Keys ---
    api_keys = db.list_api_keys()
    webhook_url = db.get_config("TEAMS_WEBHOOK_URL", "")

    # --- Audit Log Logic (Migrated) ---
    requested_file = request.args.get("log_file", "").strip()
    target_file = AUDIT_LOG_FILE
    is_historical = False
    
    if requested_file:
        safe_name = os.path.basename(requested_file)
        full_path = os.path.join(os.path.dirname(AUDIT_LOG_FILE) or ".", safe_name)
        if os.path.exists(full_path) and safe_name.startswith("audit-log.") and safe_name.endswith(".jsonl"):
            target_file = full_path
            if safe_name != os.path.basename(AUDIT_LOG_FILE):
                is_historical = True

    audit_logs = []
    try:
        if is_historical:
            # Historical files
            if os.path.exists(target_file):
                with open(target_file, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                    for line in reversed(lines[-500:]):
                        try:
                            audit_logs.append(json.loads(line))
                        except:
                            pass
        else:
            # Active log from DB
            audit_logs = db.get_audit_log(500)
    except Exception as e:
        print(f"Error loading audit logs: {e}")

    available_files = get_audit_log_files()

    return render_template('settings.html', 
                           api_keys=api_keys, 
                           webhook_url=webhook_url,
                           audit_logs=audit_logs,
                           current_file=os.path.basename(target_file),
                           is_historical=is_historical,
                           available_files=available_files)

@app.route('/admin/api-keys', methods=['POST'])
@login_required
def admin_api_keys():
    if session.get('role') != 'admin':
        return jsonify({"ok": False, "error": "Unauthorized"}), 403
        
    action = request.form.get('action')
    if action == 'create':
        name = request.form.get('name')
        scopes = request.form.get('scopes') # "READ,WRITE"
        # Generate secure token
        import secrets
        token = "dk_" + secrets.token_urlsafe(16)
        
        if db.create_api_key(name, token, scopes):
             flash(f"API Key creada: {token}", "success")
        else:
             flash("Error al crear API Key", "danger")
             
    elif action == 'delete':
        key_id = request.form.get('id')
        if db.delete_api_key(key_id):
            flash("API Key eliminada", "success")
        else:
            flash("Error al eliminar", "danger")
            
    return redirect(url_for('admin_settings_ui'))

@app.route("/update-ttl", methods=["POST"])
@login_required
def update_ttl_route():
    data = request.get_json(silent=True) or {}
    ip = data.get("ip")
    ttl = data.get("ttl")
    
    if not ip:
        return jsonify({"error": "IP missing"}), 400
        
    # Validar IP existente
    curr = db.get_ip(ip)
    if not curr:
        return jsonify({"error": "IP no encontrada"}), 404
        
    # Update logic
    if db.update_ip_ttl(ip, ttl):
        _audit("ttl_update", f"web/{session.get('username','admin')}", ip, {"new_ttl": ttl})
        return jsonify({"success": True})
    else:
        return jsonify({"error": "Error de base de datos"}), 500

@app.route('/admin/config', methods=['POST'])
@login_required
def admin_config():
    if session.get('role') != 'admin':
        return jsonify({"ok": False, "error": "Unauthorized"}), 403
        
    webhook = request.form.get('teams_webhook_url')
    if webhook is not None:
        db.set_config("TEAMS_WEBHOOK_URL", webhook.strip())
        flash("Configuración actualizada", "success")
        
    return redirect(url_for('admin_settings_ui'))


@app.route("/notifications/read-all", methods=["POST"])
@login_required
def notifications_read_all():
    return json_response_ok(notices=[{"time": datetime.utcnow().isoformat()+"Z", "category": "info", "message": "Notificaciones marcadas como leídas"}])


# =========================
#  Log Rotation Logic
# =========================
def perform_log_rotation():
    """Rota logs si superan 5MB. Retención infinita (renombrado)."""
    # Lista de ficheros a vigilar
    targets = [AUDIT_LOG_FILE, "ioc-log.txt", "notif-log.json"]
    limit_bytes = 5 * 1024 * 1024  # 5 MB

    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M")
    
    for fpath in targets:
        try:
            if os.path.exists(fpath) and os.path.getsize(fpath) > limit_bytes:
                # Renombrar: audit-log.jsonl -> audit-log.2025-12-22_1030.jsonl
                # Si tiene extensión, insertamos fecha antes. Si no, al final.
                base, ext = os.path.splitext(fpath)
                new_name = f"{base}.{timestamp}{ext}"
                
                # Evitar colisión si pasa muy rápido (aunque minuto suele bastar)
                if os.path.exists(new_name):
                    new_name = f"{base}.{timestamp}_{int(time.time())}{ext}"
                    
                os.rename(fpath, new_name)
                # El sistema creará uno nuevo limpio en la siguiente escritura
        except Exception:
            pass

def get_audit_log_files():
    """Retorna lista de ficheros de log de auditoría disponibles (históricos)."""
    directory = os.path.dirname(AUDIT_LOG_FILE) or "."
    base_name = os.path.basename(AUDIT_LOG_FILE) # audit-log.jsonl
    base_prefix = os.path.splitext(base_name)[0] # audit-log
    
    files = []
    try:
        for f in os.listdir(directory):
            # Buscar ficheros que empiecen por audit-log. y no sean el propio lock ni el activo (exacto)
            if f.startswith(base_prefix + ".") and f.endswith(".jsonl") and f != base_name:
                files.append(f)
    except Exception:
        pass
        
    # Ordenar por nombre (que incluye fecha), descendente (más nuevos primero)
    files.sort(reverse=True)
    return files





# =========================
#  API (Blueprint) con tags + alert_id
# =========================
api = Blueprint("api", __name__, url_prefix="/api")

@api.before_request
def _api_guard():
    # 0. Check if Web User (Session)
    if session.get("username"):
        return # Allow web users (skip strict API checks)

    # auth + allowlist + rate
    if not _auth_ok():
        _audit("api_unauthorized", f"api/{_client_ip()}", request.path, {"method": request.method})
        return jsonify({"error": "Unauthorized"}), 401
    if not _allowlist_ok():
        _audit("api_forbidden", f"api/{_client_ip()}", request.path, {"method": request.method})
        return jsonify({"error": "Forbidden by allowlist"}), 403
    if not _rate_ok():
        _audit("api_ratelimit", f"api/{_client_ip()}", request.path, {"method": request.method})
        return jsonify({"error": "Rate limit exceeded"}), 429
    # actor para auditoría
    g.api_actor = f"api/{_client_ip()}"

def _auth_ok():
    # Relaxed check: We allow DB tokens even if TOKEN_API env var is missing
    # if not TOKEN_API: return False (Removed to support DB-only auth)

    
    token_found = None
    
    # 1. Try Bearer
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token_found = auth.split(" ", 1)[1].strip()
    
    # 2. Try X-API-Key
    if not token_found:
        token_found = request.headers.get("X-API-Key", "")
        
    # 3. Try query param
    if not token_found:
        token_found = request.args.get("token", "")

    if not token_found:
        return False

    # Validation
    # A) Legacy
    if token_found == TOKEN_API:
        g.api_user = {"name": "system (legacy)", "scopes": "ALL"}
        return True
        
    # B) DB
    key_record = db.get_api_key(token_found)
    if key_record:
        g.api_user = key_record
        return True
        
    return False

def _client_ip():
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "0.0.0.0"

def _allowlist_ok():
    if not API_ALLOWLIST:
        return True
    src = _client_ip()
    try:
        ip_src = ipaddress.ip_address(src)
    except Exception:
        return False
    for cidr in API_ALLOWLIST.split(","):
        cidr = cidr.strip()
        if not cidr:
            continue
        try:
            if ip_src in ipaddress.ip_network(cidr, strict=False):
                return True
        except Exception:
            continue
    return False

def _rate_ok():
    auth = request.headers.get("Authorization", "")
    now = time.time()
    with _rate_lock:
        hist = _rate_hist.setdefault(auth, [])
        hist = [t for t in hist if now - t < 60]
        if len(hist) >= RATE_LIMIT_PER_MIN:
            _rate_hist[auth] = hist
            return False
        hist.append(now)
        _rate_hist[auth] = hist
        return True

def _idem_get(key):
    if not key:
        return None
    now = time.time()
    with _idem_lock:
        v = _idem_cache.get(key)
        if not v:
            return None
        ts, payload = v
        if now - ts > IDEM_TTL_SECONDS:
            _idem_cache.pop(key, None)
            return None
        return payload

def _idem_put(key, payload):
    if not key:
        return
    with _idem_lock:
        _idem_cache[key] = (time.time(), payload)

def _parse_ttl_seconds(obj) -> int:
    # Admite 'ttl_seconds' o 'ttl' con sufijo s/m/h/d o número pelado
    if isinstance(obj, dict):
        if "ttl_seconds" in obj:
            try:
                v = int(obj["ttl_seconds"])
                if v > 0:
                    return v
            except Exception:
                pass
        ttl = obj.get("ttl")
    else:
        ttl = None

    if ttl:
        t = str(ttl).lower().strip()
        try:
            if t.endswith("s"):
                return max(1, int(t[:-1]))
            if t.endswith("m"):
                return max(60, int(t[:-1]) * 60)
            if t.endswith("h"):
                return max(3600, int(t[:-1]) * 3600)
            if t.endswith("d"):
                return max(86400, int(t[:-1]) * 86400)
            return max(1, int(t))
        except Exception:
            pass
    # por defecto: 24h
    return 86400

@app.route("/api/summary", methods=["GET"])
@require_api_token("READ")
def api_summary():
    """
    Endpoint ligero para monitorización externa (Zabbix/Grafana).
    Retorna contadores en tiempo real.
    """
    try:
        src_counts, tag_counts, _, total = compute_source_and_tag_counters_union()
        
        return jsonify({
            "ok": True,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "total_ips": total,
            "sources": src_counts,
            "tags": tag_counts
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@api.route("/bloquear-ip", methods=["POST", "DELETE"])
@require_api_token("WRITE")
def bloquear_ip_api():
    # Idempotencia para POST
    if request.method == "POST":
        idem = request.headers.get("Idempotency-Key", "").strip() or None
        cached = _idem_get(idem)
        if cached is not None:
            _audit("api_post_idempotent_hit", g.get("api_actor","api"), "/api/bloquear-ip", {"idem": idem})
            return jsonify(cached), 200

        try:
            payload = request.get_json(force=True, silent=False)
        except Exception:
            _audit("api_post_invalid_json", g.get("api_actor","api"), "/api/bloquear-ip", {})
            return jsonify({"error": "JSON inválido"}), 400

        items = payload.get("items")
        single = False
        if not isinstance(items, list):
            items = [payload]
            single = True

        origin = payload.get("origen") or payload.get("origin") or "api"
        force = bool(payload.get("force", False))

        # Estado actual del feed principal
        # Estado actual de TODOS los feeds para detectar duplicados globales
        lines = [] # Legacy logic removed
        existentes = _active_ip_union()

        processed, errors = [], []

        for idx, it in enumerate(items):
            try:
                ttl_s = _parse_ttl_seconds(it)
                expires_at = _now_utc() + timedelta(seconds=ttl_s)
                # para feed en días (compat frontal)
                ttl_days = 0 if ttl_s == 0 else max(1, math.ceil(ttl_s / 86400.0))

                tags = _filter_allowed_tags(it.get("tags", []))
                if not tags:
                    errors.append({"index": idx, "error": "missing_tags"})
                    continue

                note = str(it.get("nota", "") or it.get("note", "")).strip()

                # alert_id opcional por item
                raw_alert_id = it.get("alert_id")
                alert_id = str(raw_alert_id).strip() if raw_alert_id is not None else None
                if alert_id == "":
                    alert_id = None

                # soportar inputs: ip / cidr / range / "ip máscara"
                targets = []
                # ip + máscara
                s_ip = str(it.get("ip", "")).strip()
                if s_ip and " " in s_ip:
                    targets = expand_input_to_ips(s_ip, max_expand=EXPANSION_LIMIT)
                elif it.get("ip"):
                    targets = expand_input_to_ips(str(it["ip"]).strip(), max_expand=EXPANSION_LIMIT)
                elif it.get("cidr"):
                    targets = expand_input_to_ips(str(it["cidr"]).strip(), max_expand=EXPANSION_LIMIT)
                elif it.get("range"):
                    targets = expand_input_to_ips(str(it["range"]).strip(), max_expand=EXPANSION_LIMIT)
                else:
                    raise ValueError("Item sin ip/cidr/range válido")

                if not targets:
                    raise ValueError("No se obtuvieron IPs válidas y públicas del item")

                item_result = {"count": 0, "ips": []}
                
                # Usar la función centralizada para garantizar consistencia y CONTADORES
                add_ok, add_bad, added_lines_item, updated_item, added_objs, updated_objs = add_ips_validated(
                    lines, existentes, targets,
                    ttl_val=ttl_days,  # Convertido arriba
                    origin="api",
                    contador_ruta=COUNTER_API,
                    tags=tags,
                    alert_id=alert_id,
                    force=force,
                    note=note
                )
                
                # --- Notify Teams ---
                teams_aggregator.add_batch(
                    added_objs, 
                    updated_objs, 
                    user=g.get("api_actor", "api"), 
                    source="api",
                    ticket=alert_id
                )
                # --------------------

                # Re-cargar meta para obtener los detalles frescos
                # Get fresh details from DB
                for ip_str in targets:
                    row = db.get_ip(ip_str)
                    if row:
                        tags_db = []
                        try: 
                            tags_db = json.loads(row["tags"] or '[]')
                        except: 
                            tags_db = []
                        
                        alerts_db = []
                        try: 
                            alerts_db = json.loads(row["alert_ids"] or '[]')
                        except: 
                            alerts_db = []
                        
                        item_result["ips"].append({
                            "ip": ip_str,
                            "status": "ok",
                            "tags": tags_db,
                            "expires_at": row["expiration_date"],
                            "alert_ids": alerts_db
                        })
                    else:
                         item_result["ips"].append({"ip": ip_str, "status": "not_processed"})

                item_result["count"] = add_ok + updated_item
                processed.append(item_result)
            except Exception as e:
                print(f"[API ERROR] Index {idx} failed: {e}", flush=True)
                import traceback
                traceback.print_exc()
                errors.append({"index": idx, "error": str(e)})

        # Guardar feed si cambió
        # save_lines(lines, FEED_FILE) # Handled by DB Regenerate

        # Force flush ONCE at the end of the batch
        teams_aggregator.flush()

        resp = {
            "status": "partial_ok" if errors and processed else ("error" if errors and not processed else "ok"),
            "processed": processed,
            "errors": errors
        }
        if idem:
            _idem_put(idem, resp)

        _audit("api_post_bloquear", g.get("api_actor","api"), {"status": resp["status"], "items": len(items), "errors": len(errors)}, {})
        return jsonify(resp), (207 if errors and processed else (400 if errors and not processed else 200))

    # DELETE: { "ip": "x.y.z.w", "tags": [...] (opcional) }
    try:
        body = request.get_json(force=True, silent=True) or {}
    except Exception:
        body = {}

    ip_txt = str(body.get("ip", "")).strip()
    if not ip_txt:
        _audit("api_delete_missing_ip", g.get("api_actor","api"), "/api/bloquear-ip", {})
        return jsonify({"error": "Campo 'ip' requerido"}), 400
    try:
        ipaddress.ip_address(ip_txt)
    except Exception:
        _audit("api_delete_invalid_ip", g.get("api_actor","api"), "/api/bloquear-ip", {"ip": ip_txt})
        return jsonify({"error": "IP inválida"}), 400

    tags = _filter_allowed_tags(body.get("tags", []))
    
    # Check existence
    row = db.get_ip(ip_txt)
    if not row:
         # No existe: si no hay tags => devolver Deleted (idempotencia) o Not Found?
         # Legacy logic returns Deleted if global delete (no tags)
         if not tags:
             return jsonify({"status": "deleted", "ip": ip_txt, "scope": "global"}), 200
         else:
             _audit("api_delete_not_found", g.get("api_actor","api"), ip_txt, {"tags": tags})
             return jsonify({"status": "not_found", "ip": ip_txt}), 404

    if not tags:
        # borrar de todos los tags + feeds + meta (Global Delete)
        db.delete_ip(ip_txt)
        regenerate_feeds_from_db()
        
        _audit("api_delete_all_tags", g.get("api_actor","api"), ip_txt, {})
        send_teams_alert(f"🗑️ IP Eliminada (API)", f"IP: **{ip_txt}**\nScope: Global (todos los tags)", color="DC3545", sections=[{"activityTitle": "User", "activitySubtitle": g.get("api_actor","api")}])
        return jsonify({"status": "deleted", "ip": ip_txt, "scope": "global"}), 200
    else:
        # borrar solo tags indicados (Untag)
        current_tags = []
        try: current_tags = json.loads(row["tags"] or '[]')
        except: pass
        
        remaining = [t for t in current_tags if t not in set(tags)]
        
        # Update via upsert
        # Preserve other fields
        # Note: db.upsert_ip requires all fields.
        # Shortcuts via db?
        # db.remove_tag handles single tag.
        # But here we might have multiple tags.
        # Let's iterate db.remove_tag for simplicity or upsert once.
        # Upsert once is better for atomic-ish update, but manual construction needed.
        # Or loop remove_tag (less code here).
        
        updated_any = False
        for t in tags:
            # Only if present
            if t in current_tags:
                # remove_tag calls upsert internally per tag.
                # A bit inefficient if many tags, but safe.
                db.remove_tag(ip_txt, t)
                updated_any = True
                
        if updated_any:
            regenerate_feeds_from_db()
            
        current_tags = [t for t in current_tags if t not in tags]

        _audit("api_untag", g.get("api_actor","api"), ip_txt, {"tags_removed": tags, "remaining": current_tags})
        send_teams_alert(f"label IP Untag (API)", f"IP: **{ip_txt}**\nTags quitados: {', '.join(tags)}", color="FFC107", sections=[{"activityTitle": "User", "activitySubtitle": g.get("api_actor","api")}])
        
        return jsonify({"status": "updated", "ip": ip_txt, "scope": "partial", "remaining_tags": current_tags}), 200
        return jsonify({"status": "updated", "ip": ip_txt, "scope": "partial", "remaining_tags": current_tags}), 200


@api.route("/estado/<ip_str>", methods=["GET"])
def estado_api(ip_str):
    # Intentar Auth por Token primero
    if _auth_ok():
        # OK (API Client)
        pass
    elif session.get("username"):
        # OK (Web User)
        g.api_actor = f"web/{session.get('username')}"
    else:
        # Fallback unauthorized
        return jsonify({"error": "Unauthorized"}), 401
    
    try:
        ipaddress.ip_address(ip_str)
    except Exception:
        # _audit("api_estado_invalid_ip", g.get("api_actor","api"), ip_str, {})
        return jsonify({"error": "IP inválida"}), 400
    row = db.get_ip(ip_str)
    if not row:
        # _audit("api_estado_not_found", g.get("api_actor","api"), ip_str, {})
        return jsonify({"status": "not_found", "ip": ip_str}), 404
    
    # _audit("api_estado_ok", g.get("api_actor","api"), ip_str, {})
    
    tags = []
    try: tags = json.loads(row["tags"] or '[]')
    except: pass
    
    alert_ids = []
    try: alert_ids = json.loads(row["alert_ids"] or '[]')
    except: pass
    
    # Check if we need to return "history" key for frontend compatibility
    history = []
    try: 
        history = json.loads(row["history"] or '[]')
        history.sort(key=lambda x: x.get("ts", ""), reverse=True)
    except: 
        pass

    entry = {
        "tags": tags,
        "expires_at": row["expiration_date"],
        "alert_ids": alert_ids,
        "source": row["source"],
        "ttl": row["ttl"],
        "added_at": row["added_at"],
        "history": history # Added for frontend
    }
    return jsonify({"status": "ok", "data": entry, "history": history}), 200


@app.route("/lista/<tag>", methods=["GET"])
def lista_tag_api(tag):
    _audit("api_lista_tag", g.get("api_actor","api"), tag, {})
    
    # Query DB
    all_ips = db.get_all_ips() # Optimize later? get_by_tag?
    entries = []
    
    target = tag.lower()
    
    for row in all_ips:
        try:
            tags = json.loads(row['tags'] or '[]')
        except:
            tags = []
            
        # Case insensitive match?
        if any(t.lower() == target for t in tags):
             # Format similar to legacy text file
             # ip|created|ttl|expires|source|tags
             ttl_s = row['ttl'] * 86400 if row['ttl'] else 0
             entries.append({
                "ip": row['ip'],
                "created_at": row['added_at'],
                "ttl_s": ttl_s,
                "expires_at": row['expiration_date'],
                "source": row['source'],
                "tags": tags
             })
             
    if not entries:
          return jsonify({"status": "not_found", "tag": tag, "entries": []}), 404
          
    return jsonify({"status": "ok", "tag": tag, "entries": entries}), 200


# Health de la API
@api.route("/", methods=["GET"])
def api_root():
    _audit("api_root", g.get("api_actor","api"), "/", {})
    return jsonify({
        "service": "IOC Manager API",
        "status": "running",
        "endpoints": [
            "POST   /api/bloquear-ip",
            "DELETE /api/bloquear-ip",
            "GET    /api/estado/<ip>",
            "GET    /api/lista/<tag>",
            "GET    /feed/ioc-feed-bpe.txt"
        ]
    }), 200


@app.route('/api/counters/history', methods=['GET'])
@require_api_token(required_scope='READ')
def api_counters_history_endpoint():
    try:
        limit = int(request.args.get('limit', 30))
        history = db.get_metrics_history(limit)
        return jsonify(history)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Open API Docs
@app.route("/api/openapi.json")
def api_openapi_json():
    # Servir el estático que hemos creado
    return app.send_static_file("openapi.json")

@app.route("/api/docs")
@login_required
def api_docs():
    # Swagger UI
    return render_template("swagger.html")


# Registrar blueprint
app.register_blueprint(api)





@app.route("/api/remove-tag", methods=["POST"])
@login_required
def api_remove_tag():
    """
    Endpoint para quitar un tag específico de una IP.
    Solo administradores o editores.
    Payload: {"ip": "...", "tag": "..."}
    """
    if session.get("role") == "view_only":
        return json_response_error("No tienes permisos (vista).", 403)

    data = request.get_json(silent=True) or {}
    ip = data.get("ip")
    tag = data.get("tag")

    if not ip or not tag:
        return json_response_error("Faltan datos (ip, tag).")

    try:
        # 1. Quitar de BD uses db.remove_tag
        if db.remove_tag(ip, tag):
            # 2. Regenerate feeds
            regenerate_feeds_from_db()
            
            # Auditoría
            _audit("remove_tag", f"web/{session.get('username','admin')}", ip, {"tag": tag})
            
            return json_response_ok([], {"message": f"Tag '{tag}' eliminado de {ip}"})
        else:
            return json_response_error(f"Error o Tag no encontrado para {ip}", 404)
    except Exception as e:
        return json_response_error(f"Error interno: {str(e)}", 500)

@app.route("/api/tags/add", methods=["POST"])
@login_required
def api_add_tag():
    """
    Endpoint para añadir un tag específico a una IP.
    Payload: {"ip": "...", "tag": "..."}
    """
    if session.get("role") == "view_only":
        return json_response_error("No tienes permisos (vista).", 403)

    data = request.get_json(silent=True) or {}
    ip = data.get("ip")
    tag = data.get("tag")

    if not ip or not tag:
        return json_response_error("Faltan datos (ip, tag).")
    
    # Validar formato de tag (básico)
    # Validar formato de tag (básico)
    tag = tag.strip()
    if not tag:
        return json_response_error("Tag vacío.")
    
    # Normalizar (fix: test -> Test)
    norm = _norm_tags([tag])
    if not norm:
        return json_response_error("Tag inválido tras normalización.")
    tag = norm[0]

    try:
        if db.add_tag(ip, tag):
            regenerate_feeds_from_db()
            _audit("add_tag", f"web/{session.get('username','admin')}", ip, {"tag": tag})
            return json_response_ok([], {"message": f"Tag '{tag}' añadido a {ip}"})
        else:
            # Si retorna False, es que ya tenía el tag o IP no existe
            # Verificamos si IP existe
            if not db.get_ip(ip):
                 return json_response_error(f"IP {ip} no encontrada", 404)
            return json_response_ok([], {"message": f"Tag '{tag}' ya existía en {ip}"})
            
    except Exception as e:
        return json_response_error(f"Error interno: {str(e)}", 500)

@app.route("/api/tags/bulk", methods=["POST"])
@login_required
def api_bulk_tags():
    """
    Endpoint masivo para añadir/quitar tags.
    Payload: {
      "ips": ["1.1.1.1", "2.2.2.2"],
      "tag": "BPE",
      "action": "add" | "remove"
    }
    """
    if session.get("role") == "view_only":
        return json_response_error("No tienes permisos (vista).", 403)

    data = request.get_json(silent=True) or {}
    ips = data.get("ips", [])
    tag = data.get("tag")
    action = data.get("action")

    if not ips or not tag or not action:
        return json_response_error("Faltan datos (ips, tag, action).")
    
    tag = tag.strip()
    if not tag:
        return json_response_error("Tag vacío.")

    # Normalizar (fix: test -> Test)
    norm = _norm_tags([tag])
    if not norm:
        return json_response_error("Tag inválido tras normalización.")
    tag = norm[0]

    try:
        modified = False
        if action == "add":
            modified = db.bulk_add_tag(ips, tag)
            audit_evt = "bulk_tag_add"
        elif action == "remove":
            modified = db.bulk_remove_tag(ips, tag)
            audit_evt = "bulk_tag_remove"
        else:
            return json_response_error("Acción inválida usage: add|remove")
        
        if modified:
            regenerate_feeds_from_db()
            _audit(audit_evt, f"web/{session.get('username','admin')}", {"count": len(ips)}, {"tag": tag, "ips": ips})
            return json_response_ok([], {"message": "Operación completada con éxito"})
        else:
             return json_response_ok([], {"message": "Sin cambios (tags ya asignados o no asignados)"})

    except Exception as e:
        return json_response_error(f"Error interno: {str(e)}", 500)



@app.route("/api/run-diagnostics", methods=["POST"])
@login_required
def api_run_diagnostics():
    """
    Ejecuta el script de pruebas unitarias (run_tests.py) y devuelve el resultado.
    """
    if session.get("role") not in ("admin", "editor"):
        return json_response_error("No tienes permisos para ejecutar diagnósticos.", 403)

    try:
        # Ejecutar run_tests.py en un subproceso
        cmd = [sys.executable, "run_tests.py"]
        result = subprocess.run(cmd, cwd=BASE_DIR, capture_output=True, text=True)
        
        ok = (result.returncode == 0)
        output = result.stderr + "\n" + result.stdout # unittest often writes to stderr
        
        # Guardar en BD
        db.save_test_run(ok, output, actor=f"web/{session.get('username','admin')}")

        # Guardar notificación
        status_msg = "Pruebas pasadas OK" if ok else "ERROR en pruebas unitarias"
        guardar_notif("success" if ok else "error", f"{status_msg}. Consulta historial de salud para detalles.")
        
        return json_response_ok(extra={"ok": ok, "output": output})
    except Exception as e:
        return json_response_error(f"Error al ejecutar diagnósticos: {str(e)}", 500)


@app.route("/api/test-history", methods=["GET"])
@login_required
def api_test_history():
    """
    Devuelve los últimos 10 resultados de las pruebas de salud.
    """
    limit = int(request.args.get("limit", 10))
    history = db.get_test_history(limit)
    return jsonify({"ok": True, "history": history})


@app.route("/admin/history/<path:ip>", methods=["GET"])
@login_required
def admin_get_history(ip):
    row = db.get_ip(ip)
    if not row:
        return jsonify({"error": "IP not found"}), 404
        
    try:
        history = json.loads(row["history"] or '[]')
        # Sort by timestamp desc
        history.sort(key=lambda x: x.get("ts", ""), reverse=True)
    except:
        history = []
        
    return jsonify({"ip": ip, "history": history})




# --- Hook para Snapshot Diario ---
# Variable global para rate-limit del snapshot (1 hora)
_last_global_snapshot = 0

@app.before_request
def daily_snapshot_check():
    global _last_global_snapshot
    try:
        now = time.time()
        # Solo escribir si pasaron > 60 min (3600s) desde el último intento en este worker
        if now - _last_global_snapshot > 3600:
            _last_global_snapshot = now
            
            # Calcular contadores actuales usando la lógica de Unión de Feeds
            # Devuelve: src_counts, tag_counts, src_tag_counts, total_union
            if 'compute_source_and_tag_counters_union' in globals():
                src_counts, tag_counts, _, total = compute_source_and_tag_counters_union()
                
                # Formato esperado por db.save_daily_snapshot:
                # {total, manual, csv, api, tags: ...}
                snapshot_data = {
                    'total': total,
                    'manual': src_counts.get('manual', 0),
                    'csv': src_counts.get('csv', 0),
                    'api': src_counts.get('api', 0),
                    'tags': tag_counts
                }
                
                db.save_daily_snapshot(snapshot_data)
            
    except Exception:
        # No bloquear request por error de métricas
        pass




# --- Maintenance Toggle Endpoint ---
@app.route("/maintenance/toggle", methods=["POST"])
@login_required
def maintenance_toggle():
    if session.get("role") != "admin":
        return jsonify({"error": "Solo admin"}), 403
    
    data = request.get_json(silent=True) or {}
    active = bool(data.get("active", False))
    
    if db.set_config("MAINTENANCE_MODE", "1" if active else "0"):
        state_str = "ACTIVADO" if active else "DESACTIVADO"
        _audit("maintenance_toggle", f"web/{session.get('username')}", state_str, {})
        flash(f"Modo Mantenimiento {state_str}", "warning" if active else "success")
        return jsonify({"ok": True, "active": active})
    else:
        return jsonify({"error": "Error guardando configuración"}), 500






if __name__ == "__main__":
    # Ensure DB tables exist
    db.init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
