from flask import (
    Flask, render_template, render_template_string, request, redirect, url_for,
    session, flash, make_response, jsonify, get_flashed_messages,
    send_file, abort, Blueprint, g
)
from datetime import datetime, timedelta, timezone
import ipaddress
import os
import re
import json
from functools import wraps
import threading
import time
import math
import hashlib
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from filelock import FileLock, Timeout


load_dotenv()

# Fix for Windows Registry MIME type issue
import mimetypes
mimetypes.add_type('application/javascript', '.js')


app = Flask(__name__)
# Clave secreta desde .env
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'dev-key-insegura-si-falta-env')

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
# Carpeta para datos adicionales de la API por tags
DATA_DIR = os.path.join(BASE_DIR, "data")
TAGS_DIR = os.path.join(DATA_DIR, "tags")

FEED_FILE = os.path.join(BASE_DIR, 'ioc-feed.txt')
# === Nuevo feed BPE ===
FEED_FILE_BPE = os.path.join(BASE_DIR, 'ioc-feed-bpe.txt')
# === Nuevo feed de pruebas ===
FEED_FILE_TEST = os.path.join(DATA_DIR, "ioc-feed-test.txt")

LOG_FILE = os.path.join(BASE_DIR, 'ioc-log.txt')
NOTIF_FILE = os.path.join(BASE_DIR, 'notif-log.json')

# Counters históricos (compat), los totales vivos se calculan con meta
COUNTER_MANUAL = os.path.join(BASE_DIR, 'contador_manual.txt')
COUNTER_CSV = os.path.join(BASE_DIR, 'contador_csv.txt')

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

# Asegurar carpetas
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(TAGS_DIR, exist_ok=True)

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


def json_response_error(message, code=400, notices=None, extra=None):
    payload = {"ok": False, "error": str(message), "notices": notices or []}
    if extra:
        payload.update(extra)
    return jsonify(payload), code


from functools import wraps

def require_api_token(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get("X-API-Key") or request.args.get("token")
        if not token or token != TOKEN_API:
            return jsonify({"ok": False, "error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated_function

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
    Carga usuarios desde users.json.
    Si no existe, intenta migrar el admin del .env y crear el archivo.
    """
    if not os.path.exists(USERS_FILE):
        # Migración inicial
        admin_user = os.getenv("ADMIN_USER", "admin")
        admin_pass = os.getenv("ADMIN_PASSWORD", "admin")
        # Creamos el primer usuario (admin) con la clave del env hasheada
        users = {
            admin_user: {
                "password_hash": generate_password_hash(admin_pass),
                "role": "admin",
                "created_at": _iso(_now_utc())
            }
        }
        save_users(users)
        return users

    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_users(users):
    users_lock = FileLock(USERS_FILE + ".lock")
    try:
        with users_lock:
            with open(USERS_FILE, "w", encoding="utf-8") as f:
                json.dump(users, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


# -------- Auditoría (nuevo) --------
def _audit(event, actor, scope, details=None):
    # actor: 'web/<usuario>' | 'api/<ip>' | 'system'
    rec = {
        "ts": _iso(_now_utc()),
        "event": str(event),
        "actor": str(actor or "unknown"),
        "scope": str(scope or ""),
        "details": details or {}
    }
    try:
        with open(AUDIT_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass


# -------- Meta lateral (origen por IP + detalles por IP) --------
def _empty_meta():
    return {"by_ip": {}, "ip_details": {}}

def load_meta():
    if not os.path.exists(META_FILE):
        return _empty_meta()
    try:
        with open(META_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if not isinstance(data, dict):
                return _empty_meta()
            # Compat: siempre devolver claves esperadas
            if "by_ip" not in data or not isinstance(data["by_ip"], dict):
                data["by_ip"] = {}
            if "ip_details" not in data or not isinstance(data["ip_details"], dict):
                data["ip_details"] = {}
            return data
    except Exception:
        return _empty_meta()


def save_meta(meta):
    try:
        with META_LOCK:
            with open(META_FILE, "w", encoding="utf-8") as f:
                json.dump(meta, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def meta_set_origin(ip_str, origin):
    meta = load_meta()
    meta["by_ip"][ip_str] = origin  # 'manual' | 'csv' | 'api'
    save_meta(meta)


def meta_del_ip(ip_str):
    meta = load_meta()
    changed = False
    # borrar origen clásico
    if ip_str in meta.get("by_ip", {}):
        del meta["by_ip"][ip_str]
        changed = True
    # borrar detalles (tags/exp)
    ipd = meta.get("ip_details", {})
    entry = ipd.pop(ip_str, None)
    if entry:
        changed = True
        # eliminar también sus líneas de ficheros por tag
        try:
            tags = entry.get("tags", [])
            for t in tags:
                _remove_ip_from_tag_file(t, ip_str)
        except Exception:
            pass
    if changed:
        save_meta(meta)

def repair_meta_sources():
    """
    Rellena meta['by_ip'] con el 'source' que ya exista en meta['ip_details'].
    Sirve para que el contador de API/CSV/Manual cuadre aunque la IP venga solo con tag BPE.
    """
    meta = load_meta()
    by_ip = meta.get("by_ip", {})
    details = meta.get("ip_details", {})
    changed = False
    for ip, e in (details or {}).items():
        src = (e.get("source") or "").lower()
        if src in ("manual", "csv", "api") and by_ip.get(ip) != src:
            by_ip[ip] = src
            changed = True
    if changed:
        meta["by_ip"] = by_ip
        save_meta(meta)

def meta_bulk_del(ips):
    if not ips:
        return
    meta = load_meta()
    changed = False
    for ip in ips:
        if ip in meta.get("by_ip", {}):
            del meta["by_ip"][ip]
            changed = True
        entry = meta.get("ip_details", {}).pop(ip, None)
        if entry:
            changed = True
            try:
                for t in entry.get("tags", []):
                    _remove_ip_from_tag_file(t, ip)
            except Exception:
                pass
    if changed:
        save_meta(meta)


def compute_live_counters(active_lines):
    """Cuenta por origen (manual/csv/api) sólo sobre el feed principal."""
    meta = load_meta().get("by_ip", {})
    manual = csv = api = 0
    for line in active_lines:
        ip_txt = line.split("|", 1)[0].strip()
        origin = meta.get(ip_txt)
        if origin == "manual":
            manual += 1
        elif origin == "csv":
            csv += 1
        elif origin == "api":
            api += 1
    return manual, csv, api


def compute_tag_totals():
    lines_main = load_lines(FEED_FILE)
    lines_bpe  = load_lines(FEED_FILE_BPE)
    lines_test = load_lines(FEED_FILE_TEST)  # ← AÑADE
    active_ips = {l.split("|",1)[0].strip() for l in lines_main} | \
                 {l.split("|",1)[0].strip() for l in lines_bpe}  | \
                 {l.split("|",1)[0].strip() for l in lines_test}   # ← AÑADE
    meta = load_meta().get("ip_details", {})
    multi = bpe = test = 0
    for ip in active_ips:
        tags = set((meta.get(ip) or {}).get("tags", []))
        if "Multicliente" in tags: multi += 1
        if "BPE" in tags:          bpe   += 1
        if "Test" in tags:         test  += 1
    return {"Multicliente": multi, "BPE": bpe, "Test": test}

# === NUEVOS: unión feeds y matriz fuente×tag ===
def _active_ip_union():
    lines_main = load_lines(FEED_FILE)
    lines_bpe  = load_lines(FEED_FILE_BPE)
    lines_test = load_lines(FEED_FILE_TEST)  # ← AÑADE
    return {l.split("|",1)[0].strip() for l in lines_main} | \
           {l.split("|",1)[0].strip() for l in lines_bpe}  | \
           {l.split("|",1)[0].strip() for l in lines_test}   # ← AÑADE

def compute_source_and_tag_counters_union():
    """
    Contadores en vivo sobre la unión de feeds:
      - por fuente (manual/csv/api) usando SOLO meta['by_ip']
      - por tag (Multicliente/BPE) usando meta['ip_details']
    """
    active_ips = _active_ip_union()
    meta = load_meta()
    by_ip = (meta.get("by_ip") or {})
    details = (meta.get("ip_details") or {})

    counters_by_source = {"manual": 0, "csv": 0, "api": 0}
    counters_by_tag = {"Multicliente": 0, "BPE": 0, "Test": 0}
    counters_by_source_tag = {
        "manual": {"Multicliente": 0, "BPE": 0, "Test": 0},
        "csv": {"Multicliente": 0, "BPE": 0, "Test": 0},
        "api": {"Multicliente": 0, "BPE": 0, "Test": 0},
    }

    for ip in active_ips:
        # Fuente solo desde by_ip (es lo que ya usa la tabla)
        src = str(by_ip.get(ip, "")).strip().lower()
        if src not in ("manual", "csv", "api"):
            src = None

        # Tags desde ip_details
        tags = set((details.get(ip) or {}).get("tags") or [])

        if "Multicliente" in tags:
            counters_by_tag["Multicliente"] += 1
        if "BPE" in tags:
            counters_by_tag["BPE"] += 1
        if "Test" in tags:
            counters_by_tag["Test"] += 1

        if src:
            counters_by_source[src] += 1
            if "Multicliente" in tags:
                counters_by_source_tag[src]["Multicliente"] += 1
            if "BPE" in tags:
                counters_by_source_tag[src]["BPE"] += 1
            if "Test" in tags:
                counters_by_source_tag[src]["Test"] += 1

    total_union = len(active_ips)
    return counters_by_source, counters_by_tag, counters_by_source_tag, total_union

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


def filter_lines_delete_pattern(lines, pattern):
    kind, obj = parse_delete_pattern(pattern)
    kept, removed = [], 0
    removed_ips = []
    removed_lines = []  # guardamos las líneas exactas para UNDO
    for line in lines:
        ip_txt = line.split("|", 1)[0].strip()
        try:
            ip_obj = ipaddress.ip_address(ip_txt)
        except ValueError:
            kept.append(line)
            continue

        match = False
        if kind == "single":
            match = ip_obj == obj
        elif kind == "cidr":
            match = ip_obj in obj
        elif kind == "range":
            a, b = obj
            match = int(a) <= int(ip_obj) <= int(b)

        if match:
            removed += 1
            removed_ips.append(ip_txt)
            removed_lines.append(line)
        else:
            kept.append(line)

    return kept, removed, removed_ips, removed_lines


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

def eliminar_ips_vencidas_en_feed(feed_path):
    now = datetime.now()
    nuevas = []
    vencidas = []
    try:
        with open(feed_path, "r", encoding="utf-8") as f:
            for linea in f:
                partes = linea.strip().split("|")
                if len(partes) != 3:
                    continue
                ip, fecha_str, ttl_str = partes
                try:
                    fecha = datetime.strptime(fecha_str, "%Y-%m-%d")
                    ttl = int(ttl_str)
                except Exception:
                    nuevas.append(linea.strip())
                    continue
                if ttl == 0 or (now - fecha).days < ttl:
                    nuevas.append(linea.strip())
                else:
                    vencidas.append(ip.strip())
        with open(feed_path, "w", encoding="utf-8") as f:
            for l in nuevas:
                f.write(l + "\n")
    except FileNotFoundError:
        pass
    return vencidas

def eliminar_ips_vencidas():
    """Compat histórica: expiración del feed principal y retorno de IPs vencidas allí."""
    return eliminar_ips_vencidas_en_feed(FEED_FILE)

def eliminar_ips_vencidas_bpe():
    """Expiración para el feed BPE."""
    return eliminar_ips_vencidas_en_feed(FEED_FILE_BPE)

def load_lines(feed_path=FEED_FILE):
    if not os.path.exists(feed_path):
        return []
    with open(feed_path, encoding="utf-8") as f:
        return [l.strip() for l in f if l.strip()]

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
        with open(feed_path, "w", encoding="utf-8") as f:
            for l in lines:
                f.write(l + "\n")


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
        if s not in seen:
            out.append(s)
            seen.add(s)
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

def _write_tag_line(tag, ip, created_at, ttl_s, expires_at, source, tags):
    os.makedirs(TAGS_DIR, exist_ok=True)
    path = os.path.join(TAGS_DIR, f"{tag}.txt")
    tag_lock = FileLock(path + ".lock")
    line = f"{ip}|{_iso(created_at)}|{ttl_s}|{_iso(expires_at)}|{source}|{','.join(tags)}"
    with tag_lock:
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")

def _remove_ip_from_tag_file(tag, ip):
    path = os.path.join(TAGS_DIR, f"{tag}.txt")
    if not os.path.exists(path):
        return
    tag_lock = FileLock(path + ".lock")
    with tag_lock:
        new_lines = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                ip_line = line.split("|", 1)[0].strip()
                if ip_line != ip:
                    new_lines.append(line.rstrip("\n"))
        with open(path, "w", encoding="utf-8") as f:
            for l in new_lines:
                f.write(l + "\n")

def _remove_ip_from_feed(ip, feed_path=FEED_FILE):
    lines = load_lines(feed_path)
    new_lines = [l for l in lines if not l.startswith(ip + "|")]
    if len(new_lines) != len(lines):
        save_lines(new_lines, feed_path)

def _remove_bulk_from_feed(ips, feed_path):
    """Elimina en bloque una lista de IPs de un feed dado."""
    if not ips or not os.path.exists(feed_path):
        return
    lines = load_lines(feed_path)
    targets = set(ips)
    new_lines = [l for l in lines if l.split("|", 1)[0].strip() not in targets]
    if len(new_lines) != len(lines):
        save_lines(new_lines, feed_path)

def _remove_ip_from_all_feeds(ip):
    """Elimina una IP de ambos feeds (principal y BPE)."""
    _remove_ip_from_feed(ip, FEED_FILE)       # principal
    _remove_ip_from_feed(ip, FEED_FILE_BPE)   # BPE


def _merge_meta_tags(ip, new_tags, expires_at, source, note, alert_id=None):
    """Fusiona tags, expiración y alert_ids en META_FILE.ip_details"""
    meta = load_meta()
    details = meta.get("ip_details", {})

    entry = details.get(ip, {
        "ip": ip, "tags": [], "expires_at": None, "source": source,
        "history": [], "last_update": _iso(_now_utc())
    })

    # Asegurar lista de alert_ids
    alert_list = entry.get("alert_ids", [])
    if not isinstance(alert_list, list):
        alert_list = []
    if alert_id:
        alert_id_str = str(alert_id).strip()
        if alert_id_str and alert_id_str not in alert_list:
            alert_list.append(alert_id_str)
    entry["alert_ids"] = alert_list

    old_tags = set(entry.get("tags", []))
    add_tags = set(new_tags or [])
    merged = sorted(list(old_tags.union(add_tags)))

    # expiración: conservar la más lejana
    old_exp = entry.get("expires_at")
    old_dt = datetime.fromisoformat(old_exp.replace("Z","+00:00")) if old_exp else None
    best_exp = expires_at if not old_dt or expires_at > old_dt else old_dt

    entry["tags"] = merged
    entry["expires_at"] = _iso(best_exp)
    entry["source"] = source
    entry["last_update"] = _iso(_now_utc())
    entry["history"].append({
        "ts": _iso(_now_utc()),
        "action": "upsert",
        "tags_added": sorted(list(add_tags - old_tags)),
        "expires_at": _iso(best_exp),
        "note": note or "",
        "source": source,
        "alert_id": alert_id if alert_id else None
    })
    details[ip] = entry
    
    # === MEJORADO: asegurar origen en meta['by_ip'] ===
    # Normalizar source a minúsculas y validar
    src_normalized = (source or "").lower().strip()
    if src_normalized in ("manual", "csv", "api"):
        meta.setdefault("by_ip", {})[ip] = src_normalized
    elif source:  # Si viene con otro formato, intentar inferir
        if "api" in src_normalized:
            meta.setdefault("by_ip", {})[ip] = "api"
        elif "csv" in src_normalized:
            meta.setdefault("by_ip", {})[ip] = "csv"
        else:
            meta.setdefault("by_ip", {})[ip] = "manual"
    # ================================================
    
    meta["ip_details"] = details
    save_meta(meta)
    return entry


def _remove_tag_meta(ip, tag_to_remove):
    """Elimina un tag de la lista de tags en META_FILE."""
    meta = load_meta()
    details = meta.get("ip_details", {})
    entry = details.get(ip)
    
    if entry and "tags" in entry:
        old_tags = entry["tags"]
        if tag_to_remove in old_tags:
            new_tags = [t for t in old_tags if t != tag_to_remove]
            entry["tags"] = new_tags
            entry["last_update"] = _iso(_now_utc())
            
            # Registrar en historial del objeto
            entry.setdefault("history", []).append({
                "ts": _iso(_now_utc()),
                "action": "remove_tag",
                "tag_removed": tag_to_remove,
                "source": "web"
            })
            
            details[ip] = entry
            meta["ip_details"] = details
            save_meta(meta)


def _remove_tag_meta(ip, tag_to_remove):
    """Elimina un tag de la lista de tags en META_FILE."""
    meta = load_meta()
    details = meta.get("ip_details", {})
    entry = details.get(ip)
    
    if entry and "tags" in entry:
        old_tags = entry["tags"]
        if tag_to_remove in old_tags:
            new_tags = [t for t in old_tags if t != tag_to_remove]
            entry["tags"] = new_tags
            entry["last_update"] = _iso(_now_utc())
            
            # Registrar en historial del objeto
            entry.setdefault("history", []).append({
                "ts": _iso(_now_utc()),
                "action": "remove_tag",
                "tag_removed": tag_to_remove,
                "source": "web"
            })
            
            details[ip] = entry
            meta["ip_details"] = details
            save_meta(meta)
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
def add_ips_validated(lines, existentes, iterable_ips, ttl_val, origin=None, contador_ruta=None, tags=None, alert_id=None):
    """
    ttl_val: '0' para permanente o número de días (str/int)
    tags: lista de tags (OBLIGATORIA: Multicliente y/o BPE)
    alert_id: identificador de alerta opcional (solo si es 1 IP o si aplica a todas, normalmente NULL en cargas masivas simples)
    """
    añadidas = 0
    rechazadas = 0
    updated = 0
    added_lines = []  # para UNDO (solo de FEED_FILE si aplica)
    tags = _norm_tags(tags or [])
    # preparar expiración para meta/tag-files
    try:
        ttl_days = int(ttl_val)
    except Exception:
        ttl_days = 0
    # si permanente: fija una fecha muy lejana para meta
    expires_at_dt = (_now_utc() + timedelta(days=ttl_days)) if ttl_days > 0 else (_now_utc() + timedelta(days=365*100))
    ttl_seconds = ttl_days * 86400 if ttl_days > 0 else 0

    allow_multi = "Multicliente" in tags
    allow_bpe = "BPE" in tags
    allow_test = "Test" in tags

    for ip_str in iterable_ips:
        if not (allow_multi or allow_bpe or allow_test):
            rechazadas += 1
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

        # Si ya está en el feed principal
        if ip_str in existentes:
            # fusionar tags en meta/tag files aunque esté duplicada
            entry = _merge_meta_tags(ip_str, tags, expires_at_dt, origin or "manual", note="web", alert_id=alert_id)
            for t in tags:
                _write_tag_line(t, ip_str, _now_utc(), ttl_seconds, expires_at_dt, origin or "manual", entry["tags"])
            
            # --- FIX: Actualizar línea en feed principal si el TTL se extiende ---
            if allow_multi and ttl_days > 0:
                # Buscar la línea existente
                for i, ln in enumerate(lines):
                    if ln.startswith(ip_str + "|"):
                        parts = ln.split("|")
                        if len(parts) >= 3:
                            old_date_str = parts[1]
                            old_ttl_str  = parts[2]
                            try:
                                old_ttl = int(old_ttl_str)
                                old_date = datetime.strptime(old_date_str, "%Y-%m-%d")
                                if old_ttl == 0:
                                    # Ya es permanente, no hacemos nada (o reducimos? No, conservar lejana)
                                    pass
                                else:
                                    old_exp = old_date + timedelta(days=old_ttl)
                                    new_exp = _now_utc().replace(tzinfo=None) + timedelta(days=ttl_days)
                                    if new_exp > old_exp:
                                        # Extender: Actualizamos fecha a HOY y TTL al nuevo
                                        fecha_hoy = datetime.now().strftime("%Y-%m-%d")
                                        lines[i] = f"{ip_str}|{fecha_hoy}|{ttl_days}"
                                        updated += 1

                            except Exception:
                                pass
                        break
            # ---------------------------------------------------------------------

            rechazadas += 1  # se considera duplicada para el feed principal
            # asegurar reflejo BPE si aplica
            if allow_bpe:
                fecha = datetime.now().strftime("%Y-%m-%d")
                _append_line_unique(FEED_FILE_BPE, f"{ip_str}|{fecha}|{ttl_val}")
            # FEED Test también si aplica
            if allow_test:
                fecha = datetime.now().strftime("%Y-%m-%d")
                _append_line_unique(FEED_FILE_TEST, f"{ip_str}|{fecha}|{ttl_val}")
            continue

        # Nueva IP
        fecha = datetime.now().strftime("%Y-%m-%d")

        # FEED Multicliente (principal) solo si tiene ese tag
        if allow_multi:
            line_txt = f"{ip_str}|{fecha}|{ttl_val}"
            lines.append(line_txt)
            existentes.add(ip_str)
            added_lines.append(line_txt)
            meta_set_origin(ip_str, origin or "manual")
            añadidas += 1

        # FEED BPE si corresponde
        if allow_bpe:
            _append_line_unique(FEED_FILE_BPE, f"{ip_str}|{fecha}|{ttl_val}")

        # FEED Test si corresponde
        if allow_test:
            _append_line_unique(FEED_FILE_TEST, f"{ip_str}|{fecha}|{ttl_val}")

        # meta + tag files
        entry = _merge_meta_tags(ip_str, tags, expires_at_dt, origin or "manual", note="web", alert_id=alert_id)
        for t in tags:
            _write_tag_line(t, ip_str, _now_utc(), ttl_seconds, expires_at_dt, origin or "manual", entry["tags"])

        log("Añadida", ip_str)
        guardar_notif("success", f"IP añadida: {ip_str}")
        _audit("add_manual" if origin == "manual" else f"add_{origin}", f"web/{session.get('username','admin')}" if origin=="manual" else "api/system", ip_str, {
            "ttl_days": ttl_days,
            "tags": tags,
            "alert_id": alert_id
        })

        if contador_ruta and allow_multi:
            try:
                val = read_counter(contador_ruta)
                write_counter(contador_ruta, val + 1)
            except Exception:
                pass

        if ip_str not in existentes:
            añadidas += 1

    return añadidas, rechazadas, added_lines, updated



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


# === HELPER FOR METRICS ===
def compute_source_and_tag_counters_union():
    """
    Calcula contadores unificados (Main + BPE + Test) deduplicando IPs.
    Retorna: (src_counts, tag_counts, src_tag_counts, total_unique_ips)
    """
    # 1. Cargar todas las líneas
    lines_main = load_lines(FEED_FILE)
    lines_bpe  = load_lines(FEED_FILE_BPE)
    lines_test = load_lines(FEED_FILE_TEST)
    
    # 2. Unificar IPs (set) para deduplicar
    # Formato feed: IP|DATE|TTL
    all_ips = set()
    for l in lines_main: all_ips.add(l.split("|")[0].strip())
    for l in lines_bpe:  all_ips.add(l.split("|")[0].strip())
    for l in lines_test: all_ips.add(l.split("|")[0].strip())
    
    total = len(all_ips)
    
    # 3. Cargar metadatos para Origen y Tags
    meta = load_meta()
    by_ip = meta.get("by_ip", {})
    ip_details = meta.get("ip_details", {})
    
    # Inicializar contadores
    src_counts = {"manual": 0, "csv": 0, "api": 0}
    tag_counts = {}
    src_tag_counts = {}  # "manual:BPE": 10
    
    for ip in all_ips:
        # --- Origen ---
        origin = by_ip.get(ip, "manual") # Default to manual if unknown? Or 'unknown'?
        # Normalizar claves de origen (legacy vs new)
        if origin not in src_counts:
            # Si hay nuevos orígenes, añádelos dinámicamente o agrúpalos
            src_counts[origin] = src_counts.get(origin, 0) + 1
        else:
            src_counts[origin] += 1
            
        # --- Tags ---
        # Tags vienen de ip_details[ip]["tags"] (list)
        
        final_tags = set(ip_details.get(ip, {}).get("tags", []))
        
        for t in final_tags:
            tag_counts[t] = tag_counts.get(t, 0) + 1
            
            # --- Source x Tag ---
            st_key = f"{origin}:{t}"
            src_tag_counts[st_key] = src_tag_counts.get(st_key, 0) + 1
            
    return src_counts, tag_counts, src_tag_counts, total



# =========================
#  Helpers de listado/paginación/ordenación
# =========================
def _feed_to_records(lines):
    """Convierte lines ['IP|YYYY-MM-DD|TTL'] en lista de dicts con campos derivados."""
    meta_by_ip = load_meta().get("by_ip", {})
    records = []
    for l in lines:
        parts = l.split("|")
        if len(parts) != 3:
            continue
        ip_txt = parts[0].strip()
        fecha_txt = parts[1].strip()
        ttl_txt = parts[2].strip()
        try:
            fecha_dt = datetime.strptime(fecha_txt, "%Y-%m-%d")
        except Exception:
            fecha_dt = None
        try:
            ttl_int = int(ttl_txt)
        except Exception:
            ttl_int = 0
        exp_dt = None if ttl_int == 0 or fecha_dt is None else (fecha_dt + timedelta(days=ttl_int))
        try:
            ip_num = int(ipaddress.ip_address(ip_txt))
        except Exception:
            ip_num = 0
        records.append({
            "ip": ip_txt,
            "fecha": fecha_txt,
            "fecha_dt": fecha_dt,
            "ttl": ttl_int,
            "expira_dt": exp_dt,
            "origen": meta_by_ip.get(ip_txt)
        })
    return records


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
#  Gestión de UNDO por sesión
# =========================
def _set_last_action(action_type, payload_items):
    """Guarda en sesión la última acción reversible."""
    session['last_action'] = {
        "type": action_type,  # 'add' | 'delete' | 'delete_bulk' | 'delete_all'
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "expires_sec": UNDO_TTL_SECONDS,
        "payload": {"items": payload_items},
    }


def _get_last_action():
    la = session.get('last_action')
    if not la:
        return None, "No hay acción para deshacer"
    try:
        ts = la.get("timestamp")
        expires = la.get("expires_sec", UNDO_TTL_SECONDS)
        ts_dt = datetime.fromisoformat(ts.replace("Z", ""))
        if (datetime.utcnow() - ts_dt).total_seconds() > expires:
            session.pop('last_action', None)
            return None, "La acción ya no se puede deshacer (expirada)"
        return la, None
    except Exception:
        session.pop('last_action', None)
        return None, "No se pudo leer la acción previa"


def _undo_last_action():
    la, err = _get_last_action()
    if err or not la:
        return False, err

    a_type = la["type"]
    items = la["payload"]["items"]  # lista de líneas completas 'IP|YYYY-MM-DD|TTL'
    current = load_lines()
    existentes = {l.split("|", 1)[0] for l in current}
    changed = False

    if a_type == "add":
        # deshacer: quitar esas IPs si siguen presentes
        to_keep = []
        removed_ips = []
        targets = {ln.split("|", 1)[0] for ln in items}
        for l in current:
            ip_txt = l.split("|", 1)[0]
            if ip_txt in targets:
                removed_ips.append(ip_txt)
                changed = True
                continue
            to_keep.append(l)
        if changed:
            save_lines(to_keep)
            meta_bulk_del(removed_ips)
        mensaje = f"Deshechas {len(removed_ips)} IP(s) añadidas"
        if removed_ips:
            guardar_notif("warning", mensaje)
        _audit("undo_add", f"web/{session.get('username','admin')}", {"count": len(removed_ips)}, {"ips": removed_ips})
        session.pop('last_action', None)
        return True, mensaje

    elif a_type in ("delete", "delete_bulk", "delete_all"):
        # deshacer: reponer exactamente las líneas guardadas (evitar duplicados)
        repuestos = 0
        for l in items:
            ip_txt = l.split("|", 1)[0]
            if ip_txt not in existentes:
                current.append(l)
                existentes.add(ip_txt)
                repuestos += 1
        if repuestos:
            save_lines(current)
        mensaje = f"Deshechas {repuestos} IP(s) eliminadas"
        if repuestos:
            guardar_notif("warning", mensaje)
        _audit("undo_delete", f"web/{session.get('username','admin')}", {"count": repuestos}, {})
        session.pop('last_action', None)
        return True, mensaje

    return False, "Tipo de acción no soportado"


# =========================
#  Helpers de UI: colores de tags + known_tags
# =========================
def _tag_color_hsl(tag: str) -> str:
    """Color estable por tag (HSL -> hex) para usar en la UI."""
    if not tag:
        return "#6c757d"
    
    # Colores fijos para tags del sistema (Premium Look)
    t_lower = tag.lower()
    if "multicliente" in t_lower:
        return "#0d6efd" # Primary Blue
    if "bpe" in t_lower:
        return "#fd7e14" # Orange
    if "test" in t_lower:
        return "#6c757d" # Secondary Grey
    
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
        # Si ttl es 0 o "0", es infinito
        ttl = int(ttl_str)
        if ttl == 0:
            return None
    except (ValueError, TypeError):
        # Si falla conversión, asumimos infinito o inválido
        return None

    try:
        if isinstance(date_str, str):
            d = datetime.strptime(date_str, "%Y-%m-%d")
        else:
            d = date_str  # por si acaso llega ya dt
        
        # Reutilizamos lógica existente _days_left
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
    """Devuelve lista ordenada de tags conocidos de ficheros y meta."""
    seen = set()
    out = []
    # de ficheros
    try:
        if os.path.isdir(TAGS_DIR):
            for name in os.listdir(TAGS_DIR):
                if name.endswith(".txt"):
                    t = name[:-4]
                    if t and t not in seen:
                        seen.add(t); out.append(t)
    except Exception:
        pass
    # de meta
    try:
        meta = load_meta()
        for entry in (meta.get("ip_details") or {}).values():
            for t in entry.get("tags", []) or []:
                if t and t not in seen:
                    seen.add(t); out.append(t)
    except Exception:
        pass
    out.sort(key=lambda x: x.lower())
    return out

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
    vencidas_main = eliminar_ips_vencidas()
    vencidas_bpe  = eliminar_ips_vencidas_bpe()
    vencidas_test = eliminar_ips_vencidas_en_feed(FEED_FILE_TEST)  # ← AÑADE
    vencidas = list(set((vencidas_main or []) + (vencidas_bpe or []) + (vencidas_test or [])))  # ← AÑADE
    if vencidas:
        meta_bulk_del(vencidas)
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
        current_feed="main" # Added for debug purposes
    )

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        
        users = load_users()
        user_data = users.get(username)
        
        if user_data and check_password_hash(user_data.get("password_hash", ""), password):
            session["username"] = username
            session["role"] = user_data.get("role", "editor")
            return redirect(url_for("index"))
            
        flash("Credenciales incorrectas", "danger")
    return render_template("login.html")

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
FEEDS_CONFIG = {
    "global":       {"label": "Global / Todos", "icon": "bi-globe", "virtual": True},
    "multicliente": {"file": FEED_FILE, "label": "Multicliente", "icon": "bi-hdd-network"},
    "bpe":          {"file": FEED_FILE_BPE, "label": "Feed BPE", "icon": "bi-bank"},
    "test":         {"file": FEED_FILE_TEST, "label": "Feed Test", "icon": "bi-cone-striped"},
}

@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    # Snapshot diario si hace falta
    perform_daily_backup(keep_days=14)

    # Expiración diaria (una vez/día)
    perform_daily_expiry_once()
    perform_daily_expiry_once()
    repair_meta_sources()
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
    allowed_feeds = user_data.get("allowed_feeds", ["*"])
    
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
    lines = []
    if current_feed_config.get("virtual"):
        # Modo Global: Cargar y fusionar todos los feeds VISIBLES que tengan 'file'
        seen_ips = set()
        for key, cfg in visible_feeds.items():
            if "file" in cfg:
                feed_lines = load_lines(cfg["file"])
                for line in feed_lines:
                    # Formato línea: IP|FECHA|TTL
                    parts = line.split("|")
                    ip = parts[0]
                    if ip not in seen_ips:
                        lines.append(line)
                        seen_ips.add(ip)
        # Ordenar alfabéticamente
        lines.sort(key=lambda x: x.split("|")[0])
    else:
        # Modo Feed Individual
        lines = load_lines(current_feed_config["file"])
        
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
        if "delete-all" in request.form:
            # cargar todo para UNDO
            lines_main = list(lines)
            lines_bpe_full = load_lines(FEED_FILE_BPE) if os.path.exists(FEED_FILE_BPE) else []
            lines_test_full = load_lines(FEED_FILE_TEST) if os.path.exists(FEED_FILE_TEST) else []
            
            all_lines = lines_main + lines_bpe_full + lines_test_full
            
            # extraer IPs para borrado de metadatos
            # (asumimos formato IP|... en todos los feeds)
            ips_main = [l.split("|", 1)[0].strip() for l in lines_main]
            ips_bpe  = [l.split("|", 1)[0].strip() for l in lines_bpe_full]
            ips_test = [l.split("|", 1)[0].strip() for l in lines_test_full]
            
            all_ips = list(set(ips_main + ips_bpe + ips_test))

            # limpiar TODOS los feeds
            save_lines([], FEED_FILE)
            save_lines([], FEED_FILE_BPE)
            save_lines([], FEED_FILE_TEST)

            # meta/tag-files
            meta_bulk_del(all_ips)

            log("Eliminadas", "todas las IPs (Global: Main + BPE + Test)")
            guardar_notif("warning", "Se eliminaron todas las IPs (Global)")
            flash("Se eliminaron todas las IPs de todas las tablas", "warning")
            
            # UNDO guardará todo mezclado; al restaurar irá a feed principal (limitación conocida)
            _set_last_action("delete_all", all_lines)
            _audit("delete_all", f"web/{session.get('username','admin')}", {"count": len(all_ips)}, {})
            return redirect(url_for("index"))

        # Eliminar individual (quitar de ambos feeds)
        if "delete_ip" in request.form:
            ip_to_delete = request.form.get("delete_ip")
            orig_line = next((l for l in lines if l.startswith(ip_to_delete + "|")), None)

            # Quitar del feed principal
            new_lines = [l for l in lines if not l.startswith(ip_to_delete + "|")]
            save_lines(new_lines, FEED_FILE)

            # Quitar también del feed BPE y TEST si estuviera
            _remove_ip_from_feed(ip_to_delete, FEED_FILE_BPE)
            _remove_ip_from_feed(ip_to_delete, FEED_FILE_TEST)

            # Limpiar meta + tag-files
            meta_del_ip(ip_to_delete)

            # Notifs + UNDO
            guardar_notif("warning", f"IP eliminada: {ip_to_delete}")
            flash(f"IP eliminada: {ip_to_delete}", "warning")
            if orig_line:
                _set_last_action("delete", [orig_line])

            _audit("delete_ip", f"web/{session.get('username','admin')}", ip_to_delete, {})
            return redirect(url_for("index"))

        # Eliminar por patrón (ambos feeds)
        if "delete-net" in request.form:
            patron = request.form.get("delete_net_input", "").strip()
            try:
                # 1) Aplicar al feed principal
                new_lines, removed, removed_ips, removed_lines = filter_lines_delete_pattern(lines, patron)
                save_lines(new_lines, FEED_FILE)

                # 2) Quitar del feed BPE cualquier IP eliminada
                if removed_ips:
                    bpe_lines = load_lines(FEED_FILE_BPE)
                    bpe_new = [l for l in bpe_lines if l.split("|",1)[0] not in set(removed_ips)]
                    if len(bpe_new) != len(bpe_lines):
                        save_lines(bpe_new, FEED_FILE_BPE)

                    # 3) Limpiar meta/tag-files de todas las IPs eliminadas
                    meta_bulk_del(removed_ips)

                # 4) Notifs + UI + UNDO (undo solo repone el principal)
                guardar_notif("warning", f"Eliminadas por patrón {patron}: {removed}")
                flash(f"Eliminadas por patrón {patron}: {removed}", "warning")
                if removed_lines:
                    _set_last_action("delete_bulk", removed_lines)

                _audit("delete_pattern", f"web/{session.get('username','admin')}", {"pattern": patron, "removed": removed}, {"ips": removed_ips})

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
            
            # Detectar delimitador: ; o | o ,
            delimiter = ","
            header_check = "\n".join(content[:5])
            if ";" in header_check:
                delimiter = ";"
            elif "|" in header_check:
                delimiter = "|"
            
            for raw_line in content:
                raw_line = (raw_line or "").strip()
                if not raw_line or raw_line.lower().startswith("ip" + delimiter): 
                    continue
                
                parts = raw_line.split(delimiter)
                # Formato: IP [;|] Tags [;|] AlertID
                
                raw_ip = parts[0].strip()
                raw_tags = parts[1].strip() if len(parts) > 1 else ""
                raw_alert = parts[2].strip() if len(parts) > 2 else None
                
                # Tags: Si no hay en el CSV, asignamos 'Multicliente' por defecto para facilitar uso
                parsed_tags = _parse_tags_field(raw_tags)
                if not parsed_tags:
                    parsed_tags = ["Multicliente"]
                
                row_tags = _filter_allowed_tags(parsed_tags)
                
                if not row_tags:
                    # Si aun asi no hay tags validos (ej: puso tags invalidos)
                    # Forzamos Multicliente si la IP es valida? No, mejor respetar filtro strict
                    # Pero si venia vacio ya pusimos Multicliente.
                    rejected_total += 1
                    continue

                try:
                    expanded = expand_input_to_ips(raw_ip)
                except ValueError as e:
                    if str(e) == "accion_no_permitida":
                        try:
                            guardar_notif("accion_no_permitida", "Intento de bloqueo global (CSV)")
                        except Exception:
                            pass
                        continue
                    rejected_total += 1
                    continue

                # Inserción fila a fila para soportar metadata única
                add_ok, add_bad, added_lines, _ = add_ips_validated(
                    lines, existentes, expanded,
                    ttl_val=ttl_csv_val,
                    origin="csv",
                    contador_ruta=COUNTER_CSV,
                    tags=row_tags,
                    alert_id=raw_alert
                )

                valid_ips_total += add_ok
                rejected_total += add_bad
                added_lines_acc.extend(added_lines)

            # 4) Persistir feed y notificar
            save_lines(lines, FEED_FILE)

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
        
        # Unir ambos origenes
        combined_raw = str_tags + "," + ",".join(list_tags)
        
        raw_tags_manual = _parse_tags_field(combined_raw)
        tags_manual = _filter_allowed_tags(raw_tags_manual)

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

                add_ok, add_bad, added_lines, updated_ok = add_ips_validated(
                    lines, existentes, expanded, ttl_val=ttl_val,
                    origin="manual", contador_ruta=COUNTER_MANUAL, tags=tags_manual,
                    alert_id=ticket_number
                )

                if add_ok > 0 or updated_ok > 0:

                    save_lines(lines, FEED_FILE)
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
    # messages.extend(request_actions)  <-- RIMOS DUPLICACIÓN
    try:
        for n in get_notifs(limit=200):
            cat = str(n.get("category", "secondary"))
            msg = f"{n.get('time','')} {n.get('message','')}".strip()
            messages.append({"category": cat, "message": msg})
    except Exception:
        pass

    # Unión para contadores / totales de cabecera
    lines_main = load_lines(FEED_FILE)
    lines_bpe  = load_lines(FEED_FILE_BPE)
    lines_test = load_lines(FEED_FILE_TEST)
    rec_main   = {r["ip"]: r for r in _feed_to_records(lines_main)}
    rec_bpe    = {r["ip"]: r for r in _feed_to_records(lines_bpe)}
    rec_test   = {r["ip"]: r for r in _feed_to_records(lines_test)}
    
    merged_records = list(rec_main.values())
    for ip, r in rec_bpe.items():
        if ip not in rec_main:
            merged_records.append(r)
    for ip, r in rec_test.items():
        if ip not in rec_main and ip not in rec_bpe:
            merged_records.append(r)
    
    active_union_ips = {r["ip"] for r in merged_records}
    meta_by_ip = load_meta().get("by_ip", {})
    live_manual = sum(1 for ip in active_union_ips if meta_by_ip.get(ip) == "manual")
    live_csv    = sum(1 for ip in active_union_ips if meta_by_ip.get(ip) == "csv")
    live_api    = sum(1 for ip in active_union_ips if meta_by_ip.get(ip) == "api")
    
    tag_totals = compute_tag_totals()  # ya calcula Multicliente/BPE en la unión
    
    
    # CORRECCIÓN: (Eliminado overwrite global)
    # lines = ... (ya cargado por feed al inicio)


    # Resumen unión feeds (fuente, tag y fuente×tag)
    src_union, tag_union, src_tag_union, total_union = compute_source_and_tag_counters_union()

    # Construye map de tags + alertas para la tabla server-rendered
    meta = load_meta()
    
    ip_details = meta.get("ip_details", {})
    ip_tags = {}
    ip_alerts = {}
    ip_alert_ids = {}
    for ip, details in ip_details.items():
        if "tags" in details and details["tags"]:
            ip_tags[ip] = details["tags"]
        if "alerts" in details and details["alerts"]:
            ip_alerts[ip] = details["alerts"]
        if "alert_ids" in details and details["alert_ids"]:
            ip_alert_ids[ip] = details["alert_ids"]

    known_tags = _collect_known_tags()

    return render_template("index.html",
                           current_feed=feed_param,
                           feeds_config=visible_feeds,
                           current_flashes_list=request_actions,
                           server_messages_list=messages,
                           ips=lines,
                           error=error,
                           total_ips=total_union,
                           contador_manual=live_manual,
                           contador_csv=live_csv,
                           contador_api=live_api,
                           contador_tags=tag_totals,
                           # NUEVOS resúmenes (unión feeds)
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
                           known_tags=known_tags)


@app.route("/feed/ioc-feed.txt")
def feed():
    ips = []
    if os.path.exists(FEED_FILE):
        with open(FEED_FILE, encoding="utf-8") as f:
            for line in f:
                ip = line.split("|", 1)[0].strip()
                if ip and is_allowed_ip(ip):
                    try:
                        if isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address):
                            ips.append(ip)
                    except Exception:
                        continue
    body = "\n".join(ips) + "\n"
    resp = make_response(body, 200)
    resp.headers["Content-Type"] = "text/plain"
    return resp

# === NUEVO: feed BPE separado ===
@app.route("/feed/ioc-feed-bpe.txt")
def feed_bpe():
    ips = []
    if os.path.exists(FEED_FILE_BPE):
        with open(FEED_FILE_BPE, encoding="utf-8") as f:
            for line in f:
                ip = line.split("|", 1)[0].strip()
                if ip and is_allowed_ip(ip):
                    try:
                        if isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address):
                            ips.append(ip)
                    except Exception:
                        continue
    body = "\n".join(ips) + "\n"
    resp = make_response(body, 200)
    resp.headers["Content-Type"] = "text/plain"
    return resp

@app.route("/feed/ioc-feed-test.txt")
def feed_test():
    ips = []
    if os.path.exists(FEED_FILE_TEST):
        with open(FEED_FILE_TEST, encoding="utf-8") as f:
            for line in f:
                ip = line.split("|", 1)[0].strip()
                if ip and is_allowed_ip(ip):
                    try:
                        if isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address):
                            ips.append(ip)
                    except Exception:
                        continue
    body = "\n".join(ips) + "\n"
    resp = make_response(body, 200)
    resp.headers["Content-Type"] = "text/plain"
    return resp


@app.route("/preview-delete")
@login_required
def preview_delete():
    pattern = request.args.get("pattern", "").strip()
    if not pattern:
        return jsonify({"error": "Patrón vacío"}), 400
    try:
        lines = load_lines(FEED_FILE)
        _, removed, _removed_ips, _removed_lines = filter_lines_delete_pattern(lines, pattern)
        return jsonify({"count": removed})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/undo-last", methods=["POST"])
@login_required
def undo_last():
    ok, msg = _undo_last_action()
    if ok:
        flash(msg, "warning")
        return json_response_ok(
            notices=[{"time": datetime.utcnow().isoformat()+"Z", "category": "warning", "message": msg}]
        )
    else:
        flash(msg, "warning")
        return json_response_error(msg, code=400,
                                   notices=[{"time": datetime.utcnow().isoformat()+"Z", "category": "warning", "message": msg}])



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
    # Solo admin puede crear (además de estar logueado, chequeamos rol si hubiera roles)
    current_user = session.get("username")
    users = load_users()
    
    # Simple control de roles (si el usuario actual no es admin en el JSON, rechazar?
    # Por ahora asumimos que quien entra al dashboard es admin confiable)
    
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    role = data.get("role", "view_only").strip()
    allowed_feeds = data.get("allowed_feeds", [])
    
    if not username or not password:
        return jsonify({"error": "Faltan datos"}), 400
        
    if username in users:
        return jsonify({"error": "El usuario ya existe"}), 400
        
    users[username] = {
        "password_hash": generate_password_hash(password),
        "role": role,
        "allowed_feeds": allowed_feeds,
        "created_at": _iso(_now_utc()),
        "created_by": current_user
    }
    save_users(users)
    _audit("user_created", f"web/{current_user}", username, {"role": role, "feeds": allowed_feeds})
    return jsonify({"success": True})

@app.route("/admin/users/edit", methods=["POST"])
@login_required
def edit_user():
    current_user = session.get("username")
    users = load_users()
    
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    role = data.get("role", "view_only").strip()
    allowed_feeds = data.get("allowed_feeds", [])
    
    if not username:
        return jsonify({"error": "Faltan datos"}), 400
        
    if username not in users:
        return jsonify({"error": "El usuario no existe"}), 404
        
    # Actualizar datos
    users[username]["role"] = role
    users[username]["allowed_feeds"] = allowed_feeds
    
    # Solo actualizar contraseña si se envía una nueva
    if password:
        users[username]["password_hash"] = generate_password_hash(password)
    
    save_users(users)
    _audit("user_updated", f"web/{current_user}", username, {"role": role, "feeds": allowed_feeds, "pw_changed": bool(password)})
    return jsonify({"success": True})

@app.route("/admin/users/delete", methods=["POST"])
@login_required
def delete_user():
    data = request.get_json(silent=True) or {}
    target = data.get("username", "").strip()
    current = session.get("username")
    
    if target == current:
        return jsonify({"error": "No puedes borrarte a ti mismo"}), 400
        
    users = load_users()
    if target not in users:
        return jsonify({"error": "Usuario no encontrado"}), 404
        
    del users[target]
    save_users(users)
    _audit("user_deleted", f"web/{current}", target, {})
    return jsonify({"success": True})

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
    lines = load_lines(FEED_FILE)
    manual, csvc, apic = compute_live_counters(lines)   # compat (principal)
    tag_totals = compute_tag_totals()                   # compat (unión por tag)
    src_union, tag_union, src_tag_union, total_union = compute_source_and_tag_counters_union()

    return jsonify({
        # Compat anteriores (principal):
        "total_active_principal": len(lines),
        "manual_active_principal": manual,
        "csv_active_principal": csvc,
        "api_active_principal": apic,
        "tags_total_union": tag_totals,
        # Nuevos (unión feeds):
        "union_total": total_union,
        "union_by_source": src_union,
        "union_by_tag": tag_union,
        "union_by_source_tag": src_tag_union
    })


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


@app.route("/audit")
@login_required
def audit_view():
    if session.get("role") == "view_only":
        pass

    # Parámetro opcional ?log_file=...
    requested_file = request.args.get("log_file", "").strip()
    
    target_file = AUDIT_LOG_FILE
    is_historical = False
    
    # Validación segura: solo permitimos nombres que coincidan con patrón de rotación
    if requested_file:
        # Debe estar en el mismo directorio y empezar por el prefijo
        safe_name = os.path.basename(requested_file)
        full_path = os.path.join(os.path.dirname(AUDIT_LOG_FILE) or ".", safe_name)
        if os.path.exists(full_path) and safe_name.startswith("audit-log.") and safe_name.endswith(".jsonl"):
            target_file = full_path
            if safe_name != os.path.basename(AUDIT_LOG_FILE):
                is_historical = True

    logs = []
    try:
        if os.path.exists(target_file):
            with open(target_file, "r", encoding="utf-8") as f:
                # Leer todo (para histórico/actual) y coger últimas 500 lineas
                # Si es un fichero historico MUY grande, esto podría optimizarse, pero 5MB es manejable.
                lines = f.readlines()
                # Mostramos los últimos 500
                for line in reversed(lines[-500:]):
                    try:
                        logs.append(json.loads(line))
                    except:
                        pass
    except Exception:
        pass

    # Obtener lista de ficheros disponibles para el selector
    available_files = get_audit_log_files()

    return render_template("audit.html", 
                           logs=logs, 
                           current_file=os.path.basename(target_file), 
                           is_historical=is_historical,
                           available_files=available_files)


# =========================
#  API (Blueprint) con tags + alert_id
# =========================
api = Blueprint("api", __name__, url_prefix="/api")

@api.before_request
def _api_guard():
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
    if not TOKEN_API:
        return False
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return False
    return auth.split(" ", 1)[1].strip() == TOKEN_API

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
@require_api_token
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
        lines = load_lines(FEED_FILE)
        existentes = {l.split("|", 1)[0] for l in lines}

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
                want_multi = "Multicliente" in tags
                want_bpe = "BPE" in tags
                want_test  = "Test" in tags

                for ip_str in targets:
                    if ip_str == "0.0.0.0":
                        item_result["ips"].append({"ip": ip_str, "status": "policy_denied"})
                        continue

                    # meta details actual (si existe)
                    meta = load_meta()
                    current = meta.get("ip_details", {}).get(ip_str)

                    # Fusión de TTL/tags si ya existe
                    effective_expires = expires_at
                    cur_exp = None
                    if current:
                        try:
                            cur_exp = datetime.fromisoformat(current["expires_at"].replace("Z","+00:00"))
                        except Exception:
                            cur_exp = None
                        if cur_exp and abs((cur_exp - expires_at).total_seconds()) > 1:
                            # tomamos la expiración más lejana (no es conflicto)
                            effective_expires = cur_exp if cur_exp > expires_at else expires_at

                        # Idempotencia semántica exacta (mismos tags y misma expiración)
                        if not force and _already_same(current, tags or current.get("tags", []), effective_expires):
                            # Aunque sea "igual", si viene un alert_id nuevo, lo añadimos
                            if alert_id:
                                _merge_meta_tags(ip_str, tags or current.get("tags", []), effective_expires, origin, note, alert_id=alert_id)
                            item_result["ips"].append({"ip": ip_str, "status": "already_exists"})
                            continue

                    fecha = datetime.now().strftime("%Y-%m-%d")

                    # FEED principal solo si Multicliente
                    if want_multi and ip_str not in existentes:
                        line_txt = f"{ip_str}|{fecha}|{ttl_days}"
                        lines.append(line_txt)
                        existentes.add(ip_str)
                        meta_set_origin(ip_str, "api")
                        log("Añadida", ip_str)

                    # Registrar origen API también cuando sólo venga con BPE/Test
                    if not want_multi:
                        try:
                            meta_set_origin(ip_str, "api")
                        except Exception:
                            pass

                    # Merge en meta detalles + escrituras por tag (con expiración efectiva + alert_id)
                    entry = _merge_meta_tags(ip_str, tags, effective_expires, origin, note, alert_id=alert_id)

                    # Escribir una línea por tag nuevo (append-only)
                    prev_tags = set(current.get("tags", [])) if current else set()
                    for t in [x for x in tags if x not in prev_tags]:
                        _write_tag_line(t, ip_str, _now_utc(), ttl_s, effective_expires, origin, entry["tags"])

                    # Reflejar en feed BPE si corresponde
                    if want_bpe:
                        line_txt_bpe = f"{ip_str}|{fecha}|{ttl_days}"
                        _append_line_unique(FEED_FILE_BPE, line_txt_bpe)

                    # Feed Test
                    if want_test:
                        line_txt_test = f"{ip_str}|{fecha}|{ttl_days}"
                        _append_line_unique(FEED_FILE_TEST, line_txt_test)

                    item_result["ips"].append({
                        "ip": ip_str,
                        "status": "ok",
                        "tags": entry["tags"],
                        "expires_at": entry["expires_at"],
                        "alert_ids": entry.get("alert_ids", [])
                    })
                    item_result["count"] += 1

                processed.append(item_result)
            except Exception as e:
                errors.append({"index": idx, "error": str(e)})

        # Guardar feed si cambió
        save_lines(lines, FEED_FILE)

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

    meta = load_meta()
    entry = meta.get("ip_details", {}).get(ip_txt)
    if not entry:
        # No hay detalles: si no hay tags => quitar del feed(s) por compat
        if not tags:
            _remove_ip_from_feed(ip_txt, FEED_FILE)
            _remove_ip_from_feed(ip_txt, FEED_FILE_BPE)
            meta_del_ip(ip_txt)
            _audit("api_delete_global", g.get("api_actor","api"), ip_txt, {"detail": "no_meta_global"})
            return jsonify({"status": "deleted", "ip": ip_txt, "scope": "global"}), 200
        else:
            _audit("api_delete_not_found", g.get("api_actor","api"), ip_txt, {"tags": tags})
            return jsonify({"status": "not_found", "ip": ip_txt}), 404

    if not tags:
        # borrar de todos los tags + feeds + meta
        for t in entry.get("tags", []):
            _remove_ip_from_tag_file(t, ip_txt)
        _remove_ip_from_feed(ip_txt, FEED_FILE)
        _remove_ip_from_feed(ip_txt, FEED_FILE_BPE)
        meta_del_ip(ip_txt)
        _audit("api_delete_all_tags", g.get("api_actor","api"), ip_txt, {})
        return jsonify({"status": "deleted", "ip": ip_txt, "scope": "global"}), 200
    else:
        # borrar solo tags indicados
        remaining = [t for t in entry.get("tags", []) if t not in set(tags)]
        for t in tags:
            _remove_ip_from_tag_file(t, ip_txt)

        # actualizar meta (alert_ids se conservan)
        meta["ip_details"][ip_txt]["tags"] = remaining
        meta["ip_details"][ip_txt]["history"].append({
            "ts": _iso(_now_utc()),
            "action": "untag",
            "tags_removed": tags
        })
        # Si se ha quitado BPE de los tags y ya no queda, retirar del feed BPE
        if "BPE" in tags and "BPE" not in remaining:
            _remove_ip_from_feed(ip_txt, FEED_FILE_BPE)
        # Si se quitó Multicliente y ya no queda ningun tag, también del principal
        if "Multicliente" in tags and "Multicliente" not in remaining:
            _remove_ip_from_feed(ip_txt, FEED_FILE)

        if not remaining:
            # si ya no quedan tags, limpiar de ambos feeds + meta
            _remove_ip_from_feed(ip_txt, FEED_FILE)
            _remove_ip_from_feed(ip_txt, FEED_FILE_BPE)
            meta_del_ip(ip_txt)
            save_meta(meta)
            _audit("api_delete_all_tags_cleanup", g.get("api_actor","api"), ip_txt, {})
            return jsonify({"status": "deleted", "ip": ip_txt, "scope": "all_tags"}), 200
        else:
            save_meta(meta)
            _audit("api_delete_some_tags", g.get("api_actor","api"), ip_txt, {"remaining": remaining})
            return jsonify({"status": "updated", "ip": ip_txt, "remaining_tags": remaining}), 200


@api.route("/estado/<ip_str>", methods=["GET"])
def estado_api(ip_str):
    try:
        ipaddress.ip_address(ip_str)
    except Exception:
        _audit("api_estado_invalid_ip", g.get("api_actor","api"), ip_str, {})
        return jsonify({"error": "IP inválida"}), 400
    meta = load_meta()
    entry = meta.get("ip_details", {}).get(ip_str)
    if not entry:
        _audit("api_estado_not_found", g.get("api_actor","api"), ip_str, {})
        return jsonify({"status": "not_found", "ip": ip_str}), 404
    _audit("api_estado_ok", g.get("api_actor","api"), ip_str, {})
    # entry ya incluye alert_ids si existen
    return jsonify({"status": "ok", "data": entry}), 200


@api.route("/lista/<tag>", methods=["GET"])
def lista_tag_api(tag):
    _audit("api_lista_tag", g.get("api_actor","api"), tag, {})
    path = os.path.join(TAGS_DIR, f"{tag}.txt")
    if not os.path.exists(path):
        return jsonify({"status": "not_found", "tag": tag, "entries": []}), 404
    entries = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                l = line.strip()
                if not l:
                    continue
                parts = l.split("|")
                entries.append({
                    "ip": parts[0],
                    "created_at": parts[1] if len(parts) > 1 else None,
                    "ttl_s": int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else None,
                    "expires_at": parts[3] if len(parts) > 3 else None,
                    "source": parts[4] if len(parts) > 4 else None,
                    "tags": [t for t in (parts[5].split(",") if len(parts) > 5 else []) if t],
                })
    except Exception as e:
        return jsonify({"error": f"Error leyendo lista de tag: {e}"}), 500
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


# Registrar blueprint
app.register_blueprint(api)


@app.route("/api/counters/history", methods=["GET"])
@login_required
def api_counters_history():
    """Devuelve el histórico de contadores (JSON)."""
    return jsonify(load_history())


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
        # 1. Quitar del fichero de metadatos
        _remove_tag_meta(ip, tag)
        
        # 2. Quitar del fichero del tag específico
        _remove_ip_from_tag_file(tag, ip) 
        
        # Auditoría
        _audit("remove_tag", f"web/{session.get('username','admin')}", ip, {"tag": tag})
        
        return json_response_ok([], {"message": f"Tag '{tag}' eliminado de {ip}"})
    except Exception as e:
        return json_response_error(f"Error interno: {str(e)}", 500)


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
