from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, make_response, jsonify, get_flashed_messages,
    send_file, abort, Blueprint
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

app = Flask(__name__)
app.secret_key = 'clave-secreta'

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
FEED_FILE = os.path.join(BASE_DIR, 'ioc-feed.txt')
# === Nuevo feed BPE ===
FEED_FILE_BPE = os.path.join(BASE_DIR, 'ioc-feed-bpe.txt')

LOG_FILE = os.path.join(BASE_DIR, 'ioc-log.txt')
NOTIF_FILE = os.path.join(BASE_DIR, 'notif-log.json')

# Carpeta para datos adicionales de la API por tags
DATA_DIR = os.path.join(BASE_DIR, "data")
TAGS_DIR = os.path.join(DATA_DIR, "tags")

# Counters históricos (compat), los totales vivos se calculan con meta
COUNTER_MANUAL = os.path.join(BASE_DIR, 'contador_manual.txt')
COUNTER_CSV = os.path.join(BASE_DIR, 'contador_csv.txt')

# Nuevo: meta lateral para origen por IP (no afecta al feed)
# Ampliado para ip_details con tags/expiraciones; se mantiene compat con "by_ip"
META_FILE = os.path.join(BASE_DIR, 'ioc-meta.json')

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
ALLOWED_TAGS = {"Multicliente", "BPE"}

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
    meta = load_meta().get("by_ip", {})
    manual = 0
    csv = 0
    for line in active_lines:
        ip_txt = line.split("|", 1)[0].strip()
        origin = meta.get(ip_txt)
        if origin == "manual":
            manual += 1
        elif origin == "csv":
            csv += 1
    return manual, csv


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
    except Exception:
        return []


# =========================
#  Helpers almacenamiento (feeds)
# =========================
def _append_line_unique(feed_path, line_txt):
    """Append si no existe esa IP en el feed dado."""
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
    """Devuelve sólo los tags permitidos."""
    return [t for t in _norm_tags(tags) if t in ALLOWED_TAGS]

def _parse_tags_field(val: str):
    if not val:
        return []
    items = re.split(r"[,\s]+", val.strip())
    return _norm_tags([x for x in items if x])

def _write_tag_line(tag, ip, created_at, ttl_s, expires_at, source, tags):
    os.makedirs(TAGS_DIR, exist_ok=True)
    path = os.path.join(TAGS_DIR, f"{tag}.txt")
    line = f"{ip}|{_iso(created_at)}|{ttl_s}|{_iso(expires_at)}|{source}|{','.join(tags)}"
    with open(path, "a", encoding="utf-8") as f:
        f.write(line + "\n")

def _remove_ip_from_tag_file(tag, ip):
    path = os.path.join(TAGS_DIR, f"{tag}.txt")
    if not os.path.exists(path):
        return
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

def _merge_meta_tags(ip, new_tags, expires_at, source, note):
    """Fusiona tags y actualiza expiración en META_FILE.ip_details"""
    meta = load_meta()
    details = meta.get("ip_details", {})
    entry = details.get(ip, {
        "ip": ip, "tags": [], "expires_at": None, "source": source,
        "history": [], "last_update": _iso(_now_utc())
    })
    old_tags = set(entry.get("tags", []))
    add_tags = set(new_tags)
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
        "source": source
    })
    details[ip] = entry
    meta["ip_details"] = details
    save_meta(meta)
    return entry

def _already_same(entry, tags, expires_at):
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
def add_ips_validated(lines, existentes, iterable_ips, ttl_val, origin=None, contador_ruta=None, tags=None):
    """
    ttl_val: '0' para permanente o número de días (str/int)
    tags: lista de tags (OBLIGATORIA: Multicliente y/o BPE)
    """
    añadidas = 0
    rechazadas = 0
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

    for ip_str in iterable_ips:
        if not (allow_multi or allow_bpe):
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
            entry = _merge_meta_tags(ip_str, tags, expires_at_dt, origin or "manual", note="web")
            for t in tags:
                _write_tag_line(t, ip_str, _now_utc(), ttl_seconds, expires_at_dt, origin or "manual", entry["tags"])
            rechazadas += 1  # se considera duplicada para el feed principal
            # asegurar reflejo BPE si aplica
            if allow_bpe:
                fecha = datetime.now().strftime("%Y-%m-%d")
                _append_line_unique(FEED_FILE_BPE, f"{ip_str}|{fecha}|{ttl_val}")
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

        # FEED BPE si corresponde
        if allow_bpe:
            _append_line_unique(FEED_FILE_BPE, f"{ip_str}|{fecha}|{ttl_val}")

        # meta + tag files
        entry = _merge_meta_tags(ip_str, tags, expires_at_dt, origin or "manual", note="web")
        for t in tags:
            _write_tag_line(t, ip_str, _now_utc(), ttl_seconds, expires_at_dt, origin or "manual", entry["tags"])

        log("Añadida", ip_str)
        guardar_notif("success", f"IP añadida: {ip_str}")

        if contador_ruta and allow_multi:
            try:
                val = read_counter(contador_ruta)
                write_counter(contador_ruta, val + 1)
            except Exception:
                pass

        añadidas += 1

    return añadidas, rechazadas, added_lines


# =========================
#  Flashes seguros para plantillas
# =========================
def coerce_message_pairs(raw_flashes):
    pairs = []
    for item in raw_flashes:
        if isinstance(item, (list, tuple)) and len(item) >= 2:
            pairs.append((str(item[0] or 'info'), str(item[1])))
        else:
            pairs.append(('info', str(item)))
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
        _safe_copy(FEED_FILE, day_dir)
        _safe_copy(FEED_FILE_BPE, day_dir)  # incluir BPE
        if META_FILE and os.path.exists(META_FILE):
            _safe_copy(META_FILE, day_dir)
        if NOTIF_FILE and os.path.exists(NOTIF_FILE):
            _safe_copy(NOTIF_FILE, day_dir)

        _zip_backup(day_dir, zip_path)

        with open(LAST_BACKUP_MARK, "w", encoding="utf-8") as f:
            f.write(today)

        _rotate_backups(keep_days=keep_days)

        guardar_notif("info", f"Backup diario creado: {today}")
    except Exception as e:
        guardar_notif("danger", f"Error en backup diario: {str(e)}")


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

@app.context_processor
def inject_helpers():
    return {
        "tag_color": _tag_color_hsl
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
#  Rutas
# =========================
@app.after_request
def add_security_headers(resp):
    # Cabeceras comunes
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "same-origin"

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
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data:; "
            "font-src 'self' https://cdn.jsdelivr.net data:; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "frame-ancestors 'none'"
        )
    return resp


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form.get("username") == "admin" and request.form.get("password") == "admin":
            session["username"] = "admin"
            return redirect(url_for("index"))
        flash("Credenciales incorrectas", "danger")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    # Snapshot diario si hace falta
    perform_daily_backup(keep_days=14)

    # Expirar y sincronizar meta (principal y BPE)
    vencidas_main = eliminar_ips_vencidas()
    vencidas_bpe = eliminar_ips_vencidas_bpe()
    vencidas = list(set((vencidas_main or []) + (vencidas_bpe or [])))
    if vencidas:
        meta_bulk_del(vencidas)

    error = None
    lines = load_lines(FEED_FILE)
    existentes = {l.split("|", 1)[0] for l in lines}

    # ----- Mutaciones (POST) -----
    if request.method == "POST":
        # Eliminar todas (sólo feed principal; evitamos impactos en BPE desde la tabla actual)
        if "delete-all" in request.form:
            all_lines = list(lines)  # guardar para UNDO
            all_ips = [l.split("|", 1)[0].strip() for l in lines]
            save_lines([], FEED_FILE)
            meta_bulk_del(all_ips)
            log("Eliminadas", "todas las IPs (Multicliente)")
            guardar_notif("warning", "Se eliminaron todas las IPs (Multicliente)")
            flash("Se eliminaron todas las IPs (Multicliente)", "warning")
            _set_last_action("delete_all", all_lines)
            return redirect(url_for("index"))

        # Eliminar individual (sólo del listado principal)
        if "delete_ip" in request.form:
            ip_to_delete = request.form.get("delete_ip")
            orig_line = next((l for l in lines if l.startswith(ip_to_delete + "|")), None)
            new_lines = [l for l in lines if not l.startswith(ip_to_delete + "|")]
            save_lines(new_lines, FEED_FILE)
            meta_del_ip(ip_to_delete)  # meta/tag-files coherentes
            guardar_notif("warning", f"IP eliminada (Multicliente): {ip_to_delete}")
            flash(f"IP eliminada: {ip_to_delete}", "warning")
            if orig_line:
                _set_last_action("delete", [orig_line])
            return redirect(url_for("index"))

        # Eliminar por patrón (sólo feed principal)
        if "delete-net" in request.form:
            patron = request.form.get("delete_net_input", "").strip()
            try:
                new_lines, removed, removed_ips, removed_lines = filter_lines_delete_pattern(lines, patron)
                save_lines(new_lines, FEED_FILE)
                if removed_ips:
                    meta_bulk_del(removed_ips)
                guardar_notif("warning", f"Eliminadas por patrón (Multicliente) {patron}: {removed}")
                flash(f"Eliminadas por patrón {patron}: {removed}", "warning")
                if removed_lines:
                    _set_last_action("delete_bulk", removed_lines)
            except Exception as e:
                flash(str(e), "danger")
            return redirect(url_for("index"))

        # Subida CSV/TXT
        file = request.files.get("file")
        if file and file.filename:
            ttl_csv_sel = request.form.get("ttl_csv", "permanente")
            ttl_csv_val = "0" if ttl_csv_sel == "permanente" else ttl_csv_sel
            # Tags CSV (OBLIGATORIO)
            raw_tags_csv = _parse_tags_field(request.form.get("tags_csv", ""))
            tags_csv = _filter_allowed_tags(raw_tags_csv)

            if not tags_csv:
                flash("Debes seleccionar al menos un tag válido (Multicliente y/o BPE) para el CSV.", "danger")
                return redirect(url_for("index"))

            valid_ips_total = 0
            rejected_total = 0
            added_lines_acc = []
            try:
                content = file.read().decode("utf-8", errors="ignore").splitlines()
            except Exception:
                content = []
            for raw in content:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    expanded = expand_input_to_ips(raw)
                except ValueError as e:
                    if str(e) == "accion_no_permitida":
                        flash("⚠️ Acción no permitida: bloqueo de absolutamente todo", "accion_no_permitida")
                        guardar_notif("accion_no_permitida", "Intento de bloqueo global (CSV)")
                        continue
                    else:
                        rejected_total += 1
                        continue

                add_ok, add_bad, added_lines = add_ips_validated(
                    lines, existentes, expanded, ttl_val=ttl_csv_val,
                    origin="csv", contador_ruta=COUNTER_CSV, tags=tags_csv
                )

                valid_ips_total += add_ok
                rejected_total += add_bad
                added_lines_acc.extend(added_lines)

            save_lines(lines, FEED_FILE)
            if valid_ips_total:
                guardar_notif("success", f"{valid_ips_total} IPs añadidas (CSV)")
                flash(f"{valid_ips_total} IP(s) añadida(s) correctamente (CSV)", "success")
                if added_lines_acc:
                    _set_last_action("add", added_lines_acc)
            if rejected_total:
                guardar_notif("danger", f"{rejected_total} entradas rechazadas (CSV)")
                flash(f"{rejected_total} entradas rechazadas (inválidas/privadas/duplicadas/no permitidas)", "danger")
            return redirect(url_for("index"))

        # Alta manual (Tag OBLIGATORIO: Multicliente y/o BPE)
        raw_input = request.form.get("ip", "").strip()

        ttl_man_sel = request.form.get("ttl_manual", "permanente")
        ttl_val = "0" if ttl_man_sel == "permanente" else ttl_man_sel

        raw_tags_manual = _parse_tags_field(request.form.get("tags_manual", ""))
        tags_manual = _filter_allowed_tags(raw_tags_manual)

        if not tags_manual:
            flash("Debes seleccionar al menos un tag válido (Multicliente y/o BPE).", "danger")
            return redirect(url_for("index"))

        if raw_input:
            try:
                expanded = expand_input_to_ips(raw_input)

                single_input = len(expanded) == 1
                single_ip = expanded[0] if single_input else None
                pre_notified = False
                if single_input:
                    if single_ip in existentes:
                        msg = f"IP duplicada: {single_ip}"
                        flash(msg, "danger")
                        guardar_notif("danger", msg)
                        pre_notified = True
                    else:
                        reason = ip_block_reason(single_ip)
                        if reason:
                            msg = f"IP rechazada: {single_ip} — {reason}"
                            flash(msg, "danger")
                            guardar_notif("danger", msg)
                            pre_notified = True

                add_ok, add_bad, added_lines = add_ips_validated(
                    lines, existentes, expanded, ttl_val=ttl_val,
                    origin="manual", contador_ruta=COUNTER_MANUAL, tags=tags_manual
                )

                if add_ok > 0:
                    save_lines(lines, FEED_FILE)
                    if single_input:
                        guardar_notif("success", f"IP añadida: {single_ip}")
                        flash(f"IP añadida: {single_ip}", "success")
                    else:
                        guardar_notif("success", f"{add_ok} IPs añadidas")
                        flash(f"{add_ok} IP(s) añadida(s) correctamente", "success")
                    if added_lines:
                        _set_last_action("add", added_lines)
                else:
                    if not (single_input and pre_notified):
                        flash("Nada que añadir (todas inválidas/privadas/duplicadas/no permitidas)", "danger")
                        guardar_notif("danger", "Nada que añadir (todas inválidas/privadas/duplicadas/no permitidas)")
                if add_bad > 0 and not (single_input and pre_notified):
                    flash(f"{add_bad} entradas rechazadas (inválidas/privadas/duplicadas/no permitidas)", "danger")
                    guardar_notif("danger", f"{add_bad} entradas rechazadas (manual)")

            except ValueError as e:
                if str(e) == "accion_no_permitida":
                    flash("⚠️ Acción no permitida: bloqueo de absolutamente todo", "accion_no_permitida")
                    guardar_notif("accion_no_permitida", "Intento de bloqueo global (manual)")
                else:
                    flash(str(e), "danger")
                    guardar_notif("danger", str(e))
            except Exception as e:
                flash(f"Error inesperado: {str(e)}", "danger")
                guardar_notif("danger", f"Error inesperado: {str(e)}")

            return redirect(url_for("index"))
        else:
            error = "Debes introducir una IP, red CIDR, rango A-B o IP con máscara"

    # ----- GET (vista HTML o JSON paginado) -----
    # 1) Flashes de esta petición (para TOASTS y burbuja)
    request_actions = coerce_message_pairs(get_flashed_messages(with_categories=True))

    # 2) Historial persistente añadido al final (con fecha delante)
    messages = []
    messages.extend(request_actions)
    try:
        for n in get_notifs(limit=200):
            cat = str(n.get("category", "secondary"))
            msg = f"{n.get('time','')} {n.get('message','')}".strip()
            messages.append((cat, msg))
    except Exception:
        pass

    # Totales VIVOS (manual/csv) sobre feed principal
    lines = load_lines(FEED_FILE)
    live_manual, live_csv = compute_live_counters(lines)

    # Construye map de tags para la tabla server-rendered
    meta = load_meta()
    ip_tags = {}
    try:
        active_ips = {l.split("|",1)[0] for l in lines}
        for ip, entry in (meta.get("ip_details") or {}).items():
            if ip in active_ips:
                ip_tags[ip] = entry.get("tags", [])
    except Exception:
        ip_tags = {}

    # JSON mode (paginación/ordenación/filtros)
    if request.args.get("format", "").lower() == "json":
        records = _feed_to_records(lines)
        q = request.args.get("q")
        date_param = request.args.get("date")
        sort_key = request.args.get("sort", "fecha")
        order = request.args.get("order", "desc")
        page = request.args.get("page", 1)
        page_size = request.args.get("page_size", DEFAULT_PAGE_SIZE)

        filtered = _apply_filters(records, q=q, date_param=date_param)
        ordered = _apply_sort(filtered, sort_key=sort_key, order=order)
        paged, p, ps, total = _paginate(ordered, page=page, page_size=page_size)
        meta = load_meta()
        ip_details = meta.get("ip_details", {})

        items = []
        for r in paged:
            items.append({
                "ip": r["ip"],
                "ttl": 0 if r["ttl"] is None else r["ttl"],
                "origen": r.get("origen"),
                "fecha_alta": r["fecha"] if r["fecha"] else None,
                "tags": (ip_details.get(r["ip"], {}) or {}).get("tags", [])
            })

        notices = [{"time": datetime.utcnow().isoformat()+"Z", "category": c, "message": m} for c, m in request_actions]
        return json_response_ok(
            notices=notices,
            extra={
                "items": items,
                "page": p,
                "page_size": ps,
                "total": total,
                "sort": sort_key,
                "order": order,
                "filters": {"q": q, "date": date_param},
                "counters": {
                    "total": len(lines),
                    "manual": live_manual,
                    "csv": live_csv
                }
            }
        )

    # known tags para el datalist de la UI (seguimos mostrando todo lo conocido,
    # pero en el frontal manual exigimos que sea de ALLOWED_TAGS)
    known_tags = _collect_known_tags()

    return render_template("index.html",
                           ips=lines,
                           error=error,
                           total_ips=len(lines),
                           contador_manual=live_manual,
                           contador_csv=live_csv,
                           messages=messages,
                           request_actions=request_actions,
                           ip_tags=ip_tags,
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


# ========= Rutas de backup =========
@app.route("/backup/latest.zip")
@login_required
def backup_latest_zip():
    """Descarga el ZIP más reciente; 404 si no hay."""
    if not os.path.isdir(BACKUP_DIR):
        abort(404)
    zips = [f for f in os.listdir(BACKUP_DIR) if re.fullmatch(r"\d{4}-\d{2}-\d{2}\.zip", f)]
    if not zips:
        abort(404)
    zips.sort(reverse=True)
    latest = os.path.join(BACKUP_DIR, zips[0])
    return send_file(latest, as_attachment=True, download_name=zips[0], mimetype="application/zip")


@app.route("/backup/now", methods=["POST"])
@login_required
def backup_now():
    """Fuerza un backup inmediato."""
    perform_daily_backup(keep_days=14)
    flash("Backup forzado creado", "success")
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
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}\.zip", name):
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
    manual, csvc = compute_live_counters(lines)
    return jsonify({
        "total_active": len(lines),
        "manual_active": manual,
        "csv_active": csvc
    })


@app.route("/notifications/read-all", methods=["POST"])
@login_required
def notifications_read_all():
    return json_response_ok(notices=[{"time": datetime.utcnow().isoformat()+"Z", "category": "info", "message": "Notificaciones marcadas como leídas"}])


# =========================
#  API (Blueprint) con tags
# =========================
api = Blueprint("api", __name__, url_prefix="/api")

@api.before_request
def _api_guard():
    # auth + allowlist + rate
    if not _auth_ok():
        return jsonify({"error": "Unauthorized"}), 401
    if not _allowlist_ok():
        return jsonify({"error": "Forbidden by allowlist"}), 403
    if not _rate_ok():
        return jsonify({"error": "Rate limit exceeded"}), 429

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

@api.route("/bloquear-ip", methods=["POST", "DELETE"])
def bloquear_ip_api():
    # Idempotencia para POST
    if request.method == "POST":
        idem = request.headers.get("Idempotency-Key", "").strip() or None
        cached = _idem_get(idem)
        if cached is not None:
            return jsonify(cached), 200

        try:
            payload = request.get_json(force=True, silent=False)
        except Exception:
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

                for ip_str in targets:
                    if ip_str == "0.0.0.0":
                        item_result["ips"].append({"ip": ip_str, "status": "policy_denied"})
                        continue

                    # meta details actual (si existe)
                    meta = load_meta()
                    current = meta.get("ip_details", {}).get(ip_str)

                    # Conflictos TTL si no force
                    if current and not force:
                        try:
                            cur_exp = datetime.fromisoformat(current["expires_at"].replace("Z","+00:00"))
                        except Exception:
                            cur_exp = None
                        if cur_exp and abs((cur_exp - expires_at).total_seconds()) > 1:
                            item_result["ips"].append({"ip": ip_str, "status": "conflict_ttl"})
                            continue
                        # Idempotencia semántica
                        if _already_same(current, tags or current.get("tags", []), expires_at):
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

                    # Merge en meta detalles + escrituras por tag
                    entry = _merge_meta_tags(ip_str, tags, expires_at, origin, note)
                    # Escribir una línea por tag nuevo (append-only)
                    for t in [x for x in tags if x not in set(current.get("tags", []))] if current else tags:
                        _write_tag_line(t, ip_str, _now_utc(), ttl_s, expires_at, origin, entry["tags"])

                    # Reflejar en feed BPE si corresponde
                    if want_bpe:
                        line_txt_bpe = f"{ip_str}|{fecha}|{ttl_days}"
                        _append_line_unique(FEED_FILE_BPE, line_txt_bpe)

                    item_result["ips"].append({
                        "ip": ip_str,
                        "status": "ok",
                        "tags": entry["tags"],
                        "expires_at": entry["expires_at"]
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
        return jsonify(resp), (207 if errors and processed else (400 if errors and not processed else 200))

    # DELETE: { "ip": "x.y.z.w", "tags": [...] (opcional) }
    try:
        body = request.get_json(force=True, silent=True) or {}
    except Exception:
        body = {}

    ip_txt = str(body.get("ip", "")).strip()
    if not ip_txt:
        return jsonify({"error": "Campo 'ip' requerido"}), 400
    try:
        ipaddress.ip_address(ip_txt)
    except Exception:
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
            return jsonify({"status": "deleted", "ip": ip_txt, "scope": "global"}), 200
        else:
            return jsonify({"status": "not_found", "ip": ip_txt}), 404

    if not tags:
        # borrar de todos los tags + feeds + meta
        for t in entry.get("tags", []):
            _remove_ip_from_tag_file(t, ip_txt)
        _remove_ip_from_feed(ip_txt, FEED_FILE)
        _remove_ip_from_feed(ip_txt, FEED_FILE_BPE)
        meta_del_ip(ip_txt)
        return jsonify({"status": "deleted", "ip": ip_txt, "scope": "global"}), 200
    else:
        # borrar solo tags indicados
        remaining = [t for t in entry.get("tags", []) if t not in set(tags)]
        for t in tags:
            _remove_ip_from_tag_file(t, ip_txt)

        # actualizar meta
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
            # Retiramos del principal (si ya no está Multicliente)
            _remove_ip_from_feed(ip_txt, FEED_FILE)

        if not remaining:
            # si ya no quedan tags, limpiar de ambos feeds + meta
            _remove_ip_from_feed(ip_txt, FEED_FILE)
            _remove_ip_from_feed(ip_txt, FEED_FILE_BPE)
            meta_del_ip(ip_txt)
            save_meta(meta)
            return jsonify({"status": "deleted", "ip": ip_txt, "scope": "all_tags"}), 200
        else:
            save_meta(meta)
            return jsonify({"status": "updated", "ip": ip_txt, "remaining_tags": remaining}), 200


@api.route("/estado/<ip_str>", methods=["GET"])
def estado_api(ip_str):
    try:
        ipaddress.ip_address(ip_str)
    except Exception:
        return jsonify({"error": "IP inválida"}), 400
    meta = load_meta()
    entry = meta.get("ip_details", {}).get(ip_str)
    if not entry:
        return jsonify({"status": "not_found", "ip": ip_str}), 404
    return jsonify({"status": "ok", "data": entry}), 200


@api.route("/lista/<tag>", methods=["GET"])
def lista_tag_api(tag):
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


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
