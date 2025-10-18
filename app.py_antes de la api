from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, make_response, jsonify, get_flashed_messages,
    send_file, abort
)
from datetime import datetime, timedelta
import ipaddress
import os
import re
import json
from functools import wraps

app = Flask(__name__)
app.secret_key = 'clave-secreta'

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
FEED_FILE = os.path.join(BASE_DIR, 'ioc-feed.txt')
LOG_FILE = os.path.join(BASE_DIR, 'ioc-log.txt')
NOTIF_FILE = os.path.join(BASE_DIR, 'notif-log.json')

# Counters históricos (compat), los totales vivos se calculan con meta
COUNTER_MANUAL = os.path.join(BASE_DIR, 'contador_manual.txt')
COUNTER_CSV = os.path.join(BASE_DIR, 'contador_csv.txt')

# Nuevo: meta lateral para origen por IP (no afecta al feed)
META_FILE = os.path.join(BASE_DIR, 'ioc-meta.json')

# === Copias de seguridad ===
BACKUP_DIR = os.path.join(BASE_DIR, "backups")
LAST_BACKUP_MARK = os.path.join(BACKUP_DIR, ".last_done")

MAX_EXPAND = 4096

# === Config de servidor (paginación/undo) ===
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200
UNDO_TTL_SECONDS = 600  # 10 minutos


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


# -------- Meta lateral (origen por IP) --------
def load_meta():
    if not os.path.exists(META_FILE):
        return {"by_ip": {}}
    try:
        with open(META_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if not isinstance(data, dict) or "by_ip" not in data or not isinstance(data["by_ip"], dict):
                return {"by_ip": {}}
            return {"by_ip": dict(data["by_ip"])}
    except Exception:
        return {"by_ip": {}}


def save_meta(meta):
    try:
        with open(META_FILE, "w", encoding="utf-8") as f:
            json.dump(meta, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def meta_set_origin(ip_str, origin):
    meta = load_meta()
    meta["by_ip"][ip_str] = origin  # 'manual' | 'csv'
    save_meta(meta)


def meta_del_ip(ip_str):
    meta = load_meta()
    if ip_str in meta["by_ip"]:
        del meta["by_ip"][ip_str]
        save_meta(meta)


def meta_bulk_del(ips):
    if not ips:
        return
    meta = load_meta()
    changed = False
    for ip in ips:
        if ip in meta["by_ip"]:
            del meta["by_ip"][ip]
            changed = True
    if changed:
        save_meta(meta)


def compute_live_counters(active_lines):
    meta = load_meta()["by_ip"]
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
        return ips

    # CIDR
    if "/" in raw:
        net = ipaddress.ip_network(raw, strict=False)
        size = net.num_addresses if net.prefixlen >= 31 else max(net.num_addresses - 2, 0)
        if size > max_expand:
            raise ValueError("La red expande demasiado")
        return [str(h) for h in net.hosts()]

    # IP + máscara punteada
    if " " in raw and "." in raw:
        base, mask = raw.split(" ", 1)
        prefix = dotted_netmask_to_prefix(mask.strip())
        return expand_input_to_ips("{}/{}".format(base, prefix), max_expand)

    # IP suelta
    ipaddress.ip_address(raw)
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
#  Helpers almacenamiento
# =========================
def eliminar_ips_vencidas():
    now = datetime.now()
    nuevas = []
    vencidas = []
    try:
        with open(FEED_FILE, "r", encoding="utf-8") as f:
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
        with open(FEED_FILE, "w", encoding="utf-8") as f:
            for l in nuevas:
                f.write(l + "\n")
    except FileNotFoundError:
        pass
    return vencidas


def load_lines():
    if not os.path.exists(FEED_FILE):
        return []
    with open(FEED_FILE, encoding="utf-8") as f:
        return [l.strip() for l in f if l.strip()]


def save_lines(lines):
    with open(FEED_FILE, "w", encoding="utf-8") as f:
        for l in lines:
            f.write(l + "\n")


def log(accion, ip):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"{datetime.now()} - {accion}: {ip}\n")


# =========================
#  Alta de IPs (helper)
# =========================
def add_ips_validated(lines, existentes, iterable_ips, ttl_val, origin=None, contador_ruta=None):
    añadidas = 0
    rechazadas = 0
    added_lines = []  # para UNDO
    for ip_str in iterable_ips:
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

        if ip_str in existentes:
            rechazadas += 1
            continue

        fecha = datetime.now().strftime("%Y-%m-%d")
        line_txt = f"{ip_str}|{fecha}|{ttl_val}"
        lines.append(line_txt)
        existentes.add(ip_str)
        log("Añadida", ip_str)
        guardar_notif("success", f"IP añadida: {ip_str}")

        if origin in ("manual", "csv"):
            meta_set_origin(ip_str, origin)

        if contador_ruta:
            try:
                val = read_counter(contador_ruta)
                write_counter(contador_ruta, val + 1)
            except Exception:
                pass

        añadidas += 1
        added_lines.append(line_txt)
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
def _ensure_dir(p):
    os.makedirs(p, exist_ok=True)

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
      - backups/YYYY-MM-DD/ con copias de FEED_FILE, META_FILE (si existe), NOTIF_FILE (si existe)
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
    meta = load_meta()["by_ip"]
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
            "origen": meta.get(ip_txt)
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
        "payload": {"items": payload_items},  # para add: líneas completas; para delete: líneas completas eliminadas
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

    # Expirar y sincronizar meta
    vencidas = eliminar_ips_vencidas()
    if vencidas:
        meta_bulk_del(vencidas)

    error = None
    lines = load_lines()
    existentes = {l.split("|", 1)[0] for l in lines}

    # ----- Mutaciones (POST) -----
    if request.method == "POST":
        # Eliminar todas
        if "delete-all" in request.form:
            all_lines = list(lines)  # guardar para UNDO
            all_ips = [l.split("|", 1)[0].strip() for l in lines]
            save_lines([])
            meta_bulk_del(all_ips)
            log("Eliminadas", "todas las IPs")
            guardar_notif("warning", "Se eliminaron todas las IPs")
            flash("Se eliminaron todas las IPs", "warning")
            # registrar UNDO
            _set_last_action("delete_all", all_lines)
            return redirect(url_for("index"))

        # Eliminar individual
        if "delete_ip" in request.form:
            ip_to_delete = request.form.get("delete_ip")
            # capturar línea original para UNDO
            orig_line = next((l for l in lines if l.startswith(ip_to_delete + "|")), None)
            new_lines = [l for l in lines if not l.startswith(ip_to_delete + "|")]
            save_lines(new_lines)
            meta_del_ip(ip_to_delete)
            guardar_notif("warning", f"IP eliminada: {ip_to_delete}")
            flash(f"IP eliminada: {ip_to_delete}", "warning")
            if orig_line:
                _set_last_action("delete", [orig_line])
            return redirect(url_for("index"))

        # Eliminar por patrón
        if "delete-net" in request.form:
            patron = request.form.get("delete_net_input", "").strip()
            try:
                new_lines, removed, removed_ips, removed_lines = filter_lines_delete_pattern(lines, patron)
                save_lines(new_lines)
                if removed_ips:
                    meta_bulk_del(removed_ips)
                guardar_notif("warning", f"Eliminadas por patrón {patron}: {removed}")
                flash(f"Eliminadas por patrón {patron}: {removed}", "warning")
                if removed_lines:
                    _set_last_action("delete_bulk", removed_lines)
            except Exception as e:
                flash(str(e), "danger")
            return redirect(url_for("index"))

        # Subida CSV/TXT
        file = request.files.get("file")
        if file and file.filename:
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
                    lines, existentes, expanded, ttl_val="0",
                    origin="csv", contador_ruta=COUNTER_CSV
                )
                valid_ips_total += add_ok
                rejected_total += add_bad
                added_lines_acc.extend(added_lines)

            save_lines(lines)
            if valid_ips_total:
                guardar_notif("success", f"{valid_ips_total} IPs añadidas (CSV)")
                flash(f"{valid_ips_total} IP(s) añadida(s) correctamente (CSV)", "success")
                # UNDO para todas las líneas añadidas en esta subida
                if added_lines_acc:
                    _set_last_action("add", added_lines_acc)
            if rejected_total:
                guardar_notif("danger", f"{rejected_total} entradas rechazadas (CSV)")
                flash(f"{rejected_total} entradas rechazadas (inválidas/privadas/duplicadas/no permitidas)", "danger")
            return redirect(url_for("index"))

        # Alta manual
        raw_input = request.form.get("ip", "").strip()
        ttl_sel = request.form.get("ttl", "permanente")
        ttl_val = "0" if ttl_sel == "permanente" else ttl_sel

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
                    origin="manual", contador_ruta=COUNTER_MANUAL
                )
                if add_ok > 0:
                    save_lines(lines)
                    if single_input:
                        guardar_notif("success", f"IP añadida: {single_ip}")
                        flash(f"IP añadida: {single_ip}", "success")
                    else:
                        guardar_notif("success", f"{add_ok} IPs añadidas")
                        flash(f"{add_ok} IP(s) añadida(s) correctamente", "success")
                    # UNDO
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

    # Totales VIVOS (manual/csv)
    lines = load_lines()
    live_manual, live_csv = compute_live_counters(lines)

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

        items = []
        for r in paged:
            items.append({
                "ip": r["ip"],
                "ttl": 0 if r["ttl"] is None else r["ttl"],
                "origen": r.get("origen"),
                "fecha_alta": r["fecha"] if r["fecha"] else None
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

    return render_template("index.html",
                           ips=lines,
                           error=error,
                           total_ips=len(lines),
                           contador_manual=live_manual,
                           contador_csv=live_csv,
                           messages=messages,
                           request_actions=request_actions)


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


@app.route("/preview-delete")
@login_required
def preview_delete():
    pattern = request.args.get("pattern", "").strip()
    if not pattern:
        return jsonify({"error": "Patrón vacío"}), 400
    try:
        lines = load_lines()
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
        return jsonify({"status": "ok", "time": datetime.utcnow().isoformat()+"Z"})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


@app.route("/metrics")
@login_required
def metrics():
    lines = load_lines()
    manual, csvc = compute_live_counters(lines)
    return jsonify({
        "total_active": len(lines),
        "manual_active": manual,
        "csv_active": csvc
    })


@app.route("/notifications/read-all", methods=["POST"])
@login_required
def notifications_read_all():
    # Si en el futuro guardamos 'read' server-side, aquí lo marcaríamos.
    # De momento, devolvemos OK para que el front pueda limpiar el badge local.
    return json_response_ok(notices=[{"time": datetime.utcnow().isoformat()+"Z", "category": "info", "message": "Notificaciones marcadas como leídas"}])


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5050)
