from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, make_response, jsonify, get_flashed_messages
)
from datetime import datetime
import ipaddress
import os
import re
import json

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

MAX_EXPAND = 4096


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
        else:
            kept.append(line)

    return kept, removed, removed_ips


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
        lines.append(f"{ip_str}|{fecha}|{ttl_val}")
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
    return añadidas, rechazadas


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
#  Rutas
# =========================
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
def index():
    if "username" not in session:
        return redirect(url_for("login"))

    # Expirar y sincronizar meta
    vencidas = eliminar_ips_vencidas()
    if vencidas:
        meta_bulk_del(vencidas)

    error = None
    lines = load_lines()
    existentes = {l.split("|", 1)[0] for l in lines}

    if request.method == "POST":
        # Eliminar todas
        if "delete-all" in request.form:
            all_ips = [l.split("|", 1)[0].strip() for l in lines]
            save_lines([])
            meta_bulk_del(all_ips)
            log("Eliminadas", "todas las IPs")
            guardar_notif("warning", "Se eliminaron todas las IPs")
            flash("Se eliminaron todas las IPs", "warning")
            return redirect(url_for("index"))

        # Eliminar individual
        if "delete_ip" in request.form:
            ip_to_delete = request.form.get("delete_ip")
            new_lines = [l for l in lines if not l.startswith(ip_to_delete + "|")]
            save_lines(new_lines)
            meta_del_ip(ip_to_delete)
            guardar_notif("warning", f"IP eliminada: {ip_to_delete}")
            flash(f"IP eliminada: {ip_to_delete}", "warning")
            return redirect(url_for("index"))

        # Eliminar por patrón
        if "delete-net" in request.form:
            patron = request.form.get("delete_net_input", "").strip()
            try:
                new_lines, removed, removed_ips = filter_lines_delete_pattern(lines, patron)
                save_lines(new_lines)
                if removed_ips:
                    meta_bulk_del(removed_ips)
                guardar_notif("warning", f"Eliminadas por patrón {patron}: {removed}")
                flash(f"Eliminadas por patrón {patron}: {removed}", "warning")
            except Exception as e:
                flash(str(e), "danger")
            return redirect(url_for("index"))

        # Subida CSV/TXT
        file = request.files.get("file")
        if file and file.filename:
            valid_ips_total = 0
            rejected_total = 0
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

                add_ok, add_bad = add_ips_validated(
                    lines, existentes, expanded, ttl_val="0",
                    origin="csv", contador_ruta=COUNTER_CSV
                )
                valid_ips_total += add_ok
                rejected_total += add_bad

            save_lines(lines)
            if valid_ips_total:
                guardar_notif("success", f"{valid_ips_total} IPs añadidas (CSV)")
                flash(f"{valid_ips_total} IP(s) añadida(s) correctamente (CSV)", "success")
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

                add_ok, add_bad = add_ips_validated(
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

    # ========= Datos para la plantilla =========
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
def preview_delete():
    pattern = request.args.get("pattern", "").strip()
    if not pattern:
        return jsonify({"error": "Patrón vacío"}), 400
    try:
        lines = load_lines()
        _, removed, _removed_ips = filter_lines_delete_pattern(lines, pattern)
        return jsonify({"count": removed})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5050)
