from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, make_response
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
NOTIF_FILE = os.path.join(BASE_DIR, 'notif-log.json')  # si no existe, se ignora
COUNTER_MANUAL = os.path.join(BASE_DIR, 'contador_manual.txt')
COUNTER_CSV = os.path.join(BASE_DIR, 'contador_csv.txt')

MAX_EXPAND = 4096  # límite anti-explosión


# =========================
#  Utilidades de red
# =========================
def dotted_netmask_to_prefix(mask):
    return ipaddress.IPv4Network("0.0.0.0/{0}".format(mask)).prefixlen


def is_allowed_ip(ip_str):
    """Solo IPv4 públicas; bloquea privadas, loopback, link-local, multicast, reservadas y 0.0.0.0."""
    try:
        obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    if isinstance(obj, ipaddress.IPv6Address):
        return False
    if obj.is_unspecified:   # 0.0.0.0
        return False
    if obj.is_private or obj.is_loopback or obj.is_link_local or obj.is_multicast or obj.is_reserved:
        return False
    return True


def expand_input_to_ips(text, max_expand=MAX_EXPAND):
    """
    Convierte entrada (IP, CIDR, rango A-B, IP+máscara) en lista de IPs.
    **ÚNICO cambio solicitado**:
      - 0.0.0.0 o cualquier red basada en 0.0.0.0 => ValueError("accion_no_permitida")
    El resto se mantiene igual.
    """
    if not text:
        raise ValueError("Entrada vacía")

    raw = re.sub(r"\s+", " ", text.strip())

    # --- Bloqueo global: 0.0.0.0 y variantes ---
    if raw == "0.0.0.0":
        raise ValueError("accion_no_permitida")
    if "/" in raw and raw.strip().startswith("0.0.0.0"):
        raise ValueError("accion_no_permitida")
    if " " in raw and raw.split(" ", 1)[0].strip() == "0.0.0.0":
        raise ValueError("accion_no_permitida")
    # --------------------------------------------

    # Rango A-B
    if "-" in raw and "/" not in raw:
        parts = raw.split("-", 1)
        left = parts[0].strip()
        right = parts[1].strip()
        try:
            a = ipaddress.ip_address(left)
            b = ipaddress.ip_address(right)
        except ValueError:
            raise ValueError("Rango inválido (IPs no válidas)")

        if isinstance(a, ipaddress.IPv6Address) or isinstance(b, ipaddress.IPv6Address):
            raise ValueError("IPv6 no soportado")
        if int(a) > int(b):
            raise ValueError("Rango inválido (inicio > fin)")

        total = int(b) - int(a) + 1
        if total > max_expand:
            raise ValueError("Rango expande a {0} IPs (> {1})".format(total, max_expand))

        ips = [str(ipaddress.IPv4Address(int(a) + i)) for i in range(total)]
        if "0.0.0.0" in ips:
            raise ValueError("accion_no_permitida")
        return ips

    # CIDR
    if "/" in raw:
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            raise ValueError("CIDR inválido. Ej: 203.0.113.0/24")

        size = net.num_addresses if net.prefixlen >= 31 else max(net.num_addresses - 2, 0)
        if size > max_expand:
            raise ValueError("La red expande a {0} IPs (> {1}). Use un prefijo más específico.".format(size, max_expand))

        return [str(h) for h in net.hosts()]

    # IP + máscara punteada
    if " " in raw and "." in raw:
        base, mask = raw.split(" ", 1)
        base = base.strip()
        try:
            ipaddress.ip_address(base)
            prefix = dotted_netmask_to_prefix(mask.strip())
        except ValueError:
            raise ValueError("Máscara o IP inválida. Ej: 203.0.113.0 255.255.255.0")
        return expand_input_to_ips("{0}/{1}".format(base, prefix), max_expand=max_expand)

    # IP simple
    try:
        obj = ipaddress.ip_address(raw)
    except ValueError:
        raise ValueError("IP inválida")

    if isinstance(obj, ipaddress.IPv6Address):
        raise ValueError("IPv6 no soportado")

    return [raw]


# =========================
#  Notificaciones (sin cambios funcionales)
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
            data = json.load(f)
            return data[-limit:]
    except Exception:
        return []


# =========================
#  Helpers almacenamiento y contadores
# =========================
def eliminar_ips_vencidas():
    now = datetime.now()
    nuevas_lineas = []
    eliminado = False
    try:
        with open(FEED_FILE, 'r', encoding='utf-8') as f:
            for linea in f:
                partes = linea.strip().split('|')
                if len(partes) != 3:
                    continue
                ip, fecha_str, ttl_str = partes
                try:
                    fecha_alta = datetime.strptime(fecha_str, '%Y-%m-%d')
                    ttl_dias = int(ttl_str)
                    if ttl_dias == 0 or (now - fecha_alta).days < ttl_dias:
                        nuevas_lineas.append(linea.strip())
                    else:
                        with open(LOG_FILE, 'a', encoding='utf-8') as logf:
                            logf.write("{0} - Eliminada IP vencida: {1}\n".format(now, ip))
                        eliminado = True
                except Exception:
                    nuevas_lineas.append(linea.strip())
        if eliminado:
            with open(FEED_FILE, 'w', encoding='utf-8') as f:
                f.write("\n".join(nuevas_lineas) + "\n")
    except FileNotFoundError:
        pass


def incrementar_contador(ruta):
    valor = 0
    if os.path.exists(ruta):
        with open(ruta) as f:
            try:
                valor = int(f.read().strip())
            except Exception:
                valor = 0
    valor += 1
    with open(ruta, 'w') as f:
        f.write(str(valor))


def leer_contador(ruta):
    if os.path.exists(ruta):
        with open(ruta) as f:
            try:
                return int(f.read().strip())
            except Exception:
                return 0
    return 0


def load_lines():
    if not os.path.exists(FEED_FILE):
        return []
    with open(FEED_FILE, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def save_lines(lines):
    with open(FEED_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def log(accion, ip):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write("{0} - {1}: {2}\n".format(datetime.now(), accion, ip))


# =========================
#  Core (sin cambios)
# =========================
def add_ips_validated(lines, existentes, iterable_ips, ttl_val, contador_ruta=None):
    añadidas = 0
    rechazadas = 0
    for ip_str in iterable_ips:
        if not is_allowed_ip(ip_str):
            rechazadas += 1
            continue
        if ip_str in existentes:
            rechazadas += 1
            continue
        fecha = datetime.now().strftime("%Y-%m-%d")
        lines.append("{0}|{1}|{2}".format(ip_str, fecha, ttl_val))
        existentes.add(ip_str)
        log("Añadida", ip_str)
        guardar_notif("success", "IP añadida: {0}".format(ip_str))
        if contador_ruta:
            incrementar_contador(contador_ruta)
        añadidas += 1
    return añadidas, rechazadas


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

    eliminar_ips_vencidas()

    error = None
    lines = load_lines()
    existentes = set([l.split("|", 1)[0] for l in lines])

    if request.method == "POST":
        # Eliminar todas
        if "delete-all" in request.form:
            save_lines([])
            log("Eliminadas", "todas las IPs")
            guardar_notif("warning", "Se eliminaron todas las IPs")
            flash("Todas las IPs han sido eliminadas correctamente", "success")
            return redirect(url_for("index"))

        # Eliminar individual
        if "delete_ip" in request.form:
            ip_to_delete = request.form.get("delete_ip")
            updated_lines = [l for l in lines if not l.startswith(ip_to_delete + "|")]
            if len(updated_lines) < len(lines):
                save_lines(updated_lines)
                log("Eliminada", ip_to_delete)
                guardar_notif("warning", "IP eliminada: {0}".format(ip_to_delete))
                flash("IP {0} eliminada correctamente".format(ip_to_delete), "success")
            else:
                flash("IP no encontrada", "danger")
                guardar_notif("danger", "No se encontró IP: {0}".format(ip_to_delete))
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
                    lines, existentes, expanded, ttl_val="0", contador_ruta=COUNTER_CSV
                )
                valid_ips_total += add_ok
                rejected_total += add_bad

            save_lines(lines)
            if valid_ips_total:
                flash("{0} IPs añadidas correctamente (CSV).".format(valid_ips_total), "success")
                guardar_notif("success", "{0} IPs añadidas (CSV)".format(valid_ips_total))
            if rejected_total:
                flash("{0} entradas rechazadas (inválidas/privadas/duplicadas/no permitidas)".format(rejected_total), "danger")
                guardar_notif("danger", "{0} entradas rechazadas (CSV)".format(rejected_total))
            return redirect(url_for("index"))

        # Alta manual
        raw_input = request.form.get("ip", "").strip()
        ttl_sel = request.form.get("ttl", "permanente")
        ttl_val = "0" if ttl_sel == "permanente" else ttl_sel

        if not raw_input:
            error = "Debes introducir una IP, red CIDR, rango A-B o IP con máscara"
        else:
            try:
                expanded = expand_input_to_ips(raw_input)

                # ---- NUEVO: popup exacto para entrada manual de UNA sola IP rechazada
                single_input = len(expanded) == 1
                single_ip = expanded[0] if single_input else None
                pre_notified = False
                if single_input:
                    if single_ip in existentes:
                        flash("IP duplicada: {0}".format(single_ip), "danger")
                        guardar_notif("danger", "IP duplicada: {0}".format(single_ip))
                        pre_notified = True
                    elif not is_allowed_ip(single_ip):
                        flash("IP no permitida (privada/reservada/loopback/link-local/multicast): {0}".format(single_ip), "danger")
                        guardar_notif("danger", "IP no permitida: {0}".format(single_ip))
                        pre_notified = True
                # -----------------------------------------------

                add_ok, add_bad = add_ips_validated(
                    lines, existentes, expanded, ttl_val=ttl_val, contador_ruta=COUNTER_MANUAL
                )
                if add_ok > 0:
                    save_lines(lines)
                    flash("{0} IP(s) añadida(s) correctamente".format(add_ok), "success")
                else:
                    # si ya mostramos mensaje específico para la única IP, no repitas el genérico
                    if single_input and pre_notified:
                        pass
                    else:
                        error = "Nada que añadir (todas inválidas/privadas/duplicadas/no permitidas)"
                if add_bad > 0:
                    if not (single_input and pre_notified):
                        flash("{0} entradas rechazadas (inválidas/privadas/duplicadas/no permitidas)".format(add_bad), "danger")

            except ValueError as e:
                if str(e) == "accion_no_permitida":
                    flash("⚠️ Acción no permitida: bloqueo de absolutamente todo", "accion_no_permitida")
                    guardar_notif("accion_no_permitida", "Intento de bloqueo global (manual)")
                else:
                    error = str(e)
                    guardar_notif("danger", "Error alta manual: {0}".format(error))
            except Exception as e:
                error = "Error inesperado: {0}".format(str(e))
                guardar_notif("danger", error)

    # ---- construir messages de forma segura
    messages_safe = []
    try:
        notifs = get_notifs()
        for n in notifs:
            cat = n.get("category", "secondary")
            msg = "{0} {1}".format(n.get("time", ""), n.get("message", "")).strip()
            messages_safe.append((cat, msg))
    except Exception:
        messages_safe = []

    return render_template(
        "index.html",
        ips=lines,
        error=error,
        total_ips=len(lines),
        contador_manual=leer_contador(COUNTER_MANUAL),
        contador_csv=leer_contador(COUNTER_CSV),
        messages=messages_safe
    )


# =========================
#  Feed (sin cambios de comportamiento)
# =========================
@app.route("/feed/ioc-feed.txt")
def feed():
    ips = []
    if os.path.exists(FEED_FILE):
        with open(FEED_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                ip = line.split("|", 1)[0].strip()
                if ip and is_allowed_ip(ip):
                    ips.append(ip)

    body = "\n".join(ips) + "\n"
    resp = make_response(body, 200)
    resp.headers["Content-Type"] = "text/plain"
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Content-Disposition"] = 'inline; filename="ioc-feed.txt"'

    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "-").split(",")[0].strip()
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write("{0} - FEED requested by {1} - served {2} entries\n".format(datetime.now(), client_ip, len(ips)))
    return resp


# =========================
#  Errores
# =========================
@app.errorhandler(404)
def not_found(e):
    return "Página no encontrada", 404


@app.errorhandler(500)
def server_error(e):
    return "Error interno del servidor", 500


# =========================
#  Main
# =========================
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5050)
