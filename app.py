from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, make_response
)
from datetime import datetime
import ipaddress
import os
import re

app = Flask(__name__)
app.secret_key = 'clave-secreta'

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
FEED_FILE = os.path.join(BASE_DIR, 'ioc-feed.txt')
LOG_FILE = os.path.join(BASE_DIR, 'ioc-log.txt')
COUNTER_MANUAL = os.path.join(BASE_DIR, 'contador_manual.txt')
COUNTER_CSV = os.path.join(BASE_DIR, 'contador_csv.txt')

MAX_EXPAND = 4096


# =========================
# Helpers
# =========================
def dotted_netmask_to_prefix(mask: str) -> int:
    return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen


def expand_input_to_ips(text: str, max_expand: int = MAX_EXPAND) -> list[str]:
    if not text:
        raise ValueError("Entrada vacía")
    raw = re.sub(r"\s+", " ", text.strip())

    # Crítico: bloqueo global
    if raw in ("0.0.0.0", "0.0.0.0/0") or raw.startswith("0.0.0.0 "):
        raise PermissionError("Acción no permitida: intento de bloqueo global (0.0.0.0/0)")

    # Rango
    if "-" in raw and "/" not in raw:
        a_txt, b_txt = [p.strip() for p in raw.split("-", 1)]
        a, b = ipaddress.ip_address(a_txt), ipaddress.ip_address(b_txt)
        if int(a) > int(b):
            raise ValueError("Rango inválido")
        total = int(b) - int(a) + 1
        if total > max_expand:
            raise ValueError(f"El rango expande a {total} IPs (> {max_expand})")
        return [str(ipaddress.ip_address(int(a) + i)) for i in range(total)]

    # CIDR
    if "/" in raw:
        net = ipaddress.ip_network(raw, strict=False)
        size = net.num_addresses if net.prefixlen >= 31 else net.num_addresses - 2
        if size > max_expand:
            raise ValueError(f"La red expande a {size} IPs (> {max_expand})")
        return [str(h) for h in net.hosts()]

    # "IP mascara"
    if " " in raw and "." in raw:
        base, mask = raw.split(" ", 1)
        ipaddress.ip_address(base)
        prefix = dotted_netmask_to_prefix(mask.strip())
        return expand_input_to_ips(f"{base}/{prefix}", max_expand=max_expand)

    # IP suelta
    ipaddress.ip_address(raw)
    return [raw]


def parse_delete_pattern(raw: str):
    s = re.sub(r"\s+", " ", raw.strip())
    if " " in s and "." in s and "/" not in s:
        base, mask = s.split(" ", 1)
        pfx = dotted_netmask_to_prefix(mask.strip())
        return ("cidr", ipaddress.ip_network(f"{base}/{pfx}", strict=False))
    if "/" in s:
        return ("cidr", ipaddress.ip_network(s, strict=False))
    if "-" in s:
        a_txt, b_txt = [p.strip() for p in s.split("-", 1)]
        a, b = ipaddress.ip_address(a_txt), ipaddress.ip_address(b_txt)
        return ("range", (a, b))
    return ("single", ipaddress.ip_address(s))


def filter_lines_delete_pattern(lines: list[str], pattern: str) -> tuple[list[str], int]:
    kind, obj = parse_delete_pattern(pattern)
    kept, removed = [], 0
    for line in lines:
        if not line.strip():
            continue
        ip_txt = line.split("|", 1)[0].strip()
        try:
            ip_obj = ipaddress.ip_address(ip_txt)
        except ValueError:
            kept.append(line)
            continue
        match = False
        if kind == "single":
            match = (ip_obj == obj)
        elif kind == "cidr":
            match = ip_obj in obj
        elif kind == "range":
            a, b = obj
            match = int(a) <= int(ip_obj) <= int(b)
        if match:
            removed += 1
        else:
            kept.append(line)
    return kept, removed


def eliminar_ips_vencidas():
    now = datetime.now()
    nuevas = []
    try:
        with open(FEED_FILE, 'r', encoding='utf-8') as f:
            for linea in f:
                partes = linea.strip().split('|')
                if len(partes) != 3:
                    continue
                ip, fecha_str, ttl_str = partes
                try:
                    fecha = datetime.strptime(fecha_str, '%Y-%m-%d')
                    ttl = int(ttl_str)
                    if ttl == 0 or (now - fecha).days < ttl:
                        nuevas.append(linea.strip())
                    else:
                        log("Eliminada vencida", ip)
                except:
                    nuevas.append(linea.strip())
        with open(FEED_FILE, 'w', encoding='utf-8') as f:
            for l in nuevas:
                f.write(l + "\n")
    except FileNotFoundError:
        pass


def incrementar_contador(ruta):
    val = 0
    if os.path.exists(ruta):
        try:
            with open(ruta) as f:
                val = int(f.read().strip())
        except:
            val = 0
    val += 1
    with open(ruta, "w") as f:
        f.write(str(val))


def leer_contador(ruta):
    if os.path.exists(ruta):
        try:
            with open(ruta) as f:
                return int(f.read().strip())
        except:
            return 0
    return 0


def load_lines():
    if not os.path.exists(FEED_FILE):
        return []
    with open(FEED_FILE, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def save_lines(lines):
    with open(FEED_FILE, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")


def log(accion, ip):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"{datetime.now()} - {accion}: {ip}\n")


def is_public_allowed(ip_str: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return not (obj.is_private or obj.is_loopback or obj.is_multicast or obj.is_link_local)


# =========================
# Rutas
# =========================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form["username"] == "admin" and request.form["password"] == "admin":
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
    lines = load_lines()
    existentes = {l.split("|", 1)[0] for l in lines}

    if request.method == "POST":
        # Eliminar todas
        if "delete-all" in request.form:
            save_lines([])
            log("Eliminadas", "todas")
            flash("Todas las IPs han sido eliminadas", "success")
            return redirect(url_for("index"))

        # Eliminar por patrón
        if "delete-net" in request.form:
            patron = request.form.get("delete_net_input", "").strip()
            try:
                updated, removed = filter_lines_delete_pattern(lines, patron)
                save_lines(updated)
                if removed:
                    flash(f"Se eliminaron {removed} IPs coincidiendo con {patron}", "success")
                    log("Eliminadas patrón", patron)
                else:
                    flash("Ninguna IP coincide con el patrón", "warning")
            except Exception as e:
                flash(str(e), "danger")
            return redirect(url_for("index"))

        # Añadir manual
        ip_text = request.form.get("ip", "").strip()
        ttl = request.form.get("ttl", "permanente")
        ttl_val = "0" if ttl == "permanente" else ttl

        if ip_text:
            try:
                nuevas = expand_input_to_ips(ip_text)
                añadidas = 0
                for ip in nuevas:
                    if not is_public_allowed(ip) or ip in existentes:
                        continue
                    lines.append(f"{ip}|{datetime.now().strftime('%Y-%m-%d')}|{ttl_val}")
                    existentes.add(ip)
                    añadidas += 1
                    log("Añadida", ip)
                    incrementar_contador(COUNTER_MANUAL)
                if añadidas:
                    save_lines(lines)
                    flash(f"{añadidas} IP(s) añadida(s)", "success")
                else:
                    flash("Nada que añadir (privadas, duplicadas o inválidas)", "danger")
            except PermissionError as pe:
                msg = str(pe)
                flash(msg, "accion_no_permitida")
                log("Acción no permitida", ip_text)
            except Exception as e:
                flash(str(e), "danger")
        else:
            flash("Debes introducir una IP o red", "danger")

    return render_template(
        "index.html",
        ips=lines,
        total_ips=len(lines),
        contador_manual=leer_contador(COUNTER_MANUAL),
        contador_csv=leer_contador(COUNTER_CSV),
        messages=list(session.get('_flashes', []))
    )


@app.route("/feed/ioc-feed.txt")
def feed():
    lines = []
    if os.path.exists(FEED_FILE):
        with open(FEED_FILE, "r", encoding="utf-8") as f:
            for line in f:
                ip = line.split("|", 1)[0].strip()
                if ip and ip != "0.0.0.0":
                    lines.append(ip)
    body = "\n".join(lines) + "\n" if lines else ""
    resp = make_response(body, 200)
    resp.headers["Content-Type"] = "text/plain"
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Content-Disposition"] = 'inline; filename="ioc-feed.txt"'
    client_ip = request.remote_addr or "-"
    log("FEED request", f"{client_ip} - {len(lines)} entradas")
    return resp


@app.errorhandler(404)
def not_found(e):
    return "Página no encontrada", 404


@app.errorhandler(500)
def server_error(e):
    return "Error interno del servidor", 500


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5050)
