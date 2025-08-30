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
NOTIF_FILE = os.path.join(BASE_DIR, 'notif-log.json')
COUNTER_MANUAL = os.path.join(BASE_DIR, 'contador_manual.txt')
COUNTER_CSV = os.path.join(BASE_DIR, 'contador_csv.txt')

MAX_EXPAND = 4096


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

    if raw == "0.0.0.0":
        raise ValueError("accion_no_permitida")
    if "/" in raw and raw.strip().startswith("0.0.0.0"):
        raise ValueError("accion_no_permitida")
    if " " in raw and raw.split(" ", 1)[0].strip() == "0.0.0.0":
        raise ValueError("accion_no_permitida")

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

    if "/" in raw:
        net = ipaddress.ip_network(raw, strict=False)
        size = net.num_addresses if net.prefixlen >= 31 else max(net.num_addresses - 2, 0)
        if size > max_expand:
            raise ValueError("La red expande demasiado")
        return [str(h) for h in net.hosts()]

    if " " in raw and "." in raw:
        base, mask = raw.split(" ", 1)
        prefix = dotted_netmask_to_prefix(mask.strip())
        return expand_input_to_ips(f"{base}/{prefix}", max_expand)

    ipaddress.ip_address(raw)
    return [raw]


# =========================
#  Delete pattern
# =========================
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
        a = ipaddress.ip_address(a_txt)
        b = ipaddress.ip_address(b_txt)
        if int(a) > int(b):
            a, b = b, a
        return ("range", (a, b))

    return ("single", ipaddress.ip_address(s))


def filter_lines_delete_pattern(lines: list[str], pattern: str):
    kind, obj = parse_delete_pattern(pattern)
    kept, removed = [], 0
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
        else:
            kept.append(line)

    return kept, removed


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
    try:
        with open(FEED_FILE, "r", encoding="utf-8") as f:
            for linea in f:
                ip, fecha_str, ttl_str = linea.strip().split("|")
                fecha = datetime.strptime(fecha_str, "%Y-%m-%d")
                ttl = int(ttl_str)
                if ttl == 0 or (now - fecha).days < ttl:
                    nuevas.append(linea.strip())
        with open(FEED_FILE, "w", encoding="utf-8") as f:
            for l in nuevas:
                f.write(l + "\n")
    except FileNotFoundError:
        pass


def load_lines():
    if not os.path.exists(FEED_FILE):
        return []
    return [l.strip() for l in open(FEED_FILE, encoding="utf-8") if l.strip()]


def save_lines(lines):
    with open(FEED_FILE, "w", encoding="utf-8") as f:
        for l in lines:
            f.write(l + "\n")


def log(accion, ip):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"{datetime.now()} - {accion}: {ip}\n")


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

    if request.method == "POST":
        if "delete-all" in request.form:
            save_lines([])
            log("Eliminadas", "todas las IPs")
            guardar_notif("warning", "Se eliminaron todas las IPs")
            flash("Todas las IPs eliminadas", "success")
            return redirect(url_for("index"))

        if "delete_ip" in request.form:
            ip_to_delete = request.form.get("delete_ip")
            new_lines = [l for l in lines if not l.startswith(ip_to_delete + "|")]
            save_lines(new_lines)
            flash(f"IP {ip_to_delete} eliminada", "success")
            guardar_notif("warning", f"IP eliminada: {ip_to_delete}")
            return redirect(url_for("index"))

        if "delete-net" in request.form:
            patron = request.form.get("delete_net_input", "").strip()
            try:
                new_lines, removed = filter_lines_delete_pattern(lines, patron)
                save_lines(new_lines)
                flash(f"Se eliminaron {removed} IP(s) coincidentes con {patron}", "success")
                guardar_notif("warning", f"Eliminadas por patrón {patron}: {removed}")
            except Exception as e:
                flash(str(e), "danger")
            return redirect(url_for("index"))

    return render_template("index.html",
                           ips=lines,
                           error=error,
                           total_ips=len(lines),
                           contador_manual=0,
                           contador_csv=0,
                           messages=list(session.get('_flashes', [])))


@app.route("/feed/ioc-feed.txt")
def feed():
    ips = []
    if os.path.exists(FEED_FILE):
        for line in open(FEED_FILE, encoding="utf-8"):
            ip = line.split("|")[0]
            if ip and is_allowed_ip(ip):
                ips.append(ip)
    resp = make_response("\n".join(ips) + "\n", 200)
    resp.headers["Content-Type"] = "text/plain"
    return resp


# =========================
#  Main
# =========================
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5050)
