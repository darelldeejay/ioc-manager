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
#  Helpers: notificaciones
# =========================
def add_notification(category: str, message: str):
    flash(message, category)
    historial = []
    if os.path.exists(NOTIF_FILE):
        try:
            with open(NOTIF_FILE, "r", encoding="utf-8") as f:
                historial = json.load(f)
        except Exception:
            historial = []
    historial.append({
        "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "category": category,
        "message": message
    })
    historial = historial[-500:]
    with open(NOTIF_FILE, "w", encoding="utf-8") as f:
        json.dump(historial, f, ensure_ascii=False, indent=2)


def load_notifications():
    if os.path.exists(NOTIF_FILE):
        try:
            with open(NOTIF_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            return [(n["category"], n["message"]) for n in data]
        except Exception:
            return []
    return []


# =========================
#  Helpers: contadores
# =========================
def incrementar_contador(ruta):
    valor = 0
    if os.path.exists(ruta):
        try:
            with open(ruta, 'r') as f:
                valor = int(f.read().strip() or 0)
        except Exception:
            valor = 0
    valor += 1
    with open(ruta, 'w') as f:
        f.write(str(valor))


def leer_contador(ruta):
    if os.path.exists(ruta):
        try:
            with open(ruta, 'r') as f:
                return int(f.read().strip() or 0)
        except Exception:
            return 0
    return 0


# =========================
#  Helpers: IP expansion y borrado
# =========================
def dotted_netmask_to_prefix(mask: str) -> int:
    return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen


def expand_input_to_ips(text: str, max_expand: int = MAX_EXPAND) -> list[str]:
    if not text:
        raise ValueError("Entrada vacía")
    raw = re.sub(r"\s+", " ", text.strip())
    if raw in ("0.0.0.0", "0.0.0.0/0", "0.0.0.0 0.0.0.0"):
        raise ValueError("accion_no_permitida")
    if "-" in raw and "/" not in raw:
        left, right = [p.strip() for p in raw.split("-", 1)]
        a, b = ipaddress.ip_address(left), ipaddress.ip_address(right)
        if type(a) is not type(b):
            raise ValueError("El rango mezcla IPv4 e IPv6.")
        if int(a) > int(b):
            raise ValueError("Rango inválido.")
        total = int(b) - int(a) + 1
        if total > max_expand:
            raise ValueError(f"El rango expande a {total} IPs (> {max_expand}).")
        return [str(ipaddress.ip_address(int(a) + i)) for i in range(total)]
    if "/" in raw:
        net = ipaddress.ip_network(raw, strict=False)
        if net.prefixlen == 0:
            raise ValueError("accion_no_permitida")
        return [str(h) for h in net.hosts()]
    if " " in raw and "." in raw:
        base, mask = raw.split(" ", 1)
        prefix = dotted_netmask_to_prefix(mask.strip())
        return expand_input_to_ips(f"{base}/{prefix}", max_expand=max_expand)
    ipaddress.ip_address(raw)
    if raw == "0.0.0.0":
        raise ValueError("accion_no_permitida")
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
        return ("range", (ipaddress.ip_address(a_txt), ipaddress.ip_address(b_txt)))
    return ("single", ipaddress.ip_address(s))


def filter_lines_delete_pattern(lines: list[str], pattern: str) -> tuple[list[str], int]:
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


# =========================
#  Helpers: almacenamiento
# =========================
def eliminar_ips_vencidas():
    now = datetime.now()
    nuevas, eliminado = [], False
    if not os.path.exists(FEED_FILE):
        return
    with open(FEED_FILE, "r", encoding="utf-8") as f:
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
                    eliminado = True
            except:
                nuevas.append(linea.strip())
    if eliminado:
        with open(FEED_FILE, "w", encoding="utf-8") as f:
            for l in nuevas:
                f.write(l + "\n")


def load_lines():
    if not os.path.exists(FEED_FILE):
        return []
    with open(FEED_FILE, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


def save_lines(lines):
    with open(FEED_FILE, "w", encoding="utf-8") as f:
        for l in lines:
            f.write(l + "\n")


# =========================
#  Rutas
# =========================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form["username"] == "admin" and request.form["password"] == "admin":
            session["username"] = "admin"
            return redirect(url_for("index"))
        else:
            add_notification("danger", "Credenciales incorrectas")
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
        # eliminar todas
        if "delete-all" in request.form:
            save_lines([])
            add_notification("danger", "Todas las IPs eliminadas")
            return redirect(url_for("index"))

        # eliminar individual
        if "delete_ip" in request.form:
            ip_to_delete = request.form.get("delete_ip")
            updated = [l for l in lines if not l.startswith(ip_to_delete + "|")]
            save_lines(updated)
            add_notification("success", f"IP {ip_to_delete} eliminada")
            return redirect(url_for("index"))

        # eliminar por patrón
        if "delete-net" in request.form:
            patron = request.form.get("delete_net_input", "").strip()
            try:
                updated, removed = filter_lines_delete_pattern(lines, patron)
                save_lines(updated)
                add_notification("danger", f"Eliminadas {removed} entradas con patrón {patron}")
            except Exception as e:
                add_notification("danger", str(e))
            return redirect(url_for("index"))

        # subida CSV
        file = request.files.get("file")
        if file and file.filename:
            valid, rejected = 0, 0
            content = file.read().decode("utf-8", errors="ignore").splitlines()
            for raw in content:
                try:
                    for ip_str in expand_input_to_ips(raw):
                        if ip_str in existentes:
                            rejected += 1
                            continue
                        fecha = datetime.now().strftime("%Y-%m-%d")
                        lines.append(f"{ip_str}|{fecha}|0")
                        existentes.add(ip_str)
                        valid += 1
                        incrementar_contador(COUNTER_CSV)
                except ValueError as e:
                    if str(e) == "accion_no_permitida":
                        add_notification("accion_no_permitida", f"Acción no permitida: bloqueo global ({raw})")
                    else:
                        rejected += 1
            save_lines(lines)
            if valid:
                add_notification("success", f"{valid} IPs añadidas desde archivo")
            if rejected:
                add_notification("danger", f"{rejected} entradas rechazadas (inválidas/duplicadas)")
            return redirect(url_for("index"))

        # alta manual
        raw_input = request.form.get("ip", "").strip()
        ttl_sel = request.form.get("ttl", "permanente")
        ttl_val = "0" if ttl_sel == "permanente" else ttl_sel
        if raw_input:
            try:
                nuevas = expand_input_to_ips(raw_input)
                añadidas = 0
                for ip_str in nuevas:
                    if ip_str in existentes:
                        continue
                    fecha = datetime.now().strftime("%Y-%m-%d")
                    lines.append(f"{ip_str}|{fecha}|{ttl_val}")
                    existentes.add(ip_str)
                    añadidas += 1
                    incrementar_contador(COUNTER_MANUAL)
                if añadidas:
                    save_lines(lines)
                    add_notification("success", f"{añadidas} IP(s) añadida(s) manualmente")
                else:
                    add_notification("danger", "Nada que añadir (duplicadas o inválidas)")
            except ValueError as e:
                if str(e) == "accion_no_permitida":
                    add_notification("accion_no_permitida", f"Acción no permitida: bloqueo global ({raw_input})")
                else:
                    add_notification("danger", str(e))
            return redirect(url_for("index"))

    total_ips = len(lines)
    contador_manual = leer_contador(COUNTER_MANUAL)
    contador_csv = leer_contador(COUNTER_CSV)
    return render_template("index.html",
                           ips=lines,
                           total_ips=total_ips,
                           contador_manual=contador_manual,
                           contador_csv=contador_csv,
                           messages=load_notifications())


@app.route("/feed/ioc-feed.txt")
def feed():
    lines = []
    if os.path.exists(FEED_FILE):
        with open(FEED_FILE, "r", encoding="utf-8") as f:
            lines = [line.split("|", 1)[0] for line in f if line.strip()]
    resp = make_response("\n".join(lines) + "\n", 200)
    resp.headers["Content-Type"] = "text/plain"
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    return resp


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5050)
