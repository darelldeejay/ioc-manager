from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response
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

# ====== EXPANSIÓN DE ENTRADAS (IP, CIDR, RANGO, IP+MÁSCARA) ======
MAX_EXPAND = 4096  # límite de IPs a generar por operación

def dotted_netmask_to_prefix(mask: str) -> int:
    """Convierte máscara punteada a prefijo (/n)."""
    return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen

def expand_input_to_ips(text: str, max_expand: int = MAX_EXPAND) -> list[str]:
    """
    Acepta:
      - IP: '203.0.113.5'
      - CIDR: '203.0.113.0/24' (IPv4 o IPv6)
      - Rango: '203.0.113.10-203.0.113.50'
      - IP + máscara punteada: '203.0.113.0 255.255.255.0'
    Devuelve lista de IPs (strings). Lanza ValueError si inválido o expansión excesiva.
    """
    if not text:
        raise ValueError("Entrada vacía")

    raw = re.sub(r"\s+", " ", text.strip())

    if raw == "0.0.0.0":
        raise ValueError("La IP 0.0.0.0 no está permitida.")

    # Rango A-B
    if "-" in raw and "/" not in raw:
        left, right = [p.strip() for p in raw.split("-", 1)]
        try:
            a = ipaddress.ip_address(left)
            b = ipaddress.ip_address(right)
        except ValueError:
            raise ValueError("Rango inválido. Use formato A-B con IPs válidas.")

        if type(a) is not type(b):
            raise ValueError("El rango mezcla IPv4 e IPv6.")
        if int(a) > int(b):
            raise ValueError("Rango inválido: inicio mayor que fin.")

        total = int(b) - int(a) + 1
        if total > max_expand:
            raise ValueError(f"El rango expande a {total} IPs (> {max_expand}).")

        ips = [str(ipaddress.ip_address(int(a) + i)) for i in range(total)]
        if "0.0.0.0" in ips:
            raise ValueError("El rango incluye 0.0.0.0, no permitido.")
        return ips

    # CIDR
    if "/" in raw:
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            raise ValueError("CIDR inválido. Ejemplo: 203.0.113.0/24")

        # Número aproximado de hosts a expandir
        if isinstance(net, ipaddress.IPv4Network):
            if net.prefixlen >= 31:
                size = net.num_addresses  # /31 o /32
            else:
                size = net.num_addresses - 2  # excluye red/broadcast
        else:
            # IPv6: .hosts() devuelve todos los hosts del rango (muchísimo). Protegemos por tamaño.
            size = min(net.num_addresses, max_expand + 1)

        if size > max_expand:
            raise ValueError(f"La red expande a {size} IPs (> {max_expand}). Use un prefijo más específico.")
        return [str(h) for h in net.hosts()]

    # "IP mascara"
    if " " in raw and "." in raw:
        base, mask = raw.split(" ", 1)
        ipaddress.ip_address(base)  # valida base
        prefix = dotted_netmask_to_prefix(mask.strip())
        return expand_input_to_ips(f"{base}/{prefix}", max_expand=max_expand)

    # IP suelta
    ipaddress.ip_address(raw)  # valida
    if raw == "0.0.0.0":
        raise ValueError("La IP 0.0.0.0 no está permitida.")
    return [raw]

# ====== UTILIDADES DE ARCHIVO / CONTADORES ======
def eliminar_ips_vencidas():
    now = datetime.now()
    nuevas_lineas = []
    eliminado = False
    try:
        with open(FEED_FILE, 'r', encoding='utf-8') as f:
            lineas = f.readlines()
        for linea in lineas:
            partes = linea.strip().split('|')
            if len(partes) != 3:
                continue
            ip, fecha_str, ttl_str = partes
            try:
                fecha_alta = datetime.strptime(fecha_str, '%Y-%m-%d')
                ttl_dias = int(ttl_str)
                dias_pasados = (now - fecha_alta).days
                if ttl_dias == 0 or dias_pasados < ttl_dias:
                    nuevas_lineas.append(linea.strip())
                else:
                    with open(LOG_FILE, 'a', encoding='utf-8') as logf:
                        logf.write(f"{now.strftime('%Y-%m-%d %H:%M:%S')} - Eliminada IP vencida automáticamente: {ip}\n")
                    eliminado = True
            except:
                nuevas_lineas.append(linea.strip())
        if eliminado:
            with open(FEED_FILE, 'w', encoding='utf-8') as f:
                for line in nuevas_lineas:
                    f.write(line + '\n')
    except FileNotFoundError:
        pass

def incrementar_contador(ruta):
    valor = 0
    if os.path.exists(ruta):
        with open(ruta, 'r') as f:
            try:
                valor = int(f.read().strip())
            except:
                valor = 0
    valor += 1
    with open(ruta, 'w') as f:
        f.write(str(valor))

def leer_contador(ruta):
    if os.path.exists(ruta):
        with open(ruta, 'r') as f:
            try:
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
    os.makedirs(os.path.dirname(FEED_FILE), exist_ok=True)
    with open(FEED_FILE, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")

def log(accion, ip):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"{datetime.now()} - {accion}: {ip}\n")

# ====== VALIDACIONES ======
def is_public_allowed(ip_str: str) -> bool:
    """Descarta 0.0.0.0 y redes privadas/loopback/link-local/multicast."""
    try:
        obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if ip_str == "0.0.0.0":
        return False
    return not (obj.is_private or obj.is_loopback or obj.is_link_local or obj.is_multicast)

# ================== RUTAS ==================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if username == "admin" and password == "admin":
            session["username"] = username
            return redirect(url_for("index"))
        else:
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
    total_ips = len(lines)

    # Conjunto de IPs ya existentes para evitar duplicados
    existentes = {l.split("|", 1)[0] for l in lines}

    if request.method == "POST":
        # Eliminar todas
        if "delete-all" in request.form:
            save_lines([])
            log("Eliminadas", "todas las IPs")
            flash("Todas las IPs han sido eliminadas correctamente", "success")
            return redirect(url_for("index"))

        # Eliminar una
        if "delete_ip" in request.form:
            ip_to_delete = request.form.get("delete_ip")
            updated_lines = [l for l in lines if not l.startswith(ip_to_delete + "|")]
            if len(updated_lines) < len(lines):
                save_lines(updated_lines)
                log("Eliminada", ip_to_delete)
                flash(f"IP {ip_to_delete} eliminada correctamente", "success")
            else:
                flash("IP no encontrada", "danger")
            return redirect(url_for("index"))

        # Subida CSV / TXT
        file = request.files.get("file")
        if file and file.filename:
            valid_ips = 0
            rejected = 0
            content = file.read().decode("utf-8", errors="ignore").splitlines()
            for raw in content:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    # Expansión flexible (IP, CIDR, rango, IP+máscara)
                    for ip_str in expand_input_to_ips(raw):
                        if not is_public_allowed(ip_str):
                            rejected += 1
                            continue
                        if ip_str in existentes:
                            rejected += 1
                            continue
                        fecha = datetime.now().strftime("%Y-%m-%d")
                        lines.append(f"{ip_str}|{fecha}|0")   # CSV: TTL permanente por defecto
                        existentes.add(ip_str)
                        log("Añadida", ip_str)
                        valid_ips += 1
                        incrementar_contador(COUNTER_CSV)
                except ValueError:
                    rejected += 1

            save_lines(lines)
            total_ips = len(lines)
            if valid_ips:
                flash(f"{valid_ips} IPs añadidas correctamente. Total actual: {total_ips}", "success")
            if rejected:
                flash(f"{rejected} entradas rechazadas (inválidas/privadas/duplicadas/no permitidas)", "danger")
            return redirect(url_for("index"))

        # Alta manual (campo 'ip' puede ser IP/CIDR/rango/IP+máscara)
        raw_input = request.form.get("ip", "").strip()
        ttl_sel = request.form.get("ttl", "permanente")
        ttl_val = "0" if ttl_sel == "permanente" else ttl_sel

        if not raw_input:
            error = "Debes introducir una IP, una red CIDR o un rango A-B"
        else:
            try:
                nuevas = expand_input_to_ips(raw_input)
                añadidas = 0
                for ip_str in nuevas:
                    if not is_public_allowed(ip_str):
                        continue
                    if ip_str in existentes:
                        continue
                    fecha = datetime.now().strftime("%Y-%m-%d")
                    lines.append(f"{ip_str}|{fecha}|{ttl_val}")
                    existentes.add(ip_str)
                    log("Añadida", ip_str)
                    incrementar_contador(COUNTER_MANUAL)
                    añadidas += 1
                if añadidas == 0:
                    error = "Nada que añadir (todas inválidas/privadas/duplicadas/no permitidas)"
                else:
                    save_lines(lines)
                    flash(f"{añadidas} IP(s) añadida(s) correctamente", "success")
                    return redirect(url_for("index"))
            except ValueError as e:
                error = str(e)
            except Exception as e:
                error = f"Error inesperado al guardar: {str(e)}"

    contador_manual = leer_contador(COUNTER_MANUAL)
    contador_csv = leer_contador(COUNTER_CSV)

    return render_template(
        "index.html",
        ips=lines,
        error=error,
        total_ips=total_ips,
        contador_manual=contador_manual,
        contador_csv=contador_csv,
        messages=list(session.get('_flashes', []))
    )

# ====== FEED: text/plain + no-cache + logging de acceso ======
@app.route("/feed/ioc-feed.txt", methods=["GET"])
def feed():
    """
    Feed plano para el firewall:
      - 1 IP/CIDR por línea (solo 1ª columna antes del '|')
      - Content-Type: text/plain (sin charset duplicado)
      - Cabeceras no-cache
      - Log: IP cliente + nº de entradas servidas
    """
    lines = []
    if os.path.exists(FEED_FILE):
        with open(FEED_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                ip = line.split("|", 1)[0].strip()
                if ip and ip != "0.0.0.0":
                    lines.append(ip)

    body = "\n".join(lines)
    if body and not body.endswith("\n"):
        body += "\n"

    resp = make_response(body, 200)
    resp.headers["Content-Type"] = "text/plain"
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Content-Disposition"] = 'inline; filename="ioc-feed.txt"'

    # Logging de acceso al feed
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "-")
    client_ip = client_ip.split(",")[0].strip()
    served = len(lines)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"{ts} - FEED requested by {client_ip} - served {served} entries\n")

    return resp

@app.errorhandler(404)
def not_found(e):
    return "Página no encontrada", 404

@app.errorhandler(500)
def server_error(e):
    return "Error interno del servidor", 500

if __name__ == "__main__":
    # En producción arrancas con gunicorn; este puerto es para debug local.
    app.run(debug=True, host="0.0.0.0", port=5050)
