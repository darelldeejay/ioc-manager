from flask import Flask, render_template, request, redirect, url_for, session, flash
from datetime import datetime, timedelta
import ipaddress
import os

app = Flask(__name__)
app.secret_key = 'clave-secreta'

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
FEED_FILE = os.path.join(BASE_DIR, 'ioc-feed.txt')
LOG_FILE = os.path.join(BASE_DIR, 'ioc-log.txt')

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
                    with open(LOG_FILE, 'a', encoding='utf-8') as log:
                        log.write(f"{now.strftime('%Y-%m-%d %H:%M:%S')} - Eliminada IP vencida automáticamente: {ip}\n")
                    eliminado = True
            except:
                nuevas_lineas.append(linea.strip())
        if eliminado:
            with open(FEED_FILE, 'w', encoding='utf-8') as f:
                for line in nuevas_lineas:
                    f.write(line + '\n')
    except FileNotFoundError:
        pass

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

    if request.method == "POST":
        if "delete-all" in request.form:
            save_lines([])
            log("Eliminadas", "todas las IPs")
            flash("Todas las IPs han sido eliminadas correctamente", "success")
            return redirect(url_for("index"))

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

        file = request.files.get("file")
        if file and file.filename:
            valid_ips = 0
            rejected = 0
            content = file.read().decode("utf-8").splitlines()
            for line in content:
                ip = line.strip()
                if not ip:
                    continue
                try:
                    ipaddress.ip_address(ip)
                    if ip == "0.0.0.0" or ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
                        rejected += 1
                        continue
                    if any(l.startswith(ip + "|") for l in lines):
                        rejected += 1
                        continue
                    fecha = datetime.now().strftime("%Y-%m-%d")
                    lines.append(f"{ip}|{fecha}|0")
                    log("Añadida", ip)
                    valid_ips += 1
                except ValueError:
                    rejected += 1
            save_lines(lines)
            if valid_ips:
                flash(f"{valid_ips} IPs añadidas correctamente", "success")
            if rejected:
                flash(f"{rejected} IPs rechazadas por inválidas, privadas, duplicadas o peligrosas", "danger")
            return redirect(url_for("index"))

        ip = request.form.get("ip", "").strip()
        ttl = request.form.get("ttl", "permanente")

        if not ip:
            error = "Debes introducir una IP"
        else:
            try:
                ipaddress.ip_address(ip)
                if ip == "0.0.0.0":
                    error = "IP peligrosa (0.0.0.0 no permitida)"
                elif ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
                    error = "IP privada"
                elif any(l.startswith(ip + "|") for l in lines):
                    error = "IP duplicada"
                else:
                    fecha = datetime.now().strftime("%Y-%m-%d")
                    ttl_val = "0" if ttl == "permanente" else ttl
                    lines.append(f"{ip}|{fecha}|{ttl_val}")
                    save_lines(lines)
                    log("Añadida", ip)
                    flash("IP añadida correctamente", "success")
                    return redirect(url_for("index"))
            except ValueError:
                error = "IP inválida"
            except Exception as e:
                error = f"Error inesperado al guardar la IP: {str(e)}"

    return render_template("index.html", ips=lines, error=error)

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

@app.route("/feed/ioc-feed.txt")
def feed():
    if not os.path.exists(FEED_FILE):
        return "", 200
    with open(FEED_FILE, "r", encoding="utf-8") as f:
        ips = [line.strip().split("|")[0] for line in f if line.strip()]
    return "\n".join(ips), 200

@app.errorhandler(404)
def not_found(e):
    return "Página no encontrada", 404

@app.errorhandler(500)
def server_error(e):
    return "Error interno del servidor", 500

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5050)
