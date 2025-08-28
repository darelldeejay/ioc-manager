from flask import Flask, render\_template, request, redirect, url\_for, session, flash
from datetime import datetime, timedelta
import ipaddress
import os

app = Flask(**name**)
app.secret\_key = 'clave-secreta'

BASE\_DIR = os.path.dirname(os.path.realpath(**file**))
FEED\_FILE = os.path.join(BASE\_DIR, 'ioc-feed.txt')
LOG\_FILE = os.path.join(BASE\_DIR, 'ioc-log.txt')
COUNTER\_MANUAL = os.path.join(BASE\_DIR, 'contador\_manual.txt')
COUNTER\_CSV = os.path.join(BASE\_DIR, 'contador\_csv.txt')

def eliminar\_ips\_vencidas():
now = datetime.now()
nuevas\_lineas = \[]
eliminado = False
try:
with open(FEED\_FILE, 'r', encoding='utf-8') as f:
lineas = f.readlines()
for linea in lineas:
partes = linea.strip().split('|')
if len(partes) != 3:
continue
ip, fecha\_str, ttl\_str = partes
try:
fecha\_alta = datetime.strptime(fecha\_str, '%Y-%m-%d')
ttl\_dias = int(ttl\_str)
dias\_pasados = (now - fecha\_alta).days
if ttl\_dias == 0 or dias\_pasados < ttl\_dias:
nuevas\_lineas.append(linea.strip())
else:
with open(LOG\_FILE, 'a', encoding='utf-8') as log:
log.write(f"{now\.strftime('%Y-%m-%d %H:%M:%S')} - Eliminada IP vencida automáticamente: {ip}\n")
eliminado = True
except:
nuevas\_lineas.append(linea.strip())
if eliminado:
with open(FEED\_FILE, 'w', encoding='utf-8') as f:
for line in nuevas\_lineas:
f.write(line + '\n')
except FileNotFoundError:
pass

def incrementar\_contador(ruta):
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

def leer\_contador(ruta):
if os.path.exists(ruta):
with open(ruta, 'r') as f:
try:
return int(f.read().strip())
except:
return 0
return 0

@app.route("/login", methods=\["GET", "POST"])
def login():
if request.method == "POST":
username = request.form\["username"]
password = request.form\["password"]
if username == "admin" and password == "admin":
session\["username"] = username
return redirect(url\_for("index"))
else:
flash("Credenciales incorrectas", "danger")
return render\_template("login.html")

@app.route("/logout")
def logout():
session.clear()
return redirect(url\_for("login"))

@app.route("/", methods=\["GET", "POST"])
def index():
if "username" not in session:
return redirect(url\_for("login"))

```
eliminar_ips_vencidas()

error = None
lines = load_lines()
total_ips = len(lines)

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
                incrementar_contador(COUNTER_CSV)
            except ValueError:
                rejected += 1
        save_lines(lines)
        total_ips = len(lines)
        if valid_ips:
            flash(f"{valid_ips} IPs añadidas correctamente. Total actual: {total_ips}", "success")
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
                incrementar_contador(COUNTER_MANUAL)
                flash("IP añadida correctamente", "success")
                return redirect(url_for("index"))
        except ValueError:
            error = "IP inválida"
        except Exception as e:
            error = f"Error inesperado al guardar la IP: {str(e)}"

contador_manual = leer_contador(COUNTER_MANUAL)
contador_csv = leer_contador(COUNTER_CSV)

return render_template("index.html", ips=lines, error=error, total_ips=total_ips, contador_manual=contador_manual, contador_csv=contador_csv, messages=list(session.get('_flashes', [])))
```

def load\_lines():
if not os.path.exists(FEED\_FILE):
return \[]
with open(FEED\_FILE, "r", encoding="utf-8") as f:
return \[line.strip() for line in f if line.strip()]

def save\_lines(lines):
os.makedirs(os.path.dirname(FEED\_FILE), exist\_ok=True)
with open(FEED\_FILE, "w", encoding="utf-8") as f:
for line in lines:
f.write(line + "\n")

def log(accion, ip):
with open(LOG\_FILE, "a", encoding="utf-8") as f:
f.write(f"{datetime.now()} - {accion}: {ip}\n")

@app.route("/feed/ioc-feed.txt")
def feed():
if not os.path.exists(FEED\_FILE):
return "", 200
with open(FEED\_FILE, "r", encoding="utf-8") as f:
ips = \[line.strip().split("|")\[0] for line in f if line.strip()]
return "\n".join(ips), 200

@app.errorhandler(404)
def not\_found(e):
return "Página no encontrada", 404

@app.errorhandler(500)
def server\_error(e):
return "Error interno del servidor", 500

if **name** == "**main**":
app.run(debug=True, host="0.0.0.0", port=5050)
