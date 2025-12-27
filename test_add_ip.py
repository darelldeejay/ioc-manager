
import requests
import os

BASE_URL = "http://127.0.0.1:5000"
LOGIN_URL = f"{BASE_URL}/login"
INDEX_URL = f"{BASE_URL}/"

# Credenciales por defecto (admin/admin)
CREDENTIALS = {'username': 'admin', 'password': 'admin'}

session = requests.Session()

# 1. Login
print("Iniciando sesión...")
try:
    r = session.post(LOGIN_URL, data=CREDENTIALS)
    if "Dashboard" not in r.text and r.history and r.history[0].status_code != 302:
        # A veces el login redirige. Verify login success looking for known string or cookie
        if 'session' not in session.cookies:
            print("❌ Falló el login (no session cookie)")
            exit(1)
    print("✅ Login OK (o no error obvio).")
except Exception as e:
    print(f"❌ Error conectando: {e}")
    exit(1)

# 2. Add IP Manual
# IP de prueba única con timestamp para evitar duplicados en tests repetidos
import time
test_ip = f"11.22.33.{int(time.time()) % 255}"
print(f"Intentando añadir IP: {test_ip} ...")

payload = {
    "ip": test_ip,
    "tags_manual": "Multicliente", # Tag obligatorio
    "ttl_manual": "permanente"
}

r = session.post(INDEX_URL, data=payload)

# 3. Verificar respuesta
if r.status_code == 200:
    print("✅ POST request exitoso (200 OK).")
else:
    print(f"❌ POST request falló: {r.status_code}")

# 4. Verificar archivo
try:
    with open('ioc-feed.txt', 'r', encoding='utf-8') as f:
        content = f.read()
        if test_ip in content:
            print(f"✅ ÉXITO: La IP {test_ip} se encontró en ioc-feed.txt")
        else:
            print(f"❌ FALLO: La IP {test_ip} NO está en ioc-feed.txt")
except Exception as e:
    print(f"❌ Error leyendo archivo: {e}")

