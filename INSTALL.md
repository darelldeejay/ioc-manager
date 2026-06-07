# 🛡️ IOC Manager – Guía de Instalación y Configuración

Guía para desplegar IOC Manager en un servidor Linux con Gunicorn + Systemd (recomendado para producción) o con Docker.

---

## ⚙️ Requisitos previos

| Componente | Versión mínima |
|---|---|
| Python | 3.10 (recomendado 3.11) |
| pip | 22+ |
| SQLite | 3.x (incluido en Python) |
| Gunicorn | 20+ |
| Git | cualquiera |

---

## 🐧 Instalación en Linux (Gunicorn + Systemd)

### 1. Instalar dependencias del sistema

```bash
sudo apt update && sudo apt install -y python3 python3-venv python3-pip sqlite3 git
```

### 2. Clonar el proyecto

```bash
cd /opt
sudo git clone https://github.com/darelldeejay/ioc-manager.git
sudo chown -R $USER:$USER ioc-manager
cd ioc-manager
```

### 3. Crear entorno virtual e instalar dependencias

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Configurar el entorno (.env)

```bash
cp .env.example .env
nano .env
```

Variables clave a configurar:

| Variable | Descripción |
|---|---|
| `FLASK_SECRET_KEY` | Clave larga aleatoria para sesiones Flask. Generar con: `python3 -c 'import secrets; print(secrets.token_hex(32))'` |
| `FEED2_TAG` | Nombre visible del segundo feed en la UI. Cambiar por el nombre real de tu cliente (ej: `BPE`, `ClienteA`). El archivo en disco siempre es `ioc-feed-bpe.txt`. |
| `TEAMS_WEBHOOK_URL` | (Opcional) URL de webhook de Microsoft Teams para notificaciones. |
| `TOKEN_API` | (Opcional) Token legacy para la API. Recomendado usar API Keys desde el panel de admin. |

### 5. Primer arranque y creación del administrador

Al iniciar por primera vez la app detecta que no hay usuarios y redirige a `/setup`.
Puedes verificar que funciona antes de configurar systemd:

```bash
./.venv/bin/gunicorn --bind 0.0.0.0:5000 app:app
```

Abre `http://<IP>:5000` → pantalla `/setup` → crea usuario administrador → login.

Detén gunicorn con `Ctrl+C` y continúa con el servicio systemd.

### 6. Configurar servicio Systemd

Crea el archivo del servicio:

```bash
sudo nano /etc/systemd/system/ioc-manager.service
```

Contenido (ajusta `tu_usuario` y las rutas si instalaste en otro directorio):

```ini
[Unit]
Description=IOC Manager Service
After=network.target

[Service]
User=tu_usuario
Group=tu_usuario
WorkingDirectory=/opt/ioc-manager
Environment="PATH=/opt/ioc-manager/.venv/bin"
ExecStart=/opt/ioc-manager/.venv/bin/gunicorn --config gunicorn_config.py app:app
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Activar el servicio:

```bash
sudo systemctl daemon-reload
sudo systemctl enable ioc-manager.service
sudo systemctl start ioc-manager.service
sudo systemctl status ioc-manager.service --no-pager -l
```

### 7. Verificar que está corriendo

```bash
sudo ss -lntp | grep 5000
```

Accede en el navegador: `http://<IP_SERVIDOR>:5000`

---

## 🔧 Gestión del servicio

```bash
# Ver logs en tiempo real
sudo journalctl -fu ioc-manager.service

# Reiniciar
sudo systemctl restart ioc-manager.service

# Ver últimos logs
sudo journalctl -u ioc-manager.service -n 50 --no-pager
```

---

## 🐳 Instalación con Docker (alternativa)

```bash
git clone https://github.com/darelldeejay/ioc-manager.git
cd ioc-manager
cp .env.example .env   # Editar variables
docker compose up -d --build
```

La aplicación quedará disponible en el puerto definido en `docker-compose.yml` (por defecto 5050).

```bash
docker compose logs -f   # Ver logs
docker compose down      # Detener
```

---

## 🔬 Tests

```bash
source .venv/bin/activate
pytest tests/              # Suite completa
pytest tests/test_api.py -v   # Solo API
```

---

## 💾 Backups y Restauración

- Los backups automáticos diarios se guardan en `backups/` (ZIP, rotación 14 días).
- Los backups manuales se generan desde el panel de admin (rotación últimos 5).
- Para restaurar: sube el ZIP desde el panel Admin → Backups → Restaurar.

---

## 👤 Autor

Proyecto desarrollado por **Darell Pérez**.
Licencia: MIT
