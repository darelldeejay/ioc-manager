# 🛡️ IOC Manager – Guía de Instalación

**IOC Manager** es una aplicación web ligera en **Flask** para gestionar listas dinámicas de IPs maliciosas (Indicators of Compromise).  
Pensada para integrarse con **Fortinet FortiGate** mediante conectores externos, permite mantener feeds de IPs actualizados de forma simple y segura.

---

## ⚙️ Tecnologías principales

| Componente | Descripción |
|-------------|-------------|
| **Python 3.11** | Lenguaje principal |
| **Flask 3.x** | Framework web |
| **Bootstrap 5** | Interfaz y diseño |
| **Gunicorn** | Servidor WSGI para producción |
| **Systemd** | Gestión de servicio en Linux |
| **Archivos planos** | Almacenamiento ligero (`.txt`, `.json`) |

---

## 🚀 Instalación con Gunicorn + Systemd (Recomendada)

### 1️⃣ Instalar dependencias del sistema

```bash
sudo apt update && sudo apt install -y python3 python3-venv python3-pip gunicorn
sudo apt install git
```

---

### 2️⃣ Clonar el proyecto y crear entorno virtual

```bash
cd /home/admin
git clone https://github.com/darelldeejay/ioc-manager.git
cd ioc-manager
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

> 💡 Si no existe `requirements.txt`, crea uno mínimo con:
> ```
> Flask
> gunicorn
> ```

---

### 3️⃣ Crear archivos iniciales y permisos

```bash
chmod +x install
echo 0 > contador_manual.txt
echo 0 > contador_csv.txt
touch ioc-feed.txt ioc-log.txt
```

---

### 4️⃣ Crear servicio systemd

Crea el archivo `/etc/systemd/system/ioc-manager.service` con el siguiente contenido:

```ini
[Unit]
Description=IOC Manager - Flask on 5000
After=network.target

[Service]
User=admin
Group=admin
WorkingDirectory=/home/admin/ioc-manager
ExecStart=/home/admin/ioc-manager/.venv/bin/gunicorn --chdir /home/admin/ioc-manager --config gunicorn_config.py app:app
Restart=always
RestartSec=3
Environment="PATH=/home/admin/ioc-manager/.venv/bin:/usr/local/bin:/usr/bin"
Environment="PYTHONUNBUFFERED=1"
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

---

### 5️⃣ Activar el servicio

```bash
sudo systemctl daemon-reload
sudo systemctl enable ioc-manager.service
sudo systemctl start ioc-manager.service
sudo systemctl status ioc-manager.service --no-pager -l
```

---

### 6️⃣ Verificar que Gunicorn está corriendo

```bash
sudo ss -lntp | grep 5000
```

Deberías ver algo como:

```
LISTEN 0 128 0.0.0.0:5000 ... gunicorn
```

Ahora accede a la aplicación desde tu navegador:
```
http://<IP_DEL_SERVIDOR>:5000
```

---

### 7️⃣ Logs y mantenimiento

Ver últimos logs:
```bash
sudo journalctl -u ioc-manager.service -n 50 --no-pager
```

Ver en tiempo real:
```bash
sudo journalctl -fu ioc-manager.service
```

Reiniciar el servicio:
```bash
sudo systemctl restart ioc-manager.service
```

---

### 8️⃣ Alias útiles (opcional)

Para administración rápida:
```bash
echo "alias ioc-status='sudo systemctl status ioc-manager.service --no-pager -l'" >> ~/.bashrc
echo "alias ioc-restart='sudo systemctl restart ioc-manager.service && sudo systemctl status ioc-manager.service --no-pager -l'" >> ~/.bashrc
source ~/.bashrc
```

---

## 🐳 Instalación alternativa con Docker

### 1️⃣ Preparar entorno

Clona el repo y asegúrate de tener los archivos:

```
ioc-feed.txt
notif-log.json
ioc-meta.json
ioc-log.txt
```

(Si no existen, se crean automáticamente al iniciar.)

---

### 2️⃣ Construir y levantar contenedor

```bash
docker compose build
docker compose up -d
# Accede a http://localhost:5050
```

---

### 3️⃣ Logs y mantenimiento

```bash
docker compose logs -f
docker compose down
```

---

### 4️⃣ Persistencia

| Archivo | Descripción |
|----------|--------------|
| `ioc-feed.txt` | Base principal (IP \| fecha \| TTL) |
| `notif-log.json` | Historial de notificaciones |
| `ioc-meta.json` | Meta por IP (origen manual/CSV) |
| `ioc-log.txt` | Log de acciones |

---

## 🔧 Modo desarrollo

```bash
make venv        # Crea entorno virtual
make dev         # Ejecuta Flask en modo desarrollo
make gunicorn    # Ejecuta con Gunicorn local
```

---

## 🛠️ Makefile

Tareas disponibles:

| Comando | Descripción |
|----------|-------------|
| `make venv` | Crea entorno virtual |
| `make dev` | Ejecuta Flask en desarrollo |
| `make gunicorn` | Ejecuta con Gunicorn |
| `make build` | Construye imagen Docker |
| `make up` | Levanta contenedor |
| `make down` | Detiene contenedor |
| `make logs` | Muestra logs |
| `make backup` | Copia de seguridad de archivos |
| `make restore DIR=./backup_YYYYmmdd_HHMMSS` | Restaura desde backup |

---

## 👤 Autor

Proyecto desarrollado por **Darell Pérez**.  
Todos los derechos reservados.
