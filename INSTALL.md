# 🛡️ IOC Manager – Guía de Instalación y Configuración

**IOC Manager** es una aplicación web ligera en **Flask** diseñada para gestionar listas dinámicas de IPs maliciosas (Indicators of Compromise).
Permite integrarse con **Fortinet FortiGate** (y otros sistemas) mediante conectores externos y APIs, manteniendo feeds actualizados de forma simple y segura.

---

## ⚙️ Tecnologías y Requisitos

| Componente | Descripción |
|-------------|-------------|
| **Python 3.10+** | Lenguaje principal (Recomendado 3.11) |
| **Flask 3.x** | Framework web |
| **SQLite 3** | Base de datos principal (Persistencia avanzada) |
| **Gunicorn** | Servidor WSGI para producción (Linux) |
| **Bootstrap 5** | Interfaz de usuario responsive |

---

## 🚀 Instalación en Linux (Producción)

### 1️⃣ Instalar dependencias del sistema

```bash
sudo apt update && sudo apt install -y python3 python3-venv python3-pip gunicorn sqlite3
```

### 2️⃣ Clonar el proyecto y crear entorno virtual

```bash
cd /opt
sudo git clone https://github.com/darelldeejay/ioc-manager.git
sudo chown -R $USER:$USER ioc-manager
cd ioc-manager

# Crear entorno virtual
python3 -m venv .venv
source .venv/bin/activate

# Instalar librerías
pip install --upgrade pip
pip install -r requirements.txt
```

### 3️⃣ Configuración del Entorno (.env)

El proyecto utiliza un archivo `.env` para la configuración sensible. Copia el ejemplo y edítalo:

```bash
cp .env.example .env
nano .env
```

Variables clave a configurar en `.env`:
*   `FLASK_SECRET_KEY`: Una cadena larga y aleatoria para seguridad de sesiones.
*   `ADMIN_USER` / `ADMIN_PASSWORD`: Credenciales iniciales (aunque se recomienda usar el flujo de `/setup` en el primer arranque).
*   `TEAMS_WEBHOOK_URL`: (Opcional) URL para notificaciones a Microsoft Teams.

### 4️⃣ Inicialización (Primer Arranque)

La aplicación inicializará automáticamente la base de datos `ioc_manager.db` en el primer inicio.
Puedes verificar que todo funcione ejecutando manualmente antes de crear el servicio:

```bash
# Prueba manual
./.venv/bin/gunicorn --bind 0.0.0.0:5000 app:app
```
Accede a `http://<IP_SERVIDOR>:5000`. Deberías ver la pantalla de Login o Setup.

### 5️⃣ Configurar Servicio Systemd (Persistencia)

Para que la aplicación arranque automáticamente, **debes crear manualmente** el archivo de configuración del servicio.

Ejecuta el siguiente comando para crear y abrir el archivo en el editor:

```bash
sudo nano /etc/systemd/system/ioc-manager.service
```

**Contenido del archivo (`ioc-manager.service`):**

> ⚠️ **IMPORTANTE:** Debes cambiar `tu_usuario` por el usuario real de tu sistema (ej: `ubuntu`, `debian`, o tu nombre de usuario).
> Verifica también que la ruta `WorkingDirectory` coincida con donde clonaste el repo.

```ini
[Unit]
Description=IOC Manager Service
After=network.target

[Service]
# 1. USUARIO: Cambia 'tu_usuario' por el usuario Linux que ejecutará la app
User=tu_usuario
Group=tu_usuario

# 2. RUTAS: Si instalaste en /opt/ioc-manager, deja esto así.
# Si instalaste en /home/tu_usuario/ioc-manager, ajusta estas dos líneas:
WorkingDirectory=/opt/ioc-manager
Environment="PATH=/opt/ioc-manager/.venv/bin"

# 3. EJECUCIÓN: Comando de arranque
ExecStart=/opt/ioc-manager/.venv/bin/gunicorn --workers 3 --bind 0.0.0.0:5000 app:app

# Reinicio automático en caso de fallo
Restart=always

[Install]
WantedBy=multi-user.target
```

**Activar servicio:**

```bash
sudo systemctl daemon-reload
sudo systemctl enable ioc-manager
sudo systemctl start ioc-manager
sudo systemctl status ioc-manager
```

---

## 🔧 Gestión y Mantenimiento

### Ver Logs
```bash
sudo journalctl -u ioc-manager -f
```

### Copias de Seguridad
La aplicación realiza snapshots automáticos de la base de datos en la carpeta `backups/`.
Para restaurar, simplemente detén el servicio y reemplaza `ioc_manager.db` con una copia válida.

### Tests y Diagnóstico de Salud
El sistema incluye un botón de "Salud" (Diagnóstico) en la interfaz. También puedes ejecutar los tests manualmente desde consola:

```bash
source .venv/bin/activate
# Ejecutar suite completa
python run_tests.py
# O con pytest verboles
pytest -v
```

---

## � Docker (Instalación Alternativa)

```bash
# Construir y levantar
docker compose up -d --build
```
La aplicación estará disponible en el puerto definido en `docker-compose.yml` (por defecto 5050).

---

## 👤 Autor

Proyecto desarrollado por **Darell Pérez (darelldeejay)**.
