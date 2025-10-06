# 🛡️ IOC Manager

**IOC Manager** es una aplicación web ligera en **Flask** para gestionar listas dinámicas de IPs maliciosas (Indicators of Compromise).  
Pensada especialmente para integrarse con **Fortinet FortiGate** mediante conectores externos, permite mantener feeds de IPs actualizados de forma simple y segura.

---

## ✨ Funcionalidades principales

- Alta de IPs manual (con validación de formato, duplicados y rangos)
- Carga masiva desde archivos `.csv` / `.txt`
- Eliminación individual, total o por patrón (CIDR, rango, IP + máscara)
- Sistema de notificaciones persistentes con historial y filtros (tipo / fecha)
- Toasts interactivos que muestran la última acción realizada
- Contador de IPs activas (manuales y CSV)
- Modo oscuro / claro con persistencia
- Logo fijo y UI optimizada para escritorio y móvil

---

## 🖼️ Interfaz

- Panel principal con IPs activas, fechas y TTL
- Botón de notificaciones con burbuja de “no leídas”
- Historial filtrable con paginación
- Buscador rápido de IPs en tabla

---

## ⚙️ Tecnologías usadas

| Componente | Versión / Descripción |
|-------------|-----------------------|
| **Python** | 3.11 |
| **Flask** | 3.x |
| **Bootstrap** | 5 |
| **Gunicorn** | Servidor WSGI en producción |
| **Systemd** | Gestión de servicio en Linux |
| **Archivos planos** | Almacenamiento ligero (`.txt`, `.json`) |
| **Docker / docker-compose** | (opcional) Despliegue alternativo |

---

## 🚀 Despliegue con Gunicorn + Systemd (recomendado)

### 1️⃣ Instalación de dependencias

```bash
sudo apt update && sudo apt install -y python3 python3-venv python3-pip gunicorn

2️⃣ Crear entorno y dependencias
cd /home/darelldeejay
git clone https://github.com/<tu_usuario>/ioc-manager.git
cd ioc-manager
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
Si no existe requirements.txt, crea uno mínimo:
Flask
gunicorn

3️⃣ Archivos y permisos
chmod +x install
echo 0 > contador_manual.txt
echo 0 > contador_csv.txt
touch ioc-feed.txt ioc-log.txt

4️⃣ Crear servicio systemd
Archivo: /etc/systemd/system/ioc-manager.service
[Unit]
Description=IOC Manager - Flask on 5000
After=network.target

[Service]
User=darelldeejay
Group=darelldeejay
WorkingDirectory=/home/darelldeejay/ioc-manager
ExecStart=/home/darelldeejay/ioc-manager/.venv/bin/gunicorn --chdir /home/darelldeejay/ioc-manager --config gunicorn_config.py app:app
Restart=always
RestartSec=3
Environment="PATH=/home/darelldeejay/ioc-manager/.venv/bin:/usr/local/bin:/usr/bin"
Environment="PYTHONUNBUFFERED=1"
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
Activar el servicio:
sudo systemctl daemon-reload
sudo systemctl enable ioc-manager.service
sudo systemctl start ioc-manager.service
sudo systemctl status ioc-manager.service --no-pager -l

5️⃣ Verificar ejecución
sudo ss -lntp | grep 5000
Deberías ver Gunicorn escuchando en el puerto 5000.
Luego abre en el navegador:

http://<IP_DEL_SERVIDOR>:5000

6️⃣ Logs y mantenimiento

Ver logs recientes:

sudo journalctl -u ioc-manager.service -n 50 --no-pager


Ver en tiempo real:

sudo journalctl -fu ioc-manager.service


Reiniciar:

sudo systemctl restart ioc-manager.service

7️⃣ (Opcional) Alias útiles
echo "alias ioc-status='sudo systemctl status ioc-manager.service --no-pager -l'" >> ~/.bashrc
echo "alias ioc-restart='sudo systemctl restart ioc-manager.service && sudo systemctl status ioc-manager.service --no-pager -l'" >> ~/.bashrc
source ~/.bashrc

🐳 Despliegue alternativo con Docker
1️⃣ Preparar entorno

Clona el repositorio y asegúrate de tener los archivos:

ioc-feed.txt
notif-log.json
ioc-meta.json
ioc-log.txt


(Si no existen, se crean automáticamente al iniciar.)

2️⃣ Construir y levantar
docker compose build
docker compose up -d
# Abre http://localhost:5050

3️⃣ Logs y ciclo de vida
docker compose logs -f
docker compose down

4️⃣ Persistencia

Los archivos de datos se montan desde el host:

Archivo	Descripción
ioc-feed.txt	Base principal (IP | fecha | TTL)
notif-log.json	Historial de notificaciones
ioc-meta.json	Meta por IP (origen manual/CSV)
ioc-log.txt	Log de acciones
🔧 Desarrollo local
make venv        # Crea entorno virtual
make dev         # Ejecuta Flask en modo desarrollo
make gunicorn    # Ejecuta con Gunicorn local

🛠️ Makefile

El proyecto incluye un Makefile con tareas rápidas:

Comando	Descripción
make venv	Crea entorno virtual
make dev	Ejecuta Flask en desarrollo
make gunicorn	Ejecuta con Gunicorn
make build	Construye imagen Docker
make up	Levanta contenedor
make down	Detiene contenedor
make logs	Muestra logs
make backup	Copia de seguridad de archivos
make restore DIR=./backup_YYYYmmdd_HHMMSS	Restaura desde backup
👤 Autor

Proyecto desarrollado por Darell Pérez (darelldeejay).
Todos los derechos reservados.
