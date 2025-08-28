# 🛡️ IOC Manager – Gestión de IPs maliciosas para FortiGate (Flask + Raspberry Pi)

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/)
[![Estado](https://img.shields.io/badge/Estado-En%20uso%20activo-brightgreen.svg)](#)
[![Autor](https://img.shields.io/badge/Creado%20por-Darell%20Perez-blueviolet.svg)](#)

---

## 🌐 Descripción

**IOC Manager** es una herramienta ligera basada en Flask para crear y gestionar un *Threat Feed* de IPs maliciosas compatible con FortiGate y otros firewalls. Diseñado para entornos de seguridad, permite añadir IPs con TTL, integrarse con SOAR como Torq, y correr perfectamente en una Raspberry Pi.

---

## 🚀 Características principales

- ✅ Gestión visual de IPs maliciosas
- ✅ Tiempo de vida (TTL) por IP
- ✅ Eliminación automática de IPs vencidas
- ✅ Validación de IPs privadas, duplicadas y 0.0.0.0
- ✅ Subida de IPs por CSV
- ✅ Feed accesible desde `/feed/ioc-feed.txt`
- ✅ Registro completo en `ioc-log.txt`
- ✅ Login básico (`admin/admin`)
- ✅ Interfaz limpia con modo oscuro persistente
- ✅ Contador de IPs añadidas manualmente y por CSV
- ✅ Plantilla CSV descargable desde la web
- ✅ Buscador interactivo de IPs en tiempo real
- ✅ Scripts de actualización automática (con y sin venv)
- ✅ Preparado para integraciones vía API (ej. Torq)

---

## 📦 Instalación rápida (Raspberry Pi o Linux)

```bash
git clone https://github.com/darelldeejay/ioc-manager.git
cd ioc-manager
sudo apt update && sudo apt install python3 python3-pip -y
pip3 install flask gunicorn
chmod +x install
./install
Accede desde tu navegador:

cpp
Copiar código
http://<IP_RASPBERRY>:5000
🔍 Funciones destacadas en la interfaz
Añadir IPs manualmente con selector TTL

Subida masiva mediante archivo .csv o .txt

Plantilla CSV de ejemplo descargable

Buscador de IPs para filtrar resultados rápidamente

Resumen numérico de IPs activas, manuales y por CSV

Modo oscuro persistente

Eliminación individual o total de IPs

🔗 Integración con FortiGate
Ir a Security Fabric > External Connectors

Tipo: Threat Feed (IP Address)

URL del feed:

arduino
Copiar código
http://<IP_RASPBERRY>:5000/feed/ioc-feed.txt
Validar y asociar a políticas

📁 Estructura del proyecto
graphql
Copiar código
ioc-manager/
├── app.py                        # Lógica principal Flask
├── install                       # Arranque del servidor
├── actualizar_codigo.sh          # Actualizador con entorno virtual
├── actualizar_codigo_sin_venv.sh# Actualizador sin entorno virtual
├── gunicorn_config.py            # Configuración WSGI
├── templates/
│   ├── index.html                # Interfaz principal (IPs, filtros, buscador)
│   └── login.html                # Pantalla de acceso
├── static/
│   └── plantilla.csv             # Plantilla descargable
├── ioc-feed.txt                  # IPs activas (generado automáticamente)
├── ioc-log.txt                   # Log de acciones
├── contador_manual.txt           # Contador IPs manuales
├── contador_csv.txt              # Contador IPs por CSV
└── README.md
📄 Ejemplo de plantilla CSV
Descargable desde la web o manualmente:

text
Copiar código
88.84.86.244
2.136.15.111
🔄 Actualización segura (recomendado)
Para mantener la instalación actualizada sin perder datos:

bash
Copiar código
chmod +x actualizar_codigo_sin_venv.sh
./actualizar_codigo_sin_venv.sh
Este script:

Respalda tus archivos de IPs y contadores

Ejecuta git pull con validación

Restaura los datos

Relanza Gunicorn automáticamente

También existe actualizar_codigo.sh si usas entorno virtual (venv).

⚠️ Seguridad actual
Login visual (admin/admin)

Validación estricta de IPs (no privadas, no 0.0.0.0)

Feed accesible en texto plano compatible con Firewalls

Modo oscuro persistente en localStorage

Código probado y optimizado para Raspberry Pi

🔒 Próximas mejoras:

Gestión de usuarios con roles (admin, analyst)

Hash de contraseñas (bcrypt)

Protección CSRF y cookies seguras

API externa para integraciones automáticas (Torq, SIEM)

✨ Autor
Creado y mejorado por Darell Perez
Orientado a ciberseguridad práctica, automatización y eficiencia.

📄 Licencia
Distribuido bajo licencia MIT.
