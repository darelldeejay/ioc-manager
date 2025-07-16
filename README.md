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
- ✅ Login de acceso básico (`admin/admin`)
- ✅ Interfaz limpia con modo oscuro persistente
- ✅ Preparado para integraciones futuras vía API (ej. Torq)

---

## 📦 Instalación rápida (Raspberry Pi o Linux)

```bash
git clone https://github.com/darelldeejay/ioc-manager.git
cd ioc-manager
sudo apt update && sudo apt install python3 python3-pip -y
pip3 install flask gunicorn
chmod +x install
./install
```

Accede desde tu navegador:

```
http://<IP_RASPBERRY>:5000
```

---

## 🔗 Integración con FortiGate

1. Ir a **Security Fabric > External Connectors**
2. Tipo: `Threat Feed (IP Address)`
3. URL del feed:
```
http://<IP_RASPBERRY>:5000/feed/ioc-feed.txt
```
4. Validar y asociar a políticas

---

## 🧱 Arquitectura del sistema

```
[ Navegador ] ⇆ [ Flask + Gunicorn ] ⇨ /feed/ioc-feed.txt → FortiGate/SOAR
              ⇩
    Archivos locales: ioc-feed.txt, ioc-log.txt
```

---

## 📁 Estructura del proyecto

```
ioc-manager/
├── app.py                  # Backend principal (Flask)
├── install                 # Script de arranque
├── gunicorn_config.py      # Configuración WSGI
├── templates/
│   ├── index.html          # Panel de gestión IPs
│   └── login.html          # Formulario login
├── static/
│   └── style.css           # Estilos (con modo oscuro)
├── .gitignore              # Exclusiones (logs, feed, etc.)
├── README.md               # Este archivo
├── ioc-feed.txt            # (auto-generado)
├── ioc-log.txt             # (auto-generado)
```

---

## ⚠️ Seguridad actual

- Login visual (sin hash de contraseñas aún)
- Validación de IPs para evitar errores o bloqueos
- Modo oscuro guardado en `localStorage`
- Feed en texto plano (ideal para FortiGate)

> 🔒 **Próximas mejoras previstas:**
> - Gestión de usuarios y roles (`admin`, `analyst`)
> - API segura para integración externa
> - Páginas personalizadas de error (403/404)
> - Hash de contraseñas y protección CSRF

---

## ✨ Autor

**Creado y mantenido por Darell Perez**  
Desarrollado con foco en ciberseguridad práctica y eficiencia.

---

## 📄 Licencia

Distribuido bajo licencia MIT.  
Ver archivo [`LICENSE`](LICENSE).
