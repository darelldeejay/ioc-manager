# 🛡️ IOC Manager

**IOC Manager** es una aplicación web en **Flask** para gestionar listas dinámicas de IPs maliciosas (Indicators of Compromise).
Su objetivo principal es generar y mantener **feeds de texto plano** que Fortinet FortiGate (u otros sistemas) consume vía conectores externos para bloquear IPs en tiempo real.

---

## ✨ Características principales

- Gestión de IPs: añadir, eliminar, filtrar, paginar
- Importación masiva vía CSV
- Sistema de **tags** por categoría (Multicliente, Cliente, Test, Malware, Phishing, etc.)
- **Feeds de texto plano** para FortiGate con soporte ETag/304
- TTL configurable por IP con expiración automática diaria
- **API REST** con autenticación por token y scopes (READ/WRITE)
- RBAC: roles admin/editor/view_only con feeds permitidos por usuario
- Backups automáticos diarios (ZIP, rotación 14 días)
- Notificaciones a Microsoft Teams
- Panel de auditoría con historial de acciones
- Soporte IPv4: IPs sueltas, rangos (A-B), CIDR, máscara punteada

---

## 🗂️ Stack tecnológico

| Componente | Versión | Uso |
|---|---|---|
| Python | 3.10+ | Lenguaje principal |
| Flask | 3.x | Framework web |
| SQLite | — | Base de datos |
| Bootstrap 5 | CDN jsDelivr | UI responsive |
| Gunicorn | 20+ | WSGI en producción |
| Systemd | — | Gestión del servicio en Linux |

---

## 🚀 Inicio rápido (desarrollo)

```bash
git clone https://github.com/darelldeejay/ioc-manager.git
cd ioc-manager
python3 -m venv .venv
source .venv/bin/activate        # Linux/Mac
# .venv\Scripts\activate         # Windows
pip install -r requirements.txt
cp .env.example .env             # Editar al menos FLASK_SECRET_KEY
python app.py
```

Abre `http://localhost:5000` — la app redirige a `/setup` para crear el usuario administrador en el primer arranque.

---

## 📖 Instalación en producción

Consulta **[INSTALL.md](INSTALL.md)** para la guía completa con Gunicorn + Systemd y Docker.

---

## 📡 API REST

Consulta **[API.md](API.md)** para la documentación completa de endpoints, autenticación y ejemplos.

Swagger UI disponible en `/swagger` una vez levantada la app.

---

## 🔑 Variables de entorno (.env)

| Variable | Requerida | Descripción |
|---|---|---|
| `FLASK_SECRET_KEY` | ✅ | Clave de sesión Flask |
| `FEED2_TAG` | ✅ prod | Nombre del segundo feed en la UI (default: `Cliente`) |
| `TOKEN_API` | Opcional | Token legacy para la API |
| `TEAMS_WEBHOOK_URL` | Opcional | Webhook de notificaciones a MS Teams |
| `RATE_LIMIT_PER_MIN` | Opcional | Límite req/min por token API (default: 60) |
| `EXPANSION_LIMIT` | Opcional | Máx. IPs a expandir de un CIDR (default: 2048) |

---

## 👤 Autor

Proyecto desarrollado por **Darell Pérez**.
Licencia: MIT
