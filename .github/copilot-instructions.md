# IOC Manager – Copilot Instructions

> **IMPORTANTE**: Este archivo es la fuente de verdad del proyecto. Contiene el contexto técnico completo para que GitHub Copilot nunca pierda el hilo. Actualizar tras cambios significativos.

---

## 🔴 REGLA CRÍTICA: Añadir / modificar clientes

**Cuando el usuario pida añadir un nuevo cliente o feed de cliente:**

1. **ANTES de tocar código**, leer el documento completo: `docs/ADDING_CLIENTS.md`
2. Seguir exactamente el checklist de 6 pasos indicado en ese documento.
3. **NUNCA subir nombres de clientes reales a GitHub** — `git add app.py` está prohibido cuando contiene clientes reales.
4. Desplegar primero en **preprod** (`ssh ioc-preprod`), esperar validación, luego **prod** (`ssh ioc-prod`).
5. Actualizar la tabla "Clientes activos actualmente" en `docs/ADDING_CLIENTS.md` (solo local, no a GitHub).

---

## Qué es este proyecto

**IOC Manager** es una aplicación web Flask para gestionar listas dinámicas de IPs maliciosas (Indicators of Compromise).  
Su objetivo principal es generar y mantener **feeds de texto plano** que Fortinet FortiGate consume vía conectores externos para bloquear IPs en tiempo real.

Autor: Darell Pérez  
Repositorio: https://github.com/darelldeejay/ioc-manager  
Última revisión completa del código: 2026-06-07

---

## Infraestructura / Entornos

| Entorno | SSH alias | SSH directo | Web | Hostname |
|---|---|---|---|---|
| **Preproducción** | `ssh ioc-preprod` | `ssh darell@10.254.120.123` | http://10.254.120.123:5000/ | `madsoc-iocmanager` |
| **Producción** | `ssh ioc-prod` | `ssh darell@10.240.0.84` | http://10.240.0.84:5000/ | `iocm` |

- Usuario SSH: `darell`
- Preproducción: clave `~/.ssh/id_ed25519` (ed25519)
- Producción: clave `~/.ssh/darell_prod` (RSA, convertida de `darell.ppk`)
- Ambas configuradas en `~/.ssh/config` con alias `ioc-preprod` / `ioc-prod`
- Servidor WSGI: Gunicorn en puerto **5000**
- Gestión del servicio: `systemd` (unidad `ioc-manager.service`)
- Comandos útiles en servidor:
  ```bash
  sudo systemctl status ioc-manager.service --no-pager -l
  sudo systemctl restart ioc-manager.service
  sudo journalctl -fu ioc-manager.service
  ```

---

## Stack tecnológico

| Componente | Versión | Uso |
|---|---|---|
| Python | 3.11 | Lenguaje principal |
| Flask | 3.x | Framework web |
| SQLite | — | Base de datos (via `db.py`) |
| Bootstrap 5 | CDN jsDelivr | UI/Frontend |
| Jinja2 | — | Templates HTML |
| Gunicorn | 20+ | WSGI producción |
| filelock | — | Escrituras atómicas en feeds |
| python-dotenv | — | Variables de entorno |
| requests | — | Notificaciones MS Teams |
| pytest | — | Suite de tests |

---

## Estructura del proyecto

```
IOC_MANAGER/
├── app.py                  # Aplicación Flask monolítica (~4200 líneas) — ARCHIVO CENTRAL
├── db.py                   # Capa SQLite: modelos, CRUD, helpers (~450 líneas)
├── gunicorn_config.py      # Gunicorn: workers, puerto 5000
├── requirements.txt        # flask, gunicorn, python-dotenv, filelock, requests, pytest
├── .env.example            # Variables de entorno plantilla
├── create_admin.py         # CLI: crear usuario admin inicial
├── reset_password.py       # CLI: resetear contraseña admin
├── app_debase.py           # Versión legacy/debug (NO usar en producción)
├── templates/
│   ├── index.html          # Dashboard principal (~105KB, RBAC, paginación, feeds, filtros)
│   ├── login.html          # Login page
│   ├── settings.html       # Panel admin (usuarios, API keys, webhook, backups, audit)
│   ├── setup.html          # Setup inicial (primer arranque)
│   └── swagger.html        # Swagger UI para la API
├── static/
│   ├── css/index.css       # Estilos dashboard
│   ├── js/index.js         # Lógica frontend dashboard (~43KB)
│   ├── js/users.js         # Gestión usuarios frontend
│   ├── js/login.js         # Login frontend
│   ├── openapi.json        # Especificación OpenAPI 3.0
│   └── plantilla.csv       # Plantilla CSV de importación
├── tests/
│   ├── conftest.py         # Fixtures pytest (DB temporal aislada via tempfile)
│   ├── test_api.py         # Tests endpoints API REST
│   ├── test_api_v2.py      # Tests API v2
│   ├── test_core.py        # Tests lógica de negocio
│   ├── test_db_logic.py    # Tests capa DB
│   └── test_routes.py      # Tests rutas web
├── ioc_manager.db          # SQLite DB (generado en runtime, NO en git)
├── data/
│   └── history.json        # Snapshots históricos de métricas
└── backups/                # Backups automáticos ZIP
```

### Archivos de datos (runtime, ignorados por git)
- `ioc-feed.txt` — Feed Multicliente (IP|YYYY-MM-DD|TTL_DÍAS)
- `ioc-feed-bpe.txt` — Feed BPE
- `ioc-feed-test.txt` — Feed Test
- `ioc-feed-{Tag}.txt` — Feed dinámico para tags adicionales (Malware, Phishing, etc.)
- `ioc-log.txt` — Log de acciones
- `notif-log.json` — Historial de notificaciones UI
- `data/history.json` — Snapshots históricos de métricas
- `backups/YYYY-MM-DD.zip` — Backups automáticos diarios (rotación 14 días)
- `backups/YYYY-MM-DD_HHMMSS.zip` — Backups manuales (rotación 5 últimos)

---

## Base de datos SQLite (`db.py`)

### Tablas
| Tabla | Campos clave | Propósito |
|---|---|---|
| `users` | username (PK), password_hash, role, created_at, last_login, allowed_feeds (JSON) | Autenticación y RBAC |
| `ip_metadata` | ip (PK), source, tags (JSON array), added_at, ttl (días), expiration_date, alert_ids (JSON), history (JSON) | Almacén principal de IOCs |
| `audit_log` | id, ts, event, actor, scope, details (JSON) | Log de auditoría |
| `config` | key (PK), value | Configuración dinámica (webhook, modo mantenimiento) |
| `history_metrics` | date (PK), total, manual, csv, api, tags_json | Snapshots diarios de métricas |
| `api_keys` | id, name, token (UNIQUE), scopes, created_at | Tokens de API |
| `test_runs` | id, ts, success, output, actor | Historial de ejecuciones de tests |
| `feed_access_log` | id, ts, remote_ip, user_agent, status_code, details (JSON) | Logs de acceso a feeds (máx 1000 filas) |

### Funciones clave de db.py
```python
init_db()                                    # Crea tablas e índices
get_all_ips()                                # → list[dict]
get_ip(ip)                                   # → dict|None
upsert_ip(ip, source, tags, ttl, expiration_date, alert_ids, history)
bulk_upsert_ips(ip_list)                     # Optimizado para CSV bulk
delete_ip(ip)
delete_all_ips()
add_tag(ip, tag)                             # Añade tag si no existe
remove_tag(ip, tag)                          # Quita tag
bulk_add_tag(ip_list, tag)
bulk_remove_tag(ip_list, tag)
update_ip_ttl(ip, new_ttl)
create_user(username, password_hash, role, allowed_feeds)
get_user_by_username(username)               # → dict|None
get_user_count()                             # → int
update_user(username, role, allowed_feeds, password_hash)
delete_user(username)
create_api_key(name, token, scopes)
list_api_keys()                              # → list[dict]
delete_api_key(key_id)
get_api_key(token)                           # → dict|None
db_audit(event, actor, scope, details)       # Escribe en audit_log
get_audit_log(limit=500)                     # → list[dict]
get_config(key, default=None)                # → str|None
set_config(key, value)
log_feed_access(remote_ip, user_agent, status_code, details)
get_feed_access_logs(limit=10)              # → list[dict] (más recientes primero)
get_metrics_history(limit)                   # → list[dict]
```

---

## Tags canónicos

```python
CANONICAL_TAGS = {
    "multicliente": "Multicliente",  # → ioc-feed.txt
    "bpe": "BPE",                    # → ioc-feed-bpe.txt
    "test": "Test",                  # → ioc-feed-test.txt
    "phishing": "Phishing",          # → ioc-feed-Phishing.txt
    "malware": "Malware",            # → ioc-feed-Malware.txt
    "ransomware": "Ransomware",
    "botnet": "Botnet",
    "apt": "APT",
    "spam": "Spam",
    "tor": "Tor",
    "vpn": "VPN",
    "proxy": "Proxy"
}
ALLOWED_TAGS = {"Multicliente", "BPE", "Test"}  # Tags con feed dedicado estándar
```

Cada IP puede tener múltiples tags. Un feed file se genera por cada tag que aparezca.

---

## Feeds (archivos de texto para FortiGate)

- **Formato de línea**: `IP|YYYY-MM-DD|TTL_DÍAS`
- **Solo IPv4 públicas** en los feeds (las rutas `/feed/` filtran por `is_allowed_ip()` y `IPv4Address`)
- **Escritura SIEMPRE atómica**: escribe a `.tmp` + `os.replace()` dentro de `FileLock`
- **`regenerate_feeds_from_db()`** debe llamarse SIEMPRE tras cualquier cambio en la BD
- **TTL**: `0` = permanente; `N` = días desde `added_at` hasta expiración
- **ETag/304**: respuestas con ETag MD5 del contenido; FortiGate recibe 304 si el feed no cambió
- `_get_feed_filename(tag)` calcula el path de cada feed según el tag (sanitiza el nombre)

---

## Rutas principales (app.py)

### Web UI (requieren sesión)
| Ruta | Función | Descripción |
|---|---|---|
| `GET/POST /` | `index()` | Dashboard principal |
| `GET/POST /login` | `login()` | Autenticación |
| `GET /logout` | `logout()` | Cerrar sesión |
| `GET/POST /setup` | `first_run_setup()` | Setup inicial |
| `GET /admin/settings` | `admin_settings_ui()` | Panel admin |
| `POST /admin/api-keys` | `admin_api_keys()` | Crear/eliminar API keys |
| `POST /admin/config` | `admin_config()` | Guardar configuración |
| `GET /admin/users` | `list_users()` | Listar usuarios (JSON) |
| `POST /admin/users/add` | `add_user()` | Crear usuario |
| `POST /admin/users/edit` | `edit_user()` | Editar usuario |
| `POST /admin/users/delete` | `delete_user()` | Borrar usuario |
| `POST /update-ttl` | `update_ttl_route()` | Actualizar TTL de IP |
| `GET /backup/latest.zip` | `backup_latest_zip()` | Descargar último backup |
| `POST /backup/now` | `backup_now()` | Forzar backup manual |
| `POST /backup/restore` | `backup_restore_upload()` | Restaurar desde ZIP (admin) |
| `GET /backup/list` | `backup_list()` | Listar backups (JSON) |
| `GET /healthz` | `healthz()` | Health check (sin auth) |
| `GET /metrics` | `metrics()` | Métricas JSON |
| `GET /preview-delete` | `preview_delete()` | Preview borrado por patrón |
| `GET /swagger` | `api_docs()` | Swagger UI |
| `POST /api/remove-tag` | `api_remove_tag()` | Quitar tag de IP |
| `POST /api/tags/add` | `api_add_tag()` | Añadir tag a IP |
| `POST /api/tags/bulk` | `api_bulk_tags()` | Tags masivos |

### API REST (token requerido)
| Ruta | Método | Scope | Descripción |
|---|---|---|---|
| `/api/` | GET | cualquier token | Estado del servicio |
| `/api/bloquear-ip` | POST | WRITE | Añadir IPs (única, rango, CIDR) |
| `/api/bloquear-ip` | DELETE | WRITE | Eliminar IP (global o por tags) |
| `/api/estado/<IP>` | GET | cualquier token | Detalles de una IP |
| `/api/summary` | GET | READ | Métricas en tiempo real |
| `/api/counters/history` | GET | READ | Serie temporal de métricas |
| `/api/lista/<TAG>` | GET | cualquier token | Lista JSON de IPs por tag |
| `/feed/ioc-feed.txt` | GET | — | Feed Multicliente (solo IPv4) |
| `/feed/ioc-feed-bpe.txt` | GET | — | Feed BPE (solo IPv4) |
| `/feed/ioc-feed-test.txt` | GET | — | Feed Test (solo IPv4) |

### Autenticación API
1. `Authorization: Bearer <TOKEN>` (recomendado)
2. `X-API-Key: <TOKEN>`
3. `?token=<TOKEN>`

---

## Funciones críticas de app.py

- `add_ips_validated(...)` — Procesa y persiste IPs (nuevo/update), calcula TTL, llama `regenerate_feeds_from_db()`; retorna `(añadidas, rechazadas, líneas, actualizadas, added_items, updated_items)`
- `regenerate_feeds_from_db()` — Regenera TODOS los feeds desde SQLite (SIEMPRE atómica)
- `expand_input_to_ips(text)` — Parsea IPs: suelta/rango/CIDR/máscara punteada; valida públicas
- `_expire_ips_from_db()` — Elimina IPs con TTL expirado; regenera feeds; retorna lista borrada
- `perform_daily_backup()` — Backup automático diario (zip, rota 14 días)
- `perform_manual_backup()` — Backup manual con timestamp (rota últimos 5)
- `send_teams_alert(...)` — Notificación MS Teams (asíncrono, hilo daemon)
- `TeamsAggregator` — Agrega eventos y hace flush a Teams cada 60 segundos; `flush()` para inmediato
- `_audit(event, actor, scope, details)` → `db.db_audit(...)` — Auditoría en SQLite
- `take_daily_snapshot()` — Snapshot diario de métricas en history.json
- `perform_log_rotation()` — Rota logs > 5MB (renombra con timestamp)
- `_create_feed_response(ips_list)` — Respuesta con ETag MD5 + log de acceso en DB
- `compute_source_and_tag_counters_union()` — Contadores vivos `(src, tag, src_tag, total)`

---

## Hooks before_request

- `check_setup_required` — Redirige a `/setup` si no hay usuarios en DB (excepto `/static`, `/api`, `/setup`)
- `check_maintenance_mode` — Lee `MAINTENANCE_MODE` de DB; bloquea POSTs salvo rutas permitidas
- `check_maintenance` — Hook legacy (var global); protege endpoints específicos
- `before_request` — Llama `perform_daily_expiry_once()`, `take_daily_snapshot()`, `perform_log_rotation()`

---

## Seguridad

- Contraseñas: `werkzeug.security.generate_password_hash` / `check_password_hash`
- Sesiones Flask con `FLASK_SECRET_KEY` de `.env`
- Headers de seguridad en `after_request`: X-Frame-Options DENY, X-Content-Type-Options nosniff, CSP, Referrer-Policy
- CSP diferenciada: `/login` permite jQuery/Bootstrap CDN; resto solo jsDelivr
- Rate limiting en API (en memoria, por token, configurable con `RATE_LIMIT_PER_MIN`)
- Idempotency keys (`Idempotency-Key` header) con cache de 10 min
- API allowlist por CIDR (`API_ALLOWLIST` en .env)
- RBAC: roles admin/editor/view_only; `allowed_feeds` por usuario (`["*"]` = todos)
- Validación de IPs: bloquea privadas (RFC1918), loopback, link-local, multicast, reserved, 0.0.0.0
- `X-Forwarded-For` soportado en `_client_ip()`

---

## Variables de entorno (.env)

```bash
FLASK_SECRET_KEY=<hex 32 bytes>   # OBLIGATORIO en producción
ADMIN_USER=admin                  # Solo para script create_admin.py
ADMIN_PASSWORD=admin              # Solo para script create_admin.py
TOKEN_API=<token>                 # Token legacy (opcional, usar API Keys DB)
API_ALLOWLIST=1.2.3.0/24         # Whitelist CIDRs para API (opcional)
RATE_LIMIT_PER_MIN=60             # Rate limit API por token
EXPANSION_LIMIT=2048              # Máximo IPs a expandir de un CIDR
TEAMS_WEBHOOK_URL=https://...     # Webhook MS Teams (opcional, también config DB)
```

---

## Comandos de ejecución

```bash
# Entorno virtual
python3 -m venv .venv
.venv\Scripts\activate             # Windows
source .venv/bin/activate          # Linux/Mac

# Instalar dependencias
pip install -r requirements.txt

# Desarrollo (Flask built-in)
python app.py

# Producción (Gunicorn)
gunicorn --config gunicorn_config.py app:app

# Docker
docker compose up -d               # Puerto 5050

# Tests
pytest tests/
python run_tests.py

# Utilidades
python create_admin.py             # Crear usuario admin
python reset_password.py           # Resetear contraseña admin
```

---

## Patrones de código importantes

### Escritura atómica de feeds
```python
tmp_file = feed_path + ".tmp"
with lock:
    with open(tmp_file, "w", encoding="utf-8") as f:
        for l in lines:
            f.write(l + "\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_file, feed_path)
```

### Después de cualquier cambio en DB siempre
```python
regenerate_feeds_from_db()
```

### Normalización de tags
```python
tags = _norm_tags(raw_tags)            # Para aceptar cualquier tag
tags = _filter_allowed_tags(raw_tags)  # Para feeds (solo canónicos)
```

### Auditoría
```python
_audit("event_name", f"web/{session['username']}", scope_dict_or_str, details_dict)
```

---

## Tests

- Usan `unittest.TestCase` + `pytest`
- `conftest.py`: fixtures para app Flask con DB SQLite temporal en `tempfile.mkstemp()`
- Aislamiento completo: se parchean `db.DB_FILE`, `app.FEED_FILE`, `app.FEED_FILE_BPE`, `app.FEED_FILE_TEST`, `app.META_FILE`, `app.AUDIT_LOG_FILE`
- `setUp` siempre crea usuario `admin` en DB temporal para evitar redirect a `/setup`
- Los tests de rutas también parchean `app.FEEDS_CONFIG` cuando es necesario

```bash
pytest tests/                    # Todos los tests
pytest tests/test_api.py -v      # Solo API
pytest tests/test_routes.py -v   # Solo rutas web
pytest tests/test_db_logic.py -v # Solo capa DB
```

---

## Notas técnicas / Decisiones clave

1. **Migración completada**: el proyecto migró de archivos JSON planos a SQLite. `app_debase.py` es la versión legacy/debug (no usar en producción).
2. **`app.py` es monolítico**: toda la lógica de negocio, rutas, helpers y modelos de vista están en un solo archivo (~4200 líneas).
3. **`FEEDS_CONFIG`** define qué feeds existen y sus etiquetas; se usa en templates para el selector de feed.
4. **`allowed_feeds` por usuario**: define qué feeds puede ver cada usuario (RBAC). `["*"]` = todos.
5. **`TeamsAggregator`**: agrupa notificaciones en buffer de 60s para evitar spam a Teams en bulk imports. Instancia global `teams_aggregator`. Hacer `teams_aggregator.flush()` para envío inmediato.
6. **Expiry diario**: una sola vez al día via marca de archivo `EXPIRY_MARK`. Función `perform_daily_expiry_once()`.
7. **Windows fix**: `mimetypes.add_type('application/javascript', '.js')` al inicio de app.py.
8. **`/debug-dashboard`**: ruta de desarrollo que inyecta sesión admin sin autenticación real. NO usar en producción.
9. **ETag/304 para FortiGate**: `_create_feed_response()` genera respuestas con ETag MD5. FortiGate envía `If-None-Match` para recibir 304 si el feed no cambió.
10. **Log rotation**: `perform_log_rotation()` rota `audit-log.jsonl` e `ioc-log.txt` cuando superan 5MB (renombra con timestamp).
11. **Idempotencia API**: header `Idempotency-Key` con cache en memoria de 10 min (`_idem_cache`).
12. **Rate limiting**: en memoria por token, 60 req/min por defecto (`_rate_hist`). Configurable con `RATE_LIMIT_PER_MIN`.
13. **Doble definición de `regenerate_feeds_from_db()`**: hay dos implementaciones en app.py (la segunda es la completa y activa con feeds dinámicos por tag). La segunda sobreescribe la primera.
14. **`save_users()` eliminado**: toda gestión de usuarios migró a SQLite. `load_users()` sigue existiendo (lee de SQLite) para compatibilidad de código.
15. **Blueprint `/api`**: las rutas de la REST API están en un Blueprint separado `api = Blueprint("api", __name__, url_prefix="/api")` pero se registra en el app principal.
16. **Rutas no-Blueprint**: `api/summary`, `api/counters/history`, `api/lista/<tag>`, `api/estado/<ip>` están definidas directamente en `app` (no en el Blueprint).

---

## Rutas completas (mapa exhaustivo)

### Web (sesión Flask requerida)
| Ruta | Función | Roles | Descripción |
|---|---|---|---|
| `GET/POST /` | `index()` | todos | Dashboard principal |
| `GET/POST /login` | `login()` | — | Autenticación |
| `GET /logout` | `logout()` | — | Cerrar sesión |
| `GET/POST /setup` | `first_run_setup()` | — | Setup inicial (sin usuarios en DB) |
| `GET /admin/settings` | `admin_settings_ui()` | admin | Panel configuración |
| `POST /admin/api-keys` | `admin_api_keys()` | admin | Crear/eliminar API keys |
| `POST /admin/config` | `admin_config()` | admin | Guardar webhook Teams |
| `GET /admin/users` | `list_users()` | todos | Listar usuarios (JSON) |
| `POST /admin/users/add` | `add_user()` | todos | Crear usuario |
| `POST /admin/users/edit` | `edit_user()` | todos | Editar usuario |
| `POST /admin/users/delete` | `delete_user()` | todos | Borrar usuario |
| `POST /admin/users/password` | `change_password()` | todos | Cambiar contraseña |
| `POST /update-ttl` | `update_ttl_route()` | todos | Actualizar TTL de IP |
| `GET /backup/latest.zip` | `backup_latest_zip()` | todos | Descargar último backup |
| `POST /backup/now` | `backup_now()` | todos | Forzar backup manual |
| `POST /backup/restore` | `backup_restore_upload()` | admin | Restaurar desde ZIP |
| `GET /backup/list` | `backup_list()` | todos | Listar backups (JSON) |
| `GET /metrics` | `metrics()` | todos | Métricas JSON |
| `GET /healthz` | `healthz()` | — | Health check (sin auth) |
| `GET /preview-delete` | `preview_delete()` | todos | Preview borrado por patrón |
| `GET /swagger` | `api_docs()` | todos | Swagger UI |
| `GET /debug-dashboard` | `debug_dashboard()` | — | Debug (inyecta sesión admin) |

### API REST (Blueprint `/api` + rutas directas)
| Ruta | Función | Scope | Descripción |
|---|---|---|---|
| `GET /api/` | `api_root()` | cualquier token | Health API |
| `POST /api/bloquear-ip` | `bloquear_ip_api()` | WRITE | Añadir IPs |
| `DELETE /api/bloquear-ip` | `bloquear_ip_api()` | WRITE | Eliminar IP (global o por tags) |
| `GET /api/estado/<ip>` | `estado_api()` | cualquier token | Detalles IP |
| `GET /api/lista/<tag>` | `lista_tag_api()` | cualquier token | Lista JSON de IPs por tag |
| `GET /api/summary` | `api_summary()` | READ | Métricas en tiempo real |
| `GET /api/counters/history` | `api_counters_history_endpoint()` | READ | Serie temporal métricas |
| `GET /api/openapi.json` | `api_openapi_json()` | — | Spec OpenAPI |
| `POST /api/remove-tag` | `api_remove_tag()` | sesión | Quitar tag de IP |
| `POST /api/tags/add` | `api_add_tag()` | sesión | Añadir tag a IP |
| `POST /api/tags/bulk` | `api_bulk_tags()` | sesión | Tags masivos |

### Feeds (para FortiGate, sin auth)
| Ruta | Función | Descripción |
|---|---|---|
| `GET /feed/ioc-feed.txt` | `feed()` | Feed Multicliente (solo IPv4 públicas) |
| `GET /feed/ioc-feed-bpe.txt` | `feed_bpe()` | Feed BPE |
| `GET /feed/ioc-feed-test.txt` | `feed_test()` | Feed Test |

---

## Flujo de datos completo

```
Input (Web/API/CSV)
    ↓
expand_input_to_ips()          # Parse: IP/CIDR/Rango/Máscara → lista IPs
    ↓
is_allowed_ip()                # Validar: bloquear privadas/loopback/multicast/reserved
    ↓
_norm_tags() + _filter_allowed_tags()  # Normalizar tags (case-insensitive)
    ↓
add_ips_validated()            # Persiste en SQLite via db.upsert_ip()
    ↓
regenerate_feeds_from_db()     # Regenera TODOS los .txt atómicamente
    ↓
teams_aggregator.add_batch()   # Encola notificación Teams (flush cada 60s)
    ↓
_audit()                       # Escribe en audit_log (SQLite)
```

---

## Gestión de tags: flujo detallado

```python
# 1. Input raw: "multicliente, bpe, Malware"
raw = _parse_tags_field("multicliente, bpe, Malware")
# → ["Multicliente", "BPE", "Malware"]

# 2. Normalizar (Title Case + mapa canónico)
tags = _norm_tags(raw)
# → ["Multicliente", "BPE", "Malware"]  (Malware ya está en CANONICAL_TAGS)

# 3. Filtrar solo los que tienen feed dedicado (para rutas de feed)
allowed = _filter_allowed_tags(tags)
# → ["Multicliente", "BPE"]  (Malware no está en ALLOWED_TAGS)

# NOTA: add_ips_validated usa _norm_tags (acepta cualquier tag)
# Los feeds solo se generan para tags en CANONICAL_TAGS
```

---

## Variables globales críticas de app.py

```python
BASE_DIR       # Directorio del proyecto
FEED_FILE      # ioc-feed.txt (Multicliente)
FEED_FILE_BPE  # ioc-feed-bpe.txt
FEED_FILE_TEST # ioc-feed-test.txt
LOG_FILE       # ioc-log.txt
NOTIF_FILE     # notif-log.json
HISTORY_FILE   # data/history.json
BACKUP_DIR     # backups/
EXPIRY_MARK    # Archivo marca para expiry diario
FEEDS_CONFIG   # Dict con config de feeds para el template
teams_aggregator  # Instancia global de TeamsAggregator
TOKEN_API      # Token legacy (env var)
API_ALLOWLIST  # CIDRs permitidos para la API (env var)
EXPANSION_LIMIT # Max IPs a expandir de un CIDR (default 2048)
RATE_LIMIT_PER_MIN # Límite rate API (default 60)
CANONICAL_TAGS # Dict normalización tags (keys en minúsculas)
ALLOWED_TAGS   # Set tags con feed dedicado {"Multicliente","BPE","Test"}
```

---

## Patrón CSV de importación

Formato del archivo CSV:
```
ip;tags;alert_id
1.2.3.4;Multicliente;TICKET-001
5.6.7.0/24;BPE,Malware;TICKET-002
10.0.0.1-10.0.0.50;Test;
```
- Delimitador auto-detectado: `;`, `|` o `,`
- Primera columna: IP/CIDR/Rango
- Segunda columna: tags (separados por coma dentro)
- Tercera columna: alert_id (opcional)
- Si no hay tags: asigna "Multicliente" por defecto
- TTL global para todo el CSV se selecciona en el form (`ttl_csv`)

---

## Seguridad

- Contraseñas: `werkzeug.security.generate_password_hash` / `check_password_hash`
- Sesiones Flask con `FLASK_SECRET_KEY` de `.env` (si falta, usa dev-key insegura)
- Headers de seguridad en `after_request`: X-Frame-Options DENY, X-Content-Type-Options nosniff, CSP, Referrer-Policy
- CSP diferenciada: `/login` permite jQuery/Bootstrap CDN externo; resto solo jsDelivr
- Rate limiting en API: en memoria por token, configurable con `RATE_LIMIT_PER_MIN`
- Idempotency keys (`Idempotency-Key` header) con cache de 10 min
- API allowlist por CIDR (`API_ALLOWLIST` en .env)
- RBAC: roles admin/editor/view_only; `allowed_feeds` por usuario
- Validación de IPs: bloquea privadas (RFC1918), loopback, link-local, multicast, reserved, 0.0.0.0
- `X-Forwarded-For` soportado para detectar IP real del cliente en `_client_ip()`

---

## Variables de entorno (.env)

```bash
FLASK_SECRET_KEY=<hex 32 bytes>   # OBLIGATORIO en producción
ADMIN_USER=admin                  # Solo para script create_admin.py
ADMIN_PASSWORD=admin              # Solo para script create_admin.py
TOKEN_API=<token>                 # Token legacy (opcional, usar API Keys DB)
API_ALLOWLIST=1.2.3.0/24         # Whitelist CIDRs para API (opcional)
RATE_LIMIT_PER_MIN=60             # Rate limit API por token
EXPANSION_LIMIT=2048              # Máximo IPs a expandir de un CIDR
TEAMS_WEBHOOK_URL=https://...     # Webhook MS Teams (opcional, también en config DB)
```

---

## Stack tecnológico

| Componente | Versión | Uso |
|---|---|---|
| Python | 3.11 | Lenguaje principal |
| Flask | 3.x | Framework web |
| SQLite | — | Base de datos (via `db.py`) |
| Bootstrap 5 | CDN jsDelivr | UI/Frontend |
| Jinja2 | — | Templates HTML |
| Gunicorn | 20+ | WSGI producción |
| filelock | — | Escrituras atómicas en feeds |
| python-dotenv | — | Variables de entorno |
| requests | — | Notificaciones MS Teams |
| pytest | — | Suite de tests |

---

## Estructura del proyecto

```
IOC_MANAGER/
├── app.py                  # Aplicación Flask monolítica (~4200 líneas) — ARCHIVO CENTRAL
├── db.py                   # Capa SQLite: modelos, CRUD, helpers (~450 líneas)
├── gunicorn_config.py      # Gunicorn: workers, puerto 5000
├── requirements.txt        # flask, gunicorn, python-dotenv, filelock, requests, pytest
├── .env.example            # Variables de entorno plantilla
├── create_admin.py         # CLI: crear usuario admin inicial
├── reset_password.py       # CLI: resetear contraseña admin
├── app_debase.py           # Versión legacy/debug (NO usar en producción)
├── templates/
│   ├── index.html          # Dashboard principal (~105KB, RBAC, paginación, feeds, filtros)
│   ├── login.html          # Login page
│   ├── settings.html       # Panel admin (usuarios, API keys, webhook, backups, audit)
│   ├── setup.html          # Setup inicial (primer arranque)
│   └── swagger.html        # Swagger UI para la API
├── static/
│   ├── css/index.css       # Estilos dashboard
│   ├── js/index.js         # Lógica frontend dashboard (~43KB)
│   ├── js/users.js         # Gestión usuarios frontend
│   ├── js/login.js         # Login frontend
│   ├── openapi.json        # Especificación OpenAPI 3.0
│   └── plantilla.csv       # Plantilla CSV de importación
├── tests/
│   ├── conftest.py         # Fixtures pytest (DB temporal aislada via tempfile)
│   ├── test_api.py         # Tests endpoints API REST
│   ├── test_api_v2.py      # Tests API v2
│   ├── test_core.py        # Tests lógica de negocio
│   ├── test_db_logic.py    # Tests capa DB
│   └── test_routes.py      # Tests rutas web
├── ioc_manager.db          # SQLite DB (generado en runtime, NO en git)
├── data/
│   └── history.json        # Snapshots históricos de métricas
└── backups/                # Backups automáticos ZIP
```

### Archivos de datos (runtime, ignorados por git)
- `ioc-feed.txt` — Feed Multicliente (IP|YYYY-MM-DD|TTL_DÍAS)
- `ioc-feed-bpe.txt` — Feed BPE
- `ioc-feed-test.txt` — Feed Test
- `ioc-feed-{Tag}.txt` — Feed dinámico para tags adicionales (Malware, Phishing, etc.)
- `ioc-log.txt` — Log de acciones
- `notif-log.json` — Historial de notificaciones UI
- `data/history.json` — Snapshots históricos de métricas
- `backups/YYYY-MM-DD.zip` — Backups automáticos diarios (rotación 14 días)
- `backups/YYYY-MM-DD_HHMMSS.zip` — Backups manuales (rotación 5 últimos)

---

## Base de datos SQLite (`db.py`)

### Tablas
| Tabla | Campos clave | Propósito |
|---|---|---|
| `users` | username (PK), password_hash, role, created_at, last_login, allowed_feeds (JSON) | Autenticación y RBAC |
| `ip_metadata` | ip (PK), source, tags (JSON array), added_at, ttl (días), expiration_date, alert_ids (JSON), history (JSON) | Almacén principal de IOCs |
| `audit_log` | id, ts, event, actor, scope, details (JSON) | Log de auditoría |
| `config` | key (PK), value | Configuración dinámica (webhook, modo mantenimiento) |
| `history_metrics` | date (PK), total, manual, csv, api, tags_json | Snapshots diarios de métricas |
| `api_keys` | id, name, token (UNIQUE), scopes, created_at | Tokens de API |
| `test_runs` | id, ts, success, output, actor | Historial de ejecuciones de tests |
| `feed_access_log` | id, ts, remote_ip, user_agent, status_code, details (JSON) | Logs de acceso a feeds (máx 1000 filas) |

### Funciones clave de db.py
```python
init_db()                                    # Crea tablas e índices
get_all_ips()                                # → list[dict]
get_ip(ip)                                   # → dict|None
upsert_ip(ip, source, tags, ttl, expiration_date, alert_ids, history)
bulk_upsert_ips(ip_list)                     # Optimizado para CSV bulk
delete_ip(ip)
delete_all_ips()
add_tag(ip, tag)                             # Añade tag si no existe
remove_tag(ip, tag)                          # Quita tag
bulk_add_tag(ip_list, tag)
bulk_remove_tag(ip_list, tag)
update_ip_ttl(ip, new_ttl)
create_user(username, password_hash, role, allowed_feeds)
get_user_by_username(username)               # → dict|None
get_user_count()                             # → int
update_user(username, role, allowed_feeds, password_hash)
delete_user(username)
create_api_key(name, token, scopes)
list_api_keys()                              # → list[dict]
delete_api_key(key_id)
get_api_key(token)                           # → dict|None
db_audit(event, actor, scope, details)       # Escribe en audit_log
get_audit_log(limit=500)                     # → list[dict]
get_config(key, default=None)                # → str|None
set_config(key, value)
log_feed_access(remote_ip, user_agent, status_code, details)
get_feed_access_logs(limit=10)              # → list[dict] (más recientes primero)
get_metrics_history(limit)                   # → list[dict]
```

---

## Tags canónicos

```python
CANONICAL_TAGS = {
    "multicliente": "Multicliente",  # → ioc-feed.txt
    "bpe": "BPE",                    # → ioc-feed-bpe.txt
    "test": "Test",                  # → ioc-feed-test.txt
    "phishing": "Phishing",          # → ioc-feed-Phishing.txt
    "malware": "Malware",            # → ioc-feed-Malware.txt
    "ransomware": "Ransomware",
    "botnet": "Botnet",
    "apt": "APT",
    "spam": "Spam",
    "tor": "Tor",
    "vpn": "VPN",
    "proxy": "Proxy"
}
ALLOWED_TAGS = {"Multicliente", "BPE", "Test"}  # Tags con feed dedicado estándar
```

Cada IP puede tener múltiples tags. Un feed file se genera por cada tag que aparezca.

---

## Feeds (archivos de texto para FortiGate)

- **Formato de línea**: `IP|YYYY-MM-DD|TTL_DÍAS`
- **Solo IPv4 públicas** en los feeds (las rutas `/feed/` filtran por `is_allowed_ip()` y `IPv4Address`)
- **Escritura SIEMPRE atómica**: escribe a `.tmp` + `os.replace()` dentro de `FileLock`
- **`regenerate_feeds_from_db()`** debe llamarse SIEMPRE tras cualquier cambio en la BD
- **TTL**: `0` = permanente; `N` = días desde `added_at` hasta expiración
- **ETag/304**: respuestas con ETag MD5 del contenido; FortiGate recibe 304 si el feed no cambió
- `_get_feed_filename(tag)` calcula el path de cada feed según el tag (sanitiza el nombre)

---

## Hooks before_request

1. `check_setup_required` — Redirige a `/setup` si DB tiene 0 usuarios (excepto `/static`, `/api`, `/setup`)
2. `check_maintenance_mode` — Lee `config.MAINTENANCE_MODE` de DB; bloquea POSTs salvo rutas permitidas
3. `check_maintenance` — Hook legacy (global var `MAINTENANCE_MODE`); protege endpoints específicos
4. `before_request` — Llama `perform_daily_expiry_once()`, `take_daily_snapshot()`, `perform_log_rotation()`

---

## Funciones críticas de app.py (resumen completo)

| Función | Propósito |
|---|---|
| `add_ips_validated(...)` | Procesa IPs, persiste en SQLite, retorna `(añadidas, rechazadas, líneas, actualizadas, added_items, updated_items)` |
| `regenerate_feeds_from_db()` | Regenera TODOS los feeds dinámicamente desde SQLite (atómica) |
| `expand_input_to_ips(text)` | Parsea: IP suelta / rango A-B / CIDR / IP+máscara punteada; max `EXPANSION_LIMIT` |
| `is_allowed_ip(ip_str)` | `True` si la IP es pública (no privada/loopback/multicast/reserved) |
| `ip_block_reason(ip_str)` | Retorna motivo de bloqueo o `None` si es válida |
| `parse_delete_pattern(raw)` | Parsea patrón de borrado: `("single"/"cidr"/"range", obj)` |
| `_expire_ips_from_db()` | Borra IPs cuyo TTL expiró; regenera feeds; retorna lista borrada |
| `perform_daily_backup(keep_days=14)` | Backup automático diario (zip + rotación) |
| `perform_manual_backup()` | Backup manual con timestamp (rotación últimos 5) |
| `send_teams_alert(title, text, color, sections)` | Notificación MS Teams (asíncrono, hilo daemon) |
| `TeamsAggregator.add_batch(...)` | Encola eventos; `flush()` envía digest |
| `_audit(event, actor, scope, details)` | Wrapper → `db.db_audit(...)` |
| `take_daily_snapshot()` | Snapshot diario de métricas en `data/history.json` |
| `perform_log_rotation()` | Rota logs > 5MB (renombra con timestamp) |
| `_create_feed_response(ips_list)` | Genera respuesta con ETag + log de acceso en DB |
| `_norm_tags(tags)` | Normaliza lista de tags (capitalización + mapa canónico) |
| `_filter_allowed_tags(tags)` | Filtra solo tags con feed dedicado (CANONICAL_TAGS) |
| `_parse_tags_field(val)` | Parsea string de tags separados por coma/espacio |
| `compute_source_and_tag_counters_union()` | Contadores vivos desde DB: `(src, tag, src_tag, total)` |
| `coerce_message_pairs(raw_flashes)` | Convierte flashes a `[{category, message}]` para JSON |
| `days_remaining(date_str, ttl_str)` | Días restantes para expiración |
| `_collect_known_tags()` | Lista de tags activos en DB + ALLOWED_TAGS garantizados |
| `load_users()` | Lee usuarios de SQLite; retorna dict `{username: {...}}` |
| `guardar_notif(category, message)` | Persiste notificación en `notif-log.json` |
| `get_notifs(limit=200)` | Lee últimas N notificaciones de `notif-log.json` |
| `save_lines(lines, feed_path)` | Escritura atómica de un feed (.tmp + os.replace + FileLock) |
| `_backup_critical_files(destination_dir)` | Copia feeds, meta, users, .env, data/ al dir destino |

---

## Comandos de ejecución

```bash
# Entorno virtual
python3 -m venv .venv
.venv\Scripts\activate             # Windows
source .venv/bin/activate          # Linux/Mac

# Instalar dependencias
pip install -r requirements.txt

# Desarrollo (Flask built-in)
python app.py

# Producción (Gunicorn)
gunicorn --config gunicorn_config.py app:app

# Docker
docker compose up -d               # Puerto 5050

# Tests
pytest tests/
python run_tests.py

# Utilidades
python create_admin.py             # Crear usuario admin inicial
python reset_password.py           # Resetear contraseña admin
```

---

## Patrones de código importantes

### Escritura atómica de feeds (SIEMPRE así)
```python
tmp_file = feed_path + ".tmp"
with lock:
    with open(tmp_file, "w", encoding="utf-8") as f:
        for l in lines:
            f.write(l + "\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_file, feed_path)
```

### Después de CUALQUIER cambio en DB
```python
regenerate_feeds_from_db()
```

### Normalización de tags (patrón correcto)
```python
tags = _norm_tags(raw_tags)            # Para aceptar cualquier tag
tags = _filter_allowed_tags(raw_tags)  # Para feeds (solo canónicos)
```

### Auditoría
```python
_audit("event_name", f"web/{session['username']}", scope_dict_or_str, details_dict)
# scope puede ser string (IP) o dict ({"count": N})
```

### API: añadir IP programáticamente
```python
# POST /api/bloquear-ip
# Headers: Authorization: Bearer dk_<token>
{
  "ip": "1.2.3.4",
  "tags": ["Multicliente"],
  "ttl": "30d",          # o "720h" o 2592000 (segundos)
  "note": "SSH Brute",
  "alert_id": "TICKET-123"
}
```

### Manejo de TTL en la API
```python
_parse_ttl_seconds(obj)  # Acepta: "30d", "24h", "60m", "3600s", 3600 (int)
# Retorna: segundos (int)
# Luego: ttl_days = max(1, ceil(ttl_s / 86400))
```

---

## Tests

- Usan `unittest.TestCase` + `pytest`
- `conftest.py`: fixtures para app Flask con DB SQLite temporal en `tempfile.mkstemp()`
- Aislamiento completo: se parchean `db.DB_FILE`, `app.FEED_FILE`, `app.FEED_FILE_BPE`, `app.FEED_FILE_TEST`, `app.META_FILE`, `app.AUDIT_LOG_FILE`
- `setUp` siempre crea usuario `admin` en DB temporal (`db.create_user("admin", "dummy_hash", role="admin")`) para evitar redirect a `/setup`
- Los tests de rutas (`test_routes.py`) también parchean `app.FEEDS_CONFIG` cuando es necesario

```bash
pytest tests/                    # Todos los tests
pytest tests/test_api.py -v      # Solo API
pytest tests/test_routes.py -v   # Solo rutas web
pytest tests/test_db_logic.py -v # Solo capa DB
```

---

## Licenciamiento y PayPal (2026-06-11 → 2026-06-12 ✅ UI FIXED)

Se añadió una primera base de licenciamiento comercial orientada a trial + suscripción mensual.

### Backend (db.py)

- Nueva tabla `licenses`: estado de licencia activa por instancia/cliente.
- Nueva tabla `billing_webhook_events`: idempotencia para webhooks PayPal.
- Nueva tabla `license_events`: auditoría de activaciones/renovaciones/cambios.
- Nuevos helpers DB:
  - `create_license(...)`, `update_license(...)`
  - `get_latest_license()`, `get_license_by_subscription(...)`
  - `add_license_event(...)`
  - `save_billing_webhook_event(...)`, `mark_billing_webhook_processed(...)`

### Backend (app.py)

- Variables de entorno nuevas:
  - `ENFORCE_LICENSE`
  - `LICENSE_GRACE_DAYS`
  - `PAYPAL_MODE`
  - `PAYPAL_CLIENT_ID`
  - `PAYPAL_CLIENT_SECRET`
  - `PAYPAL_WEBHOOK_ID`
- Verificación de firma de webhook PayPal via API oficial `verify-webhook-signature`.
- Hook `before_request` para bloquear escrituras cuando la licencia no es válida (si `ENFORCE_LICENSE=1`).
- Endpoint webhook público:
  - `POST /api/license/paypal/webhook`
- Endpoints admin de licencia (requieren sesión admin):
  - `GET /admin/license/status`
  - `POST /admin/license/activate`
  - `POST /admin/license/renew`
- **CRITICAL FIX (2026-06-12)**: `_get_license_state()` now ALWAYS fetches the latest license from DB, regardless of enforcement setting. This allows the UI banner to display license status even when `ENFORCE_LICENSE=0` (for testing/permissive mode).

### Frontend (templates/index.html)

- **License banner** added (~line 182-240) with 4 states:
  - 🟢 **Active**: Green alert when license is active
  - 🟠 **Grace Period**: Orange alert when expired but in grace window
  - 🔵 **Info**: Blue alert when license exists but enforcement is disabled
  - 🔴 **Unlicensed**: Red alert when no license or enforcement is on
- Banner shows: license plan, expiration date, grace period, renewal/purchase buttons

### Comportamiento actual

- Por defecto no rompe instalaciones existentes: `ENFORCE_LICENSE=0`.
- **Default de licencia manual actualizado a 30 días** (2026-06-12):
  - `admin_license_activate`: `plan_code` por defecto = `trial_30d`, `days` por defecto = `30`
  - `admin_license_renew`: `days` por defecto = `30`
- Con `ENFORCE_LICENSE=1`:
  - Sin licencia o licencia inválida: bloquea escrituras (HTTP 402).
  - Lecturas y feeds siguen permitidos.
  - Webhook PayPal y endpoints admin de licencia quedan permitidos para recuperación/renovación.
- **UI Banner visible in all modes**: Displays license status whether enforcement is enabled or not
- **Both servers validated**: Preprod + Prod banners rendering correctly as alert-info with license messages
