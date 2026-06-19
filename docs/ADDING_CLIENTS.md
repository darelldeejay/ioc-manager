# Guía: Cómo añadir un nuevo cliente (feed dedicado)

> **IMPORTANTE**: Los nombres reales de los clientes NO se suben a GitHub.
> Los cambios se implementan primero en **preprod**, se prueban, y luego se pasan a **prod** manualmente.
> `app.py` con nombres de clientes queda en local/servidores pero NO en el repositorio público.

---

## Conceptos clave

Cada cliente tiene:
- Un **tag canónico**: string normalizado que identifica al cliente (ej. `Ypfb_Refino`)
- Un **feed file**: archivo de texto plano servido a FortiGate (ej. `ioc-feed-Ypfb_Refino.txt`)
- Un **lock file**: previene escrituras concurrentes (se crea automáticamente con `FileLock`)
- Una entrada en **`FEEDS_CONFIG`**: controla qué aparece en la UI
- Una entrada en **`CANONICAL_TAGS`**: normaliza variantes de escritura del nombre del tag
- Una entrada en **`ALLOWED_TAGS`**: marca el tag como válido en el sistema
- Una entrada en **`_get_feed_filename()`**: mapea tag → ruta de archivo

### Reglas de nomenclatura de tags
- Solo letras, números, guiones y guiones bajos: `[A-Za-z0-9\-_]`
- Caracteres especiales como `&`, `.`, `/` → reemplazar por `_`
- Ejemplos:
  - `Ferrer & Ojeda` → `Ferrer_Ojeda`
  - `Ypfb Refino` → `Ypfb_Refino`
  - `BPE-Norte` → `BPE_Norte`

---

## Pasos para añadir un nuevo cliente

Supongamos que el nuevo cliente se llama `NombreCliente`.

### Paso 1 — Variable de ruta del feed

Localizar el bloque de `FEED_FILE_*` al principio de `app.py` (~línea 68) y añadir:

```python
# === Feeds adicionales clientes ===
FEED_FILE_NOMBRECLIENTE = os.path.join(BASE_DIR, 'ioc-feed-NombreCliente.txt')
```

### Paso 2 — Lock file

Localizar el bloque `LOCK FILES` (~línea 88) y añadir:

```python
FEED_NOMBRECLIENTE_LOCK = FileLock(FEED_FILE_NOMBRECLIENTE + ".lock")
```

### Paso 3 — ALLOWED_TAGS

Localizar `ALLOWED_TAGS` (~línea 131) y añadir el tag al set:

```python
ALLOWED_TAGS = {"Multicliente", FEED2_TAG, "CCP", "Test", ..., "NombreCliente"}
```

### Paso 4 — CANONICAL_TAGS

Localizar `CANONICAL_TAGS` (~línea 134) y añadir las claves de normalización:

```python
CANONICAL_TAGS = {
    ...
    "nombrecliente": "NombreCliente",       # clave en minúsculas
    "nombre_cliente": "NombreCliente",      # variante con guión bajo (si aplica)
    "nombre cliente": "NombreCliente",      # variante con espacio (si aplica)
    ...
}
```
> Añadir tantas variantes como formas pueda escribirlo un operador.

### Paso 5 — FEEDS_CONFIG

Localizar `FEEDS_CONFIG` (~línea 2229) y añadir la entrada:

```python
FEEDS_CONFIG = {
    ...
    "nombrecliente": {"file": FEED_FILE_NOMBRECLIENTE, "label": "Feed Nombre Cliente", "icon": "bi-building"},
}
```

Iconos disponibles (Bootstrap Icons): `bi-building`, `bi-briefcase`, `bi-people`, `bi-person-badge`, `bi-bank`, `bi-hdd-network`, `bi-globe`

### Paso 6 — _get_feed_filename()

Localizar la función `_get_feed_filename()` (~línea 1877) y añadir el caso antes del bloque `else`:

```python
elif t_lower in ("nombrecliente", "nombre_cliente"):
    return FEED_FILE_NOMBRECLIENTE
```

---

## Checklist completo

```
[ ] Paso 1: FEED_FILE_NOMBRECLIENTE  (variable ruta)
[ ] Paso 2: FEED_NOMBRECLIENTE_LOCK  (lock file)
[ ] Paso 3: ALLOWED_TAGS             (añadir tag al set)
[ ] Paso 4: CANONICAL_TAGS           (añadir variantes en minúsculas)
[ ] Paso 5: FEEDS_CONFIG             (añadir a UI)
[ ] Paso 6: _get_feed_filename()     (mapeo tag → archivo)
```

---

## Despliegue

### Preprod (siempre primero)
```powershell
scp "app.py" ioc-preprod:~/ioc-manager/app.py
ssh ioc-preprod "pkill -9 gunicorn; sleep 2; cd ~/ioc-manager && nohup /home/darell/ioc-manager/venv/bin/gunicorn --chdir ~/ioc-manager --config gunicorn_config.py app:app > /tmp/gunicorn.log 2>&1 &"
```

### Verificación en preprod
Confirmar que el cliente aparece en la UI y que el feed se sirve correctamente.

### Prod (solo tras validación en preprod)
```powershell
scp "app.py" ioc-prod:~/ioc-manager/app.py
ssh ioc-prod "pkill -9 gunicorn; sleep 2; cd ~/ioc-manager && nohup ~/.venv/bin/gunicorn --chdir ~/ioc-manager --config gunicorn_config.py app:app > /tmp/gunicorn.log 2>&1 &"
```

---

## GitHub — Qué NO subir

Los nombres de clientes reales son información sensible comercial.  
**Nunca hacer `git add app.py` si contiene nombres de clientes reales** a menos que estén anonimizados o sean genéricos.

Si se necesita subir una versión limpia a GitHub, restaurar el `app.py` del repo:
```bash
git checkout origin/main -- app.py
```
y hacer los cambios de clientes solo en los servidores directamente.

---

## Clientes activos actualmente

> Esta sección se mantiene en `docs/ADDING_CLIENTS.local.md` (ignorado por git).
> No aparece en GitHub. Ver ese archivo para la lista real de clientes.
