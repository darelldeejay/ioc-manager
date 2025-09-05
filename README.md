# 🛡️ IOC Manager

IOC Manager es una aplicación web ligera en **Flask** para gestionar listas dinámicas de IPs maliciosas (Indicators of Compromise) usado para el ejemplo con el fabricante **Fortinet en un FortiGate** mediante conectores externos.

## ✨ Funcionalidades principales

- Alta de IPs manual (con validación de formato, duplicados y rangos).
- Carga masiva desde archivos `.csv`/`.txt`.
- Eliminación individual, total o por patrón (CIDR, rango, IP+máscara).
- Sistema de **notificaciones persistentes** con historial y filtros (tipo/fecha).
- **Toasts interactivos** que muestran la última acción realizada.
- Contador de IPs activas (manuales y CSV).
- Modo oscuro/claro.
- Logo fijo y UI optimizada para escritorio y móvil.

## 🖼️ Interfaz

- Panel principal con IPs activas, fechas y TTL.
- Botón de notificaciones con burbuja de “no leídas”.
- Historial filtrable con paginación.
- Buscador rápido de IPs en tabla.

## ⚙️ Tecnologías usadas

- **Python 3.11**
- **Flask 3**
- **Bootstrap 5**
- **Gunicorn** (producción)
- **Docker / docker-compose** (despliegue)
- Archivos planos (`txt/json`) como almacenamiento ligero.

## 🚀 Despliegue en Docker

### 1) Prepara entorno
- Clona el repo y entra en el directorio.
- Crea `.env` a partir de `.env.example`.
- Asegúrate de tener los archivos: `ioc-feed.txt`, `notif-log.json`, `ioc-meta.json` y `ioc-log.txt`.
  (Si no existen, se crean automáticamente).

### 2) Construye y levanta
```bash
docker compose build
docker compose up -d
# Abre http://localhost:5050
```

### 3) Logs y ciclo de vida
```bash
docker compose logs -f
docker compose down
```

### 4) Persistencia
Los archivos de datos se **montan desde el host**:
- `ioc-feed.txt` – base principal (IP|fecha|ttl)
- `notif-log.json` – historial de notificaciones
- `ioc-meta.json` – meta por IP (origen manual/csv)
- `ioc-log.txt` – log de acciones

### 5) Variables útiles
Configurables por `.env` o variables del contenedor:
- `SECRET_KEY` – clave de sesión Flask
- `GUNICORN_*` – afinado de rendimiento (workers, threads, timeout, etc.)

## 🔧 Desarrollo local

### Crear entorno virtual
```bash
make venv
```

### Ejecutar en desarrollo
```bash
make dev
```

### Ejecutar con Gunicorn
```bash
make gunicorn
```

## 🛠️ Makefile

El proyecto incluye un `Makefile` con tareas rápidas:
- `make venv` → crea entorno virtual
- `make dev` → ejecuta Flask en modo desarrollo
- `make gunicorn` → ejecuta con Gunicorn local
- `make build` → construye imagen docker
- `make up` → levanta contenedor en segundo plano
- `make down` → detiene y borra contenedor
- `make logs` → muestra logs en vivo
- `make backup` → crea copia de seguridad de los archivos `.txt/.json`
- `make restore DIR=./backup_YYYYmmdd_HHMMSS` → restaura desde backup

## 👤 Autor

Proyecto desarrollado por **Darell Pérez (darelldeejay)**.  
Todos los derechos reservados.
