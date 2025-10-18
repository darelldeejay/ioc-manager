"""
gunicorn_config.py — Config optimizada para IOC Manager (API con tags)

Puntos clave:
- Mantiene compatibilidad con tu despliegue actual.
- Aumenta timeout para peticiones /api/bloquear-ip con lotes grandes (Torq, etc.).
- Activa preload_app para reducir overhead al arrancar y mejorar respuesta inicial.
- loglevel 'info' para visibilidad razonable (ajústalo a 'warning' si quieres menos ruido).
- workers=1 por defecto en equipos pequeños; súbelo a 2 si esperas más concurrencia.
"""

import os

# Trabaja siempre desde la carpeta del proyecto (evita rutas relativas raras)
os.chdir(os.path.dirname(os.path.abspath(__file__)))

# Dirección/puerto de escucha (coherente con tu app.py en 5050 si lo prefieres)
bind = "0.0.0.0:5000"  # Cambia a 0.0.0.0:5050 si quieres unificar con app.py

# Nº de workers: 1 para Raspberry/entornos pequeños. Sube a 2 si usas /api intensivamente.
workers = 1

# Timeout ampliado para lotes grandes (CIDR/rangos) y E/S de disco en ficheros de tags/meta
timeout = 180

# Precarga la app una vez por worker (reduce memoria duplicada y acelera primeras respuestas)
preload_app = True

# Nivel de logs (info recomendado en operación; warning si quieres menos ruido)
loglevel = "info"

# — Opcional: formato de access log (útil para diferenciar tráfico API vs UI) —
# access_log_format = '%(h)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(U)s'

# — Opcional: limitar tamaño de backlog si hay picos —
# backlog = 2048

# — Opcional: threads por worker (Gunicorn + gthread). Normalmente no necesario con Flask simple —
# threads = 1
