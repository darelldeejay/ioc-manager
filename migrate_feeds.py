"""
migrate_feeds.py — Migración de datos legacy (archivos planos) a SQLite.

Uso:
    python migrate_feeds.py [--dry-run]

Qué hace:
    1. Inicializa la base de datos SQLite (ioc_manager.db) si no existe.
    2. Lee ioc-feed.txt       → IPs con tag Multicliente
    3. Lee ioc-feed-bpe.txt   → IPs con tag FEED2_TAG (BPE en servidores)
    4. Lee ioc-feed-test.txt  → IPs con tag Test
    5. Inserta/actualiza cada IP en SQLite via db.upsert_ip().
    6. Regenera todos los feeds desde la DB (regenerate_feeds_from_db).

En caso de IP duplicada entre feeds, acumula los tags.
"""

import os
import sys
import json
import argparse
from datetime import datetime

# Asegurar que importamos desde el mismo directorio
BASE_DIR = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, BASE_DIR)

import db

# Cargar .env si existe
env_file = os.path.join(BASE_DIR, ".env")
if os.path.exists(env_file):
    with open(env_file) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())

FEED2_TAG = os.getenv("FEED2_TAG", "Cliente")

FEED_MAP = {
    os.path.join(BASE_DIR, "ioc-feed.txt"):      "Multicliente",
    os.path.join(BASE_DIR, "ioc-feed-bpe.txt"):  FEED2_TAG,
    os.path.join(BASE_DIR, "ioc-feed-test.txt"): "Test",
}


def parse_args():
    p = argparse.ArgumentParser(description="Migración legacy → SQLite")
    p.add_argument("--dry-run", action="store_true",
                   help="Solo muestra lo que haría, sin escribir en la DB")
    return p.parse_args()


def load_feed(path):
    """Lee un feed y devuelve lista de (ip, added_at, ttl)."""
    entries = []
    if not os.path.exists(path):
        return entries
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split("|")
            if len(parts) < 1:
                continue
            ip = parts[0].strip()
            added_at = parts[1].strip() if len(parts) > 1 else datetime.now().strftime("%Y-%m-%d")
            ttl = int(parts[2].strip()) if len(parts) > 2 else 0
            entries.append((ip, added_at, ttl))
    return entries


def main():
    args = parse_args()
    dry = args.dry_run

    print(f"{'[DRY RUN] ' if dry else ''}Iniciando migración — FEED2_TAG={FEED2_TAG}")
    print("-" * 60)

    # Recopilar todas las IPs agrupadas por IP (puede estar en varios feeds)
    ip_data = {}  # ip -> {added_at, ttl, tags: set}

    for feed_path, tag in FEED_MAP.items():
        entries = load_feed(feed_path)
        print(f"  {os.path.basename(feed_path):30s} → {len(entries):5d} IPs  (tag: {tag})")
        for ip, added_at, ttl in entries:
            if ip not in ip_data:
                ip_data[ip] = {"added_at": added_at, "ttl": ttl, "tags": set()}
            ip_data[ip]["tags"].add(tag)
            # Mantener el TTL más alto (0 = permanente)
            if ip_data[ip]["ttl"] == 0 or ttl == 0:
                ip_data[ip]["ttl"] = 0

    print("-" * 60)
    print(f"  Total IPs únicas: {len(ip_data)}")

    if dry:
        print("\n[DRY RUN] No se escribe nada. Ejecuta sin --dry-run para migrar.")
        return

    # Inicializar DB
    db.init_db()
    print("\nBase de datos inicializada.")

    # Insertar en SQLite
    ok = 0
    errors = 0
    for ip, data in ip_data.items():
        try:
            tags_list = sorted(data["tags"])
            db.upsert_ip(
                ip=ip,
                source="manual",
                tags=json.dumps(tags_list),
                ttl=data["ttl"],
                expiration_date=None,
                alert_ids="[]",
                history="[]",
            )
            ok += 1
        except Exception as e:
            print(f"  [ERROR] {ip}: {e}")
            errors += 1

    print(f"  Insertadas/actualizadas: {ok}")
    if errors:
        print(f"  Errores: {errors}")

    # Regenerar feeds desde la DB (sin importar Flask)
    print("\nRegenerando feeds desde SQLite...")
    try:
        import subprocess
        result = subprocess.run(
            [sys.executable, os.path.join(BASE_DIR, "regen_standalone.py")],
            capture_output=True, text=True, timeout=60
        )
        print(result.stdout.strip())
        if result.returncode != 0:
            print(f"  [AVISO] {result.stderr.strip()}")
    except Exception as e:
        print(f"  [AVISO] No se pudo regenerar automáticamente: {e}")
        print("  → Ejecuta: python3 regen_standalone.py")

    print("\n✓ Migración completada.")
    print(f"  Verifica con: python3 -c \"import db; rows=db.get_all_ips(); print(len(rows), 'IPs en DB')\"")


if __name__ == "__main__":
    main()
