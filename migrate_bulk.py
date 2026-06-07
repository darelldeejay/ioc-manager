"""
migrate_bulk.py — Migración bulk con UNA sola transaccion SQLite.
Evita el problema de 3940 commits individuales.
Uso: python3 migrate_bulk.py
"""
import os, sys, json, sqlite3
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, BASE_DIR)

# Cargar .env
env_file = os.path.join(BASE_DIR, ".env")
if os.path.exists(env_file):
    with open(env_file) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())

FEED2_TAG = os.getenv("FEED2_TAG", "Cliente")
DB_FILE   = os.path.join(BASE_DIR, "ioc_manager.db")

FEED_MAP = {
    os.path.join(BASE_DIR, "ioc-feed.txt"):      "Multicliente",
    os.path.join(BASE_DIR, "ioc-feed-bpe.txt"):  FEED2_TAG,
    os.path.join(BASE_DIR, "ioc-feed-test.txt"): "Test",
}

def load_feed(path):
    entries = []
    if not os.path.exists(path):
        return entries
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split("|")
            ip       = parts[0].strip()
            added_at = parts[1].strip() if len(parts) > 1 else datetime.now().strftime("%Y-%m-%d")
            ttl      = int(parts[2].strip()) if len(parts) > 2 else 0
            entries.append((ip, added_at, ttl))
    return entries

def main():
    print(f"migrate_bulk.py — FEED2_TAG={FEED2_TAG}")
    print(f"DB: {DB_FILE}")
    print("-" * 60)

    # Leer todos los feeds
    ip_data = {}
    for feed_path, tag in FEED_MAP.items():
        entries = load_feed(feed_path)
        print(f"  {os.path.basename(feed_path):30s} → {len(entries):5d} IPs  (tag: {tag})")
        for ip, added_at, ttl in entries:
            if ip not in ip_data:
                ip_data[ip] = {"added_at": added_at, "ttl": ttl, "tags": set()}
            ip_data[ip]["tags"].add(tag)
            if ttl == 0 or ip_data[ip]["ttl"] == 0:
                ip_data[ip]["ttl"] = 0

    print(f"\n  Total IPs únicas: {len(ip_data)}")

    # Conectar directamente a SQLite
    conn = sqlite3.connect(DB_FILE, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")

    # Crear tabla si no existe (misma definicion que db.py)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ip_metadata (
            ip TEXT PRIMARY KEY,
            source TEXT,
            tags TEXT DEFAULT '[]',
            added_at TEXT,
            ttl INTEGER DEFAULT 0,
            expiration_date TEXT,
            alert_ids TEXT DEFAULT '[]',
            history TEXT DEFAULT '[]'
        )
    """)
    conn.commit()

    # Bulk upsert en UNA transaccion
    print("\nInsertando en SQLite (una sola transaccion)...")
    rows = []
    now_str = datetime.now().strftime("%Y-%m-%d")
    for ip, data in ip_data.items():
        tags_list = sorted(data["tags"])
        added_at  = data["added_at"] or now_str
        rows.append((
            ip,
            "manual",
            json.dumps(tags_list),
            added_at,
            data["ttl"],
            None,
            "[]",
            "[]",
        ))

    conn.executemany("""
        INSERT INTO ip_metadata (ip, source, tags, added_at, ttl, expiration_date, alert_ids, history)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(ip) DO UPDATE SET
            source          = excluded.source,
            tags            = excluded.tags,
            added_at        = excluded.added_at,
            ttl             = excluded.ttl,
            expiration_date = excluded.expiration_date,
            alert_ids       = excluded.alert_ids,
            history         = excluded.history
    """, rows)
    conn.commit()

    # Verificar
    count = conn.execute("SELECT COUNT(*) FROM ip_metadata").fetchone()[0]
    conn.close()
    print(f"  Insertadas/actualizadas: {len(rows)}")
    print(f"  Verificacion DB: {count} IPs en ip_metadata")

    # Regenerar feeds
    print("\nRegenerando feeds desde SQLite...")
    import subprocess
    result = subprocess.run(
        [sys.executable, os.path.join(BASE_DIR, "regen_standalone.py")],
        capture_output=True, text=True, timeout=60
    )
    print(result.stdout.strip())
    if result.stderr.strip():
        print(f"STDERR: {result.stderr.strip()}")

    print("\nMigracion completada OK.")

if __name__ == "__main__":
    main()
