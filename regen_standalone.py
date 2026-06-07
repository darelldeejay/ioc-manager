"""
regen_standalone.py — Regenera feeds desde SQLite SIN importar Flask.
Uso: python3 regen_standalone.py
"""
import os, sys, json
from datetime import datetime

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

# Mapa tag → archivo de feed
TAG_FILES = {
    "Multicliente": os.path.join(BASE_DIR, "ioc-feed.txt"),
    FEED2_TAG:      os.path.join(BASE_DIR, "ioc-feed-bpe.txt"),
    "Test":         os.path.join(BASE_DIR, "ioc-feed-test.txt"),
}

def write_feed(path, lines):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)

def main():
    db.init_db()
    all_ips = db.get_all_ips()
    print(f"Total IPs en DB: {len(all_ips)}")

    # Agrupa IPs por tag
    tag_ips = {}
    for row in all_ips:
        ip = row["ip"]
        added_at = row.get("added_at") or datetime.now().strftime("%Y-%m-%d")
        # Normalizar formato fecha
        if "T" in str(added_at):
            added_at = str(added_at).split("T")[0]
        ttl = row.get("ttl", 0) or 0
        try:
            tags = json.loads(row.get("tags", "[]")) if isinstance(row.get("tags"), str) else row.get("tags", [])
        except Exception:
            tags = []
        line = f"{ip}|{added_at}|{ttl}"
        for tag in tags:
            tag_ips.setdefault(tag, []).append(line)

    # Escribe feeds canónicos
    for tag, path in TAG_FILES.items():
        lines = tag_ips.get(tag, [])
        write_feed(path, lines)
        print(f"  {os.path.basename(path):30s} → {len(lines):5d} IPs escritas")

    # Escribe feeds dinámicos para otros tags
    all_tags = set(tag_ips.keys()) - set(TAG_FILES.keys())
    for tag in sorted(all_tags):
        safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in tag)
        path = os.path.join(BASE_DIR, f"ioc-feed-{safe}.txt")
        lines = tag_ips.get(tag, [])
        write_feed(path, lines)
        print(f"  {os.path.basename(path):30s} → {len(lines):5d} IPs escritas (dyn)")

    print("\nFeeds regenerados OK.")

if __name__ == "__main__":
    main()
