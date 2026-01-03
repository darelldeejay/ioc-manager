from db import get_all_ips, init_db
import json
import os

init_db()
rows = get_all_ips()
print(f"Total IPs in DB: {len(rows)}")

tags_dist = {}
for r in rows:
    try:
        ts = json.loads(r['tags'] or '[]')
    except:
        ts = []
    
    if not ts:
        tags_dist["<NO TAGS>"] = tags_dist.get("<NO TAGS>", 0) + 1
    
    for t in ts:
        tags_dist[t] = tags_dist.get(t, 0) + 1

print("\n--- Tag Distribution ---")
for k,v in tags_dist.items():
    print(f"{k}: {v}")

# Simulation of regenerate logic validation
print("\n--- Simulation ---")
FEED_FILE = "ioc-feed.txt"
cnt = 0
for r in rows:
    ts = json.loads(r['tags'] or '[]')
    # Check if 'Multicliente' is present (case insensitive)
    if any(t.lower() == "multicliente" for t in ts):
        cnt += 1
print(f"IPs that SHOULD act as Multicliente: {cnt}")
