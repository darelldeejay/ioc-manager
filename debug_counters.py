import json

# Cargar meta
with open('ioc-meta.json', 'r', encoding='utf-8') as f:
    meta = json.load(f)

# Cargar feeds
with open('ioc-feed.txt', 'r', encoding='utf-8') as f:
    lines_main = [l.strip() for l in f if l.strip()]

with open('ioc-feed-test.txt', 'r', encoding='utf-8') as f:
    lines_test = [l.strip() for l in f if l.strip()]

# Extraer IPs de cada feed
ips_main = {l.split('|')[0] for l in lines_main}
ips_test = {l.split('|')[0] for l in lines_test}

# Unión de IPs activas
active_union_ips = ips_main.union(ips_test)

# Obtener meta by_ip
meta_by_ip = meta.get('by_ip', {})

# Calcular contadores
live_manual = sum(1 for ip in active_union_ips if meta_by_ip.get(ip) == 'manual')
live_csv = sum(1 for ip in active_union_ips if meta_by_ip.get(ip) == 'csv')
live_api = sum(1 for ip in active_union_ips if meta_by_ip.get(ip) == 'api')

print(f"IPs en feed principal: {ips_main}")
print(f"IPs en feed test: {ips_test}")
print(f"IPs activas (unión): {active_union_ips}")
print(f"\nContadores:")
print(f"  Manual: {live_manual}")
print(f"  CSV: {live_csv}")
print(f"  API: {live_api}")
print(f"\nDetalles meta['by_ip']:")
for ip in active_union_ips:
    origen = meta_by_ip.get(ip, 'NO_ENCONTRADO')
    print(f"  {ip}: {origen}")
