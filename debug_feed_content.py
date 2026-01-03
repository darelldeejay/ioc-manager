from app import app
import sys

# Hack to run route context or just mimic logic
FEED_FILE = "ioc-feed.txt"
ips = []

try:
    with open(FEED_FILE, encoding="utf-8") as f:
        for line in f:
            # Replicate app.py logic exactly
            ip = line.split("|", 1)[0].strip()
            # Simple allow check simulation
            if ip:
                ips.append(ip)
except Exception as e:
    print(e)

print(f"Total IPs loaded: {len(ips)}")
if len(ips) > 0:
    print("--- First 5 Lines ---")
    for i in range(5):
        print(f"'{ips[i]}'")
    print("---------------------")

print("--- Checking for invalid chars ---")
for ip in ips:
    if " " in ip or "/" in ip:
         print(f"Suspicious entry: '{ip}'")
         break
else:
    print("No spaces or slashes found in IPs.")
