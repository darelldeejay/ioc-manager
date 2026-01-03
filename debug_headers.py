import requests

urls = [
    "https://data-exchange.aiuken.com/attributes/text/download/ip-src",
    "http://cinsscore.com/list/ci-badguys.txt",
    "http://127.0.0.1:5000/feed/ioc-feed.txt"
]

print("=== HEADER ANALYSIS ===")
for u in urls:
    try:
        print(f"\n[TARGET] {u}")
        # Use verify=False to avoid SSL cert issues with local/self-signed if any
        h = requests.head(u, timeout=10, verify=False).headers
        for k,v in h.items():
            print(f"  {k}: {v}")
    except Exception as e:
        print(f"  ERROR: {e}")
print("\n=======================")
