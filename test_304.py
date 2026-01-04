import requests

url = "http://localhost:5000/feed/ioc-feed.txt"
headers = {"User-Agent": "FortiGate-60E"}

print(f"Requesting {url}...")
r1 = requests.get(url, headers=headers)
print(f"Response 1: {r1.status_code}")
etag = r1.headers.get("ETag")
print(f"ETag: {etag}")

if etag:
    headers["If-None-Match"] = etag
    print(f"Requesting with If-None-Match...")
    r2 = requests.get(url, headers=headers)
    print(f"Response 2: {r2.status_code}")
    if r2.status_code == 304:
        print("SUCCESS: Received 304 Not Modified")
    else:
        print(f"FAILED: Expected 304, got {r2.status_code}")
else:
    print("FAILED: No ETag returned in first response")
