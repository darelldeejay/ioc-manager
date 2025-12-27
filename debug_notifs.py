import sys
sys.path.insert(0, '.')
from app import get_notifs

# Simular lo que hace el código en index()
messages = []
request_actions = []  # Vacío para esta prueba

messages.extend(request_actions)
try:
    for n in get_notifs(limit=200):
        cat = str(n.get("category", "secondary"))
        msg = f"{n.get('time','')} {n.get('message','')}".strip()
        messages.append((cat, msg))
        print(f"Añadido: ({cat}, {msg[:50]}...)")
except Exception as e:
    print(f"ERROR: {e}")
    pass

print(f"\nTotal messages para template: {len(messages)}")
print(f"Primeros 3:")
for i, (cat, msg) in enumerate(messages[:3]):
    print(f"  {i+1}. category='{cat}', message='{msg[:60]}...'")
