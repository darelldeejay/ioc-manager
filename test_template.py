import sys
sys.path.insert(0, '.')
from app import get_notifs
from jinja2 import Template

# Simular el template
template_str = """
const serverMessages = [
  {% for category, message in (messages or []) %}
    { "category": "{{ category }}", "message": {{ message | tojson }} }{% if not loop.last %},{% endif %}
  {% endfor %}
];
"""

# Preparar datos como en index()
messages = []
try:
    for n in get_notifs(limit=200):
        cat = str(n.get("category", "secondary"))
        msg = f"{n.get('time','')} {n.get('message','')}".strip()
        messages.append((cat, msg))
except Exception as e:
    print(f"ERROR: {e}")

print(f"Total messages: {len(messages)}")
print("\nJavaScript generado:")
print("=" * 60)

template = Template(template_str)
output = template.render(messages=messages)
print(output)
print("=" * 60)

# Verificar si es JSON válido
import json
try:
    # Extraer el array
    start = output.find('[')
    end = output.rfind(']') + 1
    array_str = output[start:end]
    parsed = json.loads(array_str)
    print(f"\n✅ JSON válido! {len(parsed)} elementos parseados correctamente")
except Exception as e:
    print(f"\n❌ ERROR de JSON: {e}")
