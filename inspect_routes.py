from app import app

print("--- Rules ---")
for rule in app.url_map.iter_rules():
    print(f"{rule.endpoint}: {rule}")

print("\n--- Check backup_now ---")
if 'backup_now' in app.view_functions:
    print("backup_now FOUND in view_functions")
else:
    print("backup_now NOT FOUND in view_functions")
