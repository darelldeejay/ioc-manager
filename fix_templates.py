
import os

# Contenido CORRECTO para test_notif.html
content_test = """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Test Notificaciones</title>
</head>
<body>
    <h1>Test de Renderizado de Notificaciones</h1>
    <div id="output" style="white-space: pre; font-family: monospace; background: #f0f0f0; padding: 10px; border: 1px solid #ccc;">Cargando...</div>
    <div id="error" style="color: red; margin-top: 10px;"></div>
    
    <script>
        window.addEventListener('load', function() {
            try {
                // NOTA: La siguiente linea NO debe tener espacios entre las llaves
                const serverMessages = [
                    {% for category, message in (messages or []) %}
                        { "category": "{{ category }}", "message": {{ message | tojson }} }{% if not loop.last %},{% endif %}
                    {% endfor %}
                ];
                
                console.log('serverMessages:', serverMessages);
                const outDoc = document.getElementById('output');
                if (outDoc) {
                    outDoc.textContent = 'EXITO: ' + JSON.stringify(serverMessages, null, 2);
                    outDoc.style.backgroundColor = '#e8f5e9';
                    outDoc.style.border = '2px solid green';
                }
            } catch (e) {
                console.error('ERROR JS:', e);
                const errDoc = document.getElementById('error');
                if (errDoc) errDoc.textContent = 'Error ejecutando JS: ' + e.message;
            }
        });
    </script>
</body>
</html>"""

# Contenido para arreglar index.html (solo el bloque problematico)
# Leemos el archivo original
with open('templates/index.html', 'r', encoding='utf-8') as f:
    index_content = f.read()

# Reemplazamos el patron erroneo (con espacios) por el correcto
fixed_index = index_content.replace('{ { message | tojson } }', '{{ message | tojson }}')

# Escribimos los archivos
try:
    with open('templates/test_notif.html', 'w', encoding='utf-8') as f:
        f.write(content_test)
    print("✅ templates/test_notif.html reescrito correctamente.")
    
    if fixed_index != index_content:
        with open('templates/index.html', 'w', encoding='utf-8') as f:
            f.write(fixed_index)
        print("✅ templates/index.html corregido (se eliminaron espacios extra).")
    else:
        # Intentamos busqueda mas laxa si no coincidio exacto
        import re
        fixed_index_re = re.sub(r'\{\s+\{\s+message\s+\|\s+tojson\s+\}\s+\}', '{{ message | tojson }}', index_content)
        if fixed_index_re != index_content:
            with open('templates/index.html', 'w', encoding='utf-8') as f:
                f.write(fixed_index_re)
            print("✅ templates/index.html corregido via Regex.")
        else:
            print("ℹ️ templates/index.html parece que ya estaba bien (no se encontraron cambios).")

except Exception as e:
    print(f"❌ Error escribiendo archivos: {e}")

