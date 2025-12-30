
import pytest
import sys
import os

if __name__ == '__main__':
    # Ejecuta pytest sobre la carpeta tests
    # Devolvemos el código de salida de pytest directamente
    # -v: verbose, -c /dev/null: evita cargar configuraciones externas si las hubiera
    args = ["tests", "-v"]
    sys.exit(pytest.main(args))
