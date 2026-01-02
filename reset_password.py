
import sys
import argparse
from werkzeug.security import generate_password_hash
import db

def reset_password(username, new_password):
    """
    Resetea la contraseña de un usuario existente.
    """
    print(f"[*] Intentando resetear contraseña para: {username}")
    
    # 1. Verificar si usuario existe
    user = db.get_user_by_username(username)
    if not user:
        print(f"[!] Error: El usuario '{username}' no existe.")
        return False
        
    # 2. Hash nueva password
    pwd_hash = generate_password_hash(new_password)
    
    # 3. Actualizar DB
    if db.update_user(username, password_hash=pwd_hash):
        print(f"[+] Contraseña actualizada correctamente para '{username}'.")
        return True
    else:
        print(f"[!] Error en base de datos al actualizar.")
        return False

def main():
    parser = argparse.ArgumentParser(description="Herramienta de recuperación de contraseña IOC Manager")
    parser.add_argument("username", help="Nombre de usuario (ej: admin)")
    parser.add_argument("password", help="Nueva contraseña")
    
    args = parser.parse_args()
    
    db.init_db() # Asegurar conexión
    reset_password(args.username, args.password)

if __name__ == "__main__":
    main()
