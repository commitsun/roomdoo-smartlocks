from ttlock import TTLockClient, TTLockAuthError

CLIENT_ID     = ""
CLIENT_SECRET = ""
USERNAME      = ""
PASSWORD      = ""

client = TTLockClient(client_id=CLIENT_ID, client_secret=CLIENT_SECRET)

print("1. Obtención de token de acceso...\n" \
"2. Listado de cerraduras...\n" \
"3. Detalles de la primera cerradura...\n" \
"4. Creación de un código de acceso temporal...\n" \
"5. Borrado del código creado...\n" \
"6. Fin de la prueba."
)

print("Introduce un número del 1 al 6 para avanzar en la prueba:\n")

token = None
lock_list = None
lock_info = None
access_code_response = None

while True:
    choice = input()
    match choice:
        case "1":
            token = client.get_token(USERNAME, PASSWORD)
            print("Token:", token.access_token)
            print("Expira en:", token.expires_in, "segundos")
        
        case "2":
            if token is None:
                print("Primero obtén el token (caso 1).")
                continue
            lock_list = client.get_lock_list(token.access_token)
            print("Número de cerraduras:", lock_list.total)
            print("Cerraduras:", [lock.lock_alias for lock in lock_list.locks])
        
        case "3":
            if token is None or lock_list is None:
                print("Primero obtén el token (caso 1) y lista las cerraduras (caso 2).")
                continue
            lock_info = client.get_lock_info(token.access_token, lock_list.locks[0].lock_id)
            print("Información de la primera cerradura:", lock_info)
        
        case "4":
            if token is None:
                print("Primero obtén el token (caso 1).")
                continue
            access_code_response = client.get_access_code(
                access_token=token.access_token,
                lock_id="30264454",
                keyboard_pwd_type="1",
                keyboard_pwd_name="Código de acceso temporal 4",
                start_date=1775561055462,
                end_date=1785842640000
            )
            print("Código creado:", access_code_response.keyboard_pwd)
            print("ID del código:", access_code_response.keyboard_pwd_id)
        
        case "5":
            if token is None or access_code_response is None:
                print("Primero obtén el token (caso 1) y crea un código (caso 4).")
                continue
            deleted = client.delete_access_code(
                access_token=token.access_token,
                lock_id="30264454",
                keyboard_pwd_id=access_code_response.keyboard_pwd_id,
                delete_type=2
            )
            print("Borrado correctamente:", deleted)
        
        case "6":
            print("Fin de la prueba.")
            break
        
        case _:
            print("Opción no válida. Introduce un número del 1 al 6.")
    
    if choice != "6":
        print("\nIntroduce otro número del 1 al 6 para continuar, o 6 para salir:\n")