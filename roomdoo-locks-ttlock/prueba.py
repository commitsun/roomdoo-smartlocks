from roomdoo_locks_ttlock import TTLockProvider
from datetime import datetime, timezone, timedelta

CLIENT_ID     = "87e9544b31144fe2bd1aee5ada73bda9"
CLIENT_SECRET = "076b574ad0cb79de135852aa141d6ab9"
USERNAME      = "javierportosin@gmail.com"
PASSWORD      = "ace2a1d44d375fc3a93329c490aed077"
LOCK_ID       = "30264454"

provider = TTLockProvider(CLIENT_ID, CLIENT_SECRET, USERNAME, PASSWORD)
print(f"Autenticado correctamente. Token: {provider.accessToken[:10]}...")
print()
 
starts_at = datetime.now(timezone.utc)
ends_at   = starts_at + timedelta(hours=1)
 
print("--- Crear código ---")
result = provider.create_code(LOCK_ID, starts_at, ends_at)
print(f"PIN:          {result.pin}")
print(f"ID:           {result.code_id}")
print(f"Válido desde: {result.starts_at.strftime('%d/%m/%Y %H:%M')} UTC")
print(f"Válido hasta: {result.ends_at.strftime('%d/%m/%Y %H:%M')} UTC")
print()
 
input("Comprueba en la app de TTLock que el código existe. Pulsa Enter para modificarlo...")

print("--- Modificar código ---")
starts_at = datetime.now(timezone.utc)
ends_at   = starts_at + timedelta(hours=24)

result = provider.modify_code(LOCK_ID, result.code_id, starts_at, ends_at)
print(f"Código modificado correctamente.")
print(f"ID:           {result.code_id}")
print(f"Válido desde: {result.starts_at.strftime('%d/%m/%Y %H:%M')} UTC")
print(f"Válido hasta: {result.ends_at.strftime('%d/%m/%Y %H:%M')} UTC")
print()
