from datetime import datetime, timezone, timedelta
from smartlocks import OmnitecProvider

def main():
    lock = OmnitecProvider(
        clientId     = "4GjHHsiafbmu0W6sV5k67eUuQIIwB5VgyWv",
        clientSecret = "M6vKBxJMJIIzkfn063Ra0kjb6XW1H3dNMMq",
        username     = "omniopbdo_integrators2",
        password     = "972688"
    )

    lock_id   = "8279953"
    starts_at = datetime.now(timezone.utc)
    ends_at   = starts_at + timedelta(hours=1)

    # ── Test connection ──────────────────────────────────────────────────────
    print("=== TEST CONNECTION ===")
    result = lock.test_connection()
    print(f"Conexion correcta: {result}\n")

    # ── Codigo aleatorio ─────────────────────────────────────────────────────
    print("=== CREAR CODIGO ALEATORIO ===")
    random_result = lock.create_code(lock_id, starts_at, ends_at)
    print(f"PIN: {random_result.pin} | ID: {random_result.code_id}\n")

    # ── Modificar codigo aleatorio ───────────────────────────────────────────
    print("=== MODIFICAR CODIGO ALEATORIO ===")
    new_ends_at = ends_at + timedelta(hours=1)
    random_result = lock.modify_code(lock_id, random_result.code_id, starts_at, new_ends_at)
    print(f"PIN: {random_result.pin} | ID: {random_result.code_id}\n")

    # ── Invalidar codigo aleatorio ───────────────────────────────────────────
    print("=== INVALIDAR CODIGO ALEATORIO ===")
    lock.invalidate_code(lock_id, random_result.code_id)
    print("Codigo aleatorio invalidado\n")

    # ── Codigo personalizado ─────────────────────────────────────────────────
    print("=== CREAR CODIGO PERSONALIZADO ===")
    custom_result = lock.create_code(lock_id, starts_at, ends_at, pin="0123456")
    print(f"PIN: {custom_result.pin} | ID: {custom_result.code_id}\n")

    # ── Modificar codigo personalizado ───────────────────────────────────────
    print("=== MODIFICAR CODIGO PERSONALIZADO ===")
    custom_result = lock.modify_code(lock_id, custom_result.code_id, starts_at, new_ends_at)
    print(f"PIN: {custom_result.pin} | ID: {custom_result.code_id}\n")

    # ── Invalidar codigo personalizado ───────────────────────────────────────
    print("=== INVALIDAR CODIGO PERSONALIZADO ===")
    lock.invalidate_code(lock_id, custom_result.code_id)
    print("Codigo personalizado invalidado\n")

if __name__ == "__main__":
    main()