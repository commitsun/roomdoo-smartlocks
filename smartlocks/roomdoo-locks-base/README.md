# roomdoo-locks-base

Base contract for Roomdoo smart lock integrations. Defines the abstract interface, shared exceptions and return types that all vendor libraries must implement.

## Installation

```bash
pip install roomdoo-locks-base
```

## Implementing a vendor library

Subclass `BaseLockProvider` and implement all abstract methods:

```python
from datetime import datetime
from roomdoo_locks_base import BaseLockProvider, CodeResult


class MyVendorProvider(BaseLockProvider):

    def __init__(self, api_key: str, api_secret: str, **kwargs):
        # Authenticate, store tokens, configure retries, etc.
        ...

    def _do_create_code(self, lock_id: str, starts_at: datetime, ends_at: datetime) -> CodeResult:
        # Call vendor API, return CodeResult
        ...

    def _do_invalidate_code(self, lock_id: str, code_id: str) -> bool:
        # Call vendor API, return True
        ...

    def _do_modify_code(self, lock_id: str, code_id: str, starts_at: datetime, ends_at: datetime) -> CodeResult:
        # Modify or delete+create depending on vendor capabilities
        ...

    def test_connection(self) -> bool:
        # Verify credentials and API reachability
        ...
```

## Usage from the PMS

```python
from my_vendor_library import MyVendorProvider

provider = MyVendorProvider(api_key="...", api_secret="...")

# Create a code
result = provider.create_code("lock-123", starts_at, ends_at)
# result.code_id  -> vendor internal ID, needed for later operations
# result.pin      -> PIN the guest will type on the keypad

# Extend a checkout
new_result = provider.modify_code("lock-123", result.code_id, starts_at, new_ends_at)
# new_result.pin and new_result.code_id may have changed — always update your records

# Invalidate on checkout / cancellation
provider.invalidate_code("lock-123", new_result.code_id)
```

## Behavior rules

These rules apply to all vendor implementations:

### Datetimes

All datetimes must be **UTC** (`tzinfo` with zero offset). The base class validates this and raises `ValueError` if a non-UTC or naive datetime is passed. Timezone conversion to the hotel's local time is the PMS responsibility. `CodeResult` returns the effective datetimes as applied by the vendor, which may differ slightly from the requested ones.

The base class also validates that `starts_at < ends_at`, raising `ValueError` otherwise.

### `invalidate_code` is idempotent

If the code was already invalidated, expired, or never existed, the method returns `True` without raising an exception. The goal is to guarantee the code is not functional after the call, regardless of its previous state.

### `modify_code` abstracts the vendor strategy

Some vendors support direct modification of a code's validity window. Others don't, requiring a delete and recreate. The caller does not know or care which strategy was used. **Always treat `code_id` and `pin` in the result as potentially new values** and update records accordingly.

When using the create+delete strategy, implementations must create the new code first and delete the old one after. This ensures the guest always has a working code, even if the deletion of the old one fails. If deletion fails, raise `LockCodeDeletionError` with the new `CodeResult` and the `old_code_id` so the caller can update records and retry deletion.

### Token management is internal

The library handles token acquisition, refresh and retry transparently. The PMS passes credentials once in the constructor and never manages tokens.

### Retries are internal

Transient errors (timeouts, 5xx) are retried with exponential backoff inside the library. Only persistent failures surface as `LockConnectionError`. Auth and business errors are never retried.

## Exceptions

All exceptions inherit from `LockError`:

| Exception | Meaning |
|---|---|
| `LockAuthError` | Invalid credentials or token refresh failed |
| `LockNotFoundError` | The lock_id does not exist or is not accessible |
| `LockCodeNotFoundError` | The code_id does not exist (not raised by `invalidate_code`) |
| `LockConnectionError` | Vendor API unreachable after retries |
| `LockOperationError` | API rejected the operation (includes `message`) |
| `LockCodeDeletionError` | New code created but old one could not be invalidated (includes `old_code_id` and `new_result`) |

## CodeResult

Immutable dataclass returned by `create_code` and `modify_code`:

| Field | Type | Description |
|---|---|---|
| `code_id` | str | Vendor internal identifier, required for all subsequent operations |
| `pin` | str | PIN code the guest types on the keypad |
| `lock_id` | str | Lock identifier |
| `starts_at` | datetime | Effective start of validity (UTC) |
| `ends_at` | datetime | Effective end of validity (UTC) |
