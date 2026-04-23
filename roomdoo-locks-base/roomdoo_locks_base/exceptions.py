from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from roomdoo_locks_base.models import CodeResult


class LockError(Exception):
    """
    Base exception for all lock library errors. Not raised directly.

    Simple exceptions (LockAuthError, LockNotFoundError, etc.) use the
    default Exception constructor — the type alone is often enough context.
    LockOperationError and its subclasses require an explicit message because
    the vendor-specific reason is essential for diagnosis.
    """

    pass


class LockAuthError(LockError):
    """Invalid credentials or token refresh failed."""

    pass


class LockNotFoundError(LockError):
    """The provided lock_id does not exist or is not accessible."""

    pass


class LockCodeNotFoundError(LockError):
    """The provided code_id does not exist."""

    pass


class LockConnectionError(LockError):
    """Vendor API did not respond after exhausting retries."""

    pass


class LockOperationError(LockError):
    """Vendor API rejected the operation for a business reason."""

    def __init__(self, message: str):
        self.message = message
        super().__init__(message)


class LockCodeDeletionError(LockOperationError):
    """New code was created but the old one could not be invalidated.

    The caller should update records with ``new_result`` and retry
    invalidation of ``old_code_id`` separately.
    """

    def __init__(self, message: str, old_code_id: str, new_result: CodeResult):
        self.old_code_id = old_code_id
        self.new_result = new_result
        super().__init__(message)

class LockAPIError(LockOperationError):
    """Vendor API didn't return a body."""

    def __init__(self, message: str):
        self.message = message
        super().__init__(message)

class LockNoPermissionError(LockOperationError):
    """User doesn't have permission to perform the operation on the lock."""

    def __init__(self, message: str):
        self.message = message
        super().__init__(message)

class LockOfflineError(LockOperationError):
    """Lock is offline."""

    def __init__(self, message: str):
        self.message = message
        super().__init__(message)
