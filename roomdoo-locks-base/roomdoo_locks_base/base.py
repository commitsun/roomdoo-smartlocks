from abc import ABC, abstractmethod
from datetime import datetime, timedelta

from roomdoo_locks_base.models import CodeResult

_ZERO = timedelta(0)


class BaseLockProvider(ABC):
    """
    Abstract interface for smart lock providers.

    Each vendor implements this class. The constructor receives vendor-specific
    credentials and internally manages tokens, refresh and retries.

    Subclasses override the ``_do_*`` methods. The public methods handle
    common validation (UTC datetimes, starts_at < ends_at) before
    delegating to the vendor-specific implementation.
    """

    @staticmethod
    def _validate_time_range(starts_at: datetime, ends_at: datetime) -> None:
        for dt, name in ((starts_at, "starts_at"), (ends_at, "ends_at")):
            if dt.tzinfo is None or dt.utcoffset() != _ZERO:
                raise ValueError(f"{name} must be a UTC datetime")
        if starts_at >= ends_at:
            raise ValueError("starts_at must be before ends_at")

    def create_code(self, lock_id: str, starts_at: datetime, ends_at: datetime) -> CodeResult:
        """
        Generate a PIN code on the lock, valid between starts_at and ends_at.

        Args:
            lock_id: Lock identifier on the vendor platform.
            starts_at: Start of validity window (UTC).
            ends_at: End of validity window (UTC).

        Returns:
            CodeResult with the created code data and effective datetimes.

        Raises:
            ValueError: Non-UTC datetimes or starts_at >= ends_at.
            LockAuthError: Invalid credentials.
            LockNotFoundError: Lock not found.
            LockConnectionError: API unreachable after retries.
            LockOperationError: API rejected the operation.
        """
        self._validate_time_range(starts_at, ends_at)
        return self._do_create_code(lock_id, starts_at, ends_at)

    @abstractmethod
    def _do_create_code(self, lock_id: str, starts_at: datetime, ends_at: datetime) -> CodeResult: ...

    def invalidate_code(self, lock_id: str, code_id: str) -> bool:
        """
        Invalidate an existing code.

        Idempotent: if the code no longer exists or has already expired,
        returns True without raising an exception.

        Args:
            lock_id: Lock identifier.
            code_id: Code identifier.

        Returns:
            True if the code is no longer functional after the call.

        Raises:
            LockAuthError: Invalid credentials.
            LockConnectionError: API unreachable after retries.
        """
        return self._do_invalidate_code(lock_id, code_id)

    @abstractmethod
    def _do_invalidate_code(self, lock_id: str, code_id: str) -> bool: ...

    def modify_code(self, lock_id: str, code_id: str, starts_at: datetime, ends_at: datetime) -> CodeResult:
        """
        Modify the validity window of an existing code.

        If the vendor supports direct modification, the same PIN is kept.
        Otherwise, a new code is created and the old one invalidated.
        Callers must assume that code_id and pin may have changed.

        Args:
            lock_id: Lock identifier.
            code_id: Code identifier to modify.
            starts_at: New start of validity (UTC).
            ends_at: New end of validity (UTC).

        Returns:
            CodeResult with the resulting code data.

        Raises:
            ValueError: Non-UTC datetimes or starts_at >= ends_at.
            LockAuthError: Invalid credentials.
            LockNotFoundError: Lock not found.
            LockCodeNotFoundError: Code not found.
            LockConnectionError: API unreachable after retries.
            LockOperationError: API rejected the operation.
            LockCodeDeletionError: In create+delete flow, the new code was
                created but the old one could not be invalidated. The caller
                should update records with the new result and retry deletion.
        """
        self._validate_time_range(starts_at, ends_at)
        return self._do_modify_code(lock_id, code_id, starts_at, ends_at)

    @abstractmethod
    def _do_modify_code(self, lock_id: str, code_id: str, starts_at: datetime, ends_at: datetime) -> CodeResult: ...

    @abstractmethod
    def test_connection(self) -> bool:
        """
        Verify that credentials are valid and the vendor API is reachable.

        Returns:
            True if connection and authentication are successful.

        Raises:
            LockAuthError: Invalid credentials.
            LockConnectionError: API unreachable after retries.
        """
        ...
