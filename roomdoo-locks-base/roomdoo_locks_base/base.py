from abc import ABC, abstractmethod
from datetime import datetime, timedelta

from roomdoo_locks_base.models import AccessGrant

_ZERO = timedelta(0)


class BaseLockProvider(ABC):
    """
    Abstract interface for smart lock providers.

    Each vendor implements this class. The constructor receives vendor-specific
    credentials and internally manages tokens, refresh and retries.

    The interface is expressed in terms of *guest access*, not individual
    passcodes: the caller asks to grant one guest access to a **set of locks**
    for a validity window and gets back a single credential plus an opaque
    ``ref``. How that maps onto the vendor's primitives — a passcode replicated
    on each lock (TTLock/Omnitec), or a user assigned to a lock group (Salto) —
    is entirely the vendor's concern, kept inside the adapter. The caller never
    orchestrates lock-by-lock.

    Subclasses override the ``_do_*`` methods. The public methods handle common
    validation (UTC datetimes, starts_at < ends_at) before delegating to the
    vendor-specific implementation.
    """

    @staticmethod
    def _validate_time_range(starts_at: datetime, ends_at: datetime) -> None:
        for dt, name in ((starts_at, "starts_at"), (ends_at, "ends_at")):
            if dt.tzinfo is None or dt.utcoffset() != _ZERO:
                raise ValueError(f"{name} must be a UTC datetime")
        if starts_at >= ends_at:
            raise ValueError("starts_at must be before ends_at")

    def grant_access(
        self,
        lock_ids: list,
        starts_at: datetime,
        ends_at: datetime,
        pin: str | None = None,
    ) -> AccessGrant:
        """
        Grant one guest access to ``lock_ids`` between starts_at and ends_at.

        The guest uses a single credential (PIN) on every lock of the set.
        The vendor generates the PIN unless ``pin`` is given (e.g. to reuse an
        existing one). The returned :class:`AccessGrant` carries that PIN and an
        opaque ``ref`` to be stored and handed back to :meth:`modify_access` /
        :meth:`revoke_access`.

        Args:
            lock_ids: Lock identifiers on the vendor platform.
            starts_at: Start of validity window (UTC).
            ends_at: End of validity window (UTC).
            pin: Optional credential to set; vendor-generated when omitted.

        Returns:
            AccessGrant with the credential, opaque ref and effective dates.

        Raises:
            ValueError: Non-UTC datetimes, starts_at >= ends_at, empty lock_ids.
            LockAuthError: Invalid credentials.
            LockNotFoundError: A lock was not found.
            LockConnectionError: API unreachable after retries.
            LockOperationError: API rejected the operation.
        """
        self._validate_time_range(starts_at, ends_at)
        if not lock_ids:
            raise ValueError("lock_ids must not be empty")
        return self._do_grant_access(list(lock_ids), starts_at, ends_at, pin)

    @abstractmethod
    def _do_grant_access(
        self,
        lock_ids: list,
        starts_at: datetime,
        ends_at: datetime,
        pin: str | None,
    ) -> AccessGrant: ...

    def modify_access(self, grant_ref: str, starts_at: datetime, ends_at: datetime) -> AccessGrant:
        """
        Modify the validity window of an existing grant.

        The credential may change (vendors that delete+recreate internally);
        callers must persist the returned ``ref`` and ``pin``. When the
        returned ``pin`` is ``None`` the credential is unchanged and the
        caller must keep the PIN it already stored — this is how a vendor
        that keeps the same PIN but cannot read it back (e.g. Salto) reports
        a window change. The ``ref`` is always returned and must be persisted.

        Args:
            grant_ref: Opaque ref returned by :meth:`grant_access`.
            starts_at: New start of validity (UTC).
            ends_at: New end of validity (UTC).

        Returns:
            AccessGrant with the resulting ref and either the new PIN or
            ``None`` when the PIN is unchanged.

        Raises:
            ValueError: Non-UTC datetimes or starts_at >= ends_at.
            LockAuthError: Invalid credentials.
            LockConnectionError: API unreachable after retries.
            LockOperationError: API rejected the operation.
        """
        self._validate_time_range(starts_at, ends_at)
        return self._do_modify_access(grant_ref, starts_at, ends_at)

    @abstractmethod
    def _do_modify_access(self, grant_ref: str, starts_at: datetime, ends_at: datetime) -> AccessGrant: ...

    def revoke_access(self, grant_ref: str) -> bool:
        """
        Revoke an existing grant on every lock it covers.

        Idempotent: a grant that no longer exists or has already expired
        returns True without raising.

        Args:
            grant_ref: Opaque ref returned by :meth:`grant_access`.

        Returns:
            True if the grant is no longer functional after the call.

        Raises:
            LockAuthError: Invalid credentials.
            LockConnectionError: API unreachable after retries.
        """
        return self._do_revoke_access(grant_ref)

    @abstractmethod
    def _do_revoke_access(self, grant_ref: str) -> bool: ...

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
