from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass(frozen=True)
class CodeResult:
    """Immutable result of a single-lock code operation.

    Kept as the building block vendors use internally when fulfilling an
    access grant lock-by-lock (e.g. TTLock's per-lock keyboardPwd). The
    public contract callers program against is :class:`AccessGrant`.
    """

    code_id: str
    pin: str
    lock_id: str
    starts_at: datetime
    ends_at: datetime

    def __repr__(self) -> str:
        masked = self.pin[:1] + "***" if self.pin else "***"
        return (
            f"CodeResult(code_id={self.code_id!r}, pin={masked!r}, "
            f"lock_id={self.lock_id!r}, starts_at={self.starts_at!r}, "
            f"ends_at={self.ends_at!r})"
        )


@dataclass(frozen=True)
class AccessGrant:
    """Immutable result of granting one guest access to a set of locks.

    The *credential* (``pin``) is what the guest uses on every keypad of
    the grant; how that single credential is realised across the locks is
    the vendor's concern (TTLock/Omnitec replicate a passcode per lock;
    Salto assigns the PIN to a user and grants a lock group).

    A ``pin`` of ``None`` means *unchanged / not returned*: the credential
    is unaffected by the operation and the caller must keep the PIN it
    already stored. This is how :meth:`BaseLockProvider.modify_access`
    reports a window change on a vendor that keeps the same PIN but cannot
    read it back (e.g. Salto). An empty string is a real (if unusual) PIN
    value, distinct from ``None``.

    ``ref`` is an **opaque, vendor-specific** handle the caller stores
    verbatim and hands back to :meth:`modify_access`/:meth:`revoke_access`
    to manage the grant's lifecycle. Callers must not parse it.
    """

    pin: Optional[str]
    ref: str
    starts_at: datetime
    ends_at: datetime

    def __repr__(self) -> str:
        masked = self.pin[:1] + "***" if self.pin else "***"
        return (
            f"AccessGrant(pin={masked!r}, ref={self.ref!r}, "
            f"starts_at={self.starts_at!r}, ends_at={self.ends_at!r})"
        )
