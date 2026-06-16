"""TESA-specific exceptions.

The shared taxonomy lives in :mod:`roomdoo_locks_base.exceptions`. TESA adds two
business cases that the contract methods react to specifically, so they are kept
here instead of polluting the base. Both subclass ``LockOperationError`` so
existing callers that only catch the base type keep working.
"""

from roomdoo_locks_base.exceptions import LockOperationError


class LockPinCollisionError(LockOperationError):
    """PIN already active on another lock with an overlapping time window.

    Smartair rejects a PIN that is already in use on a different lock for an
    overlapping window. When the PIN was auto-generated the provider retries
    with a fresh one; a caller-supplied PIN surfaces this error untouched.
    """


class LockAlreadyClearedError(LockOperationError):
    """The stay being revoked is already gone (room free / pre-assignment void).

    Raised when a checkout hits a non-occupied room or a precheckin cancel hits
    an invalid pre-assignment. :meth:`revoke_access` treats it as success to stay
    idempotent.
    """
