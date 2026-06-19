import pytest
from roomdoo_locks_base import AccessGrant, BaseLockProvider


class _DummyProvider(BaseLockProvider):
    """Minimal concrete provider to exercise the base defaults."""

    def _do_grant_access(self, lock_ids, starts_at, ends_at, pin):
        return AccessGrant(pin=pin or "0000", ref="ref", starts_at=starts_at, ends_at=ends_at)

    def _do_modify_access(self, grant_ref, starts_at, ends_at, pin=None):
        return AccessGrant(pin=None, ref=grant_ref, starts_at=starts_at, ends_at=ends_at)

    def _do_revoke_access(self, grant_ref, pin=None):
        return True

    def test_connection(self):
        return True


def test_list_locks_default_raises_not_implemented():
    # Vendors that expose a listing override list_locks(); the base default
    # raises so the caller (Odoo layer) can catch and degrade gracefully.
    with pytest.raises(NotImplementedError):
        _DummyProvider().list_locks()
