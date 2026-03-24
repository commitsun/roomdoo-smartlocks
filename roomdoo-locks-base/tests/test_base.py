"""Tests for roomdoo-locks-base: models, exceptions, and validation."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from roomdoo_locks_base import (
    BaseLockProvider,
    CodeResult,
    LockAuthError,
    LockCodeDeletionError,
    LockCodeNotFoundError,
    LockConnectionError,
    LockError,
    LockNotFoundError,
    LockOperationError,
)

UTC = timezone.utc
T1 = datetime(2026, 4, 1, 14, 0, tzinfo=UTC)
T2 = datetime(2026, 4, 3, 11, 0, tzinfo=UTC)


# -- Dummy provider for testing validation ------------------------------------


class DummyProvider(BaseLockProvider):
    def _do_create_code(
        self, lock_id: str, starts_at: datetime, ends_at: datetime
    ) -> CodeResult:
        return CodeResult(
            code_id="1",
            pin="1234",
            lock_id=lock_id,
            starts_at=starts_at,
            ends_at=ends_at,
        )

    def _do_invalidate_code(self, lock_id: str, code_id: str) -> bool:
        return True

    def _do_modify_code(
        self, lock_id: str, code_id: str, starts_at: datetime, ends_at: datetime
    ) -> CodeResult:
        return CodeResult(
            code_id="2",
            pin="5678",
            lock_id=lock_id,
            starts_at=starts_at,
            ends_at=ends_at,
        )

    def test_connection(self) -> bool:
        return True


# -- Time range validation ----------------------------------------------------


class TestTimeRangeValidation:
    def test_naive_starts_at_rejected(self) -> None:
        p = DummyProvider()
        naive = datetime(2026, 4, 1, 14, 0)
        with pytest.raises(ValueError, match="starts_at must be a UTC datetime"):
            p.create_code("lock", naive, T2)

    def test_naive_ends_at_rejected(self) -> None:
        p = DummyProvider()
        naive = datetime(2026, 4, 3, 11, 0)
        with pytest.raises(ValueError, match="ends_at must be a UTC datetime"):
            p.create_code("lock", T1, naive)

    def test_non_utc_offset_rejected(self) -> None:
        p = DummyProvider()
        cet = timezone(timedelta(hours=1))
        non_utc = datetime(2026, 4, 1, 14, 0, tzinfo=cet)
        with pytest.raises(ValueError, match="starts_at must be a UTC datetime"):
            p.create_code("lock", non_utc, T2)

    def test_negative_utc_offset_rejected(self) -> None:
        p = DummyProvider()
        est = timezone(timedelta(hours=-5))
        non_utc = datetime(2026, 4, 3, 11, 0, tzinfo=est)
        with pytest.raises(ValueError, match="ends_at must be a UTC datetime"):
            p.create_code("lock", T1, non_utc)

    def test_starts_at_equals_ends_at_rejected(self) -> None:
        p = DummyProvider()
        with pytest.raises(ValueError, match="starts_at must be before ends_at"):
            p.create_code("lock", T1, T1)

    def test_starts_at_after_ends_at_rejected(self) -> None:
        p = DummyProvider()
        with pytest.raises(ValueError, match="starts_at must be before ends_at"):
            p.create_code("lock", T2, T1)

    def test_valid_utc_range_accepted(self) -> None:
        p = DummyProvider()
        result = p.create_code("lock", T1, T2)
        assert result.lock_id == "lock"
        assert result.starts_at == T1
        assert result.ends_at == T2

    def test_validation_applies_to_modify_code(self) -> None:
        p = DummyProvider()
        naive = datetime(2026, 1, 1)
        with pytest.raises(ValueError, match="starts_at must be a UTC datetime"):
            p.modify_code("lock", "1", naive, T2)

    def test_modify_code_valid_range_accepted(self) -> None:
        p = DummyProvider()
        result = p.modify_code("lock", "1", T1, T2)
        assert result.code_id == "2"

    def test_invalidate_code_has_no_time_validation(self) -> None:
        p = DummyProvider()
        assert p.invalidate_code("lock", "1") is True


# -- CodeResult ---------------------------------------------------------------


class TestCodeResult:
    def test_fields_accessible(self) -> None:
        r = CodeResult(
            code_id="1", pin="1234", lock_id="A", starts_at=T1, ends_at=T2
        )
        assert r.code_id == "1"
        assert r.pin == "1234"
        assert r.lock_id == "A"
        assert r.starts_at == T1
        assert r.ends_at == T2

    def test_immutable(self) -> None:
        r = CodeResult(
            code_id="1", pin="1234", lock_id="A", starts_at=T1, ends_at=T2
        )
        with pytest.raises(AttributeError):
            r.pin = "9999"  # type: ignore[misc]

    def test_repr_masks_pin(self) -> None:
        r = CodeResult(
            code_id="1", pin="1234", lock_id="A", starts_at=T1, ends_at=T2
        )
        text = repr(r)
        assert "1234" not in text
        assert "1***" in text

    def test_repr_empty_pin(self) -> None:
        r = CodeResult(
            code_id="1", pin="", lock_id="A", starts_at=T1, ends_at=T2
        )
        text = repr(r)
        assert "***" in text
        assert "pin='***'" in text

    def test_equality(self) -> None:
        a = CodeResult(
            code_id="1", pin="1234", lock_id="A", starts_at=T1, ends_at=T2
        )
        b = CodeResult(
            code_id="1", pin="1234", lock_id="A", starts_at=T1, ends_at=T2
        )
        assert a == b

    def test_inequality(self) -> None:
        a = CodeResult(
            code_id="1", pin="1234", lock_id="A", starts_at=T1, ends_at=T2
        )
        b = CodeResult(
            code_id="2", pin="1234", lock_id="A", starts_at=T1, ends_at=T2
        )
        assert a != b


# -- Exception hierarchy -------------------------------------------------------


class TestExceptions:
    def test_all_inherit_from_lock_error(self) -> None:
        for exc_cls in (
            LockAuthError,
            LockNotFoundError,
            LockCodeNotFoundError,
            LockConnectionError,
            LockOperationError,
        ):
            assert issubclass(exc_cls, LockError)

    def test_lock_code_deletion_error_inherits_operation_error(self) -> None:
        assert issubclass(LockCodeDeletionError, LockOperationError)
        assert issubclass(LockCodeDeletionError, LockError)

    def test_lock_code_deletion_error_attributes(self) -> None:
        result = CodeResult(
            code_id="2", pin="5678", lock_id="A", starts_at=T1, ends_at=T2
        )
        exc = LockCodeDeletionError("msg", old_code_id="1", new_result=result)
        assert exc.old_code_id == "1"
        assert exc.new_result is result
        assert exc.message == "msg"
        assert str(exc) == "msg"

    def test_lock_operation_error_requires_message(self) -> None:
        exc = LockOperationError("something went wrong")
        assert str(exc) == "something went wrong"
        assert exc.message == "something went wrong"

    def test_lock_error_can_be_caught_as_exception(self) -> None:
        with pytest.raises(Exception):
            raise LockAuthError()

    def test_lock_code_not_found_is_not_lock_not_found(self) -> None:
        assert not issubclass(LockCodeNotFoundError, LockNotFoundError)
        assert not issubclass(LockNotFoundError, LockCodeNotFoundError)
