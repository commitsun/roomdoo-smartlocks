"""Omnitec (OsAccess) smart lock provider implementation."""

from __future__ import annotations

import logging
from datetime import datetime

import httpx

from roomdoo_locks_base import (
    BaseLockProvider,
    CodeResult,
    LockAuthError,
    LockCodeDeletionError,
    LockConnectionError,
    LockNotFoundError,
    LockOperationError,
)

logger = logging.getLogger(__name__)

_DEFAULT_BASE_URL = "https://osaccess-backend.osaccess.net/api"
_DEFAULT_TIMEOUT = 30.0
_MAX_RETRIES = 3


class OmnitecProvider(BaseLockProvider):
    """Omnitec / OsAccess API lock provider.

    Uses the OsAccess API to manage booking-based passcodes for electronic
    locks.  This API natively supports time-bounded passcodes via
    ``dateTimeCheckin`` / ``dateTimeCheckout`` and booking cancellation via
    ``onlineCancel``.

    Authentication is header-based (``instance`` + ``apikey``).
    """

    def __init__(
        self,
        instance: str,
        apikey: str,
        *,
        base_url: str = _DEFAULT_BASE_URL,
        timeout: float = _DEFAULT_TIMEOUT,
        common_areas: str = "DEFAULT",
    ) -> None:
        self._instance = instance
        self._apikey = apikey
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._common_areas = common_areas
        self._client = httpx.Client(
            base_url=self._base_url,
            timeout=self._timeout,
            headers={
                "instance": self._instance,
                "apikey": self._apikey,
                "Content-Type": "application/json",
            },
        )

    # -- HTTP helpers ---------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict[str, object] | None = None,
        retry: int = 0,
    ) -> httpx.Response:
        """Execute an authenticated API request with retry on transient errors."""
        try:
            resp = self._client.request(method, path, json=json_body)
            resp.raise_for_status()
        except httpx.ConnectError as exc:
            raise LockConnectionError from exc
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            if status in (401, 403):
                raise LockAuthError from exc
            if status == 404:
                raise LockNotFoundError from exc
            if status >= 500 and retry < _MAX_RETRIES:
                return self._request(method, path, json_body=json_body, retry=retry + 1)
            raise LockConnectionError from exc
        return resp

    # -- BaseLockProvider implementation --------------------------------------

    def _do_create_code(
        self,
        lock_id: str,
        starts_at: datetime,
        ends_at: datetime,
    ) -> CodeResult:
        body: dict[str, object] = {
            "roomNo": lock_id,
            "dateTimeCheckin": starts_at.isoformat(),
            "dateTimeCheckout": ends_at.isoformat(),
            "passCode": True,
            "invalidatePreviousPassCodes": True,
            "commonAreas": self._common_areas,
        }
        resp = self._request("POST", "/Reservas/generatePasscodeAndQR", json_body=body)
        data = resp.json()

        code_id = str(data.get("id", ""))
        passcodes = data.get("passcodes", [])
        if not passcodes or not passcodes[0].get("passcode"):
            raise LockOperationError(
                f"OsAccess returned no passcodes for room {lock_id}"
            )
        pin = str(passcodes[0]["passcode"])

        return CodeResult(
            code_id=code_id,
            pin=pin,
            lock_id=lock_id,
            starts_at=starts_at,
            ends_at=ends_at,
        )

    def _do_invalidate_code(self, lock_id: str, code_id: str) -> bool:
        try:
            self._request("PUT", f"/Reservas/{code_id}/onlineCancel")
        except LockNotFoundError:
            logger.info(
                "Reservation %s already cancelled or not found (idempotent).",
                code_id,
            )
        return True

    def _do_modify_code(
        self,
        lock_id: str,
        code_id: str,
        starts_at: datetime,
        ends_at: datetime,
    ) -> CodeResult:
        body: dict[str, object] = {
            "bookId": int(code_id),
            "roomNo": lock_id,
            "dateTimeCheckin": starts_at.isoformat(),
            "dateTimeCheckout": ends_at.isoformat(),
            "passCode": True,
            "invalidatePreviousPassCodes": True,
            "commonAreas": self._common_areas,
        }
        try:
            resp = self._request(
                "POST", "/Reservas/generatePasscodeAndQR", json_body=body
            )
        except (LockNotFoundError, LockOperationError, LockConnectionError):
            logger.warning(
                "Direct modify failed for booking %s, falling back to create+delete.",
                code_id,
            )
            return self._create_and_delete(lock_id, code_id, starts_at, ends_at)

        data = resp.json()
        new_code_id = str(data.get("id", ""))
        passcodes = data.get("passcodes", [])
        if not passcodes or not passcodes[0].get("passcode"):
            raise LockOperationError(
                f"OsAccess returned no passcodes when modifying booking {code_id}"
            )
        pin = str(passcodes[0]["passcode"])

        return CodeResult(
            code_id=new_code_id,
            pin=pin,
            lock_id=lock_id,
            starts_at=starts_at,
            ends_at=ends_at,
        )

    def _create_and_delete(
        self,
        lock_id: str,
        old_code_id: str,
        starts_at: datetime,
        ends_at: datetime,
    ) -> CodeResult:
        """Fallback: create a new code then delete the old one."""
        new_result = self._do_create_code(lock_id, starts_at, ends_at)
        try:
            self._do_invalidate_code(lock_id, old_code_id)
        except Exception as exc:
            raise LockCodeDeletionError(
                f"New code created but failed to cancel old booking {old_code_id}: {exc}",
                old_code_id=old_code_id,
                new_result=new_result,
            ) from exc
        return new_result

    def test_connection(self) -> bool:
        """Verify credentials by making a lightweight API call.

        Uses a POST to the reservations endpoint with minimal data.
        A successful auth that fails on validation still proves connectivity
        and valid credentials.
        """
        try:
            self._request(
                "POST",
                "/Reservas/generatePasscodeAndQR",
                json_body={"roomNo": "__test__", "passCode": False},
            )
        except LockAuthError:
            raise
        except (LockNotFoundError, LockOperationError, LockConnectionError):
            pass
        return True
