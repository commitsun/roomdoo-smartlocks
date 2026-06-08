import json
import secrets
from datetime import datetime

import requests

from roomdoo_locks_base import AccessGrant, BaseLockProvider
from roomdoo_locks_base.exceptions import (
    LockAPIError,
    LockAuthError,
    LockConnectionError,
    LockNoPermissionError,
    LockNotFoundError,
    LockOfflineError,
    LockOperationError,
)


class OmnitecProvider(BaseLockProvider):
    """Omnitec / Rent&Pass implementation of the access-grant contract.

    Rent&Pass is a TTLock white-label: a passcode is created per lock, so a
    grant is realised by pushing the *same* passcode to every lock in the set
    (this is exactly the vendor's documented "multi-door assignment flow").
    The per-lock handles (``ID`` + ``passID``) are packed into the opaque
    ``ref`` for later modify/revoke.

    Endpoints and transport follow the previously field-tested implementation
    (verified against a real lock), not the developer guide, which diverges
    (e.g. it documents ``POST /password/add`` returning ``{"success": true}``
    while the working call is ``POST /password`` returning ``keyboardPwdId``):
      POST   /password         add a passcode  -> body has keyboardPwdId
      PUT    /password         change a passcode (``type=1``)
      DELETE /password         remove a passcode (``type=2``)
      GET    /lock/passwords   list a lock's passcodes
    All sent as query params with epoch-ms dates, as in the tested code.
    """

    BASE_URL = "https://api.rentandpass.com/api"

    # Omnitec keypads are 1-9 (no 0); kept configurable per keypad model.
    PASSCODE_ALPHABET = "123456789"
    PASSCODE_LENGTH = 6

    def __init__(self, clientId: str, clientSecret: str, username: str, password: str):
        self.clientId = clientId
        self.clientSecret = clientSecret
        self.username = username
        self.password = password
        self.accessToken = None
        self.refreshToken = None
        self._authenticate()

    # ── Authentication ────────────────────────────────────────────────────

    def _authenticate(self):
        try:
            response = requests.get(
                f"{self.BASE_URL}/signin/token",
                params={
                    "clientId": self.clientId,
                    "clientSecret": self.clientSecret,
                    "username": self.username,
                    "password": self.password,
                },
            )
            body = self._handle_response(response)
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("Unable to connect to Omnitec API")
        if "access_token" not in body:
            raise LockAuthError("Invalid credentials")
        self.accessToken = body["access_token"]
        self.refreshToken = body.get("refresh_token")

    def _refresh_token(self):
        try:
            response = requests.get(
                f"{self.BASE_URL}/signin/refreshToken",
                params={
                    "clientId": self.clientId,
                    "clientSecret": self.clientSecret,
                    "refreshToken": self.refreshToken,
                },
            )
            body = self._handle_response(response)
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("Unable to connect to Omnitec API")
        if "access_token" not in body:
            raise LockAuthError("Failed to refresh token")
        self.accessToken = body["access_token"]
        self.refreshToken = body.get("refresh_token")

    # ── Helpers ───────────────────────────────────────────────────────────

    def _handle_response(self, response: requests.Response) -> dict:
        """HTTP + business error handling. Returns the parsed JSON body."""
        if response.status_code == 401:
            raise LockAuthError(f"Authentication error [401]: {response.text}")
        if response.status_code == 404:
            raise LockNotFoundError(f"Resource not found [404]: {response.text}")
        if response.status_code == 500:
            raise LockConnectionError(f"Internal server error [500]: {response.text}")
        if not response.ok:
            raise LockOperationError(
                f"Unexpected error [{response.status_code}]: {response.text}"
            )
        try:
            body = response.json()
        except Exception:
            raise LockAPIError("Invalid response from Omnitec API")

        errcode = body.get("errcode")
        description = body.get("description", "Unknown error")
        if errcode is not None and errcode != 0:
            if errcode == -1:
                raise LockOfflineError(
                    f"Invalid password id [{errcode}]: {description}"
                )
            if errcode == -1003:
                raise LockNotFoundError(f"Lock not found [{errcode}]: {description}")
            if errcode == -1007:
                raise LockNotFoundError(
                    f"No password data for this lock [{errcode}]: {description}"
                )
            if errcode == -1008:
                raise LockNotFoundError(f"eKey not found [{errcode}]: {description}")
            if errcode in (-3, -2018, 20002, 30002):
                raise LockNoPermissionError(
                    f"Permission error [{errcode}]: {description}"
                )
            if errcode == -2009:
                raise LockNoPermissionError(
                    f"Invalid password id [{errcode}]: {description}"
                )
            if errcode == -2012:
                raise LockOfflineError(
                    f"Lock not connected to gateway [{errcode}]: {description}"
                )
            if errcode == -2025:
                raise LockOperationError(f"Lock is frozen [{errcode}]: {description}")
            if errcode in (-3002, -3003):
                raise LockOfflineError(f"Gateway error [{errcode}]: {description}")
            if errcode == -3036:
                raise LockOfflineError(f"Lock is offline [{errcode}]: {description}")
            if errcode == -3037:
                raise LockOfflineError(f"Lock is busy [{errcode}]: {description}")
            if errcode == -4043:
                raise LockOperationError(
                    f"Function not supported [{errcode}]: {description}"
                )
            if errcode == 10001:
                raise LockAuthError(f"Invalid client [{errcode}]: {description}")
            if errcode == 10003:
                raise LockAuthError(f"Invalid token [{errcode}]: {description}")
            if errcode == 10011:
                raise LockAuthError(f"Invalid refresh token [{errcode}]: {description}")
            if errcode == 20003:
                raise LockNoPermissionError(f"Invalid key [{errcode}]: {description}")
            if errcode == 20009:
                raise LockNoPermissionError(f"Invalid lock id [{errcode}]: {description}")
            if errcode == 30001:
                raise LockNoPermissionError(
                    f"Do not have permission [{errcode}]: {description}"
                )
            if errcode == 90000:
                raise LockConnectionError(
                    f"Internal server error [{errcode}]: {description}"
                )
            raise LockOperationError(f"Operation error [{errcode}]: {description}")
        return body

    def _to_ms(self, dt: datetime) -> int:
        return int(dt.timestamp() * 1000)

    def _params(self, extra: dict) -> dict:
        return {"clientId": self.clientId, "token": self.accessToken, **extra}

    def _get_lock_passwords(self, lock_id: str) -> list:
        response = requests.get(f"{self.BASE_URL}/lock/passwords", params=self._params({
            "ID": lock_id
        }))
        self._handle_response(response)
        return response.json().get("list", [])

    # ── test_connection ──────────────────────────────────────────────────────

    def test_connection(self) -> bool:
        self._authenticate()
        return True

    # ── open_lock ────────────────────────────────────────────────────────────

    def open_lock(self, lock_id: str) -> bool:
        try:
            response = requests.put(f"{self.BASE_URL}/lock/unlock", params=self._params({
                "ID": lock_id
            }))
            self._handle_response(response)
            return True
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("Unable to connect to Omnitec API")

    # ── create_code ──────────────────────

    def create_code(self, lock_id: str, starts_at: datetime, ends_at: datetime) -> CodeResult:
        self._validate_time_range(starts_at, ends_at)
        pin = f"{secrets.randbelow(1_000_000):06d}"
        return self._do_create_code(lock_id, pin, starts_at, ends_at)

    # ── Per-lock primitives ───────────────────────────────────────────────

    def _do_create_code(self, lock_id: str, pin: str, starts_at: datetime, ends_at: datetime) -> CodeResult:
        response = requests.post(f"{self.BASE_URL}/password", params=self._params({
            "ID":        lock_id,
            "password":  pin,
            "type":      2,
            "startDate": self._to_ms(starts_at),
            "endDate":   self._to_ms(ends_at)
        }))
        self._handle_response(response)
        body = response.json()

        if "keyboardPwd" not in body:
            raise LockOperationError("API did not return a random PIN code")

        return CodeResult(
            code_id   = str(body["keyboardPwdId"]),
            pin       = body["keyboardPwd"],
            lock_id   = lock_id,
            starts_at = starts_at,
            ends_at   = ends_at
        )

    # ── _do_invalidate_code ──────────────────────────────────────────────────

    def _do_invalidate_code(self, lock_id: str, code_id: str) -> bool:
        try:
            self._request(
                "DELETE",
                "/password",
                {"ID": lock_id, "passID": pass_id, "type": 2},
            )
        except (LockNotFoundError, LockNoPermissionError):
            # Idempotent: a passcode that is already gone is a successful revoke.
            pass

    # ── BaseLockProvider contract ─────────────────────────────────────────

    def _do_grant_access(
        self, lock_ids: list, starts_at: datetime, ends_at: datetime, pin: str
    ) -> AccessGrant:
        pin = pin or self._generate_pin()
        created = []
        try:
            for lock_id in lock_ids:
                pass_id = self._add_passcode(lock_id, pin, starts_at, ends_at)
                created.append({"ID": lock_id, "passID": pass_id})
        except Exception:
            # All-or-nothing: roll back what we created, best-effort, so a
            # retry starts clean instead of leaving orphan passcodes.
            for target in created:
                try:
                    self._delete_passcode(target["ID"], target["passID"])
                except Exception:
                    pass
            raise
        return AccessGrant(
            pin=pin,
            ref=self._pack_ref(created),
            starts_at=starts_at,
            ends_at=ends_at,
        )

    def _do_modify_access(
        self, grant_ref: str, starts_at: datetime, ends_at: datetime
    ) -> AccessGrant:
        targets = self._unpack_ref(grant_ref)
        for target in targets:
            self._change_passcode(target["ID"], target["passID"], starts_at, ends_at)
        pin = ""
        if targets:
            pin = self._read_pin(targets[0]["ID"], targets[0]["passID"])
        return AccessGrant(
            pin=pin, ref=grant_ref, starts_at=starts_at, ends_at=ends_at
        )

    def _do_revoke_access(self, grant_ref: str) -> bool:
        for target in self._unpack_ref(grant_ref):
            self._delete_passcode(target["ID"], target["passID"])
        return True

    def test_connection(self) -> bool:
        self._authenticate()
        return True

    # ── Extras ────────────────────────────────────────────────────────────

    def open_lock(self, lock_id) -> bool:
        self._request("PUT", "/lock/unlock", {"ID": lock_id})
        return True
