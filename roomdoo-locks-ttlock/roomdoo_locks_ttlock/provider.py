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

BASE_URL = "https://euapi.ttlock.com"


class TTLockProvider(BaseLockProvider):
    """TTLock implementation of the access-grant contract.

    TTLock has no native notion of "one credential across several locks":
    a passcode is added per lock. This adapter therefore realises a grant by
    pushing the *same* passcode to every lock in the set, and packs the
    per-lock handles (``lockId`` + ``keyboardPwdId``) into the opaque ``ref``
    so it can later change or delete them. The PIN is never stored in the
    ref — callers keep it separately in their credential store.
    """

    # The lock the team tested has a 1-7 keypad only; kept configurable so a
    # different keypad (e.g. 1-9) can be served without touching the logic.
    PASSCODE_ALPHABET = "1234567"
    PASSCODE_LENGTH = 6

    def __init__(self, clientId: str, clientSecret: str, username: str, password: str):
        self.clientId = clientId
        self.clientSecret = clientSecret
        self.username = username
        self.password = password
        self.accessToken = None
        self.tokenExpiry = None
        self.authenticate()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _handle_response(self, response: requests.Response) -> dict:
        """Centralizes HTTP and business error handling for the TTLock API."""
        if not response.ok:
            raise LockConnectionError(
                f"HTTP error [{response.status_code}]: {response.text}"
            )
        try:
            body = response.json()
        except requests.exceptions.JSONDecodeError:
            raise LockAPIError("Invalid response from TTLock API")
        errcode = body.get("errcode")
        errmsg = body.get("errmsg", "Unknown error")
        if errcode is not None and errcode != 0:
            # 10001: invalid client (clientId/clientSecret)
            # 10003: token does not exist
            # 10004: token invalid or revoked
            # 10007: invalid account or password
            # 10011: invalid refresh token
            # 30005: password must be md5-encrypted
            if errcode in (10001, 10003, 10004, 10007, 10011, 30005):
                raise LockAuthError(f"Auth error [{errcode}]: {errmsg}")
            # -3: invalid parameter; -2018: permission denied;
            # 20002: not lock admin; 30002: invalid username
            if errcode in (-3, -2018, 20002, 30002):
                raise LockNoPermissionError(f"Permission error [{errcode}]: {errmsg}")
            if errcode == 90000:
                raise LockConnectionError(
                    f"Internal server error [{errcode}]: {errmsg}"
                )
            # -1003: lock does not exist
            if errcode == -1003:
                raise LockNotFoundError(f"Lock not found [{errcode}]: {errmsg}")
            # -2025: frozen lock
            if errcode == -2025:
                raise LockConnectionError(f"Lock is frozen [{errcode}]: {errmsg}")
            # -4043: function not supported for this lock
            if errcode == -4043:
                raise LockOperationError(
                    f"Function not supported [{errcode}]: {errmsg}"
                )
            # -2009: invalid passcode
            if errcode == -2009:
                raise LockNoPermissionError(f"Invalid passcode [{errcode}]: {errmsg}")
            # -1007: no password data for this lock
            if errcode == -1007:
                raise LockNotFoundError(
                    f"No password data for this lock [{errcode}]: {errmsg}"
                )
            # -2012: lock not connected to gateway
            if errcode == -2012:
                raise LockOfflineError(
                    f"Lock not connected to gateway [{errcode}]: {errmsg}"
                )
            # -3002: gateway offline; -3003: gateway busy
            if errcode in (-3002, -3003):
                raise LockOfflineError(f"Gateway error [{errcode}]: {errmsg}")
            # -3009: lock full of passcodes (limit 250)
            if errcode == -3009:
                raise LockOperationError(
                    f"Lock is full of passcodes. Limit is 250 [{errcode}]: {errmsg}"
                )
            # -3036: lock offline
            if errcode == -3036:
                raise LockOfflineError(f"Lock is offline [{errcode}]: {errmsg}")
            # -3037: lock busy
            if errcode == -3037:
                raise LockOfflineError(f"Lock is busy [{errcode}]: {errmsg}")
            # -1008: eKey does not exist
            if errcode == -1008:
                raise LockNotFoundError(f"eKey not found [{errcode}]: {errmsg}")
            raise LockOperationError(f"Operation error [{errcode}]: {errmsg}")
        return body

    def _to_ms(self, value) -> int:
        if isinstance(value, datetime):
            return int(value.timestamp() * 1000)
        if isinstance(value, int):
            return value * 1000 if value < 1_000_000_000_000 else value
        return value

    def _now_ms(self) -> int:
        return int(datetime.now().timestamp() * 1000)

    def _generate_pin(self) -> str:
        return "".join(
            secrets.choice(self.PASSCODE_ALPHABET) for _ in range(self.PASSCODE_LENGTH)
        )

    def _post(self, path: str, payload: dict) -> dict:
        try:
            return self._handle_response(requests.post(f"{BASE_URL}{path}", data=payload))
        except requests.exceptions.RequestException as e:
            raise LockConnectionError(f"Failed to connect to TTLock API: {str(e)}")

    def _get(self, path: str, params: dict) -> dict:
        try:
            return self._handle_response(requests.get(f"{BASE_URL}{path}", params=params))
        except requests.exceptions.RequestException as e:
            raise LockConnectionError(f"Failed to connect to TTLock API: {str(e)}")

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------

    def authenticate(self):
        payload = {
            "clientId": self.clientId,
            "clientSecret": self.clientSecret,
            "username": self.username,
            "password": self.password,
        }
        try:
            response = requests.post(f"{BASE_URL}/oauth2/token", data=payload)
            data = self._handle_response(response)
            self.accessToken = data["access_token"]
            self.tokenExpiry = datetime.now().timestamp() + data["expires_in"]
        except requests.exceptions.RequestException as e:
            raise LockConnectionError(f"Failed to connect to TTLock API: {str(e)}")

    # ------------------------------------------------------------------
    # Per-lock primitives (internal to grant orchestration)
    # ------------------------------------------------------------------

    def _add_passcode(
        self, lock_id, pin: str, starts_at: datetime, ends_at: datetime
    ) -> str:
        """Push ``pin`` to a single lock; return its ``keyboardPwdId``."""
        data = self._post(
            "/v3/keyboardPwd/add",
            {
                "clientId": self.clientId,
                "accessToken": self.accessToken,
                "lockId": lock_id,
                "keyboardPwd": pin,
                "keyboardPwdType": 3,  # period code
                "startDate": self._to_ms(starts_at),
                "endDate": self._to_ms(ends_at),
                "addType": 2,  # via gateway
                "date": self._now_ms(),
            },
        )
        return str(data["keyboardPwdId"])

    def _change_passcode(
        self, lock_id, code_id: str, starts_at: datetime, ends_at: datetime
    ) -> None:
        self._post(
            "/v3/keyboardPwd/change",
            {
                "clientId": self.clientId,
                "accessToken": self.accessToken,
                "lockId": lock_id,
                "keyboardPwdId": code_id,
                "startDate": self._to_ms(starts_at),
                "endDate": self._to_ms(ends_at),
                "changeType": 2,  # via gateway
                "date": self._now_ms(),
            },
        )

    def _delete_passcode(self, lock_id, code_id: str) -> None:
        self._post(
            "/v3/keyboardPwd/delete",
            {
                "clientId": self.clientId,
                "accessToken": self.accessToken,
                "lockId": lock_id,
                "keyboardPwdId": code_id,
                "deleteType": 2,  # via gateway
                "date": self._now_ms(),
            },
        )

    def _read_pin(self, lock_id, code_id: str) -> str:
        """Read back the PIN of a passcode by its id (used after modify, where
        the contract requires returning the credential)."""
        data = self._get(
            "/v3/lock/listKeyboardPwd",
            {
                "clientId": self.clientId,
                "accessToken": self.accessToken,
                "lockId": lock_id,
                "pageNo": 1,
                "pageSize": 200,
                "orderBy": 1,
                "date": self._now_ms(),
            },
        )
        return next(
            (
                p["keyboardPwd"]
                for p in data.get("list", [])
                if str(p["keyboardPwdId"]) == str(code_id)
            ),
            "",
        )

    @staticmethod
    def _pack_ref(targets: list) -> str:
        return json.dumps(targets, separators=(",", ":"))

    @staticmethod
    def _unpack_ref(grant_ref: str) -> list:
        return json.loads(grant_ref)

    # ------------------------------------------------------------------
    # BaseLockProvider contract
    # ------------------------------------------------------------------

    def _do_grant_access(
        self, lock_ids: list, starts_at: datetime, ends_at: datetime, pin: str
    ) -> AccessGrant:
        pin = pin or self._generate_pin()
        created = []
        try:
            for lock_id in lock_ids:
                code_id = self._add_passcode(lock_id, pin, starts_at, ends_at)
                created.append({"lockId": lock_id, "keyboardPwdId": code_id})
        except Exception:
            # All-or-nothing: a partial grant would give the guest a PIN that
            # only opens some doors. Roll back what we created, best-effort,
            # then surface the original error.
            for target in created:
                try:
                    self._delete_passcode(target["lockId"], target["keyboardPwdId"])
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
        # Best-effort, idempotent: re-applying the same window to a lock that
        # already has it is harmless, so a transient failure lets the caller
        # retry the whole modify without rollback.
        for target in targets:
            self._change_passcode(
                target["lockId"], target["keyboardPwdId"], starts_at, ends_at
            )
        pin = ""
        if targets:
            pin = self._read_pin(targets[0]["lockId"], targets[0]["keyboardPwdId"])
        return AccessGrant(
            pin=pin, ref=grant_ref, starts_at=starts_at, ends_at=ends_at
        )

    def _do_revoke_access(self, grant_ref: str) -> bool:
        for target in self._unpack_ref(grant_ref):
            self._delete_passcode(target["lockId"], target["keyboardPwdId"])
        return True

    def test_connection(self) -> bool:
        self.authenticate()
        return True

    # ------------------------------------------------------------------
    # Lock info / extras (unchanged)
    # ------------------------------------------------------------------

    def get_lock_info(self, lock_id: int):
        return self._get(
            "/v3/lock/detail",
            {
                "clientId": self.clientId,
                "accessToken": self.accessToken,
                "lockId": lock_id,
                "date": self._now_ms(),
            },
        )

    def get_lock_list(
        self, pageNo: int = 1, pageSize: int = 20, lockAlias: str = None, groupId: int = None
    ):
        params = {
            "clientId": self.clientId,
            "accessToken": self.accessToken,
            "pageNo": pageNo,
            "pageSize": pageSize,
            "date": self._now_ms(),
        }
        if lockAlias:
            params["lockAlias"] = lockAlias
        if groupId:
            params["groupId"] = groupId
        return self._get("/v3/lock/list", params)

    def set_auto_lock_time(self, lock_id: int, seconds: int, type: int = 2):
        self._post(
            "/v3/lock/setAutoLockTime",
            {
                "clientId": self.clientId,
                "accessToken": self.accessToken,
                "lockId": lock_id,
                "seconds": seconds,
                "type": type,
                "date": self._now_ms(),
            },
        )
