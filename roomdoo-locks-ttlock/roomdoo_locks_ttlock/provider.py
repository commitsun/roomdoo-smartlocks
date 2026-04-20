import requests
from datetime import datetime, timezone

from roomdoo_locks_base import BaseLockProvider, CodeResult
from roomdoo_locks_base.exceptions import (
    LockAuthError,
    LockConnectionError,
    LockNotFoundError,
    LockOperationError,
    LockAPIError,
    LockNoPermissionError,
    LockOfflineError,
)

BASE_URL = "https://euapi.ttlock.com"


class TTLockProvider(BaseLockProvider):
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
        except Exception:
            raise LockAPIError("Invalid response from TTLock API")
        errcode = body.get("errcode")
        errmsg = body.get("errmsg", "Unknown error")
        if errcode is not None and errcode != 0:
            # Account and auth errors
            if errcode in (10001, 10003, 10004, 10007, 10011):
                raise LockAuthError(f"Auth error [{errcode}]: {errmsg}")
            if errcode in (-3, -2018, 20002, 30002):
                raise LockNoPermissionError(f"Permission error [{errcode}]: {errmsg}")
            if errcode == 90000:
                raise LockConnectionError(f"Internal server error [{errcode}]: {errmsg}")
            # Lock errors
            if errcode == -1003:
                raise LockNotFoundError(f"Lock not found [{errcode}]: {errmsg}")
            if errcode == -2025:
                raise LockOperationError(f"Lock is frozen [{errcode}]: {errmsg}")
            if errcode == -4043:
                raise LockOperationError(f"Function not supported [{errcode}]: {errmsg}")
            # Passcode errors
            if errcode == -2009:
                raise LockNoPermissionError(f"Invalid passcode [{errcode}]: {errmsg}")
            if errcode == -1007:
                raise LockNotFoundError(f"No password data for this lock [{errcode}]: {errmsg}")
            # Gateway and connectivity errors
            if errcode == -2012:
                raise LockOfflineError(f"Lock not connected to gateway [{errcode}]: {errmsg}")
            if errcode in (-3002, -3003):
                raise LockOfflineError(f"Gateway error [{errcode}]: {errmsg}")
            if errcode == -3036:
                raise LockOfflineError(f"Lock is offline [{errcode}]: {errmsg}")
            if errcode == -3037:
                raise LockOperationError(f"Lock is busy [{errcode}]: {errmsg}")
            # eKey errors
            if errcode == -1008:
                raise LockNotFoundError(f"eKey not found [{errcode}]: {errmsg}")
            # Fallback
            raise LockOperationError(f"Operation error [{errcode}]: {errmsg}")
        return body

    def _to_ms(self, value) -> int:
        """Convert a datetime or int (seconds) to milliseconds timestamp."""
        if isinstance(value, datetime):
            return int(value.timestamp() * 1000)
        if isinstance(value, int):
            return value * 1000 if value < 1_000_000_000_000 else value
        return value

    def _now_ms(self) -> int:
        return int(datetime.now().timestamp() * 1000)

    def _ms_to_utc(self, ms: int | None) -> datetime | None:
        """Convert milliseconds timestamp to UTC datetime."""
        if ms is None:
            return None
        return datetime.fromtimestamp(ms / 1000, tz=timezone.utc)

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------

    def authenticate(self):
        url = f"{BASE_URL}/oauth2/token"
        payload = {
            "clientId": self.clientId,
            "clientSecret": self.clientSecret,
            "username": self.username,
            "password": self.password,
        }
        try:
            response = requests.post(url, data=payload)
            data = self._handle_response(response)
            self.accessToken = data["access_token"]
            self.tokenExpiry = datetime.now().timestamp() + data["expires_in"]
        except requests.exceptions.RequestException as e:
            raise LockConnectionError(f"Failed to connect to TTLock API: {str(e)}")

    def _refresh_access_token(self):
        url = f"{BASE_URL}/oauth2/token"
        payload = {
            "clientId": self.clientId,
            "clientSecret": self.clientSecret,
            "grantType": "refresh_token",
            "refreshToken": self.accessToken,
        }
        try:
            response = requests.post(url, data=payload)
            data = self._handle_response(response)
            self.accessToken = data["access_token"]
            self.tokenExpiry = datetime.now().timestamp() + data["expires_in"]
        except requests.exceptions.RequestException as e:
            raise LockConnectionError(f"Failed to connect to TTLock API: {str(e)}")

    # ------------------------------------------------------------------
    # BaseLockProvider abstract methods
    # The base class handles validation and calls these _do_* methods.
    # ------------------------------------------------------------------

    def _do_create_code(self, lock_id: str, starts_at: datetime, ends_at: datetime) -> CodeResult:
        # Passcode types:
        # 1: One-time       2: Permanent     3: Period
        # 4: Delete all     5: Weekend       6: Daily
        # 7: Workday        8-14: Mon-Sun
        url = f"{BASE_URL}/v3/keyboardPwd/get"
        payload = {
            "clientId": self.clientId,
            "accessToken": self.accessToken,
            "lockId": lock_id,
            "keyboardPwdType": 3,  # Period code
            "startDate": self._to_ms(starts_at),
            "endDate": self._to_ms(ends_at),
            "date": self._now_ms(),
        }
        try:
            response = requests.post(url, data=payload)
            data = self._handle_response(response)
            return CodeResult(
                code_id=str(data["keyboardPwdId"]),
                pin=data["keyboardPwd"],
                lock_id=str(lock_id),
                starts_at=starts_at,
                ends_at=ends_at,
            )
        except requests.exceptions.RequestException as e:
            raise LockConnectionError(f"Failed to connect to TTLock API: {str(e)}")

    def _do_invalidate_code(self, lock_id: str, code_id: str) -> bool:
        url = f"{BASE_URL}/v3/keyboardPwd/delete"
        payload = {
            "clientId": self.clientId,
            "accessToken": self.accessToken,
            "lockId": lock_id,
            "keyboardPwdId": code_id,
            "deleteType": 2,
            "date": self._now_ms(),
        }
        try:
            self._handle_response(requests.post(url, data=payload))
            return True
        except requests.exceptions.RequestException as e:
            raise LockConnectionError(f"Failed to connect to TTLock API: {str(e)}")

    def _do_modify_code(self, lock_id: str, code_id: str, starts_at: datetime, ends_at: datetime) -> CodeResult:
        # TTLock does not support modifying codes directly — invalidate and recreate
        self._do_invalidate_code(lock_id, code_id)
        return self._do_create_code(lock_id, starts_at, ends_at)

    # ------------------------------------------------------------------
    # Lock info
    # ------------------------------------------------------------------

    def get_lock_info(self, lock_id: int):
        url = f"{BASE_URL}/v3/lock/detail"
        params = {
            "clientId": self.clientId,
            "accessToken": self.accessToken,
            "lockId": lock_id,
            "date": self._now_ms(),
        }
        try:
            return self._handle_response(requests.get(url, params=params))
        except requests.exceptions.RequestException as e:
            raise LockConnectionError(f"Failed to connect to TTLock API: {str(e)}")

    def get_lock_list(self, pageNo: int = 1, pageSize: int = 20, lockAlias: str = None, groupId: int = None):
        url = f"{BASE_URL}/v3/lock/list"
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
        try:
            return self._handle_response(requests.get(url, params=params))
        except requests.exceptions.RequestException as e:
            raise LockConnectionError(f"Failed to connect to TTLock API: {str(e)}")

    # ------------------------------------------------------------------
    # Extras
    # ------------------------------------------------------------------

    def set_auto_lock_time(self, lock_id: int, seconds: int, type: int = 2):
        url = f"{BASE_URL}/v3/lock/setAutoLockTime"
        payload = {
            "clientId": self.clientId,
            "accessToken": self.accessToken,
            "lockId": lock_id,
            "seconds": seconds,
            "type": type,
            "date": self._now_ms(),
        }
        try:
            self._handle_response(requests.post(url, data=payload))
        except requests.exceptions.RequestException as e:
            raise LockConnectionError(f"Failed to connect to TTLock API: {str(e)}")

    def test_connection(self) -> bool:
        self.authenticate()
        return True