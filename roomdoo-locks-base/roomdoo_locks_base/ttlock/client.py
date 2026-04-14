from .base import BaseClient
from .models import TokenResponse, LockInfo, LockListResponse, AccessCodeResponse


class TTLockClient:
    """
    High-level client for the TTLock EU API.

    Usage::

        client = TTLockClient(client_id="...", client_secret="...")
        token = client.get_token("user@example.com", "password123")
        locks = client.get_lock_list(token.access_token)
        for lock in locks.locks:
            print(lock.lock_alias, lock.lock_id)
    """

    def __init__(self, client_id: str, client_secret: str, timeout: int = 10):
        self._http = BaseClient(client_id, client_secret, timeout=timeout)

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------

    def get_token(self, username: str, password: str) -> TokenResponse:
        data = self._http.fetch_token(username, password)
        return TokenResponse.from_dict(data)

    # ------------------------------------------------------------------
    # Locks
    # ------------------------------------------------------------------

    def get_lock_info(self, access_token: str, lock_id: int) -> LockInfo:
        """Fetch detailed information for a single lock."""
        data = self._http.fetch_lock_detail(access_token, lock_id)
        return LockInfo.from_dict(data)

    def get_lock_list(
        self,
        access_token: str,
        page_no: int = 1,
        page_size: int = 20,
        lock_alias: str = "",
        group_id: str = "",
    ) -> LockListResponse:
        """Fetch a paginated list of locks for this account."""
        data = self._http.fetch_lock_list(
            access_token,
            page_no=page_no,
            page_size=page_size,
            lock_alias=lock_alias,
            group_id=group_id,
        )
        return LockListResponse.from_dict(data)

    def init_lock(
        self,
        access_token: str,
        lock_data: str,
        lock_alias: str,
        group_id: str = "",
        nb_init_success: int = 1,
    ) -> dict:
        """Initialize (register) a new lock."""
        return self._http.init_lock(
            access_token, lock_data, lock_alias,
            group_id=group_id, nb_init_success=nb_init_success,
        )

    # ------------------------------------------------------------------
    # Access codes (keyboard passwords)
    # ------------------------------------------------------------------

    def get_access_code(
        self,
        access_token: str,
        lock_id: int,
        keyboard_pwd_type: int,
        keyboard_pwd_name: str,
        start_date: int,
        end_date: int,
    ) -> AccessCodeResponse:
        """Generate a new keyboard passcode for a lock."""
        data = self._http.fetch_access_code(
            access_token, lock_id, keyboard_pwd_type,
            keyboard_pwd_name, start_date, end_date,
        )
        return AccessCodeResponse.from_dict(data)

    def delete_access_code(
        self,
        access_token: str,
        lock_id: int,
        keyboard_pwd_id: int,
        delete_type: int = 2,
    ) -> bool:
        """Delete a keyboard passcode. Returns True on success."""
        self._http.delete_access_code(
            access_token, lock_id, keyboard_pwd_id, delete_type=delete_type
        )
        return True
