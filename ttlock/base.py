import time
import requests

from .exceptions import TTLockAPIError, TTLockAuthError, TTLockNotFoundError

_AUTH_ERROR_CODES = {10003, 10004, 10005}
_NOT_FOUND_CODES = {10007, 10008}


def _now_ms() -> int:
    return int(time.time() * 1000)


class BaseClient:

    BASE_URL = "https://euapi.ttlock.com"

    def __init__(self, client_id: str, client_secret: str, timeout: int = 10):
        self.client_id = client_id
        self.client_secret = client_secret
        self.timeout = timeout
        self._session = requests.Session()

    def _check_response(self, data: dict) -> dict:
        errcode = data.get("errcode")
        if errcode and errcode != 0:
            errmsg = data.get("errmsg", "Unknown error")
            if errcode in _AUTH_ERROR_CODES:
                raise TTLockAuthError(errmsg, errcode=errcode, errmsg=errmsg)
            if errcode in _NOT_FOUND_CODES:
                raise TTLockNotFoundError(errmsg, errcode=errcode, errmsg=errmsg)
            raise TTLockAPIError(errmsg, errcode=errcode, errmsg=errmsg)
        return data

    def _get(self, path: str, params: dict) -> dict:
        url = f"{self.BASE_URL}{path}"
        response = self._session.get(url, params=params, timeout=self.timeout)
        response.raise_for_status()
        return self._check_response(response.json())

    def _post(self, path: str, params: dict) -> dict:
        url = f"{self.BASE_URL}{path}"
        response = self._session.post(url, data=params, timeout=self.timeout)
        response.raise_for_status()
        return self._check_response(response.json())

    def fetch_token(self, username: str, password: str) -> dict:
        return self._post("/oauth2/token", {
            "clientId": self.client_id,
            "clientSecret": self.client_secret,
            "username": username,
            "password": password,
        })

    def fetch_lock_detail(self, access_token: str, lock_id: int) -> dict:
        return self._get("/v3/lock/detail", {
            "clientId": self.client_id,
            "accessToken": access_token,
            "lockId": lock_id,
            "date": _now_ms(),
        })

    def fetch_lock_list(self, access_token: str, page_no: int = 1, page_size: int = 20, lock_alias: str = "", group_id: str = "") -> dict:
        return self._get("/v3/lock/list", {
            "clientId": self.client_id,
            "accessToken": access_token,
            "lockAlias": lock_alias,
            "groupId": group_id,
            "pageNo": page_no,
            "pageSize": page_size,
            "date": _now_ms(),
        })

    def init_lock(self, access_token: str, lock_data: str, lock_alias: str, group_id: str = "", nb_init_success: int = 1) -> dict:
        return self._post("/v3/lock/initialize", {
            "clientId": self.client_id,
            "accessToken": access_token,
            "lockData": lock_data,
            "lockAlias": lock_alias,
            "groupId": group_id,
            "nbInitSuccess": nb_init_success,
            "date": _now_ms(),
        })

    def fetch_access_code(self, access_token: str, lock_id: int, keyboard_pwd_type: int, keyboard_pwd_name: str, start_date: int, end_date: int) -> dict:
        return self._post("/v3/keyboardPwd/get", {
            "clientId": self.client_id,
            "accessToken": access_token,
            "lockId": lock_id,
            "keyboardPwdType": keyboard_pwd_type,
            "keyboardPwdName": keyboard_pwd_name,
            "startDate": start_date,
            "endDate": end_date,
            "date": _now_ms(),
        })

    def delete_access_code(self, access_token: str, lock_id: int, keyboard_pwd_id: int, delete_type: int = 2) -> dict:
        return self._post("/v3/keyboardPwd/delete", {
            "clientId": self.client_id,
            "accessToken": access_token,
            "lockId": lock_id,
            "keyboardPwdId": keyboard_pwd_id,
            "deleteType": delete_type,
            "date": _now_ms(),
        })