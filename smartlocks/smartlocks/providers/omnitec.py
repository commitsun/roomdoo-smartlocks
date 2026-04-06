import requests
from datetime import datetime
from roomdoo_locks_base import BaseLockProvider, CodeResult
from roomdoo_locks_base.exceptions import (
    LockAuthError,
    LockConnectionError,
    LockOperationError,
    LockCodeDeletionError
)


class OmnitecProvider(BaseLockProvider):

    BASE_URL = "https://api.rentandpass.com/api"

    def __init__(self, clientId: str, clientSecret: str, username: str, password: str, random_codes: bool = True):
        self.clientId     = clientId
        self.clientSecret = clientSecret
        self.username     = username
        self.password     = password
        self.random_codes = random_codes  # True = aleatorio, False = personalizado
        self.accessToken  = None
        self.refreshToken = None
        self._authenticate()

    # ── Autenticacion ────────────────────────────────────────────────────────

    def _authenticate(self):
        try:
            response = requests.get(f"{self.BASE_URL}/signin/token", params={
                "clientId":     self.clientId,
                "clientSecret": self.clientSecret,
                "username":     self.username,
                "password":     self.password
            })
            body = response.json()
            if "access_token" not in body:
                raise LockAuthError("Credenciales invalidas")
            self.accessToken  = body["access_token"]
            self.refreshToken = body["refresh_token"]
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("No se puede conectar con la API de Omnitec")

    def _refresh_token(self):
        try:
            response = requests.get(f"{self.BASE_URL}/signin/refreshToken", params={
                "clientId":     self.clientId,
                "clientSecret": self.clientSecret,
                "refreshToken": self.refreshToken
            })
            body = response.json()
            if "access_token" not in body:
                raise LockAuthError("No se ha podido refrescar el token")
            self.accessToken  = body["access_token"]
            self.refreshToken = body["refresh_token"]
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("No se puede conectar con la API de Omnitec")

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _to_ms(self, dt: datetime) -> int:
        return int(dt.timestamp() * 1000)

    def _params(self, extra: dict) -> dict:
        return {"clientId": self.clientId, "token": self.accessToken, **extra}

    # ── test_connection ──────────────────────────────────────────────────────

    def test_connection(self) -> bool:
        self._authenticate()
        return True

    # ── Creacion de codigos (interna) ────────────────────────────────────────

    def _create_random_code(self, lock_id: str, starts_at: datetime, ends_at: datetime) -> CodeResult:
        response = requests.get(f"{self.BASE_URL}/password", params=self._params({
            "ID":        lock_id,
            "type":      3,
            "startDate": self._to_ms(starts_at),
            "endDate":   self._to_ms(ends_at)
        }))
        body = response.json()

        if "keyboardPwd" not in body:
            raise LockOperationError(body.get("errmsg", "Error al generar contrasena aleatoria"))

        return CodeResult(
            code_id   = str(body["keyboardPwdId"]),
            pin       = body["keyboardPwd"],
            lock_id   = lock_id,
            starts_at = starts_at,
            ends_at   = ends_at
        )

    def _create_custom_code(self, lock_id: str, starts_at: datetime, ends_at: datetime, pin: str) -> CodeResult:
        response = requests.post(f"{self.BASE_URL}/password", params=self._params({
            "ID":        lock_id,
            "password":  pin,
            "type":      2,
            "startDate": self._to_ms(starts_at),
            "endDate":   self._to_ms(ends_at)
        }))
        body = response.json()

        if "keyboardPwdId" not in body:
            raise LockOperationError(body.get("errmsg", "Error al generar contrasena personalizada"))

        return CodeResult(
            code_id   = str(body["keyboardPwdId"]),
            pin       = pin,
            lock_id   = lock_id,
            starts_at = starts_at,
            ends_at   = ends_at
        )

    # ── _do_create_code ──────────────────────────────────────────────────────

    def create_code(self, lock_id: str, starts_at: datetime, ends_at: datetime, pin: str = None) -> CodeResult:
        self._validate_time_range(starts_at, ends_at)
        return self._do_create_code(lock_id, starts_at, ends_at, pin=pin)

    def _do_create_code(self, lock_id: str, starts_at: datetime, ends_at: datetime, pin: str = None) -> CodeResult:
        try:
            if pin:
                return self._create_custom_code(lock_id, starts_at, ends_at, pin)
            else:
                return self._create_random_code(lock_id, starts_at, ends_at)
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("No se puede conectar con la API de Omnitec")

    # ── _do_invalidate_code ──────────────────────────────────────────────────

    def _do_invalidate_code(self, lock_id: str, code_id: str) -> bool:
        try:
            response = requests.delete(f"{self.BASE_URL}/password", params=self._params({
                "ID":     lock_id,
                "passID": code_id,
                "type":   2
            }))
            body = response.json()
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("No se puede conectar con la API de Omnitec")

        if body.get("errcode") in (0, -3008):
            return True

        raise LockOperationError(body.get("errmsg", "Error al eliminar la contrasena"))

    # ── _do_modify_code ──────────────────────────────────────────────────────

    def _do_modify_code(self, lock_id: str, code_id: str, starts_at: datetime, ends_at: datetime) -> CodeResult:
        try:
            response = requests.put(f"{self.BASE_URL}/password", params=self._params({
                "ID":        lock_id,
                "passID":    code_id,
                "type":      1,
                "startDate": self._to_ms(starts_at),
                "endDate":   self._to_ms(ends_at)
            }))
            body = response.json()
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("No se puede conectar con la API de Omnitec")

        if body.get("errcode") == 0:
            passwords = self._get_lock_passwords(lock_id)
            pin = next(
                (p["keyboardPwd"] for p in passwords if str(p["keyboardPwdId"]) == code_id),
                ""
            )
            return CodeResult(
                code_id   = code_id,
                pin       = pin,
                lock_id   = lock_id,
                starts_at = starts_at,
                ends_at   = ends_at
            )

        raise LockOperationError(body.get("errmsg", "Error al modificar la contrasena"))

    def _get_lock_passwords(self, lock_id: str) -> list:
        response = requests.get(f"{self.BASE_URL}/lock/passwords", params=self._params({
            "ID": lock_id
        }))
        return response.json().get("list", [])