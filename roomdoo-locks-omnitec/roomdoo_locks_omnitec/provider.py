import requests
from datetime import datetime

from roomdoo_locks_base import BaseLockProvider, CodeResult
from roomdoo_locks_base.exceptions import (
    LockAuthError,
    LockConnectionError,
    LockNotFoundError,
    LockOperationError,
)


class OmnitecProvider(BaseLockProvider):

    BASE_URL = "https://api.rentandpass.com/api"

    def __init__(self, clientId: str, clientSecret: str, username: str, password: str):
        self.clientId     = clientId
        self.clientSecret = clientSecret
        self.username     = username
        self.password     = password
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
            self._handle_response(response)
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
            self._handle_response(response)
            body = response.json()
            if "access_token" not in body:
                raise LockAuthError("No se ha podido refrescar el token")
            self.accessToken  = body["access_token"]
            self.refreshToken = body["refresh_token"]
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("No se puede conectar con la API de Omnitec")

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _handle_response(self, response: requests.Response) -> None:
        """Centraliza la gestion de errores HTTP y de negocio de la API."""
        if response.status_code == 401:
            raise LockAuthError(
                f"Error de autenticacion [401]: {response.text}"
            )
        if response.status_code == 404:
            raise LockNotFoundError(
                f"Recurso no encontrado [404]: {response.text}"
            )
        if response.status_code == 500:
            raise LockConnectionError(
                f"Error interno del servidor [500]: {response.text}"
            )
        if not response.ok:
            raise LockOperationError(
                f"Error inesperado [{response.status_code}]: {response.text}"
            )

        # Errores de negocio dentro de respuestas 200
        try:
            body = response.json()
        except Exception:
            return

        errcode = body.get("errcode")
        errmsg  = body.get("errmsg", "Error desconocido")

        if errcode is not None and errcode != 0:
            if errcode in (-3, -4):
                raise LockAuthError(f"Error de autenticacion [{errcode}]: {errmsg}")
            if errcode == -3004:
                raise LockNotFoundError(f"Cerradura no encontrada [{errcode}]: {errmsg}")
            if errcode == -3008:
                raise LockNotFoundError(f"Codigo no encontrado [{errcode}]: {errmsg}")
            raise LockOperationError(f"Error de operacion [{errcode}]: {errmsg}")

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

    def _do_open_lock(self, lock_id: str) -> bool:
        try:
            response = requests.put(f"{self.BASE_URL}/lock/unlock", params=self._params({
                "ID": lock_id
            }))
            self._handle_response(response)
            return True
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("No se puede conectar con la API de Omnitec")

    # ── create_code (sobreescrito para aceptar pin opcional) ─────────────────

    def create_code(self, lock_id: str, starts_at: datetime, ends_at: datetime, pin: str = None) -> CodeResult:
        self._validate_time_range(starts_at, ends_at)
        return self._do_create_code(lock_id, starts_at, ends_at, pin=pin)

    # ── _do_create_code ──────────────────────────────────────────────────────

    def _do_create_code(self, lock_id: str, starts_at: datetime, ends_at: datetime, pin: str = None) -> CodeResult:
        try:
            if pin:
                return self._create_custom_code(lock_id, starts_at, ends_at, pin)
            else:
                return self._create_random_code(lock_id, starts_at, ends_at)
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("No se puede conectar con la API de Omnitec")

    def _create_random_code(self, lock_id: str, starts_at: datetime, ends_at: datetime) -> CodeResult:
        response = requests.get(f"{self.BASE_URL}/password", params=self._params({
            "ID":        lock_id,
            "type":      3,
            "startDate": self._to_ms(starts_at),
            "endDate":   self._to_ms(ends_at)
        }))
        self._handle_response(response)
        body = response.json()

        if "keyboardPwd" not in body:
            raise LockOperationError("La API no devolvio una contrasena aleatoria")

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
        self._handle_response(response)
        body = response.json()

        if "keyboardPwdId" not in body:
            raise LockOperationError("La API no devolvio el ID de la contrasena personalizada")

        return CodeResult(
            code_id   = str(body["keyboardPwdId"]),
            pin       = pin,
            lock_id   = lock_id,
            starts_at = starts_at,
            ends_at   = ends_at
        )

    # ── _do_invalidate_code ──────────────────────────────────────────────────

    def _do_invalidate_code(self, lock_id: str, code_id: str) -> bool:
        try:
            response = requests.delete(f"{self.BASE_URL}/password", params=self._params({
                "ID":     lock_id,
                "passID": code_id,
                "type":   2
            }))
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("No se puede conectar con la API de Omnitec")

        # Idempotente: codigo no encontrado se considera exito
        try:
            self._handle_response(response)
        except LockNotFoundError:
            return True

        return True

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
            self._handle_response(response)
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("No se puede conectar con la API de Omnitec")

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