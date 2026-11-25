import contextlib
import json
import secrets
from datetime import datetime, timezone
from typing import cast

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

# Rent&Pass serves at most 200 items per page, whatever ``itemsPerPage`` asks.
_LIST_PAGE_SIZE = 200


class GatewayCommandError(LockOfflineError):
    """Errcode -1: the lock did not complete a command relayed through its
    gateway (it did not answer in time or was busy). Omnitec describes it as a
    transient, generic failure: the PIN is fine and coverage is not
    necessarily bad. The command may even have been applied with only the
    response lost, so an add must be checked against the lock's passcodes
    before issuing another PIN."""


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
      PUT    /password         change a passcode (``type=2``)
      DELETE /password         remove a passcode (``type=2``)
      GET    /lock/passwords   list a lock's passcodes
    All sent as query params with epoch-ms dates, as in the tested code.

    Resumable grants: when built with a ``passcode_tag``, every passcode of the
    grant is created under that name (``keyboardPwdName``). A grant interrupted
    halfway (e.g. errcode -1 on the second lock) leaves the locks it already
    programmed in place; calling ``grant_access`` again finds them by tag,
    reuses their PIN and only adds the missing ones. The tag must be stable
    across attempts and unique per credential. Leftovers of a grant that is
    never completed are removed with ``delete_tagged_passcodes``. Without a
    tag, a failed grant is rolled back instead (all-or-nothing).
    """

    BASE_URL = "https://api.rentandpass.com/api"

    # Omnitec keypads are 1-9 (no 0); kept configurable per keypad model.
    PASSCODE_ALPHABET = "123456789"
    PASSCODE_LENGTH = 4

    def __init__(
        self,
        clientId: str,
        clientSecret: str,
        username: str,
        password: str,
        passcode_tag: str | None = None,
    ):
        self.clientId = clientId
        self.clientSecret = clientSecret
        self.username = username
        self.password = password
        self.passcode_tag = passcode_tag
        self.accessToken: str = ""
        self.refreshToken = None
        self._authenticate()

    # ── Authentication ────────────────────────────────────────────────────

    def _authenticate(self) -> None:
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
        except requests.exceptions.ConnectionError as err:
            raise LockConnectionError("Unable to connect to Omnitec API") from err
        if "access_token" not in body:
            raise LockAuthError("Invalid credentials")
        self.accessToken = body["access_token"]
        self.refreshToken = body.get("refresh_token")

    def _refresh_token(self) -> None:
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
        except requests.exceptions.ConnectionError as err:
            raise LockConnectionError("Unable to connect to Omnitec API") from err
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
            raise LockOperationError(f"Unexpected error [{response.status_code}]: {response.text}")
        try:
            body = response.json()
        except Exception as err:
            raise LockAPIError("Invalid response from Omnitec API") from err

        errcode = body.get("errcode")
        description = body.get("description", "Unknown error")
        if errcode is not None and errcode != 0:
            if errcode == -1:
                raise GatewayCommandError(f"Lock did not complete the gateway command [{errcode}]: {description}")
            if errcode == -1003:
                raise LockNotFoundError(f"Lock not found [{errcode}]: {description}")
            if errcode == -1007:
                raise LockNotFoundError(f"No password data for this lock [{errcode}]: {description}")
            if errcode == -1008:
                raise LockNotFoundError(f"eKey not found [{errcode}]: {description}")
            if errcode in (-3, -2018, 20002, 30002):
                raise LockNoPermissionError(f"Permission error [{errcode}]: {description}")
            if errcode == -2009:
                raise LockNoPermissionError(f"Invalid password id [{errcode}]: {description}")
            if errcode == -2012:
                raise LockOfflineError(f"Lock not connected to gateway [{errcode}]: {description}")
            if errcode == -2025:
                raise LockOperationError(f"Lock is frozen [{errcode}]: {description}")
            if errcode in (-3002, -3003):
                raise LockOfflineError(f"Gateway error [{errcode}]: {description}")
            if errcode == -3036:
                raise LockOfflineError(f"Lock is offline [{errcode}]: {description}")
            if errcode == -3037:
                raise LockOfflineError(f"Lock is busy [{errcode}]: {description}")
            if errcode == -4043:
                raise LockOperationError(f"Function not supported [{errcode}]: {description}")
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
                raise LockNoPermissionError(f"Do not have permission [{errcode}]: {description}")
            if errcode == 90000:
                raise LockConnectionError(f"Internal server error [{errcode}]: {description}")
            raise LockOperationError(f"Operation error [{errcode}]: {description}")
        return cast("dict", body)

    def _to_ms(self, dt: datetime) -> int:
        return int(dt.timestamp() * 1000)

    def _params(self, extra: dict) -> dict:
        return {"clientId": self.clientId, "token": self.accessToken, **extra}

    def _request(self, method: str, path: str, extra: dict) -> dict:
        try:
            response = requests.request(method, f"{self.BASE_URL}{path}", params=self._params(extra))
        except requests.exceptions.ConnectionError as err:
            raise LockConnectionError("Unable to connect to Omnitec API") from err
        return self._handle_response(response)

    def _gateway_request(self, method: str, path: str, extra: dict) -> dict:
        """``_request`` for a command the cloud relays to the lock ``extra["ID"]``
        through its gateway. When the lock does not complete it (errcode -1),
        the gateways the lock is linked to and their last reported signal are
        appended to the error: it is the first thing the vendor asks to check."""
        try:
            return self._request(method, path, extra)
        except GatewayCommandError as err:
            raise GatewayCommandError(f"{err} | {self._gateway_diagnostics(extra['ID'])}") from err

    def _gateway_diagnostics(self, lock_id: str) -> str:
        """One-line summary of the gateways linked to ``lock_id``. The signal
        (``rssi``, dBm) is the last one the gateway reported, not a live
        reading, hence its date. Never raises: a failed lookup must not hide
        the error being diagnosed."""
        try:
            gateways = self._request("GET", "/gateway/listByLock", {"ID": lock_id}).get("list") or []
        except Exception as err:
            return f"gateway diagnostics unavailable: {err}"
        if not gateways:
            return "lock linked to no gateway"
        return "gateways: " + ", ".join(
            f"{gw.get('gatewayName') or gw.get('gatewayId')} rssi {gw.get('rssi')} "
            f"({self._format_ms(gw.get('rssiUpdateDate'))})"
            for gw in gateways
        )

    @staticmethod
    def _format_ms(value: int | None) -> str:
        if not value:
            return "no date"
        return datetime.fromtimestamp(value / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    def _list_all(self, path: str, extra: dict) -> list:
        """Every item of a paginated listing, read page by page."""
        items: list = []
        page = 1
        while True:
            body = self._request("GET", path, {**extra, "firstPage": page, "itemsPerPage": _LIST_PAGE_SIZE})
            items.extend(body.get("list") or [])
            if page >= (body.get("pages") or 1):
                return items
            page += 1

    def _get_lock_passwords(self, lock_id: str) -> list:
        return self._list_all("/lock/passwords", {"ID": lock_id})

    def _find_tagged(self, lock_id: str, tag: str) -> list:
        """Passcodes of ``lock_id`` created under the name ``tag``."""
        return [p for p in self._get_lock_passwords(lock_id) if p.get("keyboardPwdName") == tag]

    def _read_pin(self, lock_id: str, pass_id: str) -> str:
        for p in self._get_lock_passwords(lock_id):
            if str(p["keyboardPwdId"]) == str(pass_id):
                return cast("str", p["keyboardPwd"])
        return ""

    def _generate_pin(self) -> str:
        return "".join(secrets.choice(self.PASSCODE_ALPHABET) for _ in range(self.PASSCODE_LENGTH))

    @staticmethod
    def _pack_ref(targets: list) -> str:
        return json.dumps(targets, separators=(",", ":"))

    @staticmethod
    def _unpack_ref(grant_ref: str) -> list:
        return cast("list", json.loads(grant_ref))

    # ── Per-lock primitives ───────────────────────────────────────────────

    def _add_passcode(self, lock_id: str, pin: str, starts_at: datetime, ends_at: datetime) -> str:
        params = {
            "ID": lock_id,
            "password": pin,
            "type": 2,  # gateway
            "startDate": self._to_ms(starts_at),
            "endDate": self._to_ms(ends_at),
        }
        if self.passcode_tag:
            params["name"] = self.passcode_tag
        body = self._gateway_request("POST", "/password", params)
        return str(body["keyboardPwdId"])

    def _change_passcode(self, lock_id: str, pass_id: str, starts_at: datetime, ends_at: datetime) -> None:
        # ``password`` omitted on purpose: changing only the window keeps the
        # existing PIN, so the same number stays valid on every lock. The API
        # default ``type=1`` ("via bluetooth") only updates the cloud record:
        # the lock would keep the window it was granted with.
        self._gateway_request(
            "PUT",
            "/password",
            {
                "ID": lock_id,
                "passID": pass_id,
                "type": 2,  # gateway
                "startDate": self._to_ms(starts_at),
                "endDate": self._to_ms(ends_at),
            },
        )

    def _delete_passcode(self, lock_id: str, pass_id: str) -> None:
        # Idempotent: a passcode that is already gone is a successful revoke.
        with contextlib.suppress(LockNotFoundError, LockNoPermissionError):
            self._gateway_request(
                "DELETE",
                "/password",
                {"ID": lock_id, "passID": pass_id, "type": 2},
            )

    # ── BaseLockProvider contract ─────────────────────────────────────────

    def _resume_tagged(self, lock_ids: list, tag: str) -> tuple[str | None, dict]:
        """What an interrupted earlier attempt of this grant left on the locks.

        Returns the PIN to resume with (``None`` if nothing was left) and, per
        lock, the ``passID`` already holding it. A tagged passcode under any
        other PIN (an add that was applied but not yet listed when the next
        attempt ran) is deleted, so the credential stays a single PIN."""
        found = {lock_id: self._find_tagged(lock_id, tag) for lock_id in lock_ids}
        pins = [passcode["keyboardPwd"] for passcodes in found.values() for passcode in passcodes]
        if not pins:
            return None, {}
        pin = cast("str", pins[0])
        resumed: dict = {}
        for lock_id, passcodes in found.items():
            for passcode in passcodes:
                pass_id = str(passcode["keyboardPwdId"])
                if passcode["keyboardPwd"] == pin and lock_id not in resumed:
                    resumed[lock_id] = pass_id
                else:
                    self._delete_passcode(lock_id, pass_id)
        return pin, resumed

    def _do_grant_access(self, lock_ids: list, starts_at: datetime, ends_at: datetime, pin: str | None) -> AccessGrant:
        # With a tag, resume what a previous attempt programmed: its PIN wins
        # over ``pin`` because it is already on the locks.
        resumed: dict = {}
        if self.passcode_tag:
            resumed_pin, resumed = self._resume_tagged(lock_ids, self.passcode_tag)
            pin = resumed_pin or pin
        pin = pin or self._generate_pin()
        targets = []
        try:
            for lock_id in lock_ids:
                pass_id = resumed.get(lock_id) or self._add_passcode(lock_id, pin, starts_at, ends_at)
                targets.append({"ID": lock_id, "passID": pass_id})
        except Exception:
            # Tagged passcodes stay on purpose: the next attempt finds them by
            # tag and resumes, so a lock already programmed is not programmed
            # again. Untagged ones could never be found again, so the grant is
            # rolled back instead (all-or-nothing, best-effort).
            if not self.passcode_tag:
                for target in targets:
                    with contextlib.suppress(Exception):
                        self._delete_passcode(target["ID"], target["passID"])
            raise
        return AccessGrant(
            pin=pin,
            ref=self._pack_ref(targets),
            starts_at=starts_at,
            ends_at=ends_at,
        )

    def _do_modify_access(
        self,
        grant_ref: str,
        starts_at: datetime,
        ends_at: datetime,
        pin: str | None = None,
    ) -> AccessGrant:
        # pin is unused: Omnitec keeps stable per-passcode handles in the ref
        # and reads the credential back, so there is no stale-handle problem.
        targets = self._unpack_ref(grant_ref)
        for target in targets:
            self._change_passcode(target["ID"], target["passID"], starts_at, ends_at)
        current_pin = ""
        if targets:
            current_pin = self._read_pin(targets[0]["ID"], targets[0]["passID"])
        return AccessGrant(pin=current_pin, ref=grant_ref, starts_at=starts_at, ends_at=ends_at)

    def _do_revoke_access(self, grant_ref: str, pin: str | None = None) -> bool:
        for target in self._unpack_ref(grant_ref):
            self._delete_passcode(target["ID"], target["passID"])
        return True

    def test_connection(self) -> bool:
        self._authenticate()
        return True

    # ── Extras ────────────────────────────────────────────────────────────

    def list_locks(self) -> list[dict]:
        """Locks as ``[{"id": lockId, "name": lockAlias}, ...]``.

        ``GET /lock/list`` returns a TTLock-shaped payload
        (``{"list": [{"lockId", "lockAlias", ...}], "pages", "total"}``),
        read page by page: an account can hold more locks than one page.
        """
        return [
            {"id": str(lock.get("lockId")), "name": lock.get("lockAlias") or ""}
            for lock in self._list_all("/lock/list", {})
        ]

    def delete_tagged_passcodes(self, lock_ids: list, tag: str) -> int:
        """Delete every passcode named ``tag`` on ``lock_ids`` and return how
        many there were.

        Clears the leftovers of a tagged grant that was never completed
        (attempts exhausted, or the credential cancelled between attempts).
        Idempotent. Not part of the provider contract: only a resumable
        Omnitec grant leaves passcodes behind without a ref to revoke."""
        if not tag:
            # An empty tag would match every unnamed passcode on the lock.
            raise ValueError("A passcode tag is required")
        deleted = 0
        for lock_id in lock_ids:
            for passcode in self._find_tagged(lock_id, tag):
                self._delete_passcode(lock_id, str(passcode["keyboardPwdId"]))
                deleted += 1
        return deleted

    def open_lock(self, lock_id: str) -> bool:
        self._request("PUT", "/lock/unlock", {"ID": lock_id})
        return True
