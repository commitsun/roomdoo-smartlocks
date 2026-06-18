import base64
import contextlib
import json
from datetime import datetime
from typing import ClassVar, cast
from zoneinfo import ZoneInfo

import requests
from roomdoo_locks_base import AccessGrant, BaseLockProvider
from roomdoo_locks_base.exceptions import (
    LockAuthError,
    LockConnectionError,
    LockNotFoundError,
    LockOperationError,
)


class SaltoProvider(BaseLockProvider):
    """SaltoKS adapter.

    Salto is user-centric: a guest is realised as a *site user* assigned to an
    *access group* that links the locks and carries a *time schedule* (the
    validity window). A single PIN, generated for that user, opens every lock of
    the group. This maps onto the PIN-per-set contract of
    :class:`BaseLockProvider`: ``grant_access`` creates the whole structure and
    returns one PIN plus an opaque ``ref`` that carries every id needed to later
    modify or revoke the grant.

    Vendor-specific configuration (the role new guests get, the access-group
    label and the synthetic guest identity) lives in the constructor, since the
    contract's ``grant_access`` only receives locks, a window and an optional
    PIN.
    """

    IDENTITY_HOSTS: ClassVar[dict[str, str]] = {
        "prod": "https://identity.eu.my-clay.com",
        "acc": "https://identity-acc.eu.my-clay.com",
    }

    API_HOSTS: ClassVar[dict[str, str]] = {
        "prod": "https://user.my-clay.com",
        "acc": "https://clp-accept-user.my-clay.com",
    }

    def __init__(
        self,
        clientId: str,
        clientSecret: str,
        username: str,
        password: str,
        siteId: str,
        role_id: str | None = None,
        env: str = "prod",
        access_group_name: str = "Roomdoo Access",
        guest_first_name: str = "Roomdoo",
        guest_last_name: str = "Guest",
        guest_email: str = "",
        time_zone: str | None = None,
    ):
        self.clientId = clientId
        self.clientSecret = clientSecret
        self.username = username
        self.password = password
        self.siteId = siteId
        self.role_id = role_id
        self.env = env
        self.access_group_name = access_group_name
        self.guest_first_name = guest_first_name
        self.guest_last_name = guest_last_name
        self.guest_email = guest_email
        # IANA timezone the site's hardware (the IQ) enforces schedules
        # against — the hotel's local timezone. Salto stores time-schedule
        # start_date/end_date as naive wall-clock and the IQ applies them in
        # its own timezone, NOT UTC, so we localize before serializing.
        self.time_zone = time_zone
        self.accessToken: str = ""
        self._authenticate()

    # ── Authentication ───────────────────────────────────────────────────────

    def _authenticate(self) -> None:
        try:
            response = requests.post(
                f"{self.IDENTITY_HOSTS[self.env]}/connect/token",
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Authorization": "Basic "
                    + base64.b64encode(f"{self.clientId}:{self.clientSecret}".encode()).decode(),
                },
                data={
                    "grant_type": "password",
                    "username": self.username,
                    "password": self.password,
                    "scope": "user_api.full_access",
                },
            )
            self._handle_response(response)
            body = response.json()
            if "access_token" not in body:
                raise LockAuthError("Invalid credentials")
            self.accessToken = body["access_token"]
        except requests.exceptions.ConnectionError as err:
            raise LockConnectionError("Unable to connect to Salto API") from err

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _handle_response(self, response: requests.Response) -> None:
        """Centralizes HTTP and business error handling for the API."""
        if response.status_code == 204:
            return None

        if response.status_code == 400:
            raise LockAuthError(f"Authentication error [400]: {response.text}")
        if response.status_code == 401:
            raise LockAuthError(f"Authentication error [401]: {response.text}")
        if response.status_code == 404:
            raise LockNotFoundError(f"Resource not found [404]: {response.text}")
        if response.status_code == 415:
            raise LockOperationError(f"Unsupported Media Type [415]: {response.text}")
        if response.status_code == 500:
            raise LockConnectionError(f"Internal server error [500]: {response.text}")
        if not response.ok:
            raise LockOperationError(f"Unexpected error [{response.status_code}]: {response.text}")

        # Successful response with an empty body: nothing to inspect.
        if not response.text.strip():
            return None

        # Business errors within 2xx responses. Some endpoints (e.g. the PIN
        # endpoint) return a bare value instead of a JSON object; a body that is
        # not a JSON object simply has no business error to inspect.
        try:
            body = response.json()
        except ValueError:
            return None

        if not isinstance(body, dict):
            return None

        errcode = body.get("ErrorCode")
        description = body.get("Message", "Unknown error")

        if errcode is not None and errcode != 0:
            raise LockOperationError(f"Operation error [{errcode}]: {description}")

    @staticmethod
    def _pack_ref(ref: dict) -> str:
        return json.dumps(ref, separators=(",", ":"))

    @staticmethod
    def _unpack_ref(grant_ref: str) -> dict:
        return cast("dict", json.loads(grant_ref))

    # ── BaseLockProvider contract ─────────────────────────────────────────────

    def _do_grant_access(self, lock_ids: list, starts_at: datetime, ends_at: datetime, pin: str | None) -> AccessGrant:
        if pin is not None:
            # Salto KS generates the PIN; setting a custom one is a premium
            # feature this adapter does not support. Fail loud rather than
            # silently issue a different PIN than the caller asked for.
            raise LockOperationError("Salto does not support setting a custom PIN")
        if not self.role_id:
            # The site user needs a role; without one Salto rejects creation.
            raise LockOperationError("Salto guest role_id is not configured")
        user = self._add_user_to_site(self.guest_first_name, self.guest_last_name, self.role_id, self.guest_email)
        site_user_id = user["site_user_id"]
        user_id = user["user_id"]

        access_group_id = None
        try:
            access_group_id = self._add_access_group_to_site(self.access_group_name)
            schedule = self._add_time_schedule_to_access_group(access_group_id, starts_at, ends_at)
            self._add_user_to_access_group(access_group_id, user_id)
            for lock_id in lock_ids:
                self._add_lock_to_access_group(access_group_id, lock_id)
            pin = self._create_modify_user_pin(site_user_id, pin)
        except Exception:
            # All-or-nothing: roll back best-effort so a retry starts clean
            # instead of leaving an orphan user/access group behind.
            if access_group_id is not None:
                with contextlib.suppress(Exception):
                    self._delete_access_group_from_site(access_group_id)
            with contextlib.suppress(Exception):
                self._delete_user_from_site(site_user_id)
            raise

        return AccessGrant(
            pin=pin,
            ref=self._pack_ref(
                {
                    "access_group_id": access_group_id,
                    "time_schedule_id": schedule["time_schedule_id"],
                    "site_user_id": site_user_id,
                    "user_id": user_id,
                    "lock_ids": list(lock_ids),
                }
            ),
            starts_at=starts_at,
            ends_at=ends_at,
        )

    def _do_modify_access(self, grant_ref: str, starts_at: datetime, ends_at: datetime) -> AccessGrant:
        ref = self._unpack_ref(grant_ref)
        self._modify_time_schedule_in_access_group(ref["access_group_id"], ref["time_schedule_id"], starts_at, ends_at)
        # Only the time schedule moves; the user and PIN are untouched. Salto
        # never lets us read a PIN back, so we report it as unchanged
        # (``pin=None``) per the contract and the caller keeps the one returned
        # by grant_access. Patching in place (not delete+recreate) is what keeps
        # that original PIN valid.
        return AccessGrant(pin=None, ref=grant_ref, starts_at=starts_at, ends_at=ends_at)

    def _do_revoke_access(self, grant_ref: str) -> bool:
        """Make the grant non-functional by *suspending* the guest user.

        Salto licenses are billed per **subscribed** user, so revoking deletes
        nothing: it unsubscribes the user (state ``suspended``), which frees the
        license and stops the PIN from opening any lock while the user, access
        group and access logs are kept for audit. The hard delete that reclaims
        those resources happens later via :meth:`delete_grant`, called by the
        caller's retention cron once the dispute window has passed.

        Idempotent: a user that is already suspended or gone still revokes.
        """
        ref = self._unpack_ref(grant_ref)
        with contextlib.suppress(LockNotFoundError):
            self._unsubscribe_user_from_site(ref["site_user_id"])
        return True

    def test_connection(self) -> bool:
        self._authenticate()
        return True

    # ── Extras ─────────────────────────────────────────────────────────────

    def delete_grant(self, grant_ref: str) -> bool:
        """Hard-delete the resources behind a (revoked) grant.

        Deletes the access group and the guest user identified by
        ``grant_ref``, reclaiming the user and its license for good. Meant to
        run from the caller's retention cron some time after
        :meth:`revoke_access` suspended the user — never as the immediate
        reaction to a checkout, which only suspends.

        Idempotent: resources already gone do not raise.
        """
        ref = self._unpack_ref(grant_ref)
        with contextlib.suppress(LockNotFoundError):
            self._delete_access_group_from_site(ref["access_group_id"])
        with contextlib.suppress(LockNotFoundError):
            self._delete_user_from_site(ref["site_user_id"])
        return True

    def delete_user(self, site_user_id: str) -> bool:
        self._delete_user_from_site(site_user_id)
        return True

    def list_roles(self) -> list:
        """Return the site's roles as ``[{"id": ..., "name": ...}, ...]``.

        Lets the caller pick the guest role (the basic *User* role, which only
        opens doors). Role ids are unique per site, so they must be discovered
        rather than hardcoded. Needs no ``role_id`` itself, so it can run before
        one is configured."""
        return [
            {
                "id": role.get("id"),
                # The API exposes the readable label as ``customer_reference``
                # (e.g. "Site User"); ``code`` is the machine slug fallback.
                "name": role.get("customer_reference") or role.get("code"),
            }
            for role in self._get_roles_from_site()
        ]

    # ── get_access_groups_from_site ──────────────────────────────────────────

    def _get_access_groups_from_site(self) -> list:
        try:
            response = requests.get(
                f"{self.API_HOSTS[self.env]}/v1.2/sites/{self.siteId}/access_groups",
                headers={"Authorization": "Bearer " + self.accessToken},
            )
            self._handle_response(response)
            body = response.json()
            if "items" not in body:
                raise LockOperationError("API did not return any Access Groups")
            return cast("list", body["items"])
        except requests.exceptions.ConnectionError as err:
            raise LockConnectionError("Unable to connect to Salto API") from err

    # ── get_time_schedules_from_access_group ─────────────────────────────────

    def _get_time_schedules_from_access_group(self, access_group_id: str) -> list:
        try:
            response = requests.get(
                f"{self.API_HOSTS[self.env]}/v1.1/sites/{self.siteId}/access_groups/{access_group_id}/time_schedules",
                headers={"Authorization": "Bearer " + self.accessToken},
            )
            self._handle_response(response)
            body = response.json()
            if "items" not in body:
                raise LockOperationError("API did not return any Time Schedules")
            return cast("list", body["items"])
        except requests.exceptions.ConnectionError as err:
            raise LockConnectionError("Unable to connect to Salto API") from err

    # ── get_users_from_site ──────────────────────────────────────────────────

    def _get_users_from_site(self) -> list:
        try:
            response = requests.get(
                f"{self.API_HOSTS[self.env]}/v1.2/sites/{self.siteId}/users",
                headers={"Authorization": "Bearer " + self.accessToken},
            )
            self._handle_response(response)
            body = response.json()
            if "items" not in body:
                raise LockOperationError("API did not return any Users")
            return cast("list", body["items"])
        except requests.exceptions.ConnectionError as err:
            raise LockConnectionError("Unable to connect to Salto API") from err

    # ── get_roles_from_site ──────────────────────────────────────────────────

    def _get_roles_from_site(self) -> list:
        try:
            response = requests.get(
                f"{self.API_HOSTS[self.env]}/v1.2/sites/{self.siteId}/roles",
                headers={"Authorization": "Bearer " + self.accessToken},
            )
            self._handle_response(response)
            body = response.json()
            if "items" not in body:
                raise LockOperationError("API did not return any Roles")
            return cast("list", body["items"])
        except requests.exceptions.ConnectionError as err:
            raise LockConnectionError("Unable to connect to Salto API") from err

    # ── add_user_to_site ─────────────────────────────────────────────────────

    def _add_user_to_site(self, first_name: str, last_name: str, role_id: str, email: str) -> dict:
        try:
            payload = {
                "alias": first_name + " " + last_name,
                "blocked": False,
                "first_name": first_name,
                "last_name": last_name,
                "override_privacy_mode": True,
                "role_ids": [role_id],
                "tag_id": "",
                "toggle_easy_office_mode": True,
                "toggle_manual_office_mode": True,
                "use_pin": True,
            }
            # Email is optional. Salto rejects an empty string ("Email '' is
            # not valid"), so only send the key when set — the PIN flow
            # deliberately leaves it empty so Salto never emails the guest.
            if email:
                payload["email"] = email
            response = requests.post(
                f"{self.API_HOSTS[self.env]}/v1.2/sites/{self.siteId}/users",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Bearer " + self.accessToken,
                },
                json=payload,
            )
            self._handle_response(response)
            body = response.json()
            if "id" not in body:
                raise LockOperationError("API did not return a site_user_id")
            if "user" not in body:
                raise LockOperationError("API did not return an user")
            if "id" not in body["user"]:
                raise LockOperationError("API did not return an user_id")
            return {
                "site_user_id": body["id"],
                "user_id": body["user"]["id"],
            }
        except requests.exceptions.ConnectionError as err:
            raise LockConnectionError("Unable to connect to Salto API") from err

    # ── delete_user_from_site ─────────────────────────────────────────────────

    def _delete_user_from_site(self, site_user_id: str) -> bool:
        try:
            response = requests.delete(
                f"{self.API_HOSTS[self.env]}/v1.2/sites/{self.siteId}/users/{site_user_id}",
                headers={"Authorization": "Bearer " + self.accessToken},
            )
            self._handle_response(response)
            return True
        except requests.exceptions.ConnectionError as err:
            raise LockConnectionError("Unable to connect to Salto API") from err

    # ── _subscribe_user_to_site ───────────────────────────────────────────────

    def _subscribe_user_to_site(self, site_user_id: str) -> bool:
        try:
            response = requests.patch(
                f"{self.API_HOSTS[self.env]}/v1.2/sites/{self.siteId}/users/{site_user_id}/subscription",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Bearer " + self.accessToken,
                },
                json={"state": "subscribed"},
            )
            self._handle_response(response)
            return True
        except requests.exceptions.ConnectionError as err:
            raise LockConnectionError("Unable to connect to Salto API") from err

    # ── _unsubscribe_user_from_site ───────────────────────────────────────────

    def _unsubscribe_user_from_site(self, site_user_id: str) -> bool:
        try:
            response = requests.patch(
                f"{self.API_HOSTS[self.env]}/v1.2/sites/{self.siteId}/users/{site_user_id}/subscription",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Bearer " + self.accessToken,
                },
                json={"state": "suspended"},
            )
            self._handle_response(response)
            return True
        except requests.exceptions.ConnectionError as err:
            raise LockConnectionError("Unable to connect to Salto API") from err

    # ── add_access_group_to_site ──────────────────────────────────────────────

    def _add_access_group_to_site(self, access_group_name: str) -> str:
        try:
            response = requests.post(
                f"{self.API_HOSTS[self.env]}/v1.2/sites/{self.siteId}/access_groups",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Bearer " + self.accessToken,
                },
                json={"customer_reference": access_group_name},
            )
            self._handle_response(response)
            body = response.json()
            if "id" not in body:
                raise LockOperationError("API did not return an access_group_id")
            return cast("str", body["id"])
        except requests.exceptions.ConnectionError as err:
            raise LockConnectionError("Unable to connect to Salto API") from err

    # ── delete_access_group_from_site ─────────────────────────────────────────

    def _delete_access_group_from_site(self, access_group_id: str) -> bool:
        try:
            response = requests.delete(
                f"{self.API_HOSTS[self.env]}/v1.2/sites/{self.siteId}/access_groups/{access_group_id}",
                headers={"Authorization": "Bearer " + self.accessToken},
            )
            self._handle_response(response)
            return True
        except requests.exceptions.ConnectionError as err:
            raise LockConnectionError("Unable to connect to Salto API") from err

    # ── time-schedule datetime formatting ─────────────────────────────────────

    def _fmt_schedule_datetime(self, dt: datetime) -> str:
        """Serialize a time-schedule datetime the way Salto expects.

        Salto stores start_date/end_date as naive wall-clock and the site's IQ
        enforces them in its own (the hotel's) timezone, not UTC. The caller
        passes UTC-aware datetimes, so convert to ``self.time_zone`` first; with
        no timezone configured, fall back to the datetime as-is (UTC wall-clock).
        """
        if self.time_zone:
            dt = dt.astimezone(ZoneInfo(self.time_zone))
        return dt.strftime("%Y-%m-%dT%H:%M:%S")

    # ── add_time_schedule_to_access_group ─────────────────────────────────────

    def _add_time_schedule_to_access_group(
        self, access_group_id: str, start_date: datetime, end_date: datetime
    ) -> dict:
        try:
            response = requests.post(
                f"{self.API_HOSTS[self.env]}/v1.1/sites/{self.siteId}/access_groups/{access_group_id}/time_schedules",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Bearer " + self.accessToken,
                },
                # Check-in/check-out (continuous) window, matching the Salto KS
                # web app: the exact start/end *time* travels in start_date/
                # end_date, while start_time/end_time stay 00:00:00-23:59:59 and
                # every weekday is enabled, so the daily filter never clips the
                # window. Putting the real hours in start_time/end_time instead
                # would make a recurring daily window and lock the guest out
                # overnight on multi-day stays.
                json={
                    "end_date": self._fmt_schedule_datetime(end_date),
                    "end_time": "23:59:59",
                    "start_date": self._fmt_schedule_datetime(start_date),
                    "start_time": "00:00:00",
                    "friday": True,
                    "monday": True,
                    "saturday": True,
                    "sunday": True,
                    "thursday": True,
                    "tuesday": True,
                    "wednesday": True,
                },
            )
            self._handle_response(response)
            body = response.json()
            if "id" not in body:
                raise LockOperationError("API did not return a time_schedule_id")
            if "start_date" not in body:
                raise LockOperationError("API did not return a start_date")
            if "end_date" not in body:
                raise LockOperationError("API did not return an end_date")
            return {
                "time_schedule_id": body["id"],
                "start_date": body["start_date"],
                "end_date": body["end_date"],
            }
        except requests.exceptions.ConnectionError as err:
            raise LockConnectionError("Unable to connect to Salto API") from err

    # ── modify_time_schedule_in_access_group ──────────────────────────────────

    def _modify_time_schedule_in_access_group(
        self,
        access_group_id: str,
        time_schedule_id: str,
        start_date: datetime,
        end_date: datetime,
    ) -> dict:
        try:
            response = requests.patch(
                f"{self.API_HOSTS[self.env]}/v1.1/sites/{self.siteId}/access_groups/{access_group_id}/time_schedules/{time_schedule_id}",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Bearer " + self.accessToken,
                },
                # See _add_time_schedule_to_access_group: continuous window, the
                # exact hours live in start_date/end_date.
                json={
                    "end_date": self._fmt_schedule_datetime(end_date),
                    "end_time": "23:59:59",
                    "friday": True,
                    "monday": True,
                    "saturday": True,
                    "start_date": self._fmt_schedule_datetime(start_date),
                    "start_time": "00:00:00",
                    "sunday": True,
                    "thursday": True,
                    "tuesday": True,
                    "wednesday": True,
                },
            )
            self._handle_response(response)
            body = response.json()
            if "id" not in body:
                raise LockOperationError("API did not return a time_schedule_id")
            if "start_date" not in body:
                raise LockOperationError("API did not return a start_date")
            if "end_date" not in body:
                raise LockOperationError("API did not return an end_date")
            return {
                "time_schedule_id": body["id"],
                "start_date": body["start_date"],
                "end_date": body["end_date"],
            }
        except requests.exceptions.ConnectionError as err:
            raise LockConnectionError("Unable to connect to Salto API") from err

    # ── delete_time_schedule_from_access_group ────────────────────────────────

    def _delete_time_schedule_from_access_group(self, access_group_id: str, time_schedule_id: str) -> bool:
        try:
            response = requests.delete(
                f"{self.API_HOSTS[self.env]}/v1.1/sites/{self.siteId}/access_groups/{access_group_id}/time_schedules/{time_schedule_id}",
                headers={"Authorization": "Bearer " + self.accessToken},
            )
            self._handle_response(response)
            return True
        except requests.exceptions.ConnectionError as err:
            raise LockConnectionError("Unable to connect to Salto API") from err

    # ── add_user_to_access_group ──────────────────────────────────────────────

    def _add_user_to_access_group(self, access_group_id: str, user_id: str) -> bool:
        try:
            response = requests.post(
                f"{self.API_HOSTS[self.env]}/v1.2/sites/{self.siteId}/access_groups/{access_group_id}/users",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Bearer " + self.accessToken,
                },
                json={"user_id": user_id},
            )
            self._handle_response(response)
            return True
        except requests.exceptions.ConnectionError as err:
            raise LockConnectionError("Unable to connect to Salto API") from err

    # ── delete_user_from_access_group ─────────────────────────────────────────

    def _delete_user_from_access_group(self, access_group_id: str, user_id: str) -> bool:
        try:
            response = requests.delete(
                f"{self.API_HOSTS[self.env]}/v1.2/sites/{self.siteId}/access_groups/{access_group_id}/users/{user_id}",
                headers={"Authorization": "Bearer " + self.accessToken},
            )
            self._handle_response(response)
            return True
        except requests.exceptions.ConnectionError as err:
            raise LockConnectionError("Unable to connect to Salto API") from err

    # ── add_lock_to_access_group ──────────────────────────────────────────────

    def _add_lock_to_access_group(self, access_group_id: str, lock_id: str) -> bool:
        try:
            response = requests.post(
                f"{self.API_HOSTS[self.env]}/v1.1/sites/{self.siteId}/access_groups/{access_group_id}/locks",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Bearer " + self.accessToken,
                },
                json={"lock_id": lock_id},
            )
            self._handle_response(response)
            return True
        except requests.exceptions.ConnectionError as err:
            raise LockConnectionError("Unable to connect to Salto API") from err

    # ── delete_lock_from_access_group ─────────────────────────────────────────

    def _delete_lock_from_access_group(self, access_group_id: str, lock_id: str) -> bool:
        try:
            response = requests.delete(
                f"{self.API_HOSTS[self.env]}/v1.1/sites/{self.siteId}/access_groups/{access_group_id}/locks/{lock_id}",
                headers={"Authorization": "Bearer " + self.accessToken},
            )
            self._handle_response(response)
            return True
        except requests.exceptions.ConnectionError as err:
            raise LockConnectionError("Unable to connect to Salto API") from err

    # ── create_modify_user_pin ────────────────────────────────────────────────

    def _create_modify_user_pin(self, site_user_id: str, pin: str | None = None) -> str:
        """Create or update the user's PIN and return it.

        With no ``pin`` Salto generates one server-side and returns it as the
        response body. A caller-supplied ``pin`` is sent for the vendor to set.
        """
        try:
            response = requests.put(
                f"{self.API_HOSTS[self.env]}/v1.2/sites/{self.siteId}/users/{site_user_id}/pin",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Bearer " + self.accessToken,
                },
                json={"pin": pin} if pin else {},
            )
            self._handle_response(response)
            return response.text.strip().strip('"')
        except requests.exceptions.ConnectionError as err:
            raise LockConnectionError("Unable to connect to Salto API") from err

    # ── get_locks_from_access_group ───────────────────────────────────────────

    def _get_locks_from_access_group(self, access_group_id: str) -> list:
        try:
            response = requests.get(
                f"{self.API_HOSTS[self.env]}/v1.1/sites/{self.siteId}/access_groups/{access_group_id}/locks",
                headers={"Authorization": "Bearer " + self.accessToken},
            )
            self._handle_response(response)
            body = response.json()
            return [lock["id"] for lock in body.get("items", [])]
        except requests.exceptions.ConnectionError as err:
            raise LockConnectionError("Unable to connect to Salto API") from err
