import requests
import json
import base64
from datetime import datetime

from roomdoo_locks_base import BaseLockProvider, AccessGrant
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

    IDENTITY_HOSTS = {
        "prod": "https://identity.eu.my-clay.com",
        "acc":  "https://identity-acc.eu.my-clay.com",
    }

    API_HOSTS = {
        "prod": "https://user.my-clay.com",
        "acc":  "https://clp-accept-user.my-clay.com",
    }

    def __init__(
        self,
        clientId: str,
        clientSecret: str,
        username: str,
        password: str,
        siteId: str,
        role_id: str,
        env: str = "prod",
        access_group_name: str = "Roomdoo Access",
        guest_first_name: str = "Roomdoo",
        guest_last_name: str = "Guest",
        guest_email: str = "",
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
        self.accessToken = None
        self._authenticate()

    # ── Authentication ───────────────────────────────────────────────────────

    def _authenticate(self):
        try:
            response = requests.post(
                f"{self.IDENTITY_HOSTS[self.env]}/connect/token",
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Authorization": "Basic " + base64.b64encode(
                        f"{self.clientId}:{self.clientSecret}".encode()
                    ).decode(),
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
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("Unable to connect to Salto API")

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
            raise LockOperationError(
                f"Unexpected error [{response.status_code}]: {response.text}"
            )

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
        return json.loads(grant_ref)

    # ── BaseLockProvider contract ─────────────────────────────────────────────

    def _do_grant_access(
        self, lock_ids: list, starts_at: datetime, ends_at: datetime, pin: str
    ) -> AccessGrant:
        user = self._add_user_to_site(
            self.guest_first_name, self.guest_last_name, self.role_id, self.guest_email
        )
        site_user_id = user["site_user_id"]
        user_id = user["user_id"]

        access_group_id = None
        try:
            access_group_id = self._add_access_group_to_site(self.access_group_name)
            schedule = self._add_time_schedule_to_access_group(
                access_group_id, starts_at, ends_at
            )
            self._add_user_to_access_group(access_group_id, user_id)
            for lock_id in lock_ids:
                self._add_lock_to_access_group(access_group_id, lock_id)
            pin = self._create_modify_user_pin(site_user_id, pin)
        except Exception:
            # All-or-nothing: roll back best-effort so a retry starts clean
            # instead of leaving an orphan user/access group behind.
            if access_group_id is not None:
                try:
                    self._delete_access_group_from_site(access_group_id)
                except Exception:
                    pass
            try:
                self._delete_user_from_site(site_user_id)
            except Exception:
                pass
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

    def _do_modify_access(
        self, grant_ref: str, starts_at: datetime, ends_at: datetime
    ) -> AccessGrant:
        ref = self._unpack_ref(grant_ref)
        self._modify_time_schedule_in_access_group(
            ref["access_group_id"], ref["time_schedule_id"], starts_at, ends_at
        )
        # The PIN does not change when only the validity window is updated; the
        # caller keeps the one returned by grant_access.
        return AccessGrant(pin="", ref=grant_ref, starts_at=starts_at, ends_at=ends_at)

    def _do_revoke_access(self, grant_ref: str) -> bool:
        ref = self._unpack_ref(grant_ref)
        # Idempotent: a grant whose resources are already gone still revokes.
        try:
            self._delete_access_group_from_site(ref["access_group_id"])
        except LockNotFoundError:
            pass
        try:
            self._delete_user_from_site(ref["site_user_id"])
        except LockNotFoundError:
            pass
        return True

    def test_connection(self) -> bool:
        self._authenticate()
        return True

    # ── Extras ─────────────────────────────────────────────────────────────

    def delete_user(self, site_user_id: str) -> bool:
        self._delete_user_from_site(site_user_id)
        return True

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
            return body["items"]
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("Unable to connect to Salto API")

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
            return body["items"]
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("Unable to connect to Salto API")

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
            return body["items"]
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("Unable to connect to Salto API")

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
            return body["items"]
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("Unable to connect to Salto API")

    # ── add_user_to_site ─────────────────────────────────────────────────────

    def _add_user_to_site(
        self, first_name: str, last_name: str, role_id: str, email: str
    ) -> dict:
        try:
            response = requests.post(
                f"{self.API_HOSTS[self.env]}/v1.2/sites/{self.siteId}/users",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Bearer " + self.accessToken,
                },
                json={
                    "alias": first_name + " " + last_name,
                    "blocked": False,
                    "email": email,
                    "first_name": first_name,
                    "last_name": last_name,
                    "override_privacy_mode": True,
                    "role_ids": [role_id],
                    "tag_id": "",
                    "toggle_easy_office_mode": True,
                    "toggle_manual_office_mode": True,
                    "use_pin": True,
                },
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
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("Unable to connect to Salto API")

    # ── delete_user_from_site ─────────────────────────────────────────────────

    def _delete_user_from_site(self, site_user_id: str) -> bool:
        try:
            response = requests.delete(
                f"{self.API_HOSTS[self.env]}/v1.2/sites/{self.siteId}/users/{site_user_id}",
                headers={"Authorization": "Bearer " + self.accessToken},
            )
            self._handle_response(response)
            return True
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("Unable to connect to Salto API")

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
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("Unable to connect to Salto API")

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
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("Unable to connect to Salto API")

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
            return body["id"]
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("Unable to connect to Salto API")

    # ── delete_access_group_from_site ─────────────────────────────────────────

    def _delete_access_group_from_site(self, access_group_id: str) -> bool:
        try:
            response = requests.delete(
                f"{self.API_HOSTS[self.env]}/v1.2/sites/{self.siteId}/access_groups/{access_group_id}",
                headers={"Authorization": "Bearer " + self.accessToken},
            )
            self._handle_response(response)
            return True
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("Unable to connect to Salto API")

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
                # end_date, while start_time/end_time stay 00:00:00–23:59:59 and
                # every weekday is enabled, so the daily filter never clips the
                # window. Putting the real hours in start_time/end_time instead
                # would make a recurring daily window and lock the guest out
                # overnight on multi-day stays.
                json={
                    "end_date": end_date.strftime("%Y-%m-%dT%H:%M:%S"),
                    "end_time": "23:59:59",
                    "start_date": start_date.strftime("%Y-%m-%dT%H:%M:%S"),
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
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("Unable to connect to Salto API")

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
                    "end_date": end_date.strftime("%Y-%m-%dT%H:%M:%S"),
                    "end_time": "23:59:59",
                    "friday": True,
                    "monday": True,
                    "saturday": True,
                    "start_date": start_date.strftime("%Y-%m-%dT%H:%M:%S"),
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
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("Unable to connect to Salto API")

    # ── delete_time_schedule_from_access_group ────────────────────────────────

    def _delete_time_schedule_from_access_group(
        self, access_group_id: str, time_schedule_id: str
    ) -> bool:
        try:
            response = requests.delete(
                f"{self.API_HOSTS[self.env]}/v1.1/sites/{self.siteId}/access_groups/{access_group_id}/time_schedules/{time_schedule_id}",
                headers={"Authorization": "Bearer " + self.accessToken},
            )
            self._handle_response(response)
            return True
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("Unable to connect to Salto API")

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
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("Unable to connect to Salto API")

    # ── delete_user_from_access_group ─────────────────────────────────────────

    def _delete_user_from_access_group(self, access_group_id: str, user_id: str) -> bool:
        try:
            response = requests.delete(
                f"{self.API_HOSTS[self.env]}/v1.2/sites/{self.siteId}/access_groups/{access_group_id}/users/{user_id}",
                headers={"Authorization": "Bearer " + self.accessToken},
            )
            self._handle_response(response)
            return True
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("Unable to connect to Salto API")

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
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("Unable to connect to Salto API")

    # ── delete_lock_from_access_group ─────────────────────────────────────────

    def _delete_lock_from_access_group(self, access_group_id: str, lock_id: str) -> bool:
        try:
            response = requests.delete(
                f"{self.API_HOSTS[self.env]}/v1.1/sites/{self.siteId}/access_groups/{access_group_id}/locks/{lock_id}",
                headers={"Authorization": "Bearer " + self.accessToken},
            )
            self._handle_response(response)
            return True
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("Unable to connect to Salto API")

    # ── create_modify_user_pin ────────────────────────────────────────────────

    def _create_modify_user_pin(self, site_user_id: str, pin: str = None) -> str:
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
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("Unable to connect to Salto API")

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
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("Unable to connect to Salto API")
