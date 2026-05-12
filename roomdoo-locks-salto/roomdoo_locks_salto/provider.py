import requests
import secrets
from datetime import datetime
import base64

from roomdoo_locks_base import BaseLockProvider, CodeResult
from roomdoo_locks_base.exceptions import (
    LockAuthError,
    LockConnectionError,
    LockNotFoundError,
    LockOperationError,
    LockAPIError,
    LockNoPermissionError,
    LockOfflineError
)


class SaltoProvider(BaseLockProvider):

    IDENTITY_HOSTS = {
        "prod": "https://identity.eu.my-clay.com",
        "acc":  "https://identity-acc.eu.my-clay.com",
    }

    API_HOSTS = {
        "prod": "https://user.my-clay.com",
        "acc":  "https://clp-accept-user.my-clay.com",
    }

    def __init__(self, clientId: str, clientSecret: str, username: str, password: str, siteId: str, env: str = "prod"):
        self.clientId     = clientId
        self.clientSecret = clientSecret
        self.username     = username
        self.password     = password
        self.siteId = siteId
        self.env = env
        self.accessToken = None
        self._authenticate()

    # ── Authentication ───────────────────────────────────────────────────────

    def _authenticate(self):
        try:
            response = requests.post(f"{self.IDENTITY_HOSTS[self.env]}/connect/token", 
            headers={
                "Content-Type" : "application/x-www-form-urlencoded",
                "Authorization" : "Basic " + base64.b64encode(f"{self.clientId}:{self.clientSecret}".encode()).decode() 
            }, 
            data={
                "grant_type" : "password",
                "username" : self.username,
                "password" : self.password,
                "scope" : "user_api.full_access"
            })
            self._handle_response(response)
            body = response.json()
            if "access_token" not in body:
                raise LockAuthError("Invalid credentials")
            self.accessToken  = body["access_token"]
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("Unable to connect to Salto API")

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _handle_response(self, response: requests.Response) -> None:
        """Centralizes HTTP and business error handling for the API."""
        if response.status_code == 204:
            return None

        if not response.text.strip():
            return None

        if response.status_code == 400:
            raise LockAuthError(
                f"Authentication error [400]: {response.text}"
            )
        if response.status_code == 401:
            raise LockAuthError(
                f"Authentication error [401]: {response.text}"
            )
        if response.status_code == 404:
            raise LockNotFoundError(
                f"Resource not found [404]: {response.text}"
            )
        if response.status_code == 415:
            raise LockOperationError(
                f"Unsupported Media Type [415]: {response.text}"
            )
        if response.status_code == 500:
            raise LockConnectionError(
                f"Internal server error [500]: {response.text}"
            )
        if not response.ok:
            raise LockOperationError(
                f"Unexpected error [{response.status_code}]: {response.text}"
            )
    
        # Business errors within 200 responses
        try:
            body = response.json()
        except Exception:
            raise LockAPIError("Invalid response from Omnitec API")

        if not isinstance(body, dict):
            return body

        errcode = body.get("ErrorCode")
        description  = body.get("Message", "Unknown error")

        if errcode is not None and errcode != 0:
            if errcode == 1100:
                raise LockOperationError(f"Invalid parameter [{errcode}]: {description}")
            if errcode == 1101:
                raise LockOperationError(f"Invalid parameter [{errcode}]: {description}")
            if errcode == 2202:
                raise LockOperationError(f"Invalid parameter [{errcode}]: {description}")
            raise LockOperationError(f"Operation error [{errcode}]: {description}")

    def _to_ms(self, dt: datetime) -> int:
        return int(dt.timestamp() * 1000)

    def _params(self, extra: dict) -> dict:
        return {"clientId": self.clientId, "token": self.accessToken, **extra}

    # ── test_connection ──────────────────────────────────────────────────────

    def test_connection(self) -> bool:
        self._authenticate()
        return True

    # ── create_code ──────────────────────

    def create_code(self, lock_id: str, start_date: datetime, end_date: datetime, first_name: str, last_name: str, role_id: str, email: str = "[EMAIL_ADDRESS]", access_group_name: str = "Grupo de Acceso") -> CodeResult:
        self._validate_time_range(start_date, end_date)
        return self._do_create_code(lock_id, start_date, end_date, first_name, last_name, role_id, email, access_group_name)

    # ── delete_user ──────────────────────

    def delete_user(self, site_user_id: str) -> bool:
        self._delete_user_from_site(site_user_id)
        return True

    # ── _do_create_code ──────────────────────

    def _do_create_code(self, lock_id: str, start_date: datetime, end_date: datetime, first_name: str, last_name: str, role_id: str, email: str, access_group_name: str):
        user = self._add_user_to_site(first_name, last_name, role_id, email)
        access_group_id = self._add_access_group_to_site(access_group_name)
        self._add_time_schedule_to_access_group(access_group_id, start_date, end_date)
        self._add_user_to_access_group(access_group_id, user["user_id"])
        self._add_lock_to_access_group(access_group_id, lock_id)
        return self._create_modify_user_pin(access_group_id, user["site_user_id"], lock_id, start_date, end_date)

    # ── _do_invalidate_code ──────────────────────────────────────────────────

    def _do_invalidate_code(self, access_group_id: str, site_user_id: str) -> bool:
        self._delete_access_group_from_site(access_group_id)
        self._unsubscribe_user_from_site(site_user_id)
        return True

    # ── _do_modify_code ──────────────────────────────────────────────────────

    def _do_modify_code(self, access_group_id: str, time_schedule_id: str, start_date: datetime, end_date: datetime) -> CodeResult:
        return self._modify_time_schedule_in_access_group(access_group_id, time_schedule_id, start_date, end_date)

    # ── get_access_groups_from_site ──────────────────────────────────────────────────────

    def _get_access_groups_from_site(self) -> list:
        try:
            response = requests.get(f"{self.API_HOSTS[self.env]}/v1.2/sites/{self.siteId}/access_groups", 
            headers={
                "Authorization" : "Bearer " + self.accessToken
            })
            self._handle_response(response)
            body = response.json()
            if "items" not in body:
                raise LockOperationError("API did not return any Access Groups")
            return body["items"]
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("Unable to connect to Salto API")

    # ── get_time_schedules_from_access_group ──────────────────────────────────────────────────────

    def _get_time_schedules_from_access_group(self, access_group_id: str) -> list:
        try:
            response = requests.get(f"{self.API_HOSTS[self.env]}/v1.1/sites/{self.siteId}/access_groups/{access_group_id}/time_schedules", 
            headers={
                "Authorization" : "Bearer " + self.accessToken
            })
            self._handle_response(response)
            body = response.json()
            if "items" not in body:
                raise LockOperationError("API did not return any Time Schedules")
            return body["items"]
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("Unable to connect to Salto API")

    # ── get_users_from_site ──────────────────────────────────────────────────────

    def _get_users_from_site(self) -> list:
        try:
            response = requests.get(f"{self.API_HOSTS[self.env]}/v1.2/sites/{self.siteId}/users", 
            headers={
                "Authorization" : "Bearer " + self.accessToken
            })
            self._handle_response(response)
            body = response.json()
            if "items" not in body:
                raise LockOperationError("API did not return any Users")
            return body["items"]
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("Unable to connect to Salto API")

    # ── get_roles_from_site ──────────────────────────────────────────────────────

    def _get_roles_from_site(self) -> list:
        try:
            response = requests.get(f"{self.API_HOSTS[self.env]}/v1.2/sites/{self.siteId}/roles", 
            headers={
                "Authorization" : "Bearer " + self.accessToken
            })
            self._handle_response(response)
            body = response.json()
            if "items" not in body:
                raise LockOperationError("API did not return any Users")
            return body["items"]
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("Unable to connect to Salto API")

    # ── add_user_to_site ──────────────────────────────────────────────────────

    def _add_user_to_site(self, first_name: str, last_name: str, role_id: str, email: str) -> dict:
        try:
            response = requests.post(f"{self.API_HOSTS[self.env]}/v1.2/sites/{self.siteId}/users", 
            headers={
                "Content-Type" : "application/json",
                "Authorization" : "Bearer " + self.accessToken
            }, 
            json={
                "alias" : first_name + " " + last_name,
                "blocked" : False,
                "email" : email,
                "first_name" : first_name,
                "last_name" : last_name,
                "override_privacy_mode" : True,
                "role_ids" : [
                    role_id,
                ],
                "tag_id" : "",
                "toggle_easy_office_mode" : True,
                "toggle_manual_office_mode" : True,
                "use_pin" : True
            })
            self._handle_response(response)
            body = response.json()
            if "id" not in body:
                raise LockOperationError("API did not return a site_user_id")
            if "user" not in body:
                raise LockOperationError("API did not return an user")
            if "id" not in body["user"]:
                raise LockOperationError("API did not return an user_id")
            site_user_id  = body["id"]
            user_id = body["user"]["id"]
            return {
                "site_user_id": site_user_id,
                "user_id": user_id
            }
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("Unable to connect to Salto API")

    # ── delete_user_from_site ──────────────────────────────────────────────────────

    def _delete_user_from_site(self, site_user_id: str) -> bool:
        try:
            response = requests.delete(f"{self.API_HOSTS[self.env]}/v1.2/sites/{self.siteId}/users/{site_user_id}", 
            headers={
                "Authorization" : "Bearer " + self.accessToken
            })
            self._handle_response(response)
            return True
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("Unable to connect to Salto API")

    # ── subscribe_user_to_site ──────────────────────────────────────────────────────

    def _subscribe_user_to_site(self, site_user_id: str) -> bool:
        try:
            response = requests.patch(f"{self.API_HOSTS[self.env]}/v1.2/sites/{self.siteId}/users/{site_user_id}/subscription", 
            headers={
                "Content-Type" : "application/json",
                "Authorization" : "Bearer " + self.accessToken
            }, 
            json={
                "state" : "subscribed"
            })
            self._handle_response(response)
            return True
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("Unable to connect to Salto API")

    # ── unsubscribe_user_from_site ──────────────────────────────────────────────────────

    def _unsubscribe_user_from_site(self, site_user_id: str) -> bool:
        try:
            response = requests.patch(f"{self.API_HOSTS[self.env]}/v1.2/sites/{self.siteId}/users/{site_user_id}/subscription", 
            headers={
                "Content-Type" : "application/json",
                "Authorization" : "Bearer " + self.accessToken
            }, 
            json={
                "state" : "suspended"
            })
            self._handle_response(response)
            return True
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("Unable to connect to Salto API")

    # ── add_access_group_to_site ──────────────────────────────────────────────────────

    def _add_access_group_to_site(self, access_group_name: str) -> str:
        try:
            response = requests.post(f"{self.API_HOSTS[self.env]}/v1.2/sites/{self.siteId}/access_groups", 
            headers={
                "Content-Type" : "application/json",
                "Authorization" : "Bearer " + self.accessToken
            }, 
            json={
                "customer_reference" : access_group_name
            })
            self._handle_response(response)
            body = response.json()
            if "id" not in body:
                raise LockOperationError("API did not return an access_group_id")
            access_group_id = body["id"]
            return access_group_id
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("Unable to connect to Salto API")

    # ── delete_access_group_from_site ──────────────────────────────────────────────────────

    def _delete_access_group_from_site(self, access_group_id: str) -> bool:
        try:
            response = requests.delete(f"{self.API_HOSTS[self.env]}/v1.2/sites/{self.siteId}/access_groups/{access_group_id}", 
            headers={
                "Authorization" : "Bearer " + self.accessToken
            })
            self._handle_response(response)
            return True
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("Unable to connect to Salto API")

    # ── add_time_schedule_to_access_group ──────────────────────────────────────────────────────

    def _add_time_schedule_to_access_group(self, access_group_id: str, start_date: datetime, end_date: datetime) -> dict:
        try:
            response = requests.post(f"{self.API_HOSTS[self.env]}/v1.1/sites/{self.siteId}/access_groups/{access_group_id}/time_schedules", 
            headers={
                "Content-Type" : "application/json",
                "Authorization" : "Bearer " + self.accessToken
            }, 
            json={
                "end_date": end_date.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3],
                "end_time": "23:59",
                "start_date": start_date.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3],
                "start_time": "00:00",
                "friday": True,
                "monday": True,
                "saturday": True,
                "sunday": True,
                "thursday": True,
                "tuesday": True,
                "wednesday": True
            })
            self._handle_response(response)
            body = response.json()
            if "id" not in body:
                raise LockOperationError("API did not return a time_schedule_id")
            time_schedule_id = body["id"]
            if "start_date" not in body:
                raise LockOperationError("API did not return a start_date")
            start_date = body["start_date"]
            if "end_date" not in body:
                raise LockOperationError("API did not return an end_date")
            send_date = body["end_date"]
            return {
                "time_schedule_id" : time_schedule_id,
                "start_date" : start_date,
                "end_date" : send_date
            }
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("Unable to connect to Salto API")

    # ── modify_time_schedule_in_access_group ──────────────────────────────────────────────────────

    def _modify_time_schedule_in_access_group(self, access_group_id: str, time_schedule_id: str, start_date: datetime, end_date: datetime) -> dict:
        try:
            response = requests.patch(f"{self.API_HOSTS[self.env]}/v1.1/sites/{self.siteId}/access_groups/{access_group_id}/time_schedules/{time_schedule_id}", 
            headers={
                "Content-Type" : "application/json",
                "Authorization" : "Bearer " + self.accessToken
            }, 
            json={
                "end_date": end_date.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3],
                "end_time": "23:59",
                "friday": True,
                "monday": True,
                "saturday": True,
                "start_date": start_date.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3],
                "start_time": "00:00",
                "sunday": True,
                "thursday": True,
                "tuesday": True,
                "wednesday": True
            })
            self._handle_response(response)
            body = response.json()
            if "id" not in body:
                raise LockOperationError("API did not return a time_schedule_id")
            time_schedule_id = body["id"]
            if "start_date" not in body:
                raise LockOperationError("API did not return a start_date")
            start_date = body["start_date"]
            if "end_date" not in body:
                raise LockOperationError("API did not return an end_date")
            end_date = body["end_date"]
            return {
                "time_schedule_id" : time_schedule_id,
                "start_date" : start_date,
                "end_date" : end_date
            }
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("Unable to connect to Salto API")

    # ── delete_time_schedule_from_access_group ──────────────────────────────────────────────────────

    def _delete_time_schedule_from_access_group(self, access_group_id: str, time_schedule_id: str) -> bool:
        try:
            response = requests.delete(f"{self.API_HOSTS[self.env]}/v1.1/sites/{self.siteId}/access_groups/{access_group_id}/time_schedules/{time_schedule_id}", 
            headers={
                "Authorization" : "Bearer " + self.accessToken
            })
            self._handle_response(response)
            return True
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("Unable to connect to Salto API")

    # ── add_user_to_access_group ──────────────────────────────────────────────────────

    def _add_user_to_access_group(self, access_group_id: str, user_id: str) -> bool:
        try:
            response = requests.post(f"{self.API_HOSTS[self.env]}/v1.2/sites/{self.siteId}/access_groups/{access_group_id}/users", 
            headers={
                "Content-Type" : "application/json",
                "Authorization" : "Bearer " + self.accessToken
            }, 
            json={
                "user_id" : user_id
            })
            self._handle_response(response)
            body = response.json()
            return True
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("Unable to connect to Salto API")

    # ── delete_user_from_access_group ──────────────────────────────────────────────────────

    def _delete_user_from_access_group(self, access_group_id: str, user_id: str) -> bool:
        try:
            response = requests.delete(f"{self.API_HOSTS[self.env]}/v1.2/sites/{self.siteId}/access_groups/{access_group_id}/users/{user_id}", 
            headers={
                "Authorization" : "Bearer " + self.accessToken
            })
            self._handle_response(response)
            return True
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("Unable to connect to Salto API")

    # ── add_lock_to_access_group ──────────────────────────────────────────────────────

    def _add_lock_to_access_group(self, access_group_id: str, lock_id: str) -> bool:
        try:
            response = requests.post(f"{self.API_HOSTS[self.env]}/v1.2/sites/{self.siteId}/access_groups/{access_group_id}/locks", 
            headers={
                "Content-Type" : "application/json",
                "Authorization" : "Bearer " + self.accessToken
            }, 
            json={
                "lock_id" : lock_id
            })
            self._handle_response(response)
            body = response.json()
            return True
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("Unable to connect to Salto API")

    # ── delete_lock_from_access_group ──────────────────────────────────────────────────────

    def _delete_lock_from_access_group(self, access_group_id: str, lock_id: str) -> bool:
        try:
            response = requests.delete(f"{self.API_HOSTS[self.env]}/v1.2/sites/{self.siteId}/access_groups/{access_group_id}/locks/{lock_id}", 
            headers={
                "Authorization" : "Bearer " + self.accessToken
            })
            self._handle_response(response)
            return True
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("Unable to connect to Salto API")

    # ── create_modify_user_pin ──────────────────────────────────────────────────────

    def _create_modify_user_pin(self, access_group_id: str, site_user_id: str, lock_id: str, start_date: datetime, end_date: datetime) -> bool:
        try:
            response = requests.put(f"{self.API_HOSTS[self.env]}/v1.2/sites/{self.siteId}/users/{site_user_id}/pin", 
            headers={
                "Content-Type" : "application/json",
                "Authorization" : "Bearer " + self.accessToken
            },
            json={
            })
            self._handle_response(response)
            pin = response.text.strip().strip('"')
            return CodeResult(
                code_id   = access_group_id,
                pin       = pin,
                lock_id   = lock_id,
                starts_at = start_date,
                ends_at   = end_date
            )
        except requests.exceptions.ConnectionError:
            raise LockConnectionError("Unable to connect to Salto API")
