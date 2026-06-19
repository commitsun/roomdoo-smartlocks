"""TESA Smartair adapter for the Roomdoo access-grant contract.

TESA Smartair is a SOAP platform (zeep client) where guest access is expressed
*per room*: a PIN is assigned to a roomId via the GuestsWebService. There is no
native notion of "one credential across several rooms", so — like TTLock — this
adapter realises a grant by pushing the *same* PIN to every room of the set and
packs the per-room handles into the opaque ``ref``.

Two TESA peculiarities shape the adapter:

* **Check-in vs pre-check-in.** ``checkin`` only applies when the guest is
  entering *now* (the room becomes occupied immediately). When ``starts_at`` is
  in the future the grant is created through ``precheckin`` instead, which
  yields a ``preAssignationId`` to manage it until activation. The whole grant
  is one or the other, decided from ``starts_at`` against the current time.
  Smartair then *auto-activates* a pre-assignment into a check-in when its
  activation time passes, so the create-time choice goes stale: modify/revoke
  re-read the room's live state and match it back to the grant by its PIN
  (Smartair returns the active ``keyPad``, unique among live credentials)
  before acting, rather than trusting the frozen flag.

* **PIN collisions.** Smartair rejects a PIN already active on another lock with
  an overlapping window. An auto-generated PIN is retried with a fresh value;
  a caller-supplied PIN surfaces :class:`LockPinCollisionError`.

Authentication is operatorName + operatorPassword sent with every request (no
session token). Endpoint layout (replace ``<host>``):

  GuestsWebService  https://<host>:8181/ServerPlatform/GuestsWebService?wsdl
  UsersWebService   https://<host>:8181/ServerPlatform/UsersWebService?wsdl
  DoorsWebService   https://<host>:8181/ServerPlatform/DoorsWebService?wsdl
"""

from __future__ import annotations

import contextlib
import json
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, ClassVar, cast

import urllib3
from requests import Session
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
from zeep import Client, Settings
from zeep.exceptions import Fault, TransportError
from zeep.transports import Transport

from roomdoo_locks_tesa.exceptions import (
    LockAlreadyClearedError,
    LockPinCollisionError,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ---------------------------------------------------------------------------
# Result types for the room-listing extras (the contract returns AccessGrant)
# ---------------------------------------------------------------------------


@dataclass
class PreAssignation:
    pre_assignation_id: int
    date_pre_activation: str | None
    date_pre_expiration: str | None
    grants_preassigned: list[str] = field(default_factory=list)


@dataclass
class RoomInfo:
    door_id: int
    door_name: str
    room_occupied: bool
    room_preassigned: bool
    date_activation: str | None
    date_expiration: str | None
    battery_status: str | None
    battery_percentage: int | None
    # PIN currently active on the occupied check-in (Smartair exposes it as
    # ``keyPad``). It is the only durable handle that ties a check-in back to
    # the grant that created it, so modify/revoke use it to confirm ownership.
    key_pad: str | None = None
    grants_occupied: list[str] = field(default_factory=list)
    pre_assignations: list[PreAssignation] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Provider
# ---------------------------------------------------------------------------


class TesaSmartairProvider(BaseLockProvider):
    """TESA Smartair implementation of the access-grant contract."""

    _WSDL: ClassVar[dict[str, str]] = {
        "guests": "GuestsWebService?wsdl",
        "users": "UsersWebService?wsdl",
        "doors": "DoorsWebService?wsdl",
    }

    # How many random PINs to try before giving up when the server reports a
    # PIN collision (same PIN active on another lock with overlapping dates).
    _MAX_PIN_ATTEMPTS = 5

    def __init__(
        self,
        host: str,
        operator_name: str,
        operator_password: str,
        port: int = 8181,
        verify_ssl: bool = False,
    ):
        """
        Args:
            host: Smartair server hostname or IP (without scheme).
            operator_name: API operator login.
            operator_password: API operator password.
            port: Server port (default 8181).
            verify_ssl: Set True if the server has a valid certificate.
        """
        self.base_url = f"https://{host}:{port}/ServerPlatform"
        self.operator_name = operator_name
        self.operator_password = operator_password

        http_session = Session()
        http_session.verify = verify_ssl
        transport = Transport(session=http_session, timeout=30)
        settings = Settings(strict=False, xml_huge_tree=True)

        self._clients: dict[str, Client] = {}
        self._transport = transport
        self._settings = settings

    # ------------------------------------------------------------------
    # Client factory (lazy — only connects when first used)
    # ------------------------------------------------------------------

    def _client(self, service: str) -> Client:
        if service not in self._clients:
            wsdl_url = f"{self.base_url}/{self._WSDL[service]}"
            try:
                self._clients[service] = Client(
                    wsdl_url,
                    transport=self._transport,
                    settings=self._settings,
                )
            except Exception as e:
                raise LockConnectionError(f"Cannot load WSDL for {service}: {e}") from e
        return self._clients[service]

    def _svc(self, service: str) -> Any:
        return self._client(service).service

    # ------------------------------------------------------------------
    # Auth fields helper
    # ------------------------------------------------------------------

    def _auth(self) -> dict:
        return {
            "operatorName": self.operator_name,
            "operatorPassword": self.operator_password,
        }

    # ------------------------------------------------------------------
    # Response handling
    # ------------------------------------------------------------------

    def _handle(self, result: Any) -> Any:
        """
        Validate an operationResult zeep object and raise on RESULT_ERROR.
        Returns the result object on success so callers can read extra fields.
        """
        if result is None:
            raise LockAPIError("Empty response from Smartair server")

        result_type = getattr(result, "type", None)
        if result_type == "RESULT_ERROR":
            error_type = getattr(result, "errorType", None) or "UNKNOWN"
            error_code = getattr(result, "errorCode", None) or ""
            error_detail = getattr(result, "errorDetail", None) or ""
            self._raise_error(str(error_type), str(error_code), str(error_detail))

        return result

    @staticmethod
    def _raise_error(error_type: str, error_code: str, detail: str) -> None:
        msg = f"[{error_code}] {error_type}"
        if detail:
            msg += f" — {detail}"

        # Detail values: PIN_ALREADY_EXISTS, PIN_ALREADY_EXISTS_CHECKINPIN,
        # PIN_ALREADY_EXISTS_PRECHECKINPIN, PIN_ALREADY_EXISTS_PIN_USER.
        if "PIN_ALREADY_EXISTS" in detail:
            raise LockPinCollisionError(msg)

        if error_type in ("ERROR_SERVICE_AUTHENTICATION", "ERROR_SERVICE_AUTHORIZATION"):
            raise LockAuthError(msg)
        if error_type == "ERROR_NOT_AUTHORIZED_IN_SERVER_SITE_LICENSE":
            raise LockNoPermissionError(msg)
        if error_type == "ERROR_OPERATION_DOOR_UNKNOWN":
            raise LockNotFoundError(msg)
        # Nothing left to revoke: the room is already free or the pre-assignment
        # no longer exists. revoke_access swallows these to stay idempotent.
        if error_type in (
            "RESULT_ERROR_CHECKIN_ROOM_NOT_OCCUPIED",
            "RESULT_ERROR_CHECKIN_INVALID_ROOM",
        ):
            raise LockAlreadyClearedError(msg)
        if error_type in (
            "ERROR_OPERATION_TIMEOUT",
            "ERROR_OPERATION_HUB_BUSY",
            "ERROR_COMMUNICATION_NO_ANSWER",
            "ERROR_COMMUNICATION_LOCK_NOT_WAKING_UP",
        ):
            raise LockOfflineError(msg)
        raise LockOperationError(msg)

    def _check_suboperations(self, result: Any) -> None:
        """
        Some Guests operations (notably checkout) return RESULT_OK at the top
        level but nest the real failure inside subOperations. Raise on the first
        nested RESULT_ERROR so callers don't get a false success.
        """
        subops = getattr(result, "subOperations", None) or []
        if not isinstance(subops, list):
            subops = [subops]
        for sub in subops:
            if getattr(sub, "type", None) == "RESULT_ERROR":
                error_type = getattr(sub, "errorType", None) or "UNKNOWN"
                error_code = getattr(sub, "errorCode", None) or ""
                error_detail = getattr(sub, "errorDetail", None) or ""
                self._raise_error(str(error_type), str(error_code), str(error_detail))

    def _call(self, service: str, method: str, **kwargs: Any) -> Any:
        """Unified SOAP call with error handling."""
        svc = self._svc(service)
        soap_method = getattr(svc, method)
        try:
            result = soap_method(**self._auth(), **kwargs)
        except Fault as e:
            raise LockOperationError(f"SOAP Fault in {method}: {e}") from e
        except TransportError as e:
            raise LockConnectionError(f"Transport error in {method}: {e}") from e
        except Exception as e:
            raise LockConnectionError(f"Unexpected error in {method}: {e}") from e
        return self._handle(result)

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _generate_pin(length: int = 4) -> str:
        # First digit non-zero so a leading zero is never lost if the server
        # ever types keyPad as an integer; the rest may include 0 (your server
        # types keyPad as String, so 0 is fine — this just widens the space).
        first = secrets.choice("123456789")
        rest = "".join(secrets.choice("0123456789") for _ in range(length - 1))
        return first + rest

    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc)

    @staticmethod
    def _guest_data(
        room_id: str | int,
        starts_at: datetime,
        ends_at: datetime,
        pin: str,
        grants: list[str] | None = None,
    ) -> dict:
        data: dict = {
            "roomId": int(room_id),
            "dateActivation": starts_at,
            "dateExpiration": ends_at,
            "pinCheckin": True,
            "keyPad": pin,
        }
        if grants:
            data["grants"] = grants
        return data

    @staticmethod
    def _pack_ref(ref: dict) -> str:
        return json.dumps(ref, separators=(",", ":"))

    @staticmethod
    def _unpack_ref(grant_ref: str) -> dict:
        return cast("dict", json.loads(grant_ref))

    # ------------------------------------------------------------------
    # BaseLockProvider contract
    # ------------------------------------------------------------------

    def _do_grant_access(self, lock_ids: list, starts_at: datetime, ends_at: datetime, pin: str | None) -> AccessGrant:
        # A checkin only applies when the guest enters now; a future start means
        # the whole grant goes through precheckin instead.
        precheckin = starts_at > self._now()
        operation = "precheckin" if precheckin else "checkin"

        # All rooms of one grant share a single PIN. A collision on any room
        # therefore invalidates the PIN for the whole set: roll the set back and
        # retry with a fresh PIN — unless the caller supplied it, in which case
        # the collision is surfaced.
        user_supplied = pin is not None
        attempts = 1 if user_supplied else self._MAX_PIN_ATTEMPTS
        last_exc: LockPinCollisionError | None = None

        for _ in range(attempts):
            candidate = pin or self._generate_pin()
            created: list[dict] = []
            try:
                for lock_id in lock_ids:
                    code_id = self._open_stay(operation, lock_id, starts_at, ends_at, candidate)
                    created.append({"lock_id": str(lock_id), "code_id": code_id})
                return AccessGrant(
                    pin=candidate,
                    ref=self._pack_ref({"precheckin": precheckin, "rooms": created}),
                    starts_at=starts_at,
                    ends_at=ends_at,
                )
            except LockPinCollisionError as exc:
                self._rollback(precheckin, created)
                if user_supplied:
                    raise
                last_exc = exc
            except Exception:
                # All-or-nothing: a partial grant would give the guest a PIN that
                # only opens some doors. Roll back, then surface the error.
                self._rollback(precheckin, created)
                raise
        if last_exc is not None:
            raise last_exc
        raise LockOperationError("Could not grant access after PIN retries")

    def _open_stay(
        self,
        operation: str,
        lock_id: str,
        starts_at: datetime,
        ends_at: datetime,
        pin: str,
    ) -> str:
        """Create one room's stay; return its handle (preAssignationId or roomId)."""
        result = self._call(
            "guests",
            operation,
            guestData=self._guest_data(lock_id, starts_at, ends_at, pin),
        )
        if operation == "precheckin":
            pre_id = getattr(result, "preAssignationId", None)
            return str(pre_id) if pre_id is not None else str(lock_id)
        # Immediate checkin has no separate identifier: the roomId is the handle.
        return str(lock_id)

    def _rollback(self, precheckin: bool, created: list[dict]) -> None:
        for room in created:
            with contextlib.suppress(Exception):
                self._clear_stay(precheckin, room)

    def _clear_stay(self, precheckin: bool, room: dict) -> None:
        if precheckin:
            self._call("guests", "precheckinCancel", preAssignationId=int(room["code_id"]))
        else:
            result = self._call("guests", "checkout", roomId=int(room["lock_id"]))
            self._check_suboperations(result)

    # Phases a grant's room can be in *right now*. Re-resolved from live server
    # state instead of trusting the flag frozen in the ref at grant time.
    _PHASE_PRECHECKIN = "precheckin"  # still a pending pre-assignment (our id present)
    _PHASE_CHECKIN = "checkin"  # activated into an occupied check-in that is ours
    _PHASE_GONE = "gone"  # not ours anymore: cancelled, expired or taken over

    def _resolve_phase(
        self,
        info: RoomInfo | None,
        room: dict,
        created_precheckin: bool,
        pin: str | None,
    ) -> str:
        """Decide which Smartair operation set applies to ``room`` *now*.

        The ref records how the grant was *created* (whether ``code_id`` is a
        preAssignationId), but Smartair auto-activates a pre-assignment into a
        check-in once its activation time passes — the frozen flag then lies.
        So we read the room's live state and match it back to our grant:

        * our preAssignationId still pending  -> precheckin ops
        * occupied and its PIN is ours        -> check-in ops
        * anything else                       -> gone

        "Gone" is the safe default: we never touch a stay we cannot prove is
        ours (the pre-assignment may have been cancelled elsewhere, or another
        guest may have taken the room over). Confirming ownership needs the PIN,
        so without it an activated grant resolves to gone rather than guessing.
        """
        if info is None:
            return self._PHASE_GONE
        if created_precheckin:
            pre_id = str(room["code_id"])
            if any(str(p.pre_assignation_id) == pre_id for p in info.pre_assignations):
                return self._PHASE_PRECHECKIN
        if info.room_occupied and pin is not None and info.key_pad == pin:
            return self._PHASE_CHECKIN
        return self._PHASE_GONE

    def _rooms_by_id(self) -> dict[int, RoomInfo]:
        """Index the current room list by door_id for one-shot phase lookups."""
        return {r.door_id: r for r in self.find_all_rooms()}

    def _do_modify_access(
        self,
        grant_ref: str,
        starts_at: datetime,
        ends_at: datetime,
        pin: str | None = None,
    ) -> AccessGrant:
        # Smartair only allows modifying the expiration date, not the PIN or the
        # start date — so starts_at is echoed back unchanged and only ends_at is
        # pushed. The PIN does not change and Smartair never reads it back, so
        # we signal "unchanged" with pin=None (the contract's convention); the
        # caller keeps the PIN it got from grant_access. Returning "" would be a
        # real empty value and overwrite the stored PIN.
        ref = self._unpack_ref(grant_ref)
        rooms_by_id = self._rooms_by_id()
        for room in ref["rooms"]:
            room_id = int(room["lock_id"])
            phase = self._resolve_phase(rooms_by_id.get(room_id), room, ref["precheckin"], pin)
            if phase == self._PHASE_PRECHECKIN:
                # precheckinModifyDate needs BOTH roomId and preAssignationId
                # (omitting roomId is rejected with ERROR_BAD_PARAMETERS).
                self._call(
                    "guests",
                    "precheckinModifyDate",
                    roomId=room_id,
                    preAssignationId=int(room["code_id"]),
                    dateExpiration=ends_at,
                )
            elif phase == self._PHASE_CHECKIN:
                self._call(
                    "guests",
                    "checkinModifyDate",
                    roomId=room_id,
                    dateExpiration=ends_at,
                )
            else:
                raise LockNotFoundError(f"Grant no longer present on room {room_id}: nothing of ours to modify")
        return AccessGrant(pin=None, ref=grant_ref, starts_at=starts_at, ends_at=ends_at)

    def _do_revoke_access(self, grant_ref: str, pin: str | None = None) -> bool:
        ref = self._unpack_ref(grant_ref)
        rooms_by_id = self._rooms_by_id()
        for room in ref["rooms"]:
            room_id = int(room["lock_id"])
            phase = self._resolve_phase(rooms_by_id.get(room_id), room, ref["precheckin"], pin)
            # Idempotent and safe: a stay that is no longer ours (cancelled,
            # expired or taken over by another guest) needs no action and must
            # not be cleared — that would revoke a stranger's access.
            if phase == self._PHASE_GONE:
                continue
            with contextlib.suppress(LockNotFoundError, LockAlreadyClearedError):
                if phase == self._PHASE_PRECHECKIN:
                    self._call("guests", "precheckinCancel", preAssignationId=int(room["code_id"]))
                else:
                    result = self._call("guests", "checkout", roomId=room_id)
                    self._check_suboperations(result)
        return True

    def test_connection(self) -> bool:
        """Verify credentials and server reachability."""
        self.find_all_rooms()
        return True

    # ------------------------------------------------------------------
    # Room listing  (analogous to a lock list/detail)
    # ------------------------------------------------------------------

    def find_all_rooms(self) -> list[RoomInfo]:
        """All rooms with current state (occupied / preassigned / free)."""
        result = self._call("guests", "findAllRooms")
        return self._parse_rooms(result)

    def find_all_occupied_rooms(self) -> list[RoomInfo]:
        """Only occupied or pre-assigned rooms — lighter call for reconciliation."""
        result = self._call("guests", "findAllOccupiedRooms")
        return self._parse_rooms(result)

    def get_room_info(self, room_id: int) -> RoomInfo | None:
        """Info for a single room (filtered from findAllRooms — no single-room endpoint)."""
        return next(
            (r for r in self.find_all_rooms() if r.door_id == room_id),
            None,
        )

    @staticmethod
    def _parse_rooms(result: Any) -> list[RoomInfo]:
        rooms = []
        door_list = getattr(result, "doorData", None) or []
        for door in door_list:
            state = getattr(door, "doorStateInfo", None)
            battery_status = getattr(state, "batteryStatus", None) if state else None
            battery_pct = getattr(state, "batteryPercentage", None) if state else None

            raw_grants = getattr(door, "grantsOccupied", None) or []
            grants_occupied = list(raw_grants) if not isinstance(raw_grants, str) else [raw_grants]

            raw_pre = getattr(door, "preAssignations", None) or []
            if not isinstance(raw_pre, list):
                raw_pre = [raw_pre]
            pre_assignations = [
                PreAssignation(
                    pre_assignation_id=int(getattr(p, "preAssignationId", 0) or 0),
                    date_pre_activation=str(getattr(p, "datePreActivation", "") or ""),
                    date_pre_expiration=str(getattr(p, "datePreExpiration", "") or ""),
                    grants_preassigned=list(getattr(p, "grantsPreassigned", None) or []),
                )
                for p in raw_pre
            ]

            rooms.append(
                RoomInfo(
                    door_id=int(getattr(door, "doorId", 0) or 0),
                    door_name=str(getattr(door, "doorName", "") or ""),
                    room_occupied=bool(getattr(door, "roomOccupied", False)),
                    room_preassigned=bool(getattr(door, "roomPreassigned", False)),
                    date_activation=str(getattr(door, "dateActivation", "") or ""),
                    date_expiration=str(getattr(door, "dateExpiration", "") or ""),
                    battery_status=str(battery_status) if battery_status else None,
                    battery_percentage=int(battery_pct) if battery_pct is not None else None,
                    key_pad=str(getattr(door, "keyPad", "") or "") or None,
                    grants_occupied=grants_occupied,
                    pre_assignations=pre_assignations,
                )
            )
        return rooms

    # ------------------------------------------------------------------
    # Extras
    # ------------------------------------------------------------------

    def modify_grants(self, lock_id: str, grants: list[str]) -> bool:
        """Replace the grant list of an active checkin (e.g. add gym access)."""
        self._call("guests", "checkinModifyGrants", roomId=int(lock_id), grants=grants)
        return True

    def add_pin_user(
        self,
        username: str,
        pin: str,
        starts_at: datetime,
        ends_at: datetime,
        grants: list[str] | None = None,
    ) -> dict:
        """
        Create a USER_PIN_USER (permanent staff PIN: cleaning, maintenance…).
        For guest room PINs use grant_access instead.
        """
        user_data: dict = {
            "userName": username,
            "userCarrier": "CAR_PIN",
            "dateActivation": starts_at,
            "dateExpiration": ends_at,
            "keyPad": pin,
        }
        if grants:
            user_data["grants"] = grants

        result = self._call("users", "userAdd", userData=user_data)
        raw = getattr(result, "userData", None)
        if raw is None:
            return {}
        return {k: getattr(raw, k, None) for k in raw.__dict__ if not k.startswith("_")}

    def delete_user(self, username: str) -> bool:
        """Delete a staff user by username."""
        self._call("users", "userDelete", userData={"userName": username})
        return True

    def open_door(self, door_id: int) -> bool:
        """Remotely open a wireless door."""
        self._call("doors", "doorOpen", doorId=door_id)
        return True
