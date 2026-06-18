"""
Tests for TesaSmartairProvider.

Strategy: patch the zeep Client at construction time so no real server is needed.
Each test builds a fake operationResult object, assigns it as the return value of
the relevant service method, and verifies that the provider behaves correctly.

Run with:  pytest roomdoo-locks-tesa/tests
"""

import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from roomdoo_locks_base import AccessGrant
from roomdoo_locks_base.exceptions import (
    LockAuthError,
    LockNoPermissionError,
    LockNotFoundError,
    LockOfflineError,
    LockOperationError,
)
from roomdoo_locks_tesa import (
    PreAssignation,
    RoomInfo,
    TesaSmartairProvider,
)
from roomdoo_locks_tesa.exceptions import (
    LockAlreadyClearedError,
    LockPinCollisionError,
)

# ---------------------------------------------------------------------------
# Helpers — build fake zeep response objects
# ---------------------------------------------------------------------------


def ok_result(**extra) -> SimpleNamespace:
    return SimpleNamespace(type="RESULT_OK", **extra)


def error_result(error_type, error_code="500", detail="") -> SimpleNamespace:
    return SimpleNamespace(
        type="RESULT_ERROR",
        errorType=error_type,
        errorCode=error_code,
        errorDetail=detail,
    )


def make_door(
    door_id=81,
    door_name="Room 101",
    occupied=False,
    preassigned=False,
    date_activation=None,
    date_expiration=None,
    battery_status="OK",
    battery_pct=90,
    grants_occupied=None,
    pre_assignations=None,
) -> SimpleNamespace:
    state = SimpleNamespace(batteryStatus=battery_status, batteryPercentage=battery_pct)
    return SimpleNamespace(
        doorId=door_id,
        doorName=door_name,
        roomOccupied=occupied,
        roomPreassigned=preassigned,
        dateActivation=date_activation,
        dateExpiration=date_expiration,
        doorStateInfo=state,
        grantsOccupied=grants_occupied or [],
        preAssignations=pre_assignations or [],
    )


# Time windows relative to "now" so checkin/precheckin selection is exercised.
def past_window():
    starts = datetime.now(timezone.utc) - timedelta(hours=1)
    ends = datetime.now(timezone.utc) + timedelta(hours=24)
    return starts, ends


def future_window():
    starts = datetime.now(timezone.utc) + timedelta(days=2)
    ends = datetime.now(timezone.utc) + timedelta(days=4)
    return starts, ends


# ---------------------------------------------------------------------------
# Base test case — provider with a mocked zeep Client
# ---------------------------------------------------------------------------


class BaseProviderTest(unittest.TestCase):
    def setUp(self):
        patcher = patch("roomdoo_locks_tesa.provider.Client")
        self.MockClient = patcher.start()
        self.addCleanup(patcher.stop)

        self.mock_client = MagicMock()
        self.MockClient.return_value = self.mock_client
        self.mock_svc = self.mock_client.service

        self.provider = TesaSmartairProvider(
            host="smartair.local",
            operator_name="operator1",
            operator_password="secret",
        )


# ---------------------------------------------------------------------------
# Authentication / connectivity
# ---------------------------------------------------------------------------


class TestConnection(BaseProviderTest):
    def test_connection_ok(self):
        self.mock_svc.findAllRooms.return_value = ok_result(doorData=[])
        self.assertTrue(self.provider.test_connection())

    def test_connection_auth_error(self):
        self.mock_svc.findAllRooms.return_value = error_result("ERROR_SERVICE_AUTHENTICATION", "500")
        with self.assertRaises(LockAuthError):
            self.provider.test_connection()

    def test_connection_license_error(self):
        self.mock_svc.findAllRooms.return_value = error_result("ERROR_NOT_AUTHORIZED_IN_SERVER_SITE_LICENSE", "604")
        with self.assertRaises(LockNoPermissionError):
            self.provider.test_connection()


# ---------------------------------------------------------------------------
# PIN generation
# ---------------------------------------------------------------------------


class TestPinGeneration(BaseProviderTest):
    def test_generated_pin_is_4_digits_and_never_leading_zero(self):
        for _ in range(500):
            pin = self.provider._generate_pin()
            self.assertEqual(len(pin), 4)
            self.assertTrue(pin.isdigit())
            self.assertNotEqual(pin[0], "0")


# ---------------------------------------------------------------------------
# ref pack/unpack
# ---------------------------------------------------------------------------


class TestRefRoundtrip(unittest.TestCase):
    def test_pack_unpack_roundtrip(self):
        ref = {
            "precheckin": True,
            "rooms": [{"lock_id": "81", "code_id": "42"}],
        }
        self.assertEqual(TesaSmartairProvider._unpack_ref(TesaSmartairProvider._pack_ref(ref)), ref)


# ---------------------------------------------------------------------------
# grant_access — immediate checkin (start now / in the past)
# ---------------------------------------------------------------------------


class TestGrantCheckin(BaseProviderTest):
    def test_grant_returns_access_grant(self):
        self.mock_svc.checkin.return_value = ok_result()
        starts, ends = past_window()
        grant = self.provider.grant_access([81], starts, ends, pin="123456")

        self.assertIsInstance(grant, AccessGrant)
        self.assertEqual(grant.pin, "123456")
        self.assertEqual(grant.starts_at, starts)
        self.assertEqual(grant.ends_at, ends)
        ref = TesaSmartairProvider._unpack_ref(grant.ref)
        self.assertFalse(ref["precheckin"])
        self.assertEqual(ref["rooms"], [{"lock_id": "81", "code_id": "81"}])

    def test_grant_uses_checkin_operation_and_passes_auth(self):
        self.mock_svc.checkin.return_value = ok_result()
        starts, ends = past_window()
        self.provider.grant_access([81], starts, ends, pin="999888")

        self.mock_svc.precheckin.assert_not_called()
        kwargs = self.mock_svc.checkin.call_args.kwargs
        self.assertEqual(kwargs["operatorName"], "operator1")
        self.assertEqual(kwargs["operatorPassword"], "secret")
        guest = kwargs["guestData"]
        self.assertEqual(guest["roomId"], 81)
        self.assertTrue(guest["pinCheckin"])
        self.assertEqual(guest["keyPad"], "999888")

    def test_grant_generates_pin_when_not_provided(self):
        self.mock_svc.checkin.return_value = ok_result()
        starts, ends = past_window()
        grant = self.provider.grant_access([81], starts, ends)
        self.assertEqual(len(grant.pin), 4)
        self.assertTrue(grant.pin.isdigit())
        self.assertNotEqual(grant.pin[0], "0")

    def test_grant_multiple_rooms_share_one_pin(self):
        self.mock_svc.checkin.return_value = ok_result()
        starts, ends = past_window()
        grant = self.provider.grant_access([81, 82], starts, ends, pin="123456")

        ref = TesaSmartairProvider._unpack_ref(grant.ref)
        self.assertEqual(
            ref["rooms"],
            [{"lock_id": "81", "code_id": "81"}, {"lock_id": "82", "code_id": "82"}],
        )
        keypads = [c.kwargs["guestData"]["keyPad"] for c in self.mock_svc.checkin.call_args_list]
        self.assertEqual(keypads, ["123456", "123456"])

    def test_grant_occupied_room_raises_operation_error(self):
        self.mock_svc.checkin.return_value = error_result("RESULT_ERROR_CHECKIN_ROOM_OCCUPIED", "300")
        starts, ends = past_window()
        with self.assertRaises(LockOperationError):
            self.provider.grant_access([81], starts, ends, pin="111111")

    def test_grant_rejects_naive_datetime(self):
        _, ends = past_window()
        with self.assertRaises(ValueError):
            self.provider.grant_access([81], datetime.now(), ends)

    def test_grant_rejects_bad_window(self):
        starts, ends = past_window()
        with self.assertRaises(ValueError):
            self.provider.grant_access([81], ends, starts)

    def test_grant_rejects_empty_locks(self):
        starts, ends = past_window()
        with self.assertRaises(ValueError):
            self.provider.grant_access([], starts, ends)


# ---------------------------------------------------------------------------
# grant_access — future start → precheckin
# ---------------------------------------------------------------------------


class TestGrantPrecheckin(BaseProviderTest):
    def test_future_start_uses_precheckin(self):
        self.mock_svc.precheckin.return_value = ok_result(preAssignationId=299)
        starts, ends = future_window()
        grant = self.provider.grant_access([82], starts, ends, pin="555444")

        self.mock_svc.checkin.assert_not_called()
        ref = TesaSmartairProvider._unpack_ref(grant.ref)
        self.assertTrue(ref["precheckin"])
        self.assertEqual(ref["rooms"], [{"lock_id": "82", "code_id": "299"}])

    def test_precheckin_falls_back_to_room_id_when_no_pre_id(self):
        self.mock_svc.precheckin.return_value = ok_result()
        starts, ends = future_window()
        grant = self.provider.grant_access([82], starts, ends, pin="555444")
        ref = TesaSmartairProvider._unpack_ref(grant.ref)
        self.assertEqual(ref["rooms"], [{"lock_id": "82", "code_id": "82"}])


# ---------------------------------------------------------------------------
# PIN collision handling
# ---------------------------------------------------------------------------


class TestPinCollision(BaseProviderTest):
    def test_collision_subclasses_operation_error(self):
        self.assertTrue(issubclass(LockPinCollisionError, LockOperationError))

    def test_user_supplied_pin_does_not_retry(self):
        self.mock_svc.checkin.side_effect = [
            error_result("ERROR_DATA_ERROR", "800", "PIN_ALREADY_EXISTS_CHECKINPIN"),
            ok_result(),
        ]
        starts, ends = past_window()
        with self.assertRaises(LockPinCollisionError):
            self.provider.grant_access([81], starts, ends, pin="123456")
        self.assertEqual(self.mock_svc.checkin.call_count, 1)

    def test_autogenerated_pin_retries_until_success(self):
        self.mock_svc.checkin.side_effect = [
            error_result("ERROR_DATA_ERROR", "800", "PIN_ALREADY_EXISTS_CHECKINPIN"),
            ok_result(),
        ]
        starts, ends = past_window()
        grant = self.provider.grant_access([81], starts, ends)  # auto PIN
        self.assertEqual(self.mock_svc.checkin.call_count, 2)
        self.assertEqual(len(grant.pin), 4)

    def test_autogenerated_pin_gives_up_after_max_attempts(self):
        self.mock_svc.checkin.side_effect = [
            error_result("ERROR_DATA_ERROR", "800", "PIN_ALREADY_EXISTS_CHECKINPIN")
            for _ in range(self.provider._MAX_PIN_ATTEMPTS)
        ]
        starts, ends = past_window()
        with self.assertRaises(LockPinCollisionError):
            self.provider.grant_access([81], starts, ends)
        self.assertEqual(self.mock_svc.checkin.call_count, self.provider._MAX_PIN_ATTEMPTS)

    def test_precheckin_autogenerated_pin_retries(self):
        self.mock_svc.precheckin.side_effect = [
            error_result("ERROR_DATA_ERROR", "800", "PIN_ALREADY_EXISTS_PRECHECKINPIN"),
            ok_result(preAssignationId=42),
        ]
        starts, ends = future_window()
        grant = self.provider.grant_access([82], starts, ends)
        self.assertEqual(self.mock_svc.precheckin.call_count, 2)
        ref = TesaSmartairProvider._unpack_ref(grant.ref)
        self.assertEqual(ref["rooms"], [{"lock_id": "82", "code_id": "42"}])


# ---------------------------------------------------------------------------
# Rollback (all-or-nothing across rooms)
# ---------------------------------------------------------------------------


class TestGrantRollback(BaseProviderTest):
    def test_rolls_back_first_room_when_second_fails(self):
        # Room 81 checks in, room 82 fails → 81 must be checked out.
        self.mock_svc.checkin.side_effect = [
            ok_result(),
            error_result("RESULT_ERROR_CHECKIN_ROOM_OCCUPIED", "300"),
        ]
        self.mock_svc.checkout.return_value = ok_result()
        starts, ends = past_window()

        with self.assertRaises(LockOperationError):
            self.provider.grant_access([81, 82], starts, ends, pin="123456")

        self.mock_svc.checkout.assert_called_once()
        self.assertEqual(self.mock_svc.checkout.call_args.kwargs["roomId"], 81)


# ---------------------------------------------------------------------------
# modify_access
# ---------------------------------------------------------------------------


class TestModifyAccess(BaseProviderTest):
    def _ref(self, precheckin, rooms):
        return TesaSmartairProvider._pack_ref({"precheckin": precheckin, "rooms": rooms})

    def test_modify_checkin_calls_checkin_modify_date(self):
        self.mock_svc.checkinModifyDate.return_value = ok_result()
        ref = self._ref(False, [{"lock_id": "81", "code_id": "81"}])
        starts, ends = past_window()
        new_ends = ends + timedelta(hours=12)

        grant = self.provider.modify_access(ref, starts, new_ends)

        self.assertEqual(grant.ref, ref)
        self.assertEqual(grant.ends_at, new_ends)
        self.assertEqual(grant.pin, "")
        kwargs = self.mock_svc.checkinModifyDate.call_args.kwargs
        self.assertEqual(kwargs["roomId"], 81)
        self.assertEqual(kwargs["dateExpiration"], new_ends)

    def test_modify_precheckin_calls_precheckin_modify_date(self):
        self.mock_svc.precheckinModifyDate.return_value = ok_result()
        ref = self._ref(True, [{"lock_id": "82", "code_id": "299"}])
        starts, ends = future_window()
        new_ends = ends + timedelta(hours=12)

        self.provider.modify_access(ref, starts, new_ends)

        self.mock_svc.checkinModifyDate.assert_not_called()
        kwargs = self.mock_svc.precheckinModifyDate.call_args.kwargs
        self.assertEqual(kwargs["preAssignationId"], 299)
        self.assertEqual(kwargs["dateExpiration"], new_ends)

    def test_modify_rejects_bad_window(self):
        ref = self._ref(False, [{"lock_id": "81", "code_id": "81"}])
        starts, ends = past_window()
        with self.assertRaises(ValueError):
            self.provider.modify_access(ref, ends, starts)


# ---------------------------------------------------------------------------
# revoke_access
# ---------------------------------------------------------------------------


class TestRevokeAccess(BaseProviderTest):
    def _ref(self, precheckin, rooms):
        return TesaSmartairProvider._pack_ref({"precheckin": precheckin, "rooms": rooms})

    def test_revoke_checkin_checks_out_every_room(self):
        self.mock_svc.checkout.return_value = ok_result()
        ref = self._ref(
            False,
            [{"lock_id": "81", "code_id": "81"}, {"lock_id": "82", "code_id": "82"}],
        )
        self.assertTrue(self.provider.revoke_access(ref))
        room_ids = [c.kwargs["roomId"] for c in self.mock_svc.checkout.call_args_list]
        self.assertEqual(room_ids, [81, 82])

    def test_revoke_precheckin_cancels_pre_assignation(self):
        self.mock_svc.precheckinCancel.return_value = ok_result()
        ref = self._ref(True, [{"lock_id": "82", "code_id": "299"}])
        self.assertTrue(self.provider.revoke_access(ref))
        self.mock_svc.checkout.assert_not_called()
        self.assertEqual(self.mock_svc.precheckinCancel.call_args.kwargs["preAssignationId"], 299)

    def test_revoke_is_idempotent_when_room_not_occupied(self):
        self.mock_svc.checkout.return_value = error_result("RESULT_ERROR_CHECKIN_ROOM_NOT_OCCUPIED", "310")
        ref = self._ref(False, [{"lock_id": "81", "code_id": "81"}])
        self.assertTrue(self.provider.revoke_access(ref))

    def test_revoke_is_idempotent_when_pre_assignation_invalid(self):
        self.mock_svc.precheckinCancel.return_value = error_result("RESULT_ERROR_CHECKIN_INVALID_ROOM", "307")
        ref = self._ref(True, [{"lock_id": "82", "code_id": "999"}])
        self.assertTrue(self.provider.revoke_access(ref))

    def test_revoke_idempotent_error_maps_to_already_cleared(self):
        self.mock_svc.checkout.return_value = error_result("RESULT_ERROR_CHECKIN_ROOM_NOT_OCCUPIED", "310")
        # Direct clear surfaces the dedicated (idempotent) error type.
        with self.assertRaises(LockAlreadyClearedError):
            self.provider._clear_stay(False, {"lock_id": "81", "code_id": "81"})


# ---------------------------------------------------------------------------
# Room listing
# ---------------------------------------------------------------------------


class TestRoomListing(BaseProviderTest):
    def test_find_all_rooms_parses_correctly(self):
        doors = [
            make_door(
                door_id=81,
                door_name="Room 101",
                occupied=True,
                battery_pct=85,
                grants_occupied=["GYM", "SPA"],
            ),
            make_door(door_id=82, door_name="Room 102", preassigned=True),
        ]
        self.mock_svc.findAllRooms.return_value = ok_result(doorData=doors)

        rooms = self.provider.find_all_rooms()

        self.assertEqual(len(rooms), 2)
        self.assertIsInstance(rooms[0], RoomInfo)
        self.assertEqual(rooms[0].door_id, 81)
        self.assertTrue(rooms[0].room_occupied)
        self.assertEqual(rooms[0].battery_percentage, 85)
        self.assertIn("GYM", rooms[0].grants_occupied)

    def test_find_all_rooms_parses_pre_assignations(self):
        pre = SimpleNamespace(
            preAssignationId=42,
            datePreActivation="2026-07-01T14:00:00",
            datePreExpiration="2026-07-05T11:00:00",
            grantsPreassigned=["POOL"],
        )
        doors = [make_door(door_id=82, preassigned=True, pre_assignations=[pre])]
        self.mock_svc.findAllRooms.return_value = ok_result(doorData=doors)

        rooms = self.provider.find_all_rooms()
        self.assertIsInstance(rooms[0].pre_assignations[0], PreAssignation)
        self.assertEqual(rooms[0].pre_assignations[0].pre_assignation_id, 42)

    def test_find_all_rooms_empty(self):
        self.mock_svc.findAllRooms.return_value = ok_result(doorData=[])
        self.assertEqual(self.provider.find_all_rooms(), [])

    def test_get_room_info_found(self):
        doors = [make_door(door_id=82, door_name="Room 102")]
        self.mock_svc.findAllRooms.return_value = ok_result(doorData=doors)
        room = self.provider.get_room_info(82)
        self.assertIsNotNone(room)
        self.assertEqual(room.door_name, "Room 102")

    def test_get_room_info_not_found(self):
        self.mock_svc.findAllRooms.return_value = ok_result(doorData=[])
        self.assertIsNone(self.provider.get_room_info(999))


# ---------------------------------------------------------------------------
# Extras: staff PIN user / open door / modify grants
# ---------------------------------------------------------------------------


class TestExtras(BaseProviderTest):
    def test_modify_grants_ok(self):
        self.mock_svc.checkinModifyGrants.return_value = ok_result()
        self.assertTrue(self.provider.modify_grants("81", ["GYM", "POOL"]))
        kwargs = self.mock_svc.checkinModifyGrants.call_args.kwargs
        self.assertEqual(kwargs["roomId"], 81)
        self.assertEqual(kwargs["grants"], ["GYM", "POOL"])

    def test_add_pin_user_ok(self):
        fake_user = SimpleNamespace(userName="cleaning1", userCarrier="CAR_PIN", keyPad="3344")
        self.mock_svc.userAdd.return_value = ok_result(userData=fake_user)
        result = self.provider.add_pin_user("cleaning1", "3344", datetime(2026, 6, 1), datetime(2026, 12, 31))
        self.assertEqual(result.get("userName"), "cleaning1")
        self.assertEqual(result.get("keyPad"), "3344")

    def test_add_pin_user_collision_raises(self):
        self.mock_svc.userAdd.return_value = error_result("ERROR_DATA_ERROR", "800", "PIN_ALREADY_EXISTS_PIN_USER")
        with self.assertRaises(LockPinCollisionError):
            self.provider.add_pin_user("cleaning1", "3344", datetime(2026, 6, 1), datetime(2026, 12, 31))

    def test_delete_user_ok(self):
        self.mock_svc.userDelete.return_value = ok_result()
        self.assertTrue(self.provider.delete_user("cleaning1"))

    def test_open_door_ok(self):
        self.mock_svc.doorOpen.return_value = ok_result()
        self.assertTrue(self.provider.open_door(81))

    def test_open_door_unknown_raises_not_found(self):
        self.mock_svc.doorOpen.return_value = error_result("ERROR_OPERATION_DOOR_UNKNOWN", "503")
        with self.assertRaises(LockNotFoundError):
            self.provider.open_door(999)

    def test_open_door_offline_raises(self):
        self.mock_svc.doorOpen.return_value = error_result("ERROR_COMMUNICATION_NO_ANSWER", "C5")
        with self.assertRaises(LockOfflineError):
            self.provider.open_door(81)


if __name__ == "__main__":
    unittest.main(verbosity=2)
