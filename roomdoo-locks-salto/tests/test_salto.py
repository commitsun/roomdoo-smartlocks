import json
import requests
import responses
import pytest
import base64
from datetime import datetime, timezone, timedelta

from roomdoo_locks_salto import SaltoProvider
from roomdoo_locks_base.exceptions import (
    LockAuthError,
    LockConnectionError,
    LockNotFoundError,
    LockOperationError,
)

# ── Constantes de prueba ─────────────────────────────────────────────────────

CLIENT_ID        = "fake_client_id"
CLIENT_SECRET    = "fake_client_secret"
USERNAME         = "fake_user"
PASSWORD         = "fake_pass"
SITE_ID          = "fake_site_id"
LOCK_ID          = "fake_lock_id"
LOCK_ID_2        = "fake_lock_id_2"
LOCK_IDS         = [LOCK_ID, LOCK_ID_2]
SITE_USER_ID     = "fake_site_user_id"
USER_ID          = "fake_user_id"
ACCESS_GROUP_ID  = "fake_access_group_id"
TIME_SCHEDULE_ID = "fake_time_schedule_id"
ROLE_ID          = "fake_role_id"

IDENTITY_URL_ACC  = "https://identity-acc.eu.my-clay.com/connect/token"
IDENTITY_URL_PROD = "https://identity.eu.my-clay.com/connect/token"
API_BASE_ACC      = "https://clp-accept-user.my-clay.com"
API_BASE_PROD     = "https://user.my-clay.com"

# ── Helpers ──────────────────────────────────────────────────────────────────

def mock_auth(env="acc"):
    url = IDENTITY_URL_ACC if env == "acc" else IDENTITY_URL_PROD
    responses.post(
        url,
        json={
            "access_token": "fake_access_token",
            "expires_in": 3600,
            "token_type": "Bearer",
            "scope": "user_api.full_access"
        }
    )

def make_provider(env="acc"):
    return SaltoProvider(CLIENT_ID, CLIENT_SECRET, USERNAME, PASSWORD, SITE_ID, env=env)

@pytest.fixture
def time_range():
    starts_at = datetime.now(timezone.utc)
    ends_at   = starts_at + timedelta(hours=24)
    return starts_at, ends_at

def mock_add_user_to_site():
    responses.post(
        f"{API_BASE_ACC}/v1.2/sites/{SITE_ID}/users",
        json={
            "id": SITE_USER_ID,
            "user": {
                "id": USER_ID,
                "email": "prueba@gmail.com",
                "first_name": "Prueba",
                "last_name": "API"
            },
            "roles": [
                {
                    "id": ROLE_ID,
                    "customer_reference": "Site User",
                    "code": "site_user"
                }
            ],
            "alias": "Prueba API",
            "subscription_state": "subscribed",
            "use_pin": True
        }
    )

def mock_add_access_group():
    responses.post(
        f"{API_BASE_ACC}/v1.2/sites/{SITE_ID}/access_groups",
        json={"id": ACCESS_GROUP_ID, "customer_reference": "Grupo de Acceso"}
    )

def mock_add_time_schedule(start_date, end_date):
    responses.post(
        f"{API_BASE_ACC}/v1.1/sites/{SITE_ID}/access_groups/{ACCESS_GROUP_ID}/time_schedules",
        json={
            "id": TIME_SCHEDULE_ID,
            "start_date": start_date.strftime("%Y-%m-%dT%H:%M:%S"),
            "end_date": end_date.strftime("%Y-%m-%dT%H:%M:%S"),
            "monday": True, "tuesday": True, "wednesday": True,
            "thursday": True, "friday": True, "saturday": True, "sunday": True,
            "start_time": "00:00:00",
            "end_time": "23:59:59"
        }
    )

def mock_add_user_to_access_group():
    responses.post(
        f"{API_BASE_ACC}/v1.2/sites/{SITE_ID}/access_groups/{ACCESS_GROUP_ID}/users",
        json={"id": USER_ID, "first_name": "Prueba", "last_name": "API"}
    )

def mock_add_lock_to_access_group(lock_id=LOCK_ID):
    responses.post(
        f"{API_BASE_ACC}/v1.2/sites/{SITE_ID}/access_groups/{ACCESS_GROUP_ID}/locks",
        json={"id": lock_id, "customer_reference": "Cerradura"}
    )

def mock_create_pin():
    responses.put(
        f"{API_BASE_ACC}/v1.2/sites/{SITE_ID}/users/{SITE_USER_ID}/pin",
        body="123456"
    )

def mock_modify_time_schedule(start_date, end_date):
    responses.patch(
        f"{API_BASE_ACC}/v1.1/sites/{SITE_ID}/access_groups/{ACCESS_GROUP_ID}/time_schedules/{TIME_SCHEDULE_ID}",
        json={
            "id": TIME_SCHEDULE_ID,
            "start_date": start_date.strftime("%Y-%m-%dT%H:%M:%S"),
            "end_date": end_date.strftime("%Y-%m-%dT%H:%M:%S"),
            "monday": True, "tuesday": True, "wednesday": True,
            "thursday": True, "friday": True, "saturday": True, "sunday": True,
            "start_time": "00:00:00",
            "end_time": "23:59:59"
        }
    )

def mock_get_locks_from_access_group(lock_ids):
    responses.put(
        f"{API_BASE_ACC}/v1.2/sites/{SITE_ID}/access_groups/{ACCESS_GROUP_ID}/locks",
        json={"items": [{"id": lock_id} for lock_id in lock_ids]}
    )

# ── Tests de autenticación ────────────────────────────────────────────────────

@responses.activate
def test_authentication_success():
    mock_auth()
    provider = make_provider()
    assert provider.accessToken == "fake_access_token"


@responses.activate
def test_authentication_prod_env():
    mock_auth(env="prod")
    provider = make_provider(env="prod")
    assert provider.accessToken == "fake_access_token"
    assert provider.env == "prod"


@responses.activate
def test_authentication_invalid_credentials():
    responses.post(IDENTITY_URL_ACC, json={"error": "invalid_client"}, status=401)
    with pytest.raises(LockAuthError):
        make_provider()


@responses.activate
def test_authentication_missing_token():
    responses.post(IDENTITY_URL_ACC, json={"error": "invalid_grant"}, status=400)
    with pytest.raises(LockAuthError):
        make_provider()


# ── Tests de test_connection ──────────────────────────────────────────────────

@responses.activate
def test_connection_success():
    mock_auth()
    provider = make_provider()
    mock_auth()
    assert provider.test_connection() is True


# ── Tests de add_user_to_site ─────────────────────────────────────────────────

@responses.activate
def test_add_user_to_site_success():
    mock_auth()
    provider = make_provider()
    mock_add_user_to_site()
    result = provider._add_user_to_site("Prueba", "API", ROLE_ID, "prueba@gmail.com")
    assert result["site_user_id"] == SITE_USER_ID
    assert result["user_id"] == USER_ID


@responses.activate
def test_add_user_to_site_not_found():
    mock_auth()
    provider = make_provider()
    responses.post(
        f"{API_BASE_ACC}/v1.2/sites/{SITE_ID}/users",
        json={"ErrorCode": "1100", "Message": "Site not found"},
        status=404
    )
    with pytest.raises(LockNotFoundError):
        provider._add_user_to_site("Prueba", "API", ROLE_ID, "prueba@gmail.com")


# ── Tests de delete_user ──────────────────────────────────────────────────────

@responses.activate
def test_delete_user_success():
    mock_auth()
    provider = make_provider()
    responses.delete(f"{API_BASE_ACC}/v1.2/sites/{SITE_ID}/users/{SITE_USER_ID}", status=204)
    assert provider.delete_user(SITE_USER_ID) is True


@responses.activate
def test_delete_user_not_found():
    mock_auth()
    provider = make_provider()
    responses.delete(
        f"{API_BASE_ACC}/v1.2/sites/{SITE_ID}/users/{SITE_USER_ID}",
        status=404,
        json={"ErrorCode": "1100", "Message": "User not found"}
    )
    with pytest.raises(LockNotFoundError):
        provider.delete_user(SITE_USER_ID)


# ── Tests de access groups ────────────────────────────────────────────────────

@responses.activate
def test_add_access_group_success():
    mock_auth()
    provider = make_provider()
    mock_add_access_group()
    assert provider._add_access_group_to_site("Grupo de Acceso") == ACCESS_GROUP_ID


@responses.activate
def test_delete_access_group_success():
    mock_auth()
    provider = make_provider()
    responses.delete(f"{API_BASE_ACC}/v1.2/sites/{SITE_ID}/access_groups/{ACCESS_GROUP_ID}", status=204)
    assert provider._delete_access_group_from_site(ACCESS_GROUP_ID) is True


# ── Tests de time schedules ───────────────────────────────────────────────────

@responses.activate
def test_add_time_schedule_success(time_range):
    mock_auth()
    provider = make_provider()
    starts_at, ends_at = time_range
    mock_add_time_schedule(starts_at, ends_at)
    result = provider._add_time_schedule_to_access_group(ACCESS_GROUP_ID, starts_at, ends_at)
    assert result["time_schedule_id"] == TIME_SCHEDULE_ID
    assert "start_date" in result
    assert "end_date" in result


@responses.activate
def test_modify_time_schedule_success(time_range):
    mock_auth()
    provider = make_provider()
    starts_at, ends_at = time_range
    new_ends_at = ends_at + timedelta(hours=12)
    mock_modify_time_schedule(starts_at, new_ends_at)
    result = provider._modify_time_schedule_in_access_group(ACCESS_GROUP_ID, TIME_SCHEDULE_ID, starts_at, new_ends_at)
    assert result["time_schedule_id"] == TIME_SCHEDULE_ID


@responses.activate
def test_delete_time_schedule_success():
    mock_auth()
    provider = make_provider()
    responses.delete(
        f"{API_BASE_ACC}/v1.1/sites/{SITE_ID}/access_groups/{ACCESS_GROUP_ID}/time_schedules/{TIME_SCHEDULE_ID}",
        status=204
    )
    assert provider._delete_time_schedule_from_access_group(ACCESS_GROUP_ID, TIME_SCHEDULE_ID) is True


# ── Tests de suscripción de usuario ──────────────────────────────────────────

@responses.activate
def test_unsubscribe_user_success():
    mock_auth()
    provider = make_provider()
    responses.patch(f"{API_BASE_ACC}/v1.2/sites/{SITE_ID}/users/{SITE_USER_ID}/subscription", status=204)
    assert provider._unsubscribe_user_from_site(SITE_USER_ID) is True


@responses.activate
def test_subscribe_user_success():
    mock_auth()
    provider = make_provider()
    responses.patch(f"{API_BASE_ACC}/v1.2/sites/{SITE_ID}/users/{SITE_USER_ID}/subscription", status=204)
    assert provider._subscribe_user_to_site(SITE_USER_ID) is True


# ── Tests de create_modify_user_pin ──────────────────────────────────────────

@responses.activate
def test_create_modify_user_pin_success(time_range):
    mock_auth()
    provider = make_provider()
    starts_at, ends_at = time_range
    mock_create_pin()
    result = provider._create_modify_user_pin(ACCESS_GROUP_ID, SITE_USER_ID, LOCK_ID, starts_at, ends_at)
    assert result.pin == "123456"
    assert result.code_id == ACCESS_GROUP_ID
    assert result.lock_id == LOCK_ID


@responses.activate
def test_create_modify_user_pin_error(time_range):
    mock_auth()
    provider = make_provider()
    starts_at, ends_at = time_range
    responses.put(
        f"{API_BASE_ACC}/v1.2/sites/{SITE_ID}/users/{SITE_USER_ID}/pin",
        json={"ErrorCode": "1100", "Message": "Invalid parameter"},
        status=400
    )
    with pytest.raises(LockAuthError):
        provider._create_modify_user_pin(ACCESS_GROUP_ID, SITE_USER_ID, LOCK_ID, starts_at, ends_at)


# ── Tests de _pack_ref / _unpack_ref ─────────────────────────────────────────

def test_pack_ref():
    targets = [
        {"ID": LOCK_ID, "passID": ACCESS_GROUP_ID},
        {"ID": LOCK_ID_2, "passID": ACCESS_GROUP_ID},
    ]
    packed = SaltoProvider._pack_ref(targets)
    assert isinstance(packed, str)
    assert json.loads(packed) == targets


def test_unpack_ref():
    targets = [
        {"ID": LOCK_ID, "passID": ACCESS_GROUP_ID},
        {"ID": LOCK_ID_2, "passID": ACCESS_GROUP_ID},
    ]
    packed = json.dumps(targets, separators=(",", ":"))
    assert SaltoProvider._unpack_ref(packed) == targets


def test_pack_unpack_roundtrip():
    targets = [{"ID": LOCK_ID, "passID": ACCESS_GROUP_ID}]
    assert SaltoProvider._unpack_ref(SaltoProvider._pack_ref(targets)) == targets


# ── Tests de grant_access / _do_grant_access (flujo completo) ────────────────

@responses.activate
def test_grant_access_single_lock(time_range):
    mock_auth()
    provider = make_provider()
    starts_at, ends_at = time_range

    mock_add_user_to_site()
    mock_add_access_group()
    mock_add_time_schedule(starts_at, ends_at)
    mock_add_user_to_access_group()
    mock_add_lock_to_access_group(LOCK_ID)
    mock_create_pin()

    result = provider._do_grant_access([LOCK_ID], starts_at, ends_at, "Prueba", "API", ROLE_ID, "prueba@gmail.com", "Grupo de Acceso")
    assert result.pin == "123456"

    unpacked = SaltoProvider._unpack_ref(result.ref)
    assert len(unpacked) == 1
    assert unpacked[0]["ID"] == LOCK_ID
    assert unpacked[0]["passID"] == ACCESS_GROUP_ID


@responses.activate
def test_grant_access_multiple_locks(time_range):
    mock_auth()
    provider = make_provider()
    starts_at, ends_at = time_range

    mock_add_user_to_site()
    mock_add_access_group()
    mock_add_time_schedule(starts_at, ends_at)
    mock_add_user_to_access_group()
    mock_add_lock_to_access_group(LOCK_ID)
    mock_add_lock_to_access_group(LOCK_ID_2)
    mock_create_pin()

    result = provider._do_grant_access(LOCK_IDS, starts_at, ends_at, "Prueba", "API", ROLE_ID, "prueba@gmail.com", "Grupo de Acceso")
    assert result.pin == "123456"

    unpacked = SaltoProvider._unpack_ref(result.ref)
    assert len(unpacked) == 2
    assert unpacked[0]["ID"] == LOCK_ID
    assert unpacked[1]["ID"] == LOCK_ID_2


@responses.activate
def test_grant_access_via_public_method(time_range):
    mock_auth()
    provider = make_provider()
    starts_at, ends_at = time_range

    mock_add_user_to_site()
    mock_add_access_group()
    mock_add_time_schedule(starts_at, ends_at)
    mock_add_user_to_access_group()
    mock_add_lock_to_access_group(LOCK_ID)
    mock_create_pin()

    result = provider.grant_access([LOCK_ID], starts_at, ends_at, "Prueba", "API", ROLE_ID)
    assert result.pin == "123456"
    assert result.starts_at == starts_at
    assert result.ends_at == ends_at


# ── Tests de _do_revoke_access ────────────────────────────────────────────────

@responses.activate
def test_revoke_access_success():
    mock_auth()
    provider = make_provider()
    responses.delete(f"{API_BASE_ACC}/v1.2/sites/{SITE_ID}/access_groups/{ACCESS_GROUP_ID}", status=204)
    responses.patch(f"{API_BASE_ACC}/v1.2/sites/{SITE_ID}/users/{SITE_USER_ID}/subscription", status=204)
    assert provider._do_revoke_access(ACCESS_GROUP_ID, SITE_USER_ID) is True


# ── Tests de _do_modify_access ────────────────────────────────────────────────

@responses.activate
def test_modify_access_success(time_range):
    mock_auth()
    provider = make_provider()
    starts_at, ends_at = time_range
    new_ends_at = ends_at + timedelta(hours=12)

    mock_modify_time_schedule(starts_at, new_ends_at)
    mock_get_locks_from_access_group([LOCK_ID])

    result = provider._do_modify_access(ACCESS_GROUP_ID, SITE_ID, TIME_SCHEDULE_ID, starts_at, new_ends_at)
    unpacked = SaltoProvider._unpack_ref(result.ref)
    assert unpacked[0]["ID"] == LOCK_ID
    assert unpacked[0]["passID"] == ACCESS_GROUP_ID
    assert result.starts_at == starts_at
    assert result.ends_at == new_ends_at


# ── Tests de validación de fechas ─────────────────────────────────────────────

@responses.activate
def test_invalid_time_range(time_range):
    mock_auth()
    provider = make_provider()
    starts_at, ends_at = time_range
    with pytest.raises(ValueError):
        provider.grant_access([LOCK_ID], ends_at, starts_at, "Prueba", "API", ROLE_ID)


@responses.activate
def test_naive_datetime(time_range):
    mock_auth()
    provider = make_provider()
    starts_at, ends_at = time_range
    with pytest.raises(ValueError):
        provider.grant_access([LOCK_ID], datetime.now(), ends_at, "Prueba", "API", ROLE_ID)


# ── Tests de errores de conexión ──────────────────────────────────────────────

@responses.activate
def test_connection_error_on_auth():
    responses.post(
        IDENTITY_URL_ACC,
        body=requests.exceptions.ConnectionError("Connection refused")
    )
    with pytest.raises(LockConnectionError):
        make_provider()


@responses.activate
def test_server_error_on_add_user():
    mock_auth()
    provider = make_provider()
    responses.post(
        f"{API_BASE_ACC}/v1.2/sites/{SITE_ID}/users",
        status=500,
        json={"ErrorCode": "9999", "Message": "Internal server error"}
    )
    with pytest.raises(LockConnectionError):
        provider._add_user_to_site("Prueba", "API", ROLE_ID, "prueba@gmail.com")