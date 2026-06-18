import json
import requests
import responses
import pytest
from datetime import datetime, timezone, timedelta

from roomdoo_locks_salto import SaltoProvider
from roomdoo_locks_base.exceptions import (
    LockAuthError,
    LockConnectionError,
    LockNotFoundError,
    LockOperationError,
)

# ── Test constants ────────────────────────────────────────────────────────────

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

# ── Helpers ────────────────────────────────────────────────────────────────────


def mock_auth(env="acc"):
    url = IDENTITY_URL_ACC if env == "acc" else IDENTITY_URL_PROD
    responses.post(
        url,
        json={
            "access_token": "fake_access_token",
            "expires_in": 3600,
            "token_type": "Bearer",
            "scope": "user_api.full_access",
        },
    )


def make_provider(env="acc"):
    return SaltoProvider(
        CLIENT_ID, CLIENT_SECRET, USERNAME, PASSWORD, SITE_ID, ROLE_ID, env=env
    )


@pytest.fixture
def time_range():
    starts_at = datetime.now(timezone.utc)
    ends_at = starts_at + timedelta(hours=24)
    return starts_at, ends_at


def mock_add_user_to_site():
    responses.post(
        f"{API_BASE_ACC}/v1.2/sites/{SITE_ID}/users",
        json={
            "id": SITE_USER_ID,
            "user": {"id": USER_ID, "first_name": "Roomdoo", "last_name": "Guest"},
            "alias": "Roomdoo Guest",
            "subscription_state": "subscribed",
            "use_pin": True,
        },
    )


def mock_add_access_group():
    responses.post(
        f"{API_BASE_ACC}/v1.2/sites/{SITE_ID}/access_groups",
        json={"id": ACCESS_GROUP_ID, "customer_reference": "Roomdoo Access"},
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
            "end_time": "23:59:59",
        },
    )


def mock_add_user_to_access_group():
    responses.post(
        f"{API_BASE_ACC}/v1.2/sites/{SITE_ID}/access_groups/{ACCESS_GROUP_ID}/users",
        json={"id": USER_ID, "first_name": "Roomdoo", "last_name": "Guest"},
    )


def mock_add_lock_to_access_group(lock_id=LOCK_ID):
    responses.post(
        f"{API_BASE_ACC}/v1.1/sites/{SITE_ID}/access_groups/{ACCESS_GROUP_ID}/locks",
        json={"id": lock_id, "customer_reference": "Lock"},
    )


def mock_create_pin(pin="123456"):
    responses.put(
        f"{API_BASE_ACC}/v1.2/sites/{SITE_ID}/users/{SITE_USER_ID}/pin",
        body=pin,
    )


def mock_delete_access_group(status=204):
    responses.delete(
        f"{API_BASE_ACC}/v1.2/sites/{SITE_ID}/access_groups/{ACCESS_GROUP_ID}",
        status=status,
    )


def mock_delete_user(status=204):
    responses.delete(
        f"{API_BASE_ACC}/v1.2/sites/{SITE_ID}/users/{SITE_USER_ID}",
        status=status,
    )


def mock_unsubscribe_user(status=204):
    responses.patch(
        f"{API_BASE_ACC}/v1.2/sites/{SITE_ID}/users/{SITE_USER_ID}/subscription",
        status=status,
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
            "end_time": "23:59:59",
        },
    )


def mock_grant_flow(starts_at, ends_at, lock_ids=(LOCK_ID,), pin="123456"):
    mock_add_user_to_site()
    mock_add_access_group()
    mock_add_time_schedule(starts_at, ends_at)
    mock_add_user_to_access_group()
    for lock_id in lock_ids:
        mock_add_lock_to_access_group(lock_id)
    mock_create_pin(pin)


def build_ref(lock_ids=(LOCK_ID,)):
    return SaltoProvider._pack_ref(
        {
            "access_group_id": ACCESS_GROUP_ID,
            "time_schedule_id": TIME_SCHEDULE_ID,
            "site_user_id": SITE_USER_ID,
            "user_id": USER_ID,
            "lock_ids": list(lock_ids),
        }
    )


# ── Authentication ──────────────────────────────────────────────────────────


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


@responses.activate
def test_connection_error_on_auth():
    responses.post(
        IDENTITY_URL_ACC, body=requests.exceptions.ConnectionError("Connection refused")
    )
    with pytest.raises(LockConnectionError):
        make_provider()


# ── test_connection ───────────────────────────────────────────────────────────


@responses.activate
def test_connection_success():
    mock_auth()
    provider = make_provider()
    mock_auth()
    assert provider.test_connection() is True


# ── ref pack/unpack ─────────────────────────────────────────────────────────


def test_pack_unpack_roundtrip():
    ref = {
        "access_group_id": ACCESS_GROUP_ID,
        "time_schedule_id": TIME_SCHEDULE_ID,
        "site_user_id": SITE_USER_ID,
        "user_id": USER_ID,
        "lock_ids": LOCK_IDS,
    }
    assert SaltoProvider._unpack_ref(SaltoProvider._pack_ref(ref)) == ref


# ── grant_access (public contract) ────────────────────────────────────────────


@responses.activate
def test_grant_access_single_lock(time_range):
    mock_auth()
    provider = make_provider()
    starts_at, ends_at = time_range
    mock_grant_flow(starts_at, ends_at, [LOCK_ID])

    result = provider.grant_access([LOCK_ID], starts_at, ends_at)

    assert result.pin == "123456"
    assert result.starts_at == starts_at
    assert result.ends_at == ends_at
    ref = SaltoProvider._unpack_ref(result.ref)
    assert ref["access_group_id"] == ACCESS_GROUP_ID
    assert ref["time_schedule_id"] == TIME_SCHEDULE_ID
    assert ref["site_user_id"] == SITE_USER_ID
    assert ref["lock_ids"] == [LOCK_ID]


@responses.activate
def test_grant_access_multiple_locks(time_range):
    mock_auth()
    provider = make_provider()
    starts_at, ends_at = time_range
    mock_grant_flow(starts_at, ends_at, LOCK_IDS)

    result = provider.grant_access(LOCK_IDS, starts_at, ends_at)

    assert result.pin == "123456"
    assert SaltoProvider._unpack_ref(result.ref)["lock_ids"] == LOCK_IDS


@responses.activate
def test_grant_access_sends_exact_checkin_checkout_datetimes(time_range):
    mock_auth()
    provider = make_provider()
    starts_at, ends_at = time_range
    mock_grant_flow(starts_at, ends_at, [LOCK_ID])

    provider.grant_access([LOCK_ID], starts_at, ends_at)

    schedule_call = next(
        c for c in responses.calls if c.request.url.endswith("/time_schedules")
    )
    body = json.loads(schedule_call.request.body)
    # Exact check-in/check-out time travels in start_date/end_date; the daily
    # window stays full-day so multi-day stays are continuous (no overnight gap).
    assert body["start_date"] == starts_at.strftime("%Y-%m-%dT%H:%M:%S")
    assert body["end_date"] == ends_at.strftime("%Y-%m-%dT%H:%M:%S")
    assert body["start_time"] == "00:00:00"
    assert body["end_time"] == "23:59:59"
    assert all(
        body[d] for d in
        ("monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday")
    )


@responses.activate
def test_grant_access_rejects_naive_datetime(time_range):
    mock_auth()
    provider = make_provider()
    _, ends_at = time_range
    with pytest.raises(ValueError):
        provider.grant_access([LOCK_ID], datetime.now(), ends_at)


@responses.activate
def test_grant_access_rejects_bad_window(time_range):
    mock_auth()
    provider = make_provider()
    starts_at, ends_at = time_range
    with pytest.raises(ValueError):
        provider.grant_access([LOCK_ID], ends_at, starts_at)


@responses.activate
def test_grant_access_rejects_empty_locks(time_range):
    mock_auth()
    provider = make_provider()
    starts_at, ends_at = time_range
    with pytest.raises(ValueError):
        provider.grant_access([], starts_at, ends_at)


@responses.activate
def test_grant_access_rejects_custom_pin(time_range):
    mock_auth()
    provider = make_provider()
    starts_at, ends_at = time_range
    # Salto generates the PIN; a caller-supplied one must fail loud (premium
    # feature this adapter does not support).
    with pytest.raises(LockOperationError):
        provider.grant_access([LOCK_ID], starts_at, ends_at, pin="1234")


@responses.activate
def test_grant_access_requires_role_id(time_range):
    mock_auth()
    provider = SaltoProvider(
        CLIENT_ID, CLIENT_SECRET, USERNAME, PASSWORD, SITE_ID, None, env="acc"
    )
    starts_at, ends_at = time_range
    with pytest.raises(LockOperationError):
        provider.grant_access([LOCK_ID], starts_at, ends_at)


@responses.activate
def test_grant_access_pin_with_leading_zero(time_range):
    mock_auth()
    provider = make_provider()
    starts_at, ends_at = time_range
    mock_grant_flow(starts_at, ends_at, [LOCK_ID], pin="012345")

    result = provider.grant_access([LOCK_ID], starts_at, ends_at)
    assert result.pin == "012345"


@responses.activate
def test_grant_access_rolls_back_on_lock_failure(time_range):
    mock_auth()
    provider = make_provider()
    starts_at, ends_at = time_range

    mock_add_user_to_site()
    mock_add_access_group()
    mock_add_time_schedule(starts_at, ends_at)
    mock_add_user_to_access_group()
    # Adding the lock fails mid-flow ...
    responses.post(
        f"{API_BASE_ACC}/v1.1/sites/{SITE_ID}/access_groups/{ACCESS_GROUP_ID}/locks",
        status=404,
        json={"Message": "Lock not found"},
    )
    # ... so the access group and user must be cleaned up.
    mock_delete_access_group()
    mock_delete_user()

    with pytest.raises(LockNotFoundError):
        provider.grant_access([LOCK_ID], starts_at, ends_at)

    deleted = {
        (c.request.method, c.request.url)
        for c in responses.calls
        if c.request.method == "DELETE"
    }
    assert (
        "DELETE",
        f"{API_BASE_ACC}/v1.2/sites/{SITE_ID}/access_groups/{ACCESS_GROUP_ID}",
    ) in deleted
    assert (
        "DELETE",
        f"{API_BASE_ACC}/v1.2/sites/{SITE_ID}/users/{SITE_USER_ID}",
    ) in deleted


# ── modify_access (public contract) ───────────────────────────────────────────


@responses.activate
def test_modify_access_success(time_range):
    mock_auth()
    provider = make_provider()
    starts_at, ends_at = time_range
    new_ends_at = ends_at + timedelta(hours=12)
    mock_modify_time_schedule(starts_at, new_ends_at)

    result = provider.modify_access(build_ref([LOCK_ID]), starts_at, new_ends_at)

    assert result.ref == build_ref([LOCK_ID])
    assert result.starts_at == starts_at
    assert result.ends_at == new_ends_at
    # Salto cannot read PINs back; a window change keeps the original PIN and
    # reports it as unchanged so the caller does not overwrite its stored value.
    assert result.pin is None


@responses.activate
def test_modify_access_rejects_bad_window(time_range):
    mock_auth()
    provider = make_provider()
    starts_at, ends_at = time_range
    with pytest.raises(ValueError):
        provider.modify_access(build_ref(), ends_at, starts_at)


# ── revoke_access (public contract) ────────────────────────────────────────────


@responses.activate
def test_revoke_access_suspends_user_without_deleting():
    mock_auth()
    provider = make_provider()
    mock_unsubscribe_user()
    assert provider.revoke_access(build_ref()) is True
    # Revoke must free the license by suspending, never delete: the user, access
    # group and audit logs stay until the retention cron calls delete_grant.
    patch_call = next(
        c for c in responses.calls if c.request.method == "PATCH"
    )
    assert patch_call.request.url.endswith(f"/users/{SITE_USER_ID}/subscription")
    assert json.loads(patch_call.request.body)["state"] == "suspended"
    assert not any(c.request.method == "DELETE" for c in responses.calls)


@responses.activate
def test_revoke_access_is_idempotent_when_already_gone():
    mock_auth()
    provider = make_provider()
    mock_unsubscribe_user(status=404)
    # A user that is already suspended or gone still revokes without raising.
    assert provider.revoke_access(build_ref()) is True


# ── delete_grant (Salto-specific hard delete) ─────────────────────────────────


@responses.activate
def test_delete_grant_deletes_group_and_user():
    mock_auth()
    provider = make_provider()
    mock_delete_access_group()
    mock_delete_user()
    assert provider.delete_grant(build_ref()) is True
    deleted = {
        c.request.url for c in responses.calls if c.request.method == "DELETE"
    }
    assert (
        f"{API_BASE_ACC}/v1.2/sites/{SITE_ID}/access_groups/{ACCESS_GROUP_ID}"
        in deleted
    )
    assert f"{API_BASE_ACC}/v1.2/sites/{SITE_ID}/users/{SITE_USER_ID}" in deleted


@responses.activate
def test_delete_grant_is_idempotent_when_already_gone():
    mock_auth()
    provider = make_provider()
    mock_delete_access_group(status=404)
    mock_delete_user(status=404)
    assert provider.delete_grant(build_ref()) is True


# ── delete_user (extra) ───────────────────────────────────────────────────────


@responses.activate
def test_delete_user_success():
    mock_auth()
    provider = make_provider()
    mock_delete_user()
    assert provider.delete_user(SITE_USER_ID) is True


@responses.activate
def test_delete_user_not_found():
    mock_auth()
    provider = make_provider()
    mock_delete_user(status=404)
    with pytest.raises(LockNotFoundError):
        provider.delete_user(SITE_USER_ID)


# ── Building blocks ────────────────────────────────────────────────────────────


@responses.activate
def test_add_user_to_site_success():
    mock_auth()
    provider = make_provider()
    mock_add_user_to_site()
    result = provider._add_user_to_site("Roomdoo", "Guest", ROLE_ID, "")
    assert result["site_user_id"] == SITE_USER_ID
    assert result["user_id"] == USER_ID


@responses.activate
def test_add_user_to_site_omits_empty_email():
    # Salto rejects an empty email ("Email '' is not valid"), so the key must
    # not be sent when no address is provided (the PIN flow never sends one).
    mock_auth()
    provider = make_provider()
    mock_add_user_to_site()
    provider._add_user_to_site("Roomdoo", "Guest", ROLE_ID, "")
    body = json.loads(responses.calls[-1].request.body)
    assert "email" not in body


@responses.activate
def test_add_user_to_site_includes_email_when_set():
    mock_auth()
    provider = make_provider()
    mock_add_user_to_site()
    provider._add_user_to_site("Roomdoo", "Guest", ROLE_ID, "guest@example.com")
    body = json.loads(responses.calls[-1].request.body)
    assert body["email"] == "guest@example.com"


@responses.activate
def test_add_user_to_site_not_found():
    mock_auth()
    provider = make_provider()
    responses.post(
        f"{API_BASE_ACC}/v1.2/sites/{SITE_ID}/users",
        json={"Message": "Site not found"},
        status=404,
    )
    with pytest.raises(LockNotFoundError):
        provider._add_user_to_site("Roomdoo", "Guest", ROLE_ID, "")


@responses.activate
def test_add_access_group_success():
    mock_auth()
    provider = make_provider()
    mock_add_access_group()
    assert provider._add_access_group_to_site("Roomdoo Access") == ACCESS_GROUP_ID


@responses.activate
def test_add_time_schedule_success(time_range):
    mock_auth()
    provider = make_provider()
    starts_at, ends_at = time_range
    mock_add_time_schedule(starts_at, ends_at)
    result = provider._add_time_schedule_to_access_group(ACCESS_GROUP_ID, starts_at, ends_at)
    assert result["time_schedule_id"] == TIME_SCHEDULE_ID


@responses.activate
def test_time_schedule_localizes_to_configured_timezone():
    # Salto enforces schedule datetimes in the site/IQ local timezone, not UTC.
    # The caller passes UTC instants; they must be sent as the local wall-clock.
    mock_auth()
    provider = SaltoProvider(
        CLIENT_ID, CLIENT_SECRET, USERNAME, PASSWORD, SITE_ID, ROLE_ID,
        env="acc", time_zone="Europe/Madrid",
    )
    starts_at = datetime(2026, 6, 16, 16, 0, 0, tzinfo=timezone.utc)  # 18:00 CEST
    ends_at = datetime(2026, 6, 17, 10, 0, 0, tzinfo=timezone.utc)    # 12:00 CEST
    mock_add_time_schedule(starts_at, ends_at)
    provider._add_time_schedule_to_access_group(ACCESS_GROUP_ID, starts_at, ends_at)
    body = json.loads(responses.calls[-1].request.body)
    assert body["start_date"] == "2026-06-16T18:00:00"
    assert body["end_date"] == "2026-06-17T12:00:00"


@responses.activate
def test_time_schedule_without_timezone_keeps_utc_wallclock():
    # No timezone configured -> fall back to the datetime as-is (UTC wall-clock).
    mock_auth()
    provider = make_provider()
    starts_at = datetime(2026, 6, 16, 16, 0, 0, tzinfo=timezone.utc)
    ends_at = datetime(2026, 6, 17, 10, 0, 0, tzinfo=timezone.utc)
    mock_add_time_schedule(starts_at, ends_at)
    provider._add_time_schedule_to_access_group(ACCESS_GROUP_ID, starts_at, ends_at)
    body = json.loads(responses.calls[-1].request.body)
    assert body["start_date"] == "2026-06-16T16:00:00"
    assert body["end_date"] == "2026-06-17T10:00:00"


@responses.activate
def test_create_pin_success():
    mock_auth()
    provider = make_provider()
    mock_create_pin()
    assert provider._create_modify_user_pin(SITE_USER_ID) == "123456"


@responses.activate
def test_create_pin_error():
    mock_auth()
    provider = make_provider()
    responses.put(
        f"{API_BASE_ACC}/v1.2/sites/{SITE_ID}/users/{SITE_USER_ID}/pin",
        json={"Message": "Invalid parameter"},
        status=400,
    )
    with pytest.raises(LockAuthError):
        provider._create_modify_user_pin(SITE_USER_ID)


@responses.activate
def test_list_roles_returns_id_and_name():
    mock_auth()
    provider = make_provider()
    responses.get(
        f"{API_BASE_ACC}/v1.2/sites/{SITE_ID}/roles",
        json={
            "items": [
                # The API labels roles with ``customer_reference``; ``code`` is
                # the fallback slug when no reference is set.
                {"id": "r1", "customer_reference": "Site User", "code": "site_user"},
                {"id": "r2", "customer_reference": None, "code": "site_admin"},
            ]
        },
    )
    assert provider.list_roles() == [
        {"id": "r1", "name": "Site User"},
        {"id": "r2", "name": "site_admin"},
    ]


@responses.activate
def test_get_locks_from_access_group_uses_get():
    mock_auth()
    provider = make_provider()
    responses.get(
        f"{API_BASE_ACC}/v1.1/sites/{SITE_ID}/access_groups/{ACCESS_GROUP_ID}/locks",
        json={"items": [{"id": LOCK_ID}, {"id": LOCK_ID_2}]},
    )
    assert provider._get_locks_from_access_group(ACCESS_GROUP_ID) == LOCK_IDS


@responses.activate
def test_server_error_on_add_user():
    mock_auth()
    provider = make_provider()
    responses.post(
        f"{API_BASE_ACC}/v1.2/sites/{SITE_ID}/users",
        status=500,
        json={"Message": "Internal server error"},
    )
    with pytest.raises(LockConnectionError):
        provider._add_user_to_site("Roomdoo", "Guest", ROLE_ID, "")
