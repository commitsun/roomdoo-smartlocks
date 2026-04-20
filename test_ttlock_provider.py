import responses
import pytest
from datetime import datetime, timezone, timedelta
from roomdoo_locks_ttlock import TTLockProvider
from roomdoo_locks_base.exceptions import LockAuthError, LockOperationError, LockOfflineError, LockNoPermissionError

CLIENT_ID     = "fake_client_id"
CLIENT_SECRET = "fake_client_secret"
USERNAME      = "fake_user"
PASSWORD      = "fake_pass_md5"
LOCK_ID       = "12345678"


def mock_auth():
    responses.post(
        "https://euapi.ttlock.com/oauth2/token",
        json={
            "access_token": "fake_access_token",
            "refresh_token": "fake_refresh_token",
            "uid": 49543138,
            "expires_in": 6741404,
            "token_type": "Bearer"
        }
    )

@pytest.fixture
def time_range():
    starts_at = datetime.now(timezone.utc)
    ends_at   = starts_at + timedelta(hours=1)
    return starts_at, ends_at


@responses.activate
def test_connection():
    mock_auth()
    provider = TTLockProvider(CLIENT_ID, CLIENT_SECRET, USERNAME, PASSWORD)
    mock_auth()
    assert provider.test_connection() is True


@responses.activate
def test_create_code(time_range):
    mock_auth()
    provider = TTLockProvider(CLIENT_ID, CLIENT_SECRET, USERNAME, PASSWORD)

    starts_at, ends_at = time_range
    responses.post(
        "https://euapi.ttlock.com/v3/keyboardPwd/get",
        json={"keyboardPwd": "533463", "keyboardPwdId": 7107456}
    )
    responses.post(
        "https://euapi.ttlock.com/v3/keyboardPwd/delete",
        json={"errcode": 0}
    )

    result = provider.create_code(LOCK_ID, starts_at, ends_at)
    assert result.pin == "533463"
    assert result.code_id == "7107456"
    assert result.lock_id == LOCK_ID
    assert result.starts_at == starts_at
    assert result.ends_at == ends_at

    provider.invalidate_code(LOCK_ID, result.code_id)


@responses.activate
def test_create_code_error(time_range):
    mock_auth()
    provider = TTLockProvider(CLIENT_ID, CLIENT_SECRET, USERNAME, PASSWORD)

    starts_at, ends_at = time_range
    responses.post(
        "https://euapi.ttlock.com/v3/keyboardPwd/get",
        json={"errcode": -2012, "errmsg": "The Lock is not connected to any Gateway."}
    )

    with pytest.raises(LockOfflineError):
        provider.create_code(LOCK_ID, starts_at, ends_at)


@responses.activate
def test_invalidate_code(time_range):
    mock_auth()
    provider = TTLockProvider(CLIENT_ID, CLIENT_SECRET, USERNAME, PASSWORD)

    starts_at, ends_at = time_range
    responses.post(
        "https://euapi.ttlock.com/v3/keyboardPwd/get",
        json={"keyboardPwd": "533463", "keyboardPwdId": 7107456}
    )
    result = provider.create_code(LOCK_ID, starts_at, ends_at)

    responses.post(
        "https://euapi.ttlock.com/v3/keyboardPwd/delete",
        json={"errcode": 0}
    )

    assert provider.invalidate_code(LOCK_ID, result.code_id) is True


@responses.activate
def test_invalidate_nonexistent_code():
    mock_auth()
    provider = TTLockProvider(CLIENT_ID, CLIENT_SECRET, USERNAME, PASSWORD)

    responses.post(
        "https://euapi.ttlock.com/v3/keyboardPwd/delete",
        json={"errcode": -2009, "errmsg": "Invalid Password"}
    )

    with pytest.raises(LockNoPermissionError):
        provider.invalidate_code(LOCK_ID, "99999999")


@responses.activate
def test_get_lock_list():
    mock_auth()
    provider = TTLockProvider(CLIENT_ID, CLIENT_SECRET, USERNAME, PASSWORD)

    responses.get(
        "https://euapi.ttlock.com/v3/lock/list",
        json={
            "pageNo": 1,
            "pageSize": 20,
            "pages": 1,
            "total": 2,
            "list": [
                {"lockId": 12345678, "lockAlias": "Puerta principal", "lockMac": "AA:BB:CC:DD:EE:FF", "electricQuantity": 85},
                {"lockId": 87654321, "lockAlias": "Puerta trasera",   "lockMac": "FF:EE:DD:CC:BB:AA", "electricQuantity": 60},
            ]
        }
    )

    locks = provider.get_lock_list()
    assert locks["total"] == 2
    assert locks["list"][0]["lockAlias"] == "Puerta principal"


@responses.activate
def test_invalid_credentials():
    responses.post(
        "https://euapi.ttlock.com/oauth2/token",
        json={"errcode": 10007, "errmsg": "invalid account or invalid password"}
    )

    with pytest.raises(LockAuthError):
        TTLockProvider(CLIENT_ID, CLIENT_SECRET, USERNAME, PASSWORD)


@responses.activate
def test_invalid_time_range(time_range):
    mock_auth()
    provider = TTLockProvider(CLIENT_ID, CLIENT_SECRET, USERNAME, PASSWORD)

    starts_at, ends_at = time_range
    with pytest.raises(ValueError):
        provider.create_code(LOCK_ID, ends_at, starts_at)


@responses.activate
def test_naive_datetime(time_range):
    mock_auth()
    provider = TTLockProvider(CLIENT_ID, CLIENT_SECRET, USERNAME, PASSWORD)

    starts_at, ends_at = time_range
    with pytest.raises(ValueError):
        provider.create_code(LOCK_ID, datetime.now(), ends_at)


@responses.activate
def test_expired_token(time_range):
    mock_auth()
    provider = TTLockProvider(CLIENT_ID, CLIENT_SECRET, USERNAME, PASSWORD)

    starts_at, ends_at = time_range
    responses.post(
        "https://euapi.ttlock.com/v3/keyboardPwd/get",
        json={"errcode": 10003, "errmsg": "token does not exist"}
    )

    with pytest.raises(LockAuthError):
        provider.create_code(LOCK_ID, starts_at, ends_at)


@responses.activate
def test_modify_code(time_range):
    mock_auth()
    provider = TTLockProvider(CLIENT_ID, CLIENT_SECRET, USERNAME, PASSWORD)

    starts_at, ends_at = time_range
    new_ends_at = ends_at + timedelta(hours=1)

    # Create original code
    responses.post(
        "https://euapi.ttlock.com/v3/keyboardPwd/get",
        json={"keyboardPwd": "533463", "keyboardPwdId": 7107456}
    )
    result = provider.create_code(LOCK_ID, starts_at, ends_at)

    # Invalidate old + create new
    responses.post(
        "https://euapi.ttlock.com/v3/keyboardPwd/delete",
        json={"errcode": 0}
    )
    responses.post(
        "https://euapi.ttlock.com/v3/keyboardPwd/get",
        json={"keyboardPwd": "891234", "keyboardPwdId": 7107457}
    )

    modified = provider.modify_code(LOCK_ID, result.code_id, starts_at, new_ends_at)
    assert modified.ends_at == new_ends_at
    assert modified.pin == "891234"