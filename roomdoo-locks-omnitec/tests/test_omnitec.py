import responses
import pytest
import requests
from datetime import datetime, timezone, timedelta
from roomdoo_locks_omnitec import OmnitecProvider
from roomdoo_locks_base.exceptions import LockAuthError, LockConnectionError, LockOperationError

CLIENT_ID     = "fake_client_id"
CLIENT_SECRET = "fake_client_secret"
USERNAME      = "fake_user"
PASSWORD      = "fake_pass"
LOCK_ID       = "8279953"

# Reusable authentication mock
def mock_auth():
    responses.get(
        "https://api.rentandpass.com/api/signin/token",
        json={"access_token": "fake_token", "refresh_token": "fake_refresh"}
    )

@pytest.fixture
def time_range():
    starts_at = datetime.now(timezone.utc)
    ends_at   = starts_at + timedelta(hours=1)
    return starts_at, ends_at


@responses.activate
def test_connection():
    mock_auth()
    provider = OmnitecProvider(CLIENT_ID, CLIENT_SECRET, USERNAME, PASSWORD)
    mock_auth()  # test_connection calls _authenticate again
    assert provider.test_connection() is True

@responses.activate
def test_open_lock():
    mock_auth()
    provider = OmnitecProvider(CLIENT_ID, CLIENT_SECRET, USERNAME, PASSWORD)

    responses.put(
        "https://api.rentandpass.com/api/lock/unlock",
        json={"errcode": 0}
    )

    assert provider.open_lock(LOCK_ID) is True


@responses.activate
def test_open_lock_error():
    mock_auth()
    provider = OmnitecProvider(CLIENT_ID, CLIENT_SECRET, USERNAME, PASSWORD)

    responses.put(
        "https://api.rentandpass.com/api/lock/unlock",
        json={"errcode": -1, "errmsg": "Lock is offline"}
    )

    with pytest.raises(LockOperationError):
        provider.open_lock(LOCK_ID)

@responses.activate
def test_create_code(time_range):
    mock_auth()
    provider = OmnitecProvider(CLIENT_ID, CLIENT_SECRET, USERNAME, PASSWORD)

    starts_at, ends_at = time_range
    responses.post(
        "https://api.rentandpass.com/api/password",
        json={"keyboardPwdId": 7107456}
    )
    responses.delete(
        "https://api.rentandpass.com/api/password",
        json={"errcode": 0}
    )

    result = provider.create_code(LOCK_ID, starts_at, ends_at)
    assert len(result.pin) == 6
    assert result.pin.isdigit()
    assert result.code_id == "7107456"

    provider.invalidate_code(LOCK_ID, result.code_id)

@responses.activate
def test_create_code_custom_pin(time_range):
    mock_auth()
    provider = OmnitecProvider(CLIENT_ID, CLIENT_SECRET, USERNAME, PASSWORD)

    starts_at, ends_at = time_range
    responses.post(
        "https://api.rentandpass.com/api/password",
        json={"keyboardPwdId": 7107456}
    )
    responses.delete(
        "https://api.rentandpass.com/api/password",
        json={"errcode": 0}
    )

    result = provider.create_code(LOCK_ID, starts_at, ends_at, pin="0123456")
    assert result.pin == "0123456"
    assert result.code_id == "7107456"

    provider.invalidate_code(LOCK_ID, result.code_id)


@responses.activate
def test_modify_code(time_range):
    mock_auth()
    provider = OmnitecProvider(CLIENT_ID, CLIENT_SECRET, USERNAME, PASSWORD)

    starts_at, ends_at = time_range
    responses.post(
        "https://api.rentandpass.com/api/password",
        json={"keyboardPwd": "533463", "keyboardPwdId": 7107456}
    )
    result = provider.create_code(LOCK_ID, starts_at, ends_at)

    new_ends_at = ends_at + timedelta(hours=1)
    responses.put(
        "https://api.rentandpass.com/api/password",
        json={"errcode": 0}
    )
    responses.get(
        "https://api.rentandpass.com/api/lock/passwords",
        json={"list": [{"keyboardPwdId": 7107456, "keyboardPwd": "533463"}]}
    )

    modified = provider.modify_code(LOCK_ID, result.code_id, starts_at, new_ends_at)
    assert modified.code_id == result.code_id

    responses.delete(
        "https://api.rentandpass.com/api/password",
        json={"errcode": 0}
    )
    provider.invalidate_code(LOCK_ID, modified.code_id)


@responses.activate
def test_invalid_time_range(time_range):
    mock_auth()
    provider = OmnitecProvider(CLIENT_ID, CLIENT_SECRET, USERNAME, PASSWORD)

    starts_at, ends_at = time_range
    with pytest.raises(ValueError):
        provider.create_code(LOCK_ID, ends_at, starts_at)


@responses.activate
def test_naive_datetime(time_range):
    mock_auth()
    provider = OmnitecProvider(CLIENT_ID, CLIENT_SECRET, USERNAME, PASSWORD)

    starts_at, ends_at = time_range
    with pytest.raises(ValueError):
        provider.create_code(LOCK_ID, datetime.now(), ends_at)

@responses.activate
def test_invalid_credentials():
    responses.get(
        "https://api.rentandpass.com/api/signin/token",
        json={"error": "Unauthorized"},
        status=401
    )
    with pytest.raises(LockAuthError):
        OmnitecProvider(CLIENT_ID, CLIENT_SECRET, USERNAME, PASSWORD)


@responses.activate
def test_invalidate_nonexistent_code():
    mock_auth()
    provider = OmnitecProvider(CLIENT_ID, CLIENT_SECRET, USERNAME, PASSWORD)

    responses.delete(
        "https://api.rentandpass.com/api/password",
        json={"errcode": -2009, "errmsg": "Invalid Password"}
    )

    assert provider.invalidate_code(LOCK_ID, "99999999") is True

@responses.activate
def test_get_locks():
    mock_auth()
    provider = OmnitecProvider(CLIENT_ID, CLIENT_SECRET, USERNAME, PASSWORD)

    responses.get(
        "https://api.rentandpass.com/api/lock/list",
        json={
            "list": [
                {"lockId": 8279953, "lockAlias": "0101"},
                {"lockId": 8279954, "lockAlias": "0102"},
            ]
        }
    )

    result = provider._do_get_locks()
    assert len(result) == 2
    assert result[0] == [8279953, "0101"]
    assert result[1] == [8279954, "0102"]

@responses.activate
def test_get_locks_empty():
    mock_auth()
    provider = OmnitecProvider(CLIENT_ID, CLIENT_SECRET, USERNAME, PASSWORD)

    responses.get(
        "https://api.rentandpass.com/api/lock/list",
        json={"list": []}
    )

    result = provider._do_get_locks()
    assert result == []

@responses.activate
def test_get_locks_connection_error():
    mock_auth()
    provider = OmnitecProvider(CLIENT_ID, CLIENT_SECRET, USERNAME, PASSWORD)

    responses.get(
        "https://api.rentandpass.com/api/lock/list",
        body=requests.exceptions.ConnectionError()
    )

    with pytest.raises(LockConnectionError):
        provider._do_get_locks()