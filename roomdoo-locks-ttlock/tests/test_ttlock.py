import json
from datetime import datetime, timedelta, timezone

import pytest
import responses
from roomdoo_locks_base.exceptions import (
    LockAuthError,
    LockOfflineError,
)
from roomdoo_locks_ttlock import TTLockProvider

CLIENT_ID = "fake_client_id"
CLIENT_SECRET = "fake_client_secret"
USERNAME = "fake_user"
PASSWORD = "fake_pass_md5"
LOCK_A = "12345678"
LOCK_B = "87654321"

ADD_URL = "https://euapi.ttlock.com/v3/keyboardPwd/add"
CHANGE_URL = "https://euapi.ttlock.com/v3/keyboardPwd/change"
DELETE_URL = "https://euapi.ttlock.com/v3/keyboardPwd/delete"
LIST_URL = "https://euapi.ttlock.com/v3/lock/listKeyboardPwd"


def mock_auth():
    responses.post(
        "https://euapi.ttlock.com/oauth2/token",
        json={
            "access_token": "fake_access_token",
            "refresh_token": "fake_refresh_token",
            "expires_in": 6741404,
            "token_type": "Bearer",
        },
    )


def make_provider():
    """Build an authenticated provider. Must be called inside an active
    ``responses`` context (i.e. from within an ``@responses.activate`` test),
    since the constructor authenticates over HTTP."""
    mock_auth()
    return TTLockProvider(CLIENT_ID, CLIENT_SECRET, USERNAME, PASSWORD)


@pytest.fixture
def window():
    starts_at = datetime.now(timezone.utc)
    return starts_at, starts_at + timedelta(hours=1)


@responses.activate
def test_connection():
    provider = make_provider()
    mock_auth()
    assert provider.test_connection() is True


@responses.activate
def test_invalid_credentials():
    responses.post(
        "https://euapi.ttlock.com/oauth2/token",
        json={"errcode": 10007, "errmsg": "invalid account or invalid password"},
    )
    with pytest.raises(LockAuthError):
        TTLockProvider(CLIENT_ID, CLIENT_SECRET, USERNAME, PASSWORD)


@responses.activate
def test_grant_access_forces_pin_and_packs_ref(window):
    provider = make_provider()
    starts_at, ends_at = window
    responses.post(ADD_URL, json={"keyboardPwdId": 111})
    responses.post(ADD_URL, json={"keyboardPwdId": 222})

    grant = provider.grant_access([LOCK_A, LOCK_B], starts_at, ends_at, pin="123456")

    assert grant.pin == "123456"
    assert json.loads(grant.ref) == [
        {"lockId": LOCK_A, "keyboardPwdId": "111"},
        {"lockId": LOCK_B, "keyboardPwdId": "222"},
    ]
    # The same PIN was pushed to every lock.
    add_calls = [c for c in responses.calls if c.request.url.startswith(ADD_URL)]
    assert len(add_calls) == 2
    for call in add_calls:
        assert "keyboardPwd=123456" in call.request.body


@responses.activate
def test_grant_access_generates_pin_when_omitted(window):
    provider = make_provider()
    starts_at, ends_at = window
    responses.post(ADD_URL, json={"keyboardPwdId": 111})

    grant = provider.grant_access([LOCK_A], starts_at, ends_at)

    assert len(grant.pin) == TTLockProvider.PASSCODE_LENGTH
    assert set(grant.pin) <= set(TTLockProvider.PASSCODE_ALPHABET)


@responses.activate
def test_grant_access_rolls_back_on_partial_failure(window):
    provider = make_provider()
    starts_at, ends_at = window
    # First lock succeeds, second is offline -> whole grant must roll back.
    responses.post(ADD_URL, json={"keyboardPwdId": 111})
    responses.post(ADD_URL, json={"errcode": -3002, "errmsg": "Gateway is offline"})
    responses.post(DELETE_URL, json={"errcode": 0})

    with pytest.raises(LockOfflineError):
        provider.grant_access([LOCK_A, LOCK_B], starts_at, ends_at, pin="123456")

    delete_calls = [c for c in responses.calls if c.request.url.startswith(DELETE_URL)]
    assert len(delete_calls) == 1
    assert "keyboardPwdId=111" in delete_calls[0].request.body


@responses.activate
def test_modify_access_changes_each_lock_and_returns_pin(window):
    provider = make_provider()
    starts_at, ends_at = window
    new_ends_at = ends_at + timedelta(hours=2)
    ref = json.dumps([{"lockId": LOCK_A, "keyboardPwdId": "111"}])

    responses.post(CHANGE_URL, json={"errcode": 0})
    responses.get(
        LIST_URL,
        json={"list": [{"keyboardPwdId": 111, "keyboardPwd": "123456"}]},
    )

    grant = provider.modify_access(ref, starts_at, new_ends_at)

    assert grant.pin == "123456"
    assert grant.ref == ref
    assert grant.ends_at == new_ends_at


@responses.activate
def test_revoke_access_deletes_every_lock():
    provider = make_provider()
    ref = json.dumps(
        [
            {"lockId": LOCK_A, "keyboardPwdId": "111"},
            {"lockId": LOCK_B, "keyboardPwdId": "222"},
        ]
    )
    responses.post(DELETE_URL, json={"errcode": 0})

    assert provider.revoke_access(ref) is True
    delete_calls = [c for c in responses.calls if c.request.url.startswith(DELETE_URL)]
    assert len(delete_calls) == 2


@responses.activate
def test_grant_access_rejects_empty_lock_ids(window):
    provider = make_provider()
    starts_at, ends_at = window
    with pytest.raises(ValueError):
        provider.grant_access([], starts_at, ends_at)


@responses.activate
def test_grant_access_rejects_bad_window(window):
    provider = make_provider()
    starts_at, ends_at = window
    with pytest.raises(ValueError):
        provider.grant_access([LOCK_A], ends_at, starts_at)


@responses.activate
def test_grant_access_rejects_naive_datetime(window):
    provider = make_provider()
    _, ends_at = window
    with pytest.raises(ValueError):
        provider.grant_access([LOCK_A], datetime.now(), ends_at)


@responses.activate
def test_get_lock_list():
    provider = make_provider()
    responses.get(
        "https://euapi.ttlock.com/v3/lock/list",
        json={"total": 1, "list": [{"lockId": 12345678, "lockAlias": "Main"}]},
    )
    locks = provider.get_lock_list()
    assert locks["total"] == 1
