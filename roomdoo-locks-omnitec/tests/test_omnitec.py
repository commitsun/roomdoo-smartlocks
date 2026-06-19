import json
from datetime import datetime, timedelta, timezone

import pytest
import responses
from roomdoo_locks_base.exceptions import LockAuthError, LockOfflineError
from roomdoo_locks_omnitec import OmnitecProvider

CLIENT_ID = "fake_client_id"
CLIENT_SECRET = "fake_client_secret"
USERNAME = "fake_user"
PASSWORD = "fake_pass"
LOCK_A = "8279953"
LOCK_B = "8279954"

ADD_URL = "https://api.rentandpass.com/api/password"  # POST
CHANGE_URL = "https://api.rentandpass.com/api/password"  # PUT
DELETE_URL = "https://api.rentandpass.com/api/password"  # DELETE
LIST_URL = "https://api.rentandpass.com/api/lock/passwords"  # GET


def mock_auth():
    responses.get(
        "https://api.rentandpass.com/api/signin/token",
        json={"access_token": "fake_token", "refresh_token": "fake_refresh"},
    )


def make_provider():
    """Build an authenticated provider. Must be called inside an active
    ``responses`` context, since the constructor authenticates over HTTP."""
    mock_auth()
    return OmnitecProvider(CLIENT_ID, CLIENT_SECRET, USERNAME, PASSWORD)


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
    responses.get(
        "https://api.rentandpass.com/api/signin/token",
        json={"error": "Unauthorized"},
        status=401,
    )
    with pytest.raises(LockAuthError):
        OmnitecProvider(CLIENT_ID, CLIENT_SECRET, USERNAME, PASSWORD)


@responses.activate
def test_grant_access_forces_pin_and_packs_ref(window):
    provider = make_provider()
    starts_at, ends_at = window
    responses.post(ADD_URL, json={"keyboardPwdId": 111, "keyboardPwd": "135790"})
    responses.post(ADD_URL, json={"keyboardPwdId": 222, "keyboardPwd": "135790"})

    grant = provider.grant_access([LOCK_A, LOCK_B], starts_at, ends_at, pin="135790")

    assert grant.pin == "135790"
    assert json.loads(grant.ref) == [
        {"ID": LOCK_A, "passID": "111"},
        {"ID": LOCK_B, "passID": "222"},
    ]


@responses.activate
def test_grant_access_generates_pin_when_omitted(window):
    provider = make_provider()
    starts_at, ends_at = window
    responses.post(ADD_URL, json={"keyboardPwdId": 111})

    grant = provider.grant_access([LOCK_A], starts_at, ends_at)

    assert len(grant.pin) == OmnitecProvider.PASSCODE_LENGTH
    assert set(grant.pin) <= set(OmnitecProvider.PASSCODE_ALPHABET)


@responses.activate
def test_grant_access_rolls_back_on_partial_failure(window):
    provider = make_provider()
    starts_at, ends_at = window
    responses.post(ADD_URL, json={"keyboardPwdId": 111})
    responses.post(ADD_URL, json={"errcode": -3002, "errmsg": "Gateway offline"})
    responses.delete(DELETE_URL, json={"errcode": 0})

    with pytest.raises(LockOfflineError):
        provider.grant_access([LOCK_A, LOCK_B], starts_at, ends_at, pin="135790")

    delete_calls = [c for c in responses.calls if c.request.method == "DELETE" and c.request.url.startswith(DELETE_URL)]
    assert len(delete_calls) == 1
    assert "passID=111" in delete_calls[0].request.url


@responses.activate
def test_modify_access_returns_pin(window):
    provider = make_provider()
    starts_at, ends_at = window
    new_ends_at = ends_at + timedelta(hours=2)
    ref = json.dumps([{"ID": LOCK_A, "passID": "111"}])

    responses.put(CHANGE_URL, json={"errcode": 0})
    responses.get(LIST_URL, json={"list": [{"keyboardPwdId": 111, "keyboardPwd": "135790"}]})

    grant = provider.modify_access(ref, starts_at, new_ends_at)

    assert grant.pin == "135790"
    assert grant.ref == ref
    assert grant.ends_at == new_ends_at


@responses.activate
def test_revoke_access_deletes_every_lock():
    provider = make_provider()
    ref = json.dumps([{"ID": LOCK_A, "passID": "111"}, {"ID": LOCK_B, "passID": "222"}])
    responses.delete(DELETE_URL, json={"errcode": 0})

    assert provider.revoke_access(ref) is True
    delete_calls = [c for c in responses.calls if c.request.method == "DELETE"]
    assert len(delete_calls) == 2


@responses.activate
def test_revoke_access_is_idempotent():
    provider = make_provider()
    ref = json.dumps([{"ID": LOCK_A, "passID": "99999"}])
    responses.delete(DELETE_URL, json={"errcode": -2009, "errmsg": "Invalid Password"})
    assert provider.revoke_access(ref) is True


@responses.activate
def test_grant_access_rejects_bad_window(window):
    provider = make_provider()
    starts_at, ends_at = window
    with pytest.raises(ValueError):
        provider.grant_access([LOCK_A], ends_at, starts_at)


@responses.activate
def test_list_locks_maps_id_and_name():
    provider = make_provider()
    responses.get(
        "https://api.rentandpass.com/api/lock/list",
        json={
            "total": 2,
            "pages": 1,
            "list": [
                {"lockId": 31812694, "lockAlias": "PUERTA CORUÑA Puerta Principal"},
                {"lockId": 31812695, "lockAlias": "Room 101"},
            ],
        },
    )
    assert provider.list_locks() == [
        {"id": "31812694", "name": "PUERTA CORUÑA Puerta Principal"},
        {"id": "31812695", "name": "Room 101"},
    ]
