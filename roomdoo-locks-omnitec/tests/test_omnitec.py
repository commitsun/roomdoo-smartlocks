import json
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import pytest
import responses
from roomdoo_locks_base.exceptions import LockAuthError, LockOfflineError
from roomdoo_locks_omnitec import GatewayCommandError, OmnitecProvider

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
def test_modify_access_reaches_every_lock_through_the_gateway(window):
    provider = make_provider()
    starts_at, ends_at = window
    ref = json.dumps([{"ID": LOCK_A, "passID": "111"}, {"ID": LOCK_B, "passID": "222"}])
    responses.put(CHANGE_URL, json={"errcode": 0})
    responses.get(LIST_URL, json={"list": [{"keyboardPwdId": 111, "keyboardPwd": "135790"}]})

    provider.modify_access(ref, starts_at, ends_at + timedelta(days=1))

    changes = calls("PUT", CHANGE_URL)
    assert [(query(c)["ID"], query(c)["type"]) for c in changes] == [(LOCK_A, "2"), (LOCK_B, "2")]


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


# ── errcode -1 and gateway diagnostics ────────────────────────────────────

GATEWAYS_URL = "https://api.rentandpass.com/api/gateway/listByLock"  # GET
TAG = "F2600001#17"
FAILED_COMMAND = {"errcode": -1, "description": "An error has ocurred"}


def query(call):
    """Query params of a recorded request, single values unwrapped."""
    return {k: v[0] for k, v in parse_qs(urlparse(call.request.url).query).items()}


def calls(method, url):
    return [c for c in responses.calls if c.request.method == method and c.request.url.startswith(url)]


@responses.activate
def test_minus_one_is_transient_and_reports_the_gateways(window):
    provider = make_provider()
    starts_at, ends_at = window
    responses.post(ADD_URL, json=FAILED_COMMAND)
    responses.get(
        GATEWAYS_URL,
        json={
            "list": [
                {"gatewayId": 1, "gatewayName": "Gateway A", "rssi": -70, "rssiUpdateDate": 1767225600000},
                {"gatewayId": 2, "gatewayName": "Gateway B", "rssi": -95, "rssiUpdateDate": 1767225660000},
            ]
        },
    )

    with pytest.raises(GatewayCommandError) as err:
        provider.grant_access([LOCK_A], starts_at, ends_at)

    assert isinstance(err.value, LockOfflineError)
    message = str(err.value)
    assert "[-1]: An error has ocurred" in message
    assert "Gateway A rssi -70 (2026-01-01 00:00 UTC)" in message
    assert "Gateway B rssi -95" in message
    assert query(calls("GET", GATEWAYS_URL)[0])["ID"] == LOCK_A


@responses.activate
def test_minus_one_without_gateway(window):
    provider = make_provider()
    starts_at, ends_at = window
    responses.post(ADD_URL, json=FAILED_COMMAND)
    responses.get(GATEWAYS_URL, json={"list": []})

    with pytest.raises(GatewayCommandError, match="lock linked to no gateway"):
        provider.grant_access([LOCK_A], starts_at, ends_at)


@responses.activate
def test_gateway_diagnostics_never_hide_the_error():
    provider = make_provider()
    ref = json.dumps([{"ID": LOCK_A, "passID": "111"}])
    responses.delete(DELETE_URL, json=FAILED_COMMAND)
    responses.get(GATEWAYS_URL, status=500)

    with pytest.raises(GatewayCommandError, match="gateway diagnostics unavailable"):
        provider.revoke_access(ref)


# ── Resumable (tagged) grants ─────────────────────────────────────────────


def make_tagged_provider():
    mock_auth()
    return OmnitecProvider(CLIENT_ID, CLIENT_SECRET, USERNAME, PASSWORD, passcode_tag=TAG)


def tagged(pass_id, pin):
    return {"keyboardPwdId": pass_id, "keyboardPwd": pin, "keyboardPwdName": TAG}


@responses.activate
def test_tagged_grant_names_every_passcode(window):
    provider = make_tagged_provider()
    starts_at, ends_at = window
    responses.get(LIST_URL, json={"list": []})
    responses.get(LIST_URL, json={"list": []})
    responses.post(ADD_URL, json={"keyboardPwdId": 111})
    responses.post(ADD_URL, json={"keyboardPwdId": 222})

    grant = provider.grant_access([LOCK_A, LOCK_B], starts_at, ends_at)

    adds = calls("POST", ADD_URL)
    assert [query(c)["name"] for c in adds] == [TAG, TAG]
    assert {query(c)["password"] for c in adds} == {grant.pin}
    # The whole listing is read, not the first page of 20.
    assert all(query(c)["itemsPerPage"] == "999" for c in calls("GET", LIST_URL))


@responses.activate
def test_tagged_grant_keeps_programmed_locks_on_failure(window):
    provider = make_tagged_provider()
    starts_at, ends_at = window
    responses.get(LIST_URL, json={"list": []})
    responses.get(LIST_URL, json={"list": []})
    responses.post(ADD_URL, json={"keyboardPwdId": 111})
    responses.post(ADD_URL, json=FAILED_COMMAND)
    responses.get(GATEWAYS_URL, json={"list": []})

    with pytest.raises(GatewayCommandError):
        provider.grant_access([LOCK_A, LOCK_B], starts_at, ends_at)

    assert calls("DELETE", DELETE_URL) == []


@responses.activate
def test_tagged_grant_resumes_a_previous_attempt(window):
    provider = make_tagged_provider()
    starts_at, ends_at = window
    # Lock A was programmed by the interrupted attempt; lock B was not, and
    # holds an unrelated passcode that must be left alone.
    responses.get(LIST_URL, json={"list": [tagged(111, "4721")]})
    responses.get(LIST_URL, json={"list": [{"keyboardPwdId": 999, "keyboardPwd": "4721", "keyboardPwdName": ""}]})
    responses.post(ADD_URL, json={"keyboardPwdId": 222})

    grant = provider.grant_access([LOCK_A, LOCK_B], starts_at, ends_at)

    assert grant.pin == "4721"
    assert json.loads(grant.ref) == [{"ID": LOCK_A, "passID": "111"}, {"ID": LOCK_B, "passID": "222"}]
    adds = calls("POST", ADD_URL)
    assert len(adds) == 1
    assert query(adds[0])["ID"] == LOCK_B
    assert query(adds[0])["password"] == "4721"
    assert calls("DELETE", DELETE_URL) == []


@responses.activate
def test_tagged_grant_completed_by_lost_response_adds_nothing(window):
    provider = make_tagged_provider()
    starts_at, ends_at = window
    # Errcode -1 on lock B, yet the passcode was applied: both are listed.
    responses.get(LIST_URL, json={"list": [tagged(111, "4721")]})
    responses.get(LIST_URL, json={"list": [tagged(222, "4721")]})

    grant = provider.grant_access([LOCK_A, LOCK_B], starts_at, ends_at)

    assert grant.pin == "4721"
    assert json.loads(grant.ref) == [{"ID": LOCK_A, "passID": "111"}, {"ID": LOCK_B, "passID": "222"}]
    assert calls("POST", ADD_URL) == []


@responses.activate
def test_tagged_grant_drops_tagged_passcodes_under_another_pin(window):
    provider = make_tagged_provider()
    starts_at, ends_at = window
    responses.get(LIST_URL, json={"list": [tagged(111, "4721")]})
    responses.get(LIST_URL, json={"list": [tagged(333, "9135")]})
    responses.delete(DELETE_URL, json={"errcode": 0})
    responses.post(ADD_URL, json={"keyboardPwdId": 222})

    grant = provider.grant_access([LOCK_A, LOCK_B], starts_at, ends_at)

    assert grant.pin == "4721"
    deletes = calls("DELETE", DELETE_URL)
    assert [(query(c)["ID"], query(c)["passID"]) for c in deletes] == [(LOCK_B, "333")]
    assert query(calls("POST", ADD_URL)[0])["password"] == "4721"


@responses.activate
def test_delete_tagged_passcodes_only_deletes_the_tag():
    provider = make_provider()
    responses.get(
        LIST_URL,
        json={
            "list": [
                tagged(111, "4721"),
                {"keyboardPwdId": 888, "keyboardPwd": "1234"},
                {"keyboardPwdId": 999, "keyboardPwd": "5678", "keyboardPwdName": "Reception"},
            ]
        },
    )
    responses.get(LIST_URL, json={"list": [tagged(222, "4721")]})
    responses.delete(DELETE_URL, json={"errcode": 0})

    assert provider.delete_tagged_passcodes([LOCK_A, LOCK_B], TAG) == 2
    deletes = calls("DELETE", DELETE_URL)
    assert [(query(c)["ID"], query(c)["passID"]) for c in deletes] == [(LOCK_A, "111"), (LOCK_B, "222")]


@responses.activate
def test_delete_tagged_passcodes_requires_a_tag():
    provider = make_provider()
    with pytest.raises(ValueError):
        provider.delete_tagged_passcodes([LOCK_A], "")
