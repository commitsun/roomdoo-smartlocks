"""Tests for OmnitecProvider (OsAccess API)."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import httpx
import pytest
import respx

from roomdoo_locks_base import (
    LockAuthError,
    LockCodeDeletionError,
    LockConnectionError,
    LockNotFoundError,
    LockOperationError,
)
from roomdoo_locks_omnitec import OmnitecProvider

BASE = "https://osaccess-backend.osaccess.net/api"
RESERVAS_URL = f"{BASE}/Reservas/generatePasscodeAndQR"
STARTS = datetime(2026, 4, 1, 14, 0, tzinfo=timezone.utc)
ENDS = datetime(2026, 4, 3, 11, 0, tzinfo=timezone.utc)


def _ok_response(book_id: int = 42, passcode: str = "987654") -> httpx.Response:
    return httpx.Response(
        200,
        json={"id": book_id, "passcodes": [{"passcode": passcode}]},
    )


@pytest.fixture()
def provider() -> OmnitecProvider:
    return OmnitecProvider(instance="test-hotel", apikey="secret-key")


# -- Auth headers -------------------------------------------------------------


@respx.mock
def test_auth_headers_sent_on_every_request(provider: OmnitecProvider) -> None:
    route = respx.post(RESERVAS_URL).mock(return_value=_ok_response())
    provider.create_code("101", STARTS, ENDS)

    assert route.called
    req = route.calls.last.request
    assert req.headers["instance"] == "test-hotel"
    assert req.headers["apikey"] == "secret-key"
    assert req.headers["content-type"] == "application/json"


# -- create_code --------------------------------------------------------------


@respx.mock
def test_create_code_returns_correct_result(provider: OmnitecProvider) -> None:
    respx.post(RESERVAS_URL).mock(return_value=_ok_response(42, "987654"))

    result = provider.create_code("101", STARTS, ENDS)

    assert result.code_id == "42"
    assert result.pin == "987654"
    assert result.lock_id == "101"
    assert result.starts_at == STARTS
    assert result.ends_at == ENDS


@respx.mock
def test_create_code_sends_correct_body(provider: OmnitecProvider) -> None:
    route = respx.post(RESERVAS_URL).mock(return_value=_ok_response())
    provider.create_code("205", STARTS, ENDS)

    payload = json.loads(route.calls.last.request.content)
    assert payload["roomNo"] == "205"
    assert payload["dateTimeCheckin"] == STARTS.isoformat()
    assert payload["dateTimeCheckout"] == ENDS.isoformat()
    assert payload["passCode"] is True
    assert payload["invalidatePreviousPassCodes"] is True
    assert payload["commonAreas"] == "DEFAULT"


@respx.mock
def test_create_code_custom_common_areas() -> None:
    p = OmnitecProvider(instance="h", apikey="k", common_areas="POOL,GYM")
    route = respx.post(RESERVAS_URL).mock(return_value=_ok_response())
    p.create_code("101", STARTS, ENDS)

    payload = json.loads(route.calls.last.request.content)
    assert payload["commonAreas"] == "POOL,GYM"


@respx.mock
def test_create_code_empty_passcodes_raises(provider: OmnitecProvider) -> None:
    respx.post(RESERVAS_URL).mock(
        return_value=httpx.Response(200, json={"id": 1, "passcodes": []})
    )
    with pytest.raises(LockOperationError, match="no passcodes"):
        provider.create_code("101", STARTS, ENDS)


@respx.mock
def test_create_code_null_passcode_raises(provider: OmnitecProvider) -> None:
    respx.post(RESERVAS_URL).mock(
        return_value=httpx.Response(
            200, json={"id": 1, "passcodes": [{"passcode": None}]}
        )
    )
    with pytest.raises(LockOperationError, match="no passcodes"):
        provider.create_code("101", STARTS, ENDS)


# -- invalidate_code ----------------------------------------------------------


@respx.mock
def test_invalidate_code_success(provider: OmnitecProvider) -> None:
    route = respx.put(f"{BASE}/Reservas/42/onlineCancel").mock(
        return_value=httpx.Response(200, json={"success": True})
    )
    assert provider.invalidate_code("101", "42") is True
    assert route.called


@respx.mock
def test_invalidate_code_idempotent_on_404(provider: OmnitecProvider) -> None:
    respx.put(f"{BASE}/Reservas/99/onlineCancel").mock(
        return_value=httpx.Response(404)
    )
    assert provider.invalidate_code("101", "99") is True


@respx.mock
def test_invalidate_code_propagates_auth_error(provider: OmnitecProvider) -> None:
    respx.put(f"{BASE}/Reservas/42/onlineCancel").mock(
        return_value=httpx.Response(401)
    )
    with pytest.raises(LockAuthError):
        provider.invalidate_code("101", "42")


# -- modify_code (direct) ----------------------------------------------------


@respx.mock
def test_modify_code_direct_success(provider: OmnitecProvider) -> None:
    respx.post(RESERVAS_URL).mock(return_value=_ok_response(43, "555555"))

    result = provider.modify_code("101", "42", STARTS, ENDS)

    assert result.code_id == "43"
    assert result.pin == "555555"
    assert result.lock_id == "101"


@respx.mock
def test_modify_code_sends_book_id(provider: OmnitecProvider) -> None:
    route = respx.post(RESERVAS_URL).mock(return_value=_ok_response(43, "555555"))
    provider.modify_code("101", "42", STARTS, ENDS)

    payload = json.loads(route.calls.last.request.content)
    assert payload["bookId"] == 42
    assert payload["roomNo"] == "101"
    assert payload["invalidatePreviousPassCodes"] is True


# -- modify_code (fallback create+delete) -------------------------------------


@respx.mock
def test_modify_code_fallback_on_404(provider: OmnitecProvider) -> None:
    """When direct modify returns 404, falls back to create+delete."""
    responses = iter([
        httpx.Response(404),  # modify attempt → LockNotFoundError → fallback
        _ok_response(99, "777777"),  # create in fallback
    ])
    respx.post(RESERVAS_URL).mock(side_effect=lambda _req: next(responses))
    respx.put(f"{BASE}/Reservas/42/onlineCancel").mock(
        return_value=httpx.Response(200)
    )

    result = provider.modify_code("101", "42", STARTS, ENDS)

    assert result.code_id == "99"
    assert result.pin == "777777"


@respx.mock
def test_modify_code_fallback_deletion_error(provider: OmnitecProvider) -> None:
    """Fallback: create succeeds but old code deletion fails → LockCodeDeletionError."""
    responses = iter([
        httpx.Response(404),  # modify attempt fails
        _ok_response(99, "777777"),  # create succeeds
    ])
    respx.post(RESERVAS_URL).mock(side_effect=lambda _req: next(responses))
    respx.put(f"{BASE}/Reservas/42/onlineCancel").mock(
        return_value=httpx.Response(401)  # deletion fails with auth error
    )

    with pytest.raises(LockCodeDeletionError) as exc_info:
        provider.modify_code("101", "42", STARTS, ENDS)

    assert exc_info.value.old_code_id == "42"
    assert exc_info.value.new_result.code_id == "99"
    assert exc_info.value.new_result.pin == "777777"


# -- test_connection ----------------------------------------------------------


@respx.mock
def test_connection_success_on_non_auth_error(provider: OmnitecProvider) -> None:
    """test_connection returns True even if the API rejects the dummy data."""
    respx.post(RESERVAS_URL).mock(return_value=httpx.Response(404))
    assert provider.test_connection() is True


@respx.mock
def test_connection_success_on_200(provider: OmnitecProvider) -> None:
    respx.post(RESERVAS_URL).mock(return_value=_ok_response())
    assert provider.test_connection() is True


@respx.mock
def test_connection_raises_on_auth_error(provider: OmnitecProvider) -> None:
    respx.post(RESERVAS_URL).mock(return_value=httpx.Response(401))
    with pytest.raises(LockAuthError):
        provider.test_connection()


@respx.mock
def test_connection_raises_on_403(provider: OmnitecProvider) -> None:
    respx.post(RESERVAS_URL).mock(return_value=httpx.Response(403))
    with pytest.raises(LockAuthError):
        provider.test_connection()


# -- Error mapping ------------------------------------------------------------


@respx.mock
def test_error_401_raises_lock_auth_error(provider: OmnitecProvider) -> None:
    respx.post(RESERVAS_URL).mock(return_value=httpx.Response(401))
    with pytest.raises(LockAuthError):
        provider.create_code("101", STARTS, ENDS)


@respx.mock
def test_error_403_raises_lock_auth_error(provider: OmnitecProvider) -> None:
    respx.post(RESERVAS_URL).mock(return_value=httpx.Response(403))
    with pytest.raises(LockAuthError):
        provider.create_code("101", STARTS, ENDS)


@respx.mock
def test_error_404_raises_lock_not_found(provider: OmnitecProvider) -> None:
    respx.post(RESERVAS_URL).mock(return_value=httpx.Response(404))
    with pytest.raises(LockNotFoundError):
        provider.create_code("101", STARTS, ENDS)


@respx.mock
def test_error_5xx_retries_then_raises_connection_error(
    provider: OmnitecProvider,
) -> None:
    route = respx.post(RESERVAS_URL).mock(return_value=httpx.Response(502))
    with pytest.raises(LockConnectionError):
        provider.create_code("101", STARTS, ENDS)
    # 1 original + 3 retries = 4 calls
    assert route.call_count == 4


@respx.mock
def test_error_5xx_recovers_on_retry(provider: OmnitecProvider) -> None:
    """If a 5xx is followed by a 200, the retry succeeds."""
    responses = iter([
        httpx.Response(502),
        _ok_response(10, "111111"),
    ])
    respx.post(RESERVAS_URL).mock(side_effect=lambda _req: next(responses))

    result = provider.create_code("101", STARTS, ENDS)

    assert result.code_id == "10"
    assert result.pin == "111111"
