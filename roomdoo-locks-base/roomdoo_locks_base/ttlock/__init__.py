"""
ttlock
~~~~~~
A Python library for the TTLock EU API.

Quick start::

    from ttlock import TTLockClient

    client = TTLockClient(client_id="...", client_secret="...")
    token  = client.get_token("user@example.com", "password")
    locks  = client.get_lock_list(token.access_token)
"""

from .client import TTLockClient
from .exceptions import TTLockAPIError, TTLockAuthError, TTLockNotFoundError
from .models import TokenResponse, LockInfo, LockListResponse, AccessCodeResponse

__all__ = [
    "TTLockClient",
    "TTLockAPIError",
    "TTLockAuthError",
    "TTLockNotFoundError",
    "TokenResponse",
    "LockInfo",
    "LockListResponse",
    "AccessCodeResponse",
]
