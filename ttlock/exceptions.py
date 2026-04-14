class TTLockAPIError(Exception):
    """Raised when the TTLock API returns an error response."""

    def __init__(self, message: str, errcode: int | None = None, errmsg: str | None = None):
        self.errcode = errcode
        self.errmsg = errmsg
        super().__init__(message)

    def __str__(self):
        if self.errcode:
            return f"[{self.errcode}] {self.errmsg or self.args[0]}"
        return self.args[0]


class TTLockAuthError(TTLockAPIError):
    """Raised when authentication fails (bad credentials or expired token)."""


class TTLockNotFoundError(TTLockAPIError):
    """Raised when a requested resource (lock, passcode, etc.) is not found."""
