from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class CodeResult:
    """Immutable result of a code creation or modification operation."""

    code_id: str
    pin: str
    lock_id: str
    starts_at: datetime
    ends_at: datetime

    def __repr__(self) -> str:
        masked = self.pin[:1] + "***" if self.pin else "***"
        return (
            f"CodeResult(code_id={self.code_id!r}, pin={masked!r}, "
            f"lock_id={self.lock_id!r}, starts_at={self.starts_at!r}, "
            f"ends_at={self.ends_at!r})"
        )
