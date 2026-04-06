from roomdoo_locks_base import BaseLockProvider, CodeResult
from datetime import datetime

class TTLockProvider(BaseLockProvider):

    def _do_create_code(self, lock_id: str, starts_at: datetime, ends_at: datetime) -> CodeResult:
        raise NotImplementedError("TTLock aún no está implementado")

    def _do_invalidate_code(self, lock_id: str, code_id: str) -> bool:
        raise NotImplementedError("TTLock aún no está implementado")

    def _do_modify_code(self, lock_id: str, code_id: str, starts_at: datetime, ends_at: datetime) -> CodeResult:
        raise NotImplementedError("TTLock aún no está implementado")

    def test_connection(self) -> bool:
        raise NotImplementedError("TTLock aún no está implementado")