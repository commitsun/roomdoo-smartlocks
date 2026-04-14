from dataclasses import dataclass, field
from typing import Any


@dataclass
class TokenResponse:
    access_token: str
    token_type: str
    refresh_token: str
    expires_in: int
    scope: str
    uid: int

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TokenResponse":
        return cls(
            access_token=data["access_token"],
            token_type=data.get("token_type", "bearer"),
            refresh_token=data.get("refresh_token", ""),
            expires_in=data.get("expires_in", 0),
            scope=data.get("scope", ""),
            uid=data.get("uid", 0),
        )


@dataclass
class LockInfo:
    lock_id: int
    lock_alias: str
    lock_mac: str
    lock_version: dict[str, Any] = field(default_factory=dict)
    electric_quantity: int = 0
    has_gateway: int = 0
    group_id: int = 0

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "LockInfo":
        return cls(
            lock_id=data.get("lockId", 0),
            lock_alias=data.get("lockAlias", ""),
            lock_mac=data.get("lockMac", ""),
            lock_version=data.get("lockVersion", {}),
            electric_quantity=data.get("electricQuantity", 0),
            has_gateway=data.get("hasGateway", 0),
            group_id=data.get("groupId", 0),
        )


@dataclass
class LockListResponse:
    page_no: int
    page_size: int
    pages: int
    total: int
    locks: list[LockInfo] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "LockListResponse":
        locks = [LockInfo.from_dict(lock) for lock in data.get("list", [])]
        return cls(
            page_no=data.get("pageNo", 1),
            page_size=data.get("pageSize", 10),
            pages=data.get("pages", 0),
            total=data.get("total", 0),
            locks=locks,
        )


@dataclass
class AccessCodeResponse:
    keyboard_pwd_id: int
    keyboard_pwd: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AccessCodeResponse":
        return cls(
            keyboard_pwd_id=data.get("keyboardPwdId", 0),
            keyboard_pwd=data.get("keyboardPwd", ""),
        )
    