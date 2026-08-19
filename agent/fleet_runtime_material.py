from __future__ import annotations

import re
import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Iterator, cast

from hermes_secure_store import InjectionTarget, open_default_store

_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,511}$")
_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_HANDLE_RE = re.compile(r"^hvh1_[A-Za-z0-9_-]{20,120}$")
_MAX_HANDLES = 64
_RESERVED_ENV_NAMES = frozenset({
    "API_SERVER_KEY",
    "DOCKER_CONTEXT",
    "DOCKER_HOST",
    "HOME",
    "PATH",
    "PYTHONPATH",
    "SHELL",
    "SSH_AGENT_PID",
    "SSH_AUTH_SOCK",
    "USER",
})
_RESERVED_ENV_PREFIXES = (
    "DOCKER_",
    "FLEET_",
    "HERMES_",
    "KERYX_",
    "NODESCALE_",
    "SSH_",
)


class FleetRuntimeMaterialError(RuntimeError):
    """Run-scoped Vault handle binding is malformed or unavailable."""


@dataclass(frozen=True, slots=True, repr=False)
class FleetRuntimeMaterialHandle:
    handle: str
    injection_kind: str
    injection_target: str
    version: int
    expires_at_ms: int

    def __post_init__(self) -> None:
        if type(self.handle) is not str or _HANDLE_RE.fullmatch(self.handle) is None:
            raise FleetRuntimeMaterialError("temporary runtime handle is invalid")
        try:
            InjectionTarget(self.injection_kind, self.injection_target)
        except ValueError as error:
            raise FleetRuntimeMaterialError(
                "runtime injection descriptor is invalid"
            ) from error
        if self.injection_kind == "env" and (
            self.injection_target in _RESERVED_ENV_NAMES
            or any(
                self.injection_target.startswith(prefix)
                for prefix in _RESERVED_ENV_PREFIXES
            )
        ):
            raise FleetRuntimeMaterialError(
                "runtime material may not override Fleet/Hermes control environment"
            )
        if (
            isinstance(self.version, bool)
            or type(self.version) is not int
            or self.version < 1
        ):
            raise FleetRuntimeMaterialError("runtime material version is invalid")
        if (
            isinstance(self.expires_at_ms, bool)
            or type(self.expires_at_ms) is not int
            or self.expires_at_ms < 1
        ):
            raise FleetRuntimeMaterialError("runtime handle expiry is invalid")

    def __repr__(self) -> str:
        return (
            "FleetRuntimeMaterialHandle(<opaque>, injection="
            f"{self.injection_kind}:{self.injection_target}, version={self.version})"
        )

    @property
    def injection(self) -> InjectionTarget:
        return InjectionTarget(self.injection_kind, self.injection_target)

    @classmethod
    def from_request(cls, value: object) -> "FleetRuntimeMaterialHandle":
        if type(value) is not dict or set(value) != {
            "handle",
            "injection",
            "version",
            "expires_at_ms",
        }:
            raise FleetRuntimeMaterialError("runtime handle has an invalid shape")
        document = cast(dict[str, Any], value)
        injection_value = document["injection"]
        if type(injection_value) is not dict or set(injection_value) != {
            "kind",
            "target",
        }:
            raise FleetRuntimeMaterialError("runtime injection has an invalid shape")
        injection = cast(dict[str, Any], injection_value)
        return cls(
            handle=cast(str, document["handle"]),
            injection_kind=cast(str, injection["kind"]),
            injection_target=cast(str, injection["target"]),
            version=cast(int, document["version"]),
            expires_at_ms=cast(int, document["expires_at_ms"]),
        )

    def to_request(self) -> dict[str, object]:
        return {
            "handle": self.handle,
            "injection": {
                "kind": self.injection_kind,
                "target": self.injection_target,
            },
            "version": self.version,
            "expires_at_ms": self.expires_at_ms,
        }


@dataclass(frozen=True, slots=True, repr=False)
class FleetVaultBinding:
    run_id: str
    run_authority_hash: str
    handles: tuple[FleetRuntimeMaterialHandle, ...]
    version: str = "fleet-vault-v1"

    def __post_init__(self) -> None:
        if self.version != "fleet-vault-v1":
            raise FleetRuntimeMaterialError(
                "Fleet Vault binding version is unsupported"
            )
        if (
            type(self.run_id) is not str
            or _IDENTIFIER_RE.fullmatch(self.run_id) is None
        ):
            raise FleetRuntimeMaterialError("Fleet Vault run id is invalid")
        if (
            type(self.run_authority_hash) is not str
            or _HASH_RE.fullmatch(self.run_authority_hash) is None
        ):
            raise FleetRuntimeMaterialError("Fleet Vault RunAuthority hash is invalid")
        if type(self.handles) not in {tuple, list}:
            raise FleetRuntimeMaterialError("Fleet Vault handles are invalid")
        handles = tuple(self.handles)
        if (
            len(handles) > _MAX_HANDLES
            or any(type(handle) is not FleetRuntimeMaterialHandle for handle in handles)
            or len({handle.handle for handle in handles}) != len(handles)
            or len({
                (handle.injection_kind, handle.injection_target) for handle in handles
            })
            != len(handles)
        ):
            raise FleetRuntimeMaterialError("Fleet Vault handles are invalid")
        object.__setattr__(self, "handles", handles)

    def __repr__(self) -> str:
        return (
            f"FleetVaultBinding(run_id={self.run_id!r}, "
            f"run_authority_hash={self.run_authority_hash!r}, handles={len(self.handles)})"
        )

    @classmethod
    def from_request(cls, value: object) -> "FleetVaultBinding":
        if type(value) is not dict or set(value) != {
            "version",
            "run_id",
            "run_authority_hash",
            "handles",
        }:
            raise FleetRuntimeMaterialError("Fleet Vault binding has an invalid shape")
        document = cast(dict[str, Any], value)
        raw_handles_value = document["handles"]
        if type(raw_handles_value) is not list:
            raise FleetRuntimeMaterialError("Fleet Vault handles must be a list")
        raw_handles = cast(list[object], raw_handles_value)
        return cls(
            version=cast(str, document["version"]),
            run_id=cast(str, document["run_id"]),
            run_authority_hash=cast(str, document["run_authority_hash"]),
            handles=tuple(
                FleetRuntimeMaterialHandle.from_request(item) for item in raw_handles
            ),
        )

    def to_request(self) -> dict[str, object]:
        return {
            "version": self.version,
            "run_id": self.run_id,
            "run_authority_hash": self.run_authority_hash,
            "handles": [handle.to_request() for handle in self.handles],
        }

    def handle_for(self, kind: str, target: str) -> FleetRuntimeMaterialHandle | None:
        for handle in self.handles:
            if handle.injection_kind == kind and handle.injection_target == target:
                return handle
        return None


_FLEET_VAULT: ContextVar[FleetVaultBinding | None] = ContextVar(
    "_FLEET_VAULT", default=None
)


@contextmanager
def fleet_vault_scope(binding: FleetVaultBinding | None) -> Iterator[None]:
    token = _FLEET_VAULT.set(binding)
    try:
        yield
    finally:
        _FLEET_VAULT.reset(token)


def get_fleet_vault() -> FleetVaultBinding | None:
    return _FLEET_VAULT.get()


def validate_fleet_vault_expiry(
    binding: FleetVaultBinding, *, now_ms: int | None = None
) -> None:
    if type(binding) is not FleetVaultBinding:
        raise FleetRuntimeMaterialError("Fleet Vault binding is invalid")
    current = int(time.time() * 1000) if now_ms is None else now_ms
    if isinstance(current, bool) or type(current) is not int or current < 1:
        raise FleetRuntimeMaterialError("Fleet Vault clock is invalid")
    if any(handle.expires_at_ms <= current for handle in binding.handles):
        raise FleetRuntimeMaterialError("Fleet Vault handle has expired")


def _redeem(handle: FleetRuntimeMaterialHandle, *, run_id: str) -> bytes:
    try:
        return open_default_store().redeem_handle(
            handle.handle,
            run_id=run_id,
            expected_injection=handle.injection,
        )
    except Exception as error:
        raise FleetRuntimeMaterialError("runtime material redemption failed") from error


def redeem_environment_material() -> dict[str, str]:
    binding = get_fleet_vault()
    if binding is None:
        return {}
    validate_fleet_vault_expiry(binding)
    result: dict[str, str] = {}
    for handle in binding.handles:
        if handle.injection_kind != "env":
            continue
        payload = _redeem(handle, run_id=binding.run_id)
        try:
            value = payload.decode("utf-8")
        except UnicodeDecodeError as error:
            raise FleetRuntimeMaterialError(
                "environment material is not UTF-8"
            ) from error
        if not value or any(character in value for character in ("\x00", "\n", "\r")):
            raise FleetRuntimeMaterialError("environment material is invalid")
        result[handle.injection_target] = value
    return result


def redeem_file_material() -> dict[str, bytes]:
    binding = get_fleet_vault()
    if binding is None:
        return {}
    validate_fleet_vault_expiry(binding)
    result: dict[str, bytes] = {}
    for handle in binding.handles:
        if handle.injection_kind == "file":
            result[handle.injection_target] = _redeem(handle, run_id=binding.run_id)
    return result


def redeem_broker_material(target: str) -> str:
    binding = get_fleet_vault()
    if binding is None:
        raise FleetRuntimeMaterialError("no Fleet Vault binding is active")
    validate_fleet_vault_expiry(binding)
    handle = binding.handle_for("broker", target)
    if handle is None:
        raise FleetRuntimeMaterialError(
            "broker material is not authorized for this run"
        )
    payload = _redeem(handle, run_id=binding.run_id)
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise FleetRuntimeMaterialError("broker material is not UTF-8") from error


__all__ = [
    "FleetRuntimeMaterialError",
    "FleetRuntimeMaterialHandle",
    "FleetVaultBinding",
    "fleet_vault_scope",
    "get_fleet_vault",
    "redeem_broker_material",
    "redeem_environment_material",
    "redeem_file_material",
    "validate_fleet_vault_expiry",
]
