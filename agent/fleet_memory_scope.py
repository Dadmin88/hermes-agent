"""Run-scoped Fleet persistent-memory authorization carried only by ContextVar state."""

from __future__ import annotations

import hashlib
import json
import re
from contextlib import contextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass
from typing import Iterator

_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,511}$")
_SCOPE_KINDS = frozenset({"principal", "project", "network", "owner", "agent_instance"})
_PRINCIPAL_KINDS = frozenset({"owner", "project", "network", "device", "service"})
_MAX_READ_SCOPES = 16


class FleetMemoryScopeError(ValueError):
    """A Fleet memory scope is malformed or would permit ambiguous isolation."""


def _hash(value: object, label: str) -> str:
    if type(value) is not str or _HASH_RE.fullmatch(value) is None:
        raise FleetMemoryScopeError(f"{label} is invalid")
    return value


def _identifier(value: object, label: str) -> str:
    if type(value) is not str or _IDENTIFIER_RE.fullmatch(value) is None:
        raise FleetMemoryScopeError(f"{label} is invalid")
    return value


@dataclass(frozen=True, slots=True)
class FleetMemoryScopeRef:
    kind: str
    scope_id: str

    def __post_init__(self) -> None:
        if self.kind not in _SCOPE_KINDS:
            raise FleetMemoryScopeError("Fleet memory scope kind is invalid")
        if self.kind in {"principal", "agent_instance"}:
            _hash(self.scope_id, "Fleet memory scope id")
        else:
            _identifier(self.scope_id, "Fleet memory scope id")

    @classmethod
    def from_request(cls, value: object) -> "FleetMemoryScopeRef":
        if type(value) is not dict or set(value) != {"kind", "scope_id"}:
            raise FleetMemoryScopeError("Fleet memory scope reference has an invalid shape")
        return cls(kind=value["kind"], scope_id=value["scope_id"])

    def to_request(self) -> dict[str, str]:
        return {"kind": self.kind, "scope_id": self.scope_id}

    @property
    def storage_key(self) -> str:
        payload = json.dumps(
            self.to_request(),
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True, slots=True)
class FleetMemoryBinding:
    version: str
    principal_id: str
    principal_kind: str
    principal_generation: int
    principal_binding_hash: str
    agent_instance_id: str
    source_run: str
    read_scopes: tuple[FleetMemoryScopeRef, ...]
    write_scope: FleetMemoryScopeRef
    retention_until_ms: int | None = None

    def __post_init__(self) -> None:
        if self.version != "fleet-memory-v1":
            raise FleetMemoryScopeError("unsupported Fleet memory version")
        _hash(self.principal_id, "Fleet memory principal id")
        if self.principal_kind not in _PRINCIPAL_KINDS:
            raise FleetMemoryScopeError("Fleet memory principal kind is invalid")
        if (
            isinstance(self.principal_generation, bool)
            or type(self.principal_generation) is not int
            or self.principal_generation < 1
        ):
            raise FleetMemoryScopeError("Fleet memory principal generation is invalid")
        _hash(self.principal_binding_hash, "Fleet memory principal binding hash")
        _hash(self.agent_instance_id, "Fleet memory Agent Instance id")
        _identifier(self.source_run, "Fleet memory source run")
        if (
            type(self.read_scopes) not in {tuple, list}
            or not 1 <= len(self.read_scopes) <= _MAX_READ_SCOPES
            or any(type(item) is not FleetMemoryScopeRef for item in self.read_scopes)
        ):
            raise FleetMemoryScopeError("Fleet memory read scopes are invalid")
        read_scopes = tuple(self.read_scopes)
        if len(set(read_scopes)) != len(read_scopes):
            raise FleetMemoryScopeError("Fleet memory read scopes contain duplicates")
        principal_scope = FleetMemoryScopeRef("principal", self.principal_id)
        if principal_scope not in read_scopes:
            raise FleetMemoryScopeError("Fleet memory read scopes must include the principal")
        if type(self.write_scope) is not FleetMemoryScopeRef:
            raise FleetMemoryScopeError("Fleet memory write scope is invalid")
        if self.write_scope != principal_scope:
            raise FleetMemoryScopeError("Fleet memory writes must remain principal-private")
        if self.retention_until_ms is not None and (
            isinstance(self.retention_until_ms, bool)
            or type(self.retention_until_ms) is not int
            or self.retention_until_ms < 1
        ):
            raise FleetMemoryScopeError("Fleet memory retention deadline is invalid")
        object.__setattr__(self, "read_scopes", read_scopes)

    @classmethod
    def from_request(cls, value: object) -> "FleetMemoryBinding":
        if type(value) is not dict or set(value) != {
            "version",
            "principal",
            "agent_instance_id",
            "source_run",
            "read_scopes",
            "write_scope",
            "retention_until_ms",
        }:
            raise FleetMemoryScopeError("fleet_memory has an invalid shape")
        principal = value["principal"]
        if type(principal) is not dict or set(principal) != {
            "principal_id",
            "kind",
            "generation",
            "binding_hash",
        }:
            raise FleetMemoryScopeError("Fleet memory principal has an invalid shape")
        read_scopes = value["read_scopes"]
        if type(read_scopes) is not list:
            raise FleetMemoryScopeError("Fleet memory read scopes are invalid")
        return cls(
            version=value["version"],
            principal_id=principal["principal_id"],
            principal_kind=principal["kind"],
            principal_generation=principal["generation"],
            principal_binding_hash=principal["binding_hash"],
            agent_instance_id=value["agent_instance_id"],
            source_run=value["source_run"],
            read_scopes=tuple(FleetMemoryScopeRef.from_request(item) for item in read_scopes),
            write_scope=FleetMemoryScopeRef.from_request(value["write_scope"]),
            retention_until_ms=value["retention_until_ms"],
        )

    def to_request(self) -> dict[str, object]:
        return {
            "version": self.version,
            "principal": {
                "principal_id": self.principal_id,
                "kind": self.principal_kind,
                "generation": self.principal_generation,
                "binding_hash": self.principal_binding_hash,
            },
            "agent_instance_id": self.agent_instance_id,
            "source_run": self.source_run,
            "read_scopes": [item.to_request() for item in self.read_scopes],
            "write_scope": self.write_scope.to_request(),
            "retention_until_ms": self.retention_until_ms,
        }


_current_fleet_memory: ContextVar[FleetMemoryBinding | None] = ContextVar(
    "fleet_memory_binding",
    default=None,
)


def get_fleet_memory() -> FleetMemoryBinding | None:
    return _current_fleet_memory.get()


def set_fleet_memory(
    binding: FleetMemoryBinding | None,
) -> Token[FleetMemoryBinding | None]:
    if binding is not None and type(binding) is not FleetMemoryBinding:
        raise FleetMemoryScopeError("Fleet memory binding is invalid")
    return _current_fleet_memory.set(binding)


def reset_fleet_memory(token: Token[FleetMemoryBinding | None]) -> None:
    _current_fleet_memory.reset(token)


@contextmanager
def fleet_memory_scope(binding: FleetMemoryBinding | None) -> Iterator[None]:
    token = set_fleet_memory(binding)
    try:
        yield
    finally:
        reset_fleet_memory(token)
