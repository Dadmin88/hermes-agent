"""Run-scoped Fleet context-firewall authorization carried by ContextVar state."""

from __future__ import annotations

import re
from contextlib import contextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass
from typing import Any, Iterator, cast

_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_PRINCIPAL_KINDS = frozenset({"owner", "project", "network", "device", "service"})


class FleetContextScopeError(ValueError):
    """A Fleet context binding is malformed or ambiguous."""


def _hash(value: object, label: str) -> str:
    if type(value) is not str or _HASH_RE.fullmatch(value) is None:
        raise FleetContextScopeError(f"{label} is invalid")
    return value


@dataclass(frozen=True, slots=True)
class FleetContextBinding:
    """Exact principal/Agent/RunAuthority/base binding for one Fleet run."""

    version: str
    principal_id: str
    principal_kind: str
    principal_generation: int
    principal_binding_hash: str
    agent_instance_id: str
    base_manifest_digest: str
    run_authority_hash: str

    def __post_init__(self) -> None:
        if self.version != "fleet-context-v1":
            raise FleetContextScopeError("unsupported Fleet context version")
        _hash(self.principal_id, "Fleet context principal id")
        if self.principal_kind not in _PRINCIPAL_KINDS:
            raise FleetContextScopeError("Fleet context principal kind is invalid")
        if (
            isinstance(self.principal_generation, bool)
            or type(self.principal_generation) is not int
            or self.principal_generation < 1
        ):
            raise FleetContextScopeError("Fleet context principal generation is invalid")
        _hash(self.principal_binding_hash, "Fleet context principal binding hash")
        _hash(self.agent_instance_id, "Fleet context Agent Instance id")
        _hash(self.base_manifest_digest, "Fleet context base manifest digest")
        _hash(self.run_authority_hash, "Fleet context RunAuthority hash")

    @classmethod
    def from_request(cls, value: object) -> "FleetContextBinding":
        if type(value) is not dict or set(value) != {
            "version",
            "principal",
            "agent_instance_id",
            "base_manifest_digest",
            "run_authority_hash",
        }:
            raise FleetContextScopeError("fleet_context has an invalid shape")
        document = cast(dict[str, Any], value)
        principal = document["principal"]
        if type(principal) is not dict or set(principal) != {
            "principal_id",
            "kind",
            "generation",
            "binding_hash",
        }:
            raise FleetContextScopeError("Fleet context principal has an invalid shape")
        principal_document = cast(dict[str, Any], principal)
        return cls(
            version=document["version"],
            principal_id=principal_document["principal_id"],
            principal_kind=principal_document["kind"],
            principal_generation=principal_document["generation"],
            principal_binding_hash=principal_document["binding_hash"],
            agent_instance_id=document["agent_instance_id"],
            base_manifest_digest=document["base_manifest_digest"],
            run_authority_hash=document["run_authority_hash"],
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
            "base_manifest_digest": self.base_manifest_digest,
            "run_authority_hash": self.run_authority_hash,
        }


_current_fleet_context: ContextVar[FleetContextBinding | None] = ContextVar(
    "fleet_context_binding",
    default=None,
)


def get_fleet_context() -> FleetContextBinding | None:
    return _current_fleet_context.get()


def set_fleet_context(
    binding: FleetContextBinding | None,
) -> Token[FleetContextBinding | None]:
    if binding is not None and type(binding) is not FleetContextBinding:
        raise FleetContextScopeError("Fleet context binding is invalid")
    return _current_fleet_context.set(binding)


def reset_fleet_context(token: Token[FleetContextBinding | None]) -> None:
    _current_fleet_context.reset(token)


@contextmanager
def fleet_context_scope(binding: FleetContextBinding | None) -> Iterator[None]:
    token = set_fleet_context(binding)
    try:
        yield
    finally:
        reset_fleet_context(token)


__all__ = [
    "FleetContextBinding",
    "FleetContextScopeError",
    "fleet_context_scope",
    "get_fleet_context",
]
