"""Phase 25 Fleet-issued right-to-forget authorization.

The authorization names one durable learning identity, never a filesystem path.
It is authority-free, short-lived, and content-addressed so Hermes can reject
stale, malformed, substituted, or path-shaped deletion requests before touching
native learning state.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from typing import Any, cast

FORGET_VERSION = "fleet-forget-v1"
FORGET_POLICY_VERSION = "phase25-v1"
_MAX_TTL_MS = 15 * 60 * 1000
_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_MEMORY_KEY_RE = re.compile(r"^(memory|user):sha256:[0-9a-f]{64}$")
_PRINCIPAL_KINDS = frozenset({"owner", "project", "network", "device", "service"})
_SUBJECT_KINDS = frozenset({"memory", "skill"})


class FleetForgetError(RuntimeError):
    """A Fleet right-to-forget authorization is malformed or stale."""


def _hash(value: object, label: str) -> str:
    if type(value) is not str or _HASH_RE.fullmatch(value) is None:
        raise FleetForgetError(f"{label} is invalid")
    return value


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise FleetForgetError("forget authorization is not canonical JSON") from error


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


@dataclass(frozen=True, slots=True)
class FleetForgetAdministrator:
    principal_id: str
    kind: str
    generation: int
    binding_hash: str

    def __post_init__(self) -> None:
        _hash(self.principal_id, "forget administrator principal")
        _hash(self.binding_hash, "forget administrator binding")
        if self.kind not in _PRINCIPAL_KINDS:
            raise FleetForgetError("forget administrator kind is invalid")
        if (
            isinstance(self.generation, bool)
            or type(self.generation) is not int
            or self.generation < 1
        ):
            raise FleetForgetError("forget administrator generation is invalid")

    @classmethod
    def from_request(cls, value: object) -> "FleetForgetAdministrator":
        if type(value) is not dict or set(value) != {
            "principal_id",
            "kind",
            "generation",
            "binding_hash",
        }:
            raise FleetForgetError("forget administrator has an invalid shape")
        document = cast(dict[str, Any], value)
        return cls(
            principal_id=cast(str, document["principal_id"]),
            kind=cast(str, document["kind"]),
            generation=cast(int, document["generation"]),
            binding_hash=cast(str, document["binding_hash"]),
        )

    def to_request(self) -> dict[str, object]:
        return {
            "principal_id": self.principal_id,
            "kind": self.kind,
            "generation": self.generation,
            "binding_hash": self.binding_hash,
        }


@dataclass(frozen=True, slots=True)
class FleetForgetAuthorization:
    subject_kind: str
    subject_key: str
    source_owner_principal_id: str
    agent_instance_id: str
    administrator: FleetForgetAdministrator
    issued_at_ms: int
    expires_at_ms: int
    forget_id: str
    policy_version: str = FORGET_POLICY_VERSION
    version: str = FORGET_VERSION

    def __post_init__(self) -> None:
        if (
            self.version != FORGET_VERSION
            or self.policy_version != FORGET_POLICY_VERSION
        ):
            raise FleetForgetError("forget authorization version is unsupported")
        if self.subject_kind not in _SUBJECT_KINDS:
            raise FleetForgetError("forget subject kind is invalid")
        if self.subject_kind == "memory":
            if (
                type(self.subject_key) is not str
                or _MEMORY_KEY_RE.fullmatch(self.subject_key) is None
            ):
                raise FleetForgetError("forget memory subject key is invalid")
        else:
            _hash(self.subject_key, "forget skill candidate ID")
        _hash(self.source_owner_principal_id, "forget source owner principal")
        _hash(self.agent_instance_id, "forget Agent Instance")
        _hash(self.forget_id, "forget ID")
        for value, label in (
            (self.issued_at_ms, "issue time"),
            (self.expires_at_ms, "expiry"),
        ):
            if isinstance(value, bool) or type(value) is not int or value < 1:
                raise FleetForgetError(f"forget {label} is invalid")
        if (
            not self.issued_at_ms
            < self.expires_at_ms
            <= self.issued_at_ms + _MAX_TTL_MS
        ):
            raise FleetForgetError("forget authorization lifetime is invalid")
        if self.forget_id != _digest(self.unsigned_document()):
            raise FleetForgetError("forget ID does not match the exact authorization")

    def unsigned_document(self) -> dict[str, object]:
        return {
            "version": self.version,
            "policy_version": self.policy_version,
            "subject_kind": self.subject_kind,
            "subject_key": self.subject_key,
            "source_owner_principal_id": self.source_owner_principal_id,
            "agent_instance_id": self.agent_instance_id,
            "administrator": self.administrator.to_request(),
            "issued_at_ms": self.issued_at_ms,
            "expires_at_ms": self.expires_at_ms,
            "authority": "none",
        }

    def to_request(self) -> dict[str, object]:
        return {**self.unsigned_document(), "forget_id": self.forget_id}

    @classmethod
    def from_request(
        cls,
        value: object,
        *,
        now_ms: int | None = None,
    ) -> "FleetForgetAuthorization":
        expected = {
            "version",
            "policy_version",
            "subject_kind",
            "subject_key",
            "source_owner_principal_id",
            "agent_instance_id",
            "administrator",
            "issued_at_ms",
            "expires_at_ms",
            "authority",
            "forget_id",
        }
        if type(value) is not dict or set(value) != expected:
            raise FleetForgetError("forget authorization has an invalid shape")
        document = cast(dict[str, Any], value)
        if document["authority"] != "none":
            raise FleetForgetError(
                "forget authorization cannot carry execution authority"
            )
        authorization = cls(
            version=cast(str, document["version"]),
            policy_version=cast(str, document["policy_version"]),
            subject_kind=cast(str, document["subject_kind"]),
            subject_key=cast(str, document["subject_key"]),
            source_owner_principal_id=cast(str, document["source_owner_principal_id"]),
            agent_instance_id=cast(str, document["agent_instance_id"]),
            administrator=FleetForgetAdministrator.from_request(
                document["administrator"]
            ),
            issued_at_ms=cast(int, document["issued_at_ms"]),
            expires_at_ms=cast(int, document["expires_at_ms"]),
            forget_id=cast(str, document["forget_id"]),
        )
        current = int(time.time() * 1000) if now_ms is None else now_ms
        if (
            isinstance(current, bool)
            or type(current) is not int
            or current < authorization.issued_at_ms
        ):
            raise FleetForgetError("forget authorization clock is invalid")
        if current >= authorization.expires_at_ms:
            raise FleetForgetError("forget authorization has expired")
        return authorization


__all__ = [
    "FORGET_POLICY_VERSION",
    "FORGET_VERSION",
    "FleetForgetAdministrator",
    "FleetForgetAuthorization",
    "FleetForgetError",
]
