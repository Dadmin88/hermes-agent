"""Phase 18 Fleet-issued durable-learning promotion authorization.

Hermes validates the exact, short-lived Fleet document before mutating native
memory/skill state. The document is visibility authority only; it can never
carry execution authority.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from typing import Any, Mapping, cast

PROMOTION_VERSION = "fleet-promotion-v1"
PROMOTION_POLICY_VERSION = "phase18-v1"
_SCOPE_KINDS = frozenset({"principal", "project", "network", "owner"})
_SUBJECT_KINDS = frozenset({"memory", "skill"})
_SCOPE_RANK = {"principal": 0, "project": 1, "network": 2, "owner": 3}
_PRINCIPAL_KINDS = frozenset({"owner", "project", "network", "device", "service"})
_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,511}$")
_MAX_TTL_MS = 15 * 60 * 1000


class FleetPromotionError(RuntimeError):
    """Fleet promotion authorization is malformed, stale, or inconsistent."""


def _hash(value: object, label: str) -> str:
    if type(value) is not str or _HASH_RE.fullmatch(value) is None:
        raise FleetPromotionError(f"{label} is invalid")
    return value


def _identifier(value: object, label: str) -> str:
    if type(value) is not str or _IDENTIFIER_RE.fullmatch(value) is None:
        raise FleetPromotionError(f"{label} is invalid")
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
        raise FleetPromotionError("promotion document is not canonical JSON") from error


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


@dataclass(frozen=True, slots=True)
class FleetPromotionScopeRef:
    kind: str
    scope_id: str

    def __post_init__(self) -> None:
        if self.kind not in _SCOPE_KINDS:
            raise FleetPromotionError("promotion scope kind is invalid")
        if self.kind == "principal":
            _hash(self.scope_id, "promotion principal scope")
        else:
            _identifier(self.scope_id, "promotion scope id")

    @classmethod
    def from_request(cls, value: object) -> "FleetPromotionScopeRef":
        if type(value) is not dict or set(value) != {"kind", "scope_id"}:
            raise FleetPromotionError("promotion scope has an invalid shape")
        document = cast(dict[str, Any], value)
        return cls(kind=cast(str, document["kind"]), scope_id=cast(str, document["scope_id"]))

    def to_request(self) -> dict[str, str]:
        return {"kind": self.kind, "scope_id": self.scope_id}


@dataclass(frozen=True, slots=True)
class FleetPromotionAdministrator:
    principal_id: str
    kind: str
    generation: int
    binding_hash: str

    def __post_init__(self) -> None:
        _hash(self.principal_id, "promotion administrator principal")
        _hash(self.binding_hash, "promotion administrator binding")
        if self.kind not in _PRINCIPAL_KINDS:
            raise FleetPromotionError("promotion administrator kind is invalid")
        if isinstance(self.generation, bool) or type(self.generation) is not int or self.generation < 1:
            raise FleetPromotionError("promotion administrator generation is invalid")

    @classmethod
    def from_request(cls, value: object) -> "FleetPromotionAdministrator":
        if type(value) is not dict or set(value) != {
            "principal_id",
            "kind",
            "generation",
            "binding_hash",
        }:
            raise FleetPromotionError("promotion administrator has an invalid shape")
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
class FleetPromotionAuthorization:
    subject_kind: str
    subject_key: str
    source_owner_principal_id: str
    agent_instance_id: str
    source_scope: FleetPromotionScopeRef
    target_scope: FleetPromotionScopeRef
    source_content_hash: str
    approved_content_hash: str
    administrator: FleetPromotionAdministrator
    issued_at_ms: int
    expires_at_ms: int
    verification_digest: str | None
    expected_current_promotion_id: str | None
    rollback_to_promotion_id: str | None
    operation: str
    promotion_id: str
    policy_version: str = PROMOTION_POLICY_VERSION
    version: str = PROMOTION_VERSION

    def __post_init__(self) -> None:
        if self.version != PROMOTION_VERSION or self.policy_version != PROMOTION_POLICY_VERSION:
            raise FleetPromotionError("promotion version is unsupported")
        if self.subject_kind not in _SUBJECT_KINDS:
            raise FleetPromotionError("promotion subject kind is invalid")
        _identifier(self.subject_key, "promotion subject key")
        if self.operation not in {"promote", "rollback"}:
            raise FleetPromotionError("promotion operation is invalid")
        if self.expected_current_promotion_id is not None:
            _hash(self.expected_current_promotion_id, "expected current promotion ID")
        if self.operation == "rollback":
            _hash(self.rollback_to_promotion_id, "rollback promotion ID")
            if self.expected_current_promotion_id is None:
                raise FleetPromotionError("rollback requires the exact current promotion ID")
            if self.rollback_to_promotion_id == self.expected_current_promotion_id:
                raise FleetPromotionError("rollback target is already current")
        elif self.rollback_to_promotion_id is not None:
            raise FleetPromotionError("normal promotion cannot carry a rollback target")
        _hash(self.source_owner_principal_id, "promotion source owner principal")
        _hash(self.agent_instance_id, "promotion Agent Instance")
        _hash(self.source_content_hash, "promotion source content hash")
        _hash(self.approved_content_hash, "promotion approved content hash")
        _hash(self.promotion_id, "promotion ID")
        if self.source_scope.kind == "principal" and (
            self.source_scope.scope_id != self.source_owner_principal_id
        ):
            raise FleetPromotionError("promotion private source scope does not match its owner")
        if _SCOPE_RANK[self.target_scope.kind] <= _SCOPE_RANK[self.source_scope.kind]:
            raise FleetPromotionError("promotion target must be broader than the source scope")
        # Independent defense: Fleet's administrator proof must at minimum be a
        # principal of the same scope kind being widened. Fleet remains owner of
        # the full principal/scope policy decision.
        if self.administrator.kind != self.target_scope.kind:
            raise FleetPromotionError("promotion administrator kind does not match target scope")
        for value, label in ((self.issued_at_ms, "issue time"), (self.expires_at_ms, "expiry")):
            if isinstance(value, bool) or type(value) is not int or value < 1:
                raise FleetPromotionError(f"promotion {label} is invalid")
        if not self.issued_at_ms < self.expires_at_ms <= self.issued_at_ms + _MAX_TTL_MS:
            raise FleetPromotionError("promotion lifetime is invalid")
        if self.subject_kind == "skill":
            _hash(self.verification_digest, "promotion skill verification digest")
        elif self.verification_digest is not None:
            raise FleetPromotionError("memory promotion cannot carry skill verification evidence")
        if self.promotion_id != _digest(self.unsigned_document()):
            raise FleetPromotionError("promotion ID does not match the exact authorization")

    def unsigned_document(self) -> dict[str, object]:
        return {
            "version": self.version,
            "policy_version": self.policy_version,
            "subject_kind": self.subject_kind,
            "subject_key": self.subject_key,
            "source_owner_principal_id": self.source_owner_principal_id,
            "agent_instance_id": self.agent_instance_id,
            "source_scope": self.source_scope.to_request(),
            "target_scope": self.target_scope.to_request(),
            "source_content_hash": self.source_content_hash,
            "approved_content_hash": self.approved_content_hash,
            "administrator": self.administrator.to_request(),
            "issued_at_ms": self.issued_at_ms,
            "expires_at_ms": self.expires_at_ms,
            "verification_digest": self.verification_digest,
            "expected_current_promotion_id": self.expected_current_promotion_id,
            "rollback_to_promotion_id": self.rollback_to_promotion_id,
            "operation": self.operation,
            "authority": "none",
        }

    @classmethod
    def from_request(
        cls,
        value: object,
        *,
        now_ms: int | None = None,
    ) -> "FleetPromotionAuthorization":
        expected = {
            "version",
            "policy_version",
            "subject_kind",
            "subject_key",
            "source_owner_principal_id",
            "agent_instance_id",
            "source_scope",
            "target_scope",
            "source_content_hash",
            "approved_content_hash",
            "administrator",
            "issued_at_ms",
            "expires_at_ms",
            "verification_digest",
            "expected_current_promotion_id",
            "rollback_to_promotion_id",
            "operation",
            "authority",
            "promotion_id",
        }
        if type(value) is not dict or set(value) != expected:
            raise FleetPromotionError("promotion authorization has an invalid shape")
        document = cast(dict[str, Any], value)
        if document["authority"] != "none":
            raise FleetPromotionError("promotion cannot carry execution authority")
        authorization = cls(
            version=cast(str, document["version"]),
            policy_version=cast(str, document["policy_version"]),
            subject_kind=cast(str, document["subject_kind"]),
            subject_key=cast(str, document["subject_key"]),
            source_owner_principal_id=cast(str, document["source_owner_principal_id"]),
            agent_instance_id=cast(str, document["agent_instance_id"]),
            source_scope=FleetPromotionScopeRef.from_request(document["source_scope"]),
            target_scope=FleetPromotionScopeRef.from_request(document["target_scope"]),
            source_content_hash=cast(str, document["source_content_hash"]),
            approved_content_hash=cast(str, document["approved_content_hash"]),
            administrator=FleetPromotionAdministrator.from_request(document["administrator"]),
            issued_at_ms=cast(int, document["issued_at_ms"]),
            expires_at_ms=cast(int, document["expires_at_ms"]),
            verification_digest=cast(str | None, document["verification_digest"]),
            expected_current_promotion_id=cast(str | None, document["expected_current_promotion_id"]),
            rollback_to_promotion_id=cast(str | None, document["rollback_to_promotion_id"]),
            operation=cast(str, document["operation"]),
            promotion_id=cast(str, document["promotion_id"]),
        )
        current = int(time.time() * 1000) if now_ms is None else now_ms
        if isinstance(current, bool) or type(current) is not int or current < authorization.issued_at_ms:
            raise FleetPromotionError("promotion clock is invalid")
        if current >= authorization.expires_at_ms:
            raise FleetPromotionError("promotion authorization has expired")
        return authorization


__all__ = [
    "FleetPromotionAdministrator",
    "FleetPromotionAuthorization",
    "FleetPromotionError",
    "FleetPromotionScopeRef",
    "PROMOTION_POLICY_VERSION",
    "PROMOTION_VERSION",
]
