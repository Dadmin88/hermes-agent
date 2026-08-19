from __future__ import annotations

import re
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Iterator, cast

_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,511}$")
_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_PRINCIPAL_KINDS = frozenset({"owner", "project", "network", "device", "service"})
_NETWORK_MODES = frozenset(
    {"none", "provider-only", "project-allowlist", "explicitly-approved-internet"}
)
_FS_MODES = frozenset({"read-only", "read-write"})
_MAX_ITEMS = 64


class FleetSkillLearningScopeError(RuntimeError):
    """Run-scoped Fleet skill-learning authorization is malformed."""


def _identifier(value: object, label: str) -> str:
    if type(value) is not str or _IDENTIFIER_RE.fullmatch(value) is None:
        raise FleetSkillLearningScopeError(f"{label} is invalid")
    return value


def _hash(value: object, label: str) -> str:
    if type(value) is not str or _HASH_RE.fullmatch(value) is None:
        raise FleetSkillLearningScopeError(f"{label} is invalid")
    return value


@dataclass(frozen=True, slots=True)
class FleetSkillFilesystemNeed:
    project_id: str
    relative_path: str
    target: str
    mode: str
    max_bytes: int

    def __post_init__(self) -> None:
        _identifier(self.project_id, "skill-learning filesystem project")
        if (
            type(self.relative_path) is not str
            or not self.relative_path
            or self.relative_path.startswith("/")
            or ".." in self.relative_path.split("/")
            or len(self.relative_path) > 1024
        ):
            raise FleetSkillLearningScopeError(
                "skill-learning filesystem relative path is invalid"
            )
        if (
            type(self.target) is not str
            or not self.target.startswith("/workspace/")
            or ".." in self.target.split("/")
            or len(self.target) > 1024
        ):
            raise FleetSkillLearningScopeError(
                "skill-learning filesystem target is invalid"
            )
        if type(self.mode) is not str or self.mode not in _FS_MODES:
            raise FleetSkillLearningScopeError("skill-learning filesystem mode is invalid")
        if (
            isinstance(self.max_bytes, bool)
            or type(self.max_bytes) is not int
            or not 0 < self.max_bytes <= 1 << 40
        ):
            raise FleetSkillLearningScopeError(
                "skill-learning filesystem byte bound is invalid"
            )

    @classmethod
    def from_request(cls, value: object) -> "FleetSkillFilesystemNeed":
        if type(value) is not dict or set(value) != {
            "project_id",
            "relative_path",
            "target",
            "mode",
            "max_bytes",
        }:
            raise FleetSkillLearningScopeError(
                "skill-learning filesystem need has an invalid shape"
            )
        document = cast(dict[str, Any], value)
        return cls(
            project_id=cast(str, document["project_id"]),
            relative_path=cast(str, document["relative_path"]),
            target=cast(str, document["target"]),
            mode=cast(str, document["mode"]),
            max_bytes=cast(int, document["max_bytes"]),
        )

    def to_request(self) -> dict[str, object]:
        return {
            "project_id": self.project_id,
            "relative_path": self.relative_path,
            "target": self.target,
            "mode": self.mode,
            "max_bytes": self.max_bytes,
        }


@dataclass(frozen=True, slots=True)
class FleetSkillLearningBinding:
    principal_id: str
    principal_kind: str
    principal_generation: int
    principal_binding_hash: str
    agent_instance_id: str
    source_run: str
    scope_kind: str
    scope_id: str
    run_authority_hash: str
    recipe_hash: str
    resolved_recipe_hash: str
    plan_fingerprint: str
    capabilities_hash: str
    target_digest: str
    toolsets: tuple[str, ...]
    filesystem_needs: tuple[FleetSkillFilesystemNeed, ...]
    network_mode: str
    network_policy_hash: str
    secret_need_fingerprints: tuple[str, ...]
    version: str = "fleet-skill-learning-v1"

    def __post_init__(self) -> None:
        if self.version != "fleet-skill-learning-v1":
            raise FleetSkillLearningScopeError(
                "Fleet skill-learning binding version is unsupported"
            )
        for value, label in (
            (self.principal_id, "principal ID"),
            (self.principal_binding_hash, "principal binding hash"),
            (self.agent_instance_id, "Agent Instance ID"),
            (self.run_authority_hash, "RunAuthority hash"),
            (self.recipe_hash, "Recipe hash"),
            (self.resolved_recipe_hash, "ResolvedRecipe hash"),
            (self.plan_fingerprint, "plan fingerprint"),
            (self.capabilities_hash, "capabilities hash"),
            (self.target_digest, "target digest"),
            (self.network_policy_hash, "network policy hash"),
        ):
            _hash(value, f"Fleet skill-learning {label}")
        _identifier(self.source_run, "Fleet skill-learning source run")
        if type(self.principal_kind) is not str or self.principal_kind not in _PRINCIPAL_KINDS:
            raise FleetSkillLearningScopeError(
                "Fleet skill-learning principal kind is invalid"
            )
        if (
            isinstance(self.principal_generation, bool)
            or type(self.principal_generation) is not int
            or self.principal_generation < 1
        ):
            raise FleetSkillLearningScopeError(
                "Fleet skill-learning principal generation is invalid"
            )
        if self.scope_kind != "principal" or self.scope_id != self.principal_id:
            raise FleetSkillLearningScopeError(
                "Phase 15 skill-learning scope must be principal-private"
            )
        toolsets = tuple(self.toolsets)
        if (
            len(toolsets) > _MAX_ITEMS
            or any(
                type(item) is not str or _IDENTIFIER_RE.fullmatch(item) is None
                for item in toolsets
            )
            or len(toolsets) != len(set(toolsets))
        ):
            raise FleetSkillLearningScopeError("Fleet skill-learning toolsets are invalid")
        object.__setattr__(self, "toolsets", tuple(sorted(toolsets)))
        filesystem = tuple(self.filesystem_needs)
        if (
            len(filesystem) > _MAX_ITEMS
            or any(type(item) is not FleetSkillFilesystemNeed for item in filesystem)
        ):
            raise FleetSkillLearningScopeError(
                "Fleet skill-learning filesystem needs are invalid"
            )
        object.__setattr__(
            self,
            "filesystem_needs",
            tuple(
                sorted(
                    filesystem,
                    key=lambda item: (
                        item.project_id,
                        item.relative_path,
                        item.target,
                        item.mode,
                        item.max_bytes,
                    ),
                )
            ),
        )
        if type(self.network_mode) is not str or self.network_mode not in _NETWORK_MODES:
            raise FleetSkillLearningScopeError(
                "Fleet skill-learning network mode is invalid"
            )
        fingerprints = tuple(self.secret_need_fingerprints)
        if (
            len(fingerprints) > _MAX_ITEMS
            or any(
                type(item) is not str or _HASH_RE.fullmatch(item) is None
                for item in fingerprints
            )
            or len(fingerprints) != len(set(fingerprints))
        ):
            raise FleetSkillLearningScopeError(
                "Fleet skill-learning secret-need fingerprints are invalid"
            )
        object.__setattr__(self, "secret_need_fingerprints", tuple(sorted(fingerprints)))

    @classmethod
    def from_request(cls, value: object) -> "FleetSkillLearningBinding":
        if type(value) is not dict or set(value) != {
            "version",
            "principal",
            "agent_instance_id",
            "source_run",
            "scope",
            "run_authority_hash",
            "provenance",
            "needs",
        }:
            raise FleetSkillLearningScopeError(
                "Fleet skill-learning binding has an invalid shape"
            )
        document = cast(dict[str, Any], value)
        principal_value = document["principal"]
        scope_value = document["scope"]
        provenance_value = document["provenance"]
        needs_value = document["needs"]
        if type(principal_value) is not dict or set(principal_value) != {
            "principal_id",
            "kind",
            "generation",
            "binding_hash",
        }:
            raise FleetSkillLearningScopeError(
                "Fleet skill-learning principal has an invalid shape"
            )
        if type(scope_value) is not dict or set(scope_value) != {"kind", "scope_id"}:
            raise FleetSkillLearningScopeError(
                "Fleet skill-learning scope has an invalid shape"
            )
        if type(provenance_value) is not dict or set(provenance_value) != {
            "recipe_hash",
            "resolved_recipe_hash",
            "plan_fingerprint",
            "capabilities_hash",
            "target_digest",
        }:
            raise FleetSkillLearningScopeError(
                "Fleet skill-learning provenance has an invalid shape"
            )
        if type(needs_value) is not dict or set(needs_value) != {
            "tools",
            "filesystem",
            "network",
            "secret_fingerprints",
        }:
            raise FleetSkillLearningScopeError(
                "Fleet skill-learning needs have an invalid shape"
            )
        principal = cast(dict[str, Any], principal_value)
        scope = cast(dict[str, Any], scope_value)
        provenance = cast(dict[str, Any], provenance_value)
        needs = cast(dict[str, Any], needs_value)
        network_value = needs["network"]
        if type(network_value) is not dict or set(network_value) != {"mode", "policy_hash"}:
            raise FleetSkillLearningScopeError(
                "Fleet skill-learning network need has an invalid shape"
            )
        network = cast(dict[str, Any], network_value)
        raw_tools = needs["tools"]
        raw_filesystem = needs["filesystem"]
        raw_secret_fingerprints = needs["secret_fingerprints"]
        if type(raw_tools) is not list or type(raw_filesystem) is not list or type(
            raw_secret_fingerprints
        ) is not list:
            raise FleetSkillLearningScopeError(
                "Fleet skill-learning needs collections are invalid"
            )
        return cls(
            version=cast(str, document["version"]),
            principal_id=cast(str, principal["principal_id"]),
            principal_kind=cast(str, principal["kind"]),
            principal_generation=cast(int, principal["generation"]),
            principal_binding_hash=cast(str, principal["binding_hash"]),
            agent_instance_id=cast(str, document["agent_instance_id"]),
            source_run=cast(str, document["source_run"]),
            scope_kind=cast(str, scope["kind"]),
            scope_id=cast(str, scope["scope_id"]),
            run_authority_hash=cast(str, document["run_authority_hash"]),
            recipe_hash=cast(str, provenance["recipe_hash"]),
            resolved_recipe_hash=cast(str, provenance["resolved_recipe_hash"]),
            plan_fingerprint=cast(str, provenance["plan_fingerprint"]),
            capabilities_hash=cast(str, provenance["capabilities_hash"]),
            target_digest=cast(str, provenance["target_digest"]),
            toolsets=tuple(cast(list[str], raw_tools)),
            filesystem_needs=tuple(
                FleetSkillFilesystemNeed.from_request(item)
                for item in cast(list[object], raw_filesystem)
            ),
            network_mode=cast(str, network["mode"]),
            network_policy_hash=cast(str, network["policy_hash"]),
            secret_need_fingerprints=tuple(
                cast(list[str], raw_secret_fingerprints)
            ),
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
            "scope": {"kind": self.scope_kind, "scope_id": self.scope_id},
            "run_authority_hash": self.run_authority_hash,
            "provenance": {
                "recipe_hash": self.recipe_hash,
                "resolved_recipe_hash": self.resolved_recipe_hash,
                "plan_fingerprint": self.plan_fingerprint,
                "capabilities_hash": self.capabilities_hash,
                "target_digest": self.target_digest,
            },
            "needs": {
                "tools": list(self.toolsets),
                "filesystem": [item.to_request() for item in self.filesystem_needs],
                "network": {
                    "mode": self.network_mode,
                    "policy_hash": self.network_policy_hash,
                },
                "secret_fingerprints": list(self.secret_need_fingerprints),
            },
        }


_FLEET_SKILL_LEARNING: ContextVar[FleetSkillLearningBinding | None] = ContextVar(
    "fleet_skill_learning", default=None
)


@contextmanager
def fleet_skill_learning_scope(
    binding: FleetSkillLearningBinding | None,
) -> Iterator[None]:
    token = _FLEET_SKILL_LEARNING.set(binding)
    try:
        yield
    finally:
        _FLEET_SKILL_LEARNING.reset(token)


def get_fleet_skill_learning() -> FleetSkillLearningBinding | None:
    return _FLEET_SKILL_LEARNING.get()


__all__ = [
    "FleetSkillFilesystemNeed",
    "FleetSkillLearningBinding",
    "FleetSkillLearningScopeError",
    "fleet_skill_learning_scope",
    "get_fleet_skill_learning",
]
