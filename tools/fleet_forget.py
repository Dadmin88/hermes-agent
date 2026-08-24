"""Phase 25 irreversible deletion of Fleet-managed Hermes learning derivatives."""

from __future__ import annotations

import json
import os
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from agent.fleet_forget import FleetForgetAuthorization
from agent.fleet_memory_scope import FleetMemoryScopeRef, FleetMemoryScopeError
from hermes_constants import get_hermes_home
from tools.fleet_base_overlay import _report_root
from tools.fleet_promotion import (
    FleetPromotionMutationError,
    _promotion_lock,
    _promotion_root,
    _read_json,
    _record_path,
    _skill_version_dir,
    _write_memory_metadata,
)
from tools.fleet_skill_candidates import (
    FleetSkillCandidateError,
    _candidate_root,
    _load_existing_metadata,
)
from tools.memory_tool import (
    FLEET_MEMORY_SCOPE_SCHEMA,
    MemoryStore,
    get_fleet_memory_root,
)
from utils import atomic_write_text

_FORGET_SCHEMA = "fleet.forget-result.v1"
_TOMBSTONE_SCHEMA = "fleet.forget-tombstone.v1"
_MAX_PROMOTION_RECORDS = 4096
_MAX_SCOPE_DIRECTORIES = 4096


class FleetForgetMutationError(RuntimeError):
    """Hermes cannot prove an irreversible Fleet deletion is complete."""


@dataclass(frozen=True, slots=True)
class FleetForgetResult:
    forget_id: str
    subject_kind: str
    memory_entries: int = 0
    promotion_records: int = 0
    promotion_states: int = 0
    skill_bundles: int = 0
    skill_candidate: bool = False
    base_overlay_reports: int = 0
    idempotent: bool = False

    def to_document(self) -> dict[str, object]:
        return {
            "schema": _FORGET_SCHEMA,
            "forget_id": self.forget_id,
            "subject_kind": self.subject_kind,
            "deleted": {
                "memory_entries": self.memory_entries,
                "promotion_records": self.promotion_records,
                "promotion_states": self.promotion_states,
                "skill_bundles": self.skill_bundles,
                "skill_candidate": self.skill_candidate,
                "base_overlay_reports": self.base_overlay_reports,
            },
            "idempotent": self.idempotent,
            "authority": "none",
        }


def _private_directory(path: Path, *, create: bool = False) -> Path:
    if create:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not path.exists():
        raise FleetForgetMutationError("forget state directory is unavailable")
    try:
        info = path.lstat()
    except OSError as error:
        raise FleetForgetMutationError(
            "forget state directory is unavailable"
        ) from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise FleetForgetMutationError("forget state directory is unsafe")
    if os.name != "nt":
        path.chmod(0o700)
    return path


def _tombstone_root() -> Path:
    return _private_directory(get_hermes_home() / ".fleet" / "forget-v1", create=True)


def _tombstone_path(forget_id: str) -> Path:
    return _tombstone_root() / f"{forget_id.removeprefix('sha256:')}.json"


def _read_tombstone(
    authorization: FleetForgetAuthorization,
) -> FleetForgetResult | None:
    path = _tombstone_path(authorization.forget_id)
    if not path.exists():
        return None
    try:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise FleetForgetMutationError("forget tombstone is unsafe")
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise FleetForgetMutationError("forget tombstone is unreadable") from error
    if (
        type(document) is not dict
        or document.get("schema") != _TOMBSTONE_SCHEMA
        or document.get("forget_id") != authorization.forget_id
        or document.get("subject_kind") != authorization.subject_kind
        or document.get("subject_key") != authorization.subject_key
        or document.get("source_owner_principal_id")
        != authorization.source_owner_principal_id
        or document.get("agent_instance_id") != authorization.agent_instance_id
        or document.get("authority") != "none"
    ):
        raise FleetForgetMutationError("forget tombstone identity changed")
    deleted = document.get("deleted")
    expected_deleted = {
        "memory_entries",
        "promotion_records",
        "promotion_states",
        "skill_bundles",
        "skill_candidate",
        "base_overlay_reports",
    }
    if type(deleted) is not dict or set(deleted) != expected_deleted:
        raise FleetForgetMutationError("forget tombstone counters are invalid")
    integer_fields = expected_deleted - {"skill_candidate"}
    for field in integer_fields:
        value = deleted[field]
        if isinstance(value, bool) or type(value) is not int or value < 0:
            raise FleetForgetMutationError("forget tombstone counters are invalid")
    if type(deleted["skill_candidate"]) is not bool:
        raise FleetForgetMutationError("forget tombstone counters are invalid")
    return FleetForgetResult(
        forget_id=authorization.forget_id,
        subject_kind=authorization.subject_kind,
        memory_entries=deleted["memory_entries"],
        promotion_records=deleted["promotion_records"],
        promotion_states=deleted["promotion_states"],
        skill_bundles=deleted["skill_bundles"],
        skill_candidate=deleted["skill_candidate"],
        base_overlay_reports=deleted["base_overlay_reports"],
        idempotent=True,
    )


def _write_tombstone(
    authorization: FleetForgetAuthorization, result: FleetForgetResult
) -> None:
    document = {
        "schema": _TOMBSTONE_SCHEMA,
        "forget_id": authorization.forget_id,
        "subject_kind": authorization.subject_kind,
        "subject_key": authorization.subject_key,
        "source_owner_principal_id": authorization.source_owner_principal_id,
        "agent_instance_id": authorization.agent_instance_id,
        "deleted": result.to_document()["deleted"],
        "authority": "none",
    }
    path = _tombstone_path(authorization.forget_id)
    atomic_write_text(
        path,
        json.dumps(
            document,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
    )
    if os.name != "nt":
        path.chmod(0o600)


def _promotion_records() -> dict[str, dict[str, Any]]:
    root = _promotion_root() / "records"
    if not root.exists():
        return {}
    _private_directory(root)
    paths = sorted(root.glob("*.json"))
    if len(paths) > _MAX_PROMOTION_RECORDS:
        raise FleetForgetMutationError("promotion record count exceeds forget bound")
    result: dict[str, dict[str, Any]] = {}
    for path in paths:
        record = _read_json(path)
        if record is None:
            continue
        promotion_id = record.get("promotion_id")
        if type(promotion_id) is not str or _record_path(promotion_id) != path:
            raise FleetForgetMutationError("promotion record identity is invalid")
        result[promotion_id] = record
    return result


def _record_identity_matches(
    record: Mapping[str, Any], authorization: FleetForgetAuthorization
) -> bool:
    auth = record.get("authorization")
    if type(auth) is not dict:
        raise FleetForgetMutationError("promotion record authorization is malformed")
    return (
        auth.get("subject_kind") == authorization.subject_kind
        and auth.get("source_owner_principal_id")
        == authorization.source_owner_principal_id
        and auth.get("agent_instance_id") == authorization.agent_instance_id
    )


def _promotion_graph(
    authorization: FleetForgetAuthorization,
) -> tuple[set[str], set[str], dict[str, dict[str, Any]]]:
    records = _promotion_records()
    selected: set[str] = set()
    content_hashes: set[str] = set()
    if authorization.subject_kind == "memory":
        _target, initial_hash = authorization.subject_key.split(":", 1)
        content_hashes.add(initial_hash)
        changed = True
        while changed:
            changed = False
            for promotion_id, record in records.items():
                if promotion_id in selected or not _record_identity_matches(
                    record, authorization
                ):
                    continue
                source_hash = record.get("source_content_hash")
                approved_hash = record.get("approved_content_hash")
                if type(source_hash) is not str or type(approved_hash) is not str:
                    raise FleetForgetMutationError(
                        "memory promotion record hashes are malformed"
                    )
                if (
                    source_hash not in content_hashes
                    and approved_hash not in content_hashes
                ):
                    continue
                selected.add(promotion_id)
                before = len(content_hashes)
                content_hashes.update((source_hash, approved_hash))
                changed = changed or len(content_hashes) != before
    else:
        for promotion_id, record in records.items():
            if not _record_identity_matches(record, authorization):
                continue
            record_auth = record["authorization"]
            if record_auth.get("subject_key") == authorization.subject_key:
                selected.add(promotion_id)
    return selected, content_hashes, records


def _matching_subject_states(
    authorization: FleetForgetAuthorization,
    promotion_ids: set[str],
) -> list[Path]:
    root = _promotion_root() / "subjects"
    if not root.exists():
        return []
    _private_directory(root)
    result: list[Path] = []
    for path in sorted(root.glob("*.json")):
        state = _read_json(path)
        if state is None:
            continue
        if (
            state.get("subject_kind") != authorization.subject_kind
            or state.get("source_owner_principal_id")
            != authorization.source_owner_principal_id
            or state.get("agent_instance_id") != authorization.agent_instance_id
        ):
            continue
        history = state.get("history")
        current = state.get("current_promotion_id")
        if type(history) is not list or any(type(item) is not str for item in history):
            raise FleetForgetMutationError("promotion subject history is malformed")
        state_ids = set(history)
        if type(current) is str:
            state_ids.add(current)
        elif current is not None:
            raise FleetForgetMutationError("promotion subject current ID is malformed")
        if state_ids & promotion_ids:
            result.append(path)
    return result


def _enumerate_memory_scopes() -> list[FleetMemoryScopeRef]:
    root = get_fleet_memory_root()
    if not root.exists():
        return []
    MemoryStore._require_private_directory(root)
    directories: list[Path] = []
    for kind_dir in sorted(root.iterdir()):
        if kind_dir.name.startswith("."):
            continue
        if kind_dir.is_symlink() or not kind_dir.is_dir():
            raise FleetForgetMutationError("Fleet memory scope root is unsafe")
        directories.extend(
            path
            for path in sorted(kind_dir.iterdir())
            if path.is_dir() or path.is_symlink()
        )
    if len(directories) > _MAX_SCOPE_DIRECTORIES:
        raise FleetForgetMutationError("Fleet memory scope count exceeds forget bound")
    scopes: list[FleetMemoryScopeRef] = []
    for directory in directories:
        if directory.is_symlink() or not directory.is_dir():
            raise FleetForgetMutationError("Fleet memory scope directory is unsafe")
        descriptor = directory / "SCOPE.json"
        if not MemoryStore._require_private_file(descriptor, allow_missing=False):
            raise FleetForgetMutationError(
                "Fleet memory scope descriptor is unavailable"
            )
        try:
            document = json.loads(descriptor.read_text(encoding="utf-8"))
            if (
                type(document) is not dict
                or set(document) != {"schema", "scope"}
                or document.get("schema") != FLEET_MEMORY_SCOPE_SCHEMA
            ):
                raise FleetForgetMutationError(
                    "Fleet memory scope descriptor is malformed"
                )
            scope = FleetMemoryScopeRef.from_request(document["scope"])
        except (
            OSError,
            UnicodeError,
            json.JSONDecodeError,
            FleetMemoryScopeError,
        ) as error:
            raise FleetForgetMutationError(
                "Fleet memory scope descriptor is malformed"
            ) from error
        if directory.name != scope.storage_key:
            raise FleetForgetMutationError(
                "Fleet memory scope storage identity changed"
            )
        scopes.append(scope)
    return scopes


def _forget_memory_entries(
    authorization: FleetForgetAuthorization,
    content_hashes: set[str],
) -> int:
    target, _source_hash = authorization.subject_key.split(":", 1)
    store = MemoryStore(memory_char_limit=64 * 1024, user_char_limit=64 * 1024)
    deleted = 0
    for scope in _enumerate_memory_scopes():
        scope_dir = store._scope_dir(scope)
        path = scope_dir / store._target_filename(target)
        metadata_path = store._metadata_path(target, scope)
        if not path.exists() and not metadata_path.exists():
            continue
        with store._file_lock(path):
            entries = (
                store._read_file(path) if store._require_private_file(path) else []
            )
            metadata = store._read_fleet_metadata(target, scope)
            entry_by_hash = {store._entry_hash(entry): entry for entry in entries}
            changed = False
            for content_hash in sorted(content_hashes):
                entry = entry_by_hash.get(content_hash)
                item = metadata.get(content_hash)
                if (entry is None) != (item is None):
                    raise FleetForgetMutationError(
                        "Fleet memory content/metadata drift blocks forget"
                    )
                if item is None:
                    continue
                if (
                    item.get("owner_principal_id")
                    != authorization.source_owner_principal_id
                    or item.get("agent_instance_id") != authorization.agent_instance_id
                ):
                    continue
                entries.remove(entry)
                metadata.pop(content_hash)
                deleted += 1
                changed = True
            if changed:
                store._write_file(path, entries)
                if path.exists():
                    store._require_private_file(path, allow_missing=False)
                _write_memory_metadata(
                    store, target=target, scope=scope, metadata=metadata
                )
    return deleted


def _forget_skill_candidate(authorization: FleetForgetAuthorization) -> bool:
    candidate = _candidate_root() / authorization.subject_key.removeprefix("sha256:")
    if not candidate.exists() and not candidate.is_symlink():
        return False
    if candidate.is_symlink() or not candidate.is_dir():
        raise FleetForgetMutationError("skill candidate path is unsafe")
    try:
        metadata = _load_existing_metadata(candidate)
    except FleetSkillCandidateError as error:
        raise FleetForgetMutationError(
            "skill candidate metadata is unavailable"
        ) from error
    if metadata is None:
        raise FleetForgetMutationError("skill candidate metadata is unavailable")
    principal = metadata.get("principal")
    if (
        metadata.get("candidate_id") != authorization.subject_key
        or type(principal) is not dict
        or principal.get("principal_id") != authorization.source_owner_principal_id
        or metadata.get("agent_instance_id") != authorization.agent_instance_id
    ):
        raise FleetForgetMutationError(
            "skill candidate identity does not match forget authorization"
        )
    shutil.rmtree(candidate)
    return True


def _forget_skill_bundles(promotion_ids: set[str]) -> int:
    deleted = 0
    for promotion_id in sorted(promotion_ids):
        bundle = _skill_version_dir(promotion_id)
        version_dir = bundle.parent
        if not version_dir.exists() and not version_dir.is_symlink():
            continue
        if version_dir.is_symlink() or not version_dir.is_dir():
            raise FleetForgetMutationError("promoted skill version path is unsafe")
        shutil.rmtree(version_dir)
        deleted += 1
    return deleted


def _purge_base_overlay_reports(agent_instance_id: str) -> int:
    root = _report_root()
    directory = root / agent_instance_id.removeprefix("sha256:")
    if not directory.exists() and not directory.is_symlink():
        return 0
    if directory.is_symlink() or not directory.is_dir():
        raise FleetForgetMutationError("base overlay report directory is unsafe")
    count = sum(
        1 for path in directory.iterdir() if path.is_file() and not path.is_symlink()
    )
    shutil.rmtree(directory)
    return count


def forget_fleet_learning(authorization: FleetForgetAuthorization) -> FleetForgetResult:
    """Irreversibly erase one Fleet learning identity and its Hermes derivatives."""
    if type(authorization) is not FleetForgetAuthorization:
        raise FleetForgetMutationError("forget authorization is invalid")
    existing = _read_tombstone(authorization)
    if existing is not None:
        return existing

    with _promotion_lock():
        promotion_ids, content_hashes, records = _promotion_graph(authorization)
        state_paths = _matching_subject_states(authorization, promotion_ids)

        memory_entries = 0
        skill_candidate = False
        skill_bundles = 0
        base_overlay_reports = 0
        if authorization.subject_kind == "memory":
            memory_entries = _forget_memory_entries(authorization, content_hashes)
        else:
            skill_candidate = _forget_skill_candidate(authorization)
            skill_bundles = _forget_skill_bundles(promotion_ids)
            base_overlay_reports = _purge_base_overlay_reports(
                authorization.agent_instance_id
            )

        for promotion_id in sorted(promotion_ids):
            path = _record_path(promotion_id)
            if promotion_id not in records or not path.exists():
                raise FleetForgetMutationError(
                    "promotion record disappeared during forget"
                )
            path.unlink()
        for path in state_paths:
            path.unlink()

        if authorization.subject_kind == "skill":
            try:
                from agent.prompt_builder import clear_skills_system_prompt_cache
                from tools import skills_tool

                clear_skills_system_prompt_cache(clear_snapshot=True)
                skills_tool._SKILLS_CACHE.clear()
            except Exception as error:
                raise FleetForgetMutationError(
                    "skill retrieval caches could not be cleared"
                ) from error

        result = FleetForgetResult(
            forget_id=authorization.forget_id,
            subject_kind=authorization.subject_kind,
            memory_entries=memory_entries,
            promotion_records=len(promotion_ids),
            promotion_states=len(state_paths),
            skill_bundles=skill_bundles,
            skill_candidate=skill_candidate,
            base_overlay_reports=base_overlay_reports,
        )
        _write_tombstone(authorization, result)
        return result


__all__ = [
    "FleetForgetMutationError",
    "FleetForgetResult",
    "forget_fleet_learning",
]
