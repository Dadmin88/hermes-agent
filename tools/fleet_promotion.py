"""Phase 18 prepare/commit primitives for promoted Fleet learning.

Preparation is non-mutating: Hermes re-reads the exact private source,
re-verifies skills, strips secrets/private identifiers from text, and returns
the exact sanitized hash that Fleet must approve. Commit is implemented below
against the same exact source and approved hash so a changed source cannot be
promoted under a stale decision.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Mapping

from agent.fleet_memory_scope import FleetMemoryScopeRef
from agent.fleet_promotion import (
    FleetPromotionAuthorization,
    FleetPromotionError,
    FleetPromotionScopeRef,
)
from agent.fleet_skill_learning_scope import (
    FleetSkillFilesystemNeed,
    FleetSkillLearningBinding,
)
from agent.monitoring.redaction import redact_for_export
from hermes_constants import get_hermes_home
from utils import atomic_write_text
from tools.fleet_skill_candidates import (
    FleetSkillCandidateError,
    _bundle_manifest,
    _candidate_root,
    _load_existing_metadata,
)
from tools.fleet_skill_verification import (
    FleetSkillVerificationError,
    verify_skill_candidate,
)
from tools.memory_tool import MemoryStore

_MAX_SKILL_FILES = 128
_MAX_SKILL_BYTES = 2 * 1024 * 1024


class FleetPromotionMutationError(RuntimeError):
    """A Phase 18 prepare/commit operation cannot be proven safe."""


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
        raise FleetPromotionMutationError("promotion material is not canonical JSON") from error


def _sha256(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _sanitize_text(value: str) -> tuple[str, bool]:
    sanitized = redact_for_export(value)
    if sanitized is None or "[redaction-unavailable]" in sanitized:
        raise FleetPromotionMutationError("promotion sanitizer is unavailable")
    return sanitized, sanitized != value


@dataclass(frozen=True, slots=True)
class PreparedPromotion:
    subject_kind: str
    subject_key: str
    source_content_hash: str
    approved_content_hash: str
    sanitized: bool
    verification_digest: str | None = None

    def to_document(self) -> dict[str, object]:
        return {
            "subject_kind": self.subject_kind,
            "subject_key": self.subject_key,
            "source_content_hash": self.source_content_hash,
            "approved_content_hash": self.approved_content_hash,
            "sanitized": self.sanitized,
            "verification_digest": self.verification_digest,
            "authority": "none",
        }


def _memory_source_entry(
    *,
    target: str,
    source_scope: FleetMemoryScopeRef,
    source_content_hash: str,
    source_owner_principal_id: str,
    agent_instance_id: str,
) -> tuple[str, dict[str, Any]]:
    if target not in {"memory", "user"}:
        raise FleetPromotionMutationError("memory promotion target is invalid")
    store = MemoryStore()
    try:
        metadata = store._read_fleet_metadata(target, source_scope)
        scope_dir = store._scope_dir(source_scope)
        entries = store._read_file(scope_dir / store._target_filename(target))
    except RuntimeError as error:
        raise FleetPromotionMutationError("memory promotion source is unavailable") from error
    item = metadata.get(source_content_hash)
    if item is None:
        raise FleetPromotionMutationError("memory promotion source hash is unavailable")
    if item.get("owner_principal_id") != source_owner_principal_id:
        raise FleetPromotionMutationError("memory promotion source owner changed")
    if item.get("agent_instance_id") != agent_instance_id:
        raise FleetPromotionMutationError("memory promotion Agent Instance changed")
    if item.get("revoked_at_ms") is not None:
        raise FleetPromotionMutationError("memory promotion source is revoked")
    matches = [entry for entry in entries if store._entry_hash(entry) == source_content_hash]
    if len(matches) != 1:
        raise FleetPromotionMutationError("memory promotion source content/metadata drifted")
    return matches[0], item


def prepare_memory_promotion(
    *,
    target: str,
    source_scope: FleetMemoryScopeRef,
    source_content_hash: str,
    source_owner_principal_id: str,
    agent_instance_id: str,
) -> PreparedPromotion:
    """Sanitize one exact memory entry and return the hash Fleet may approve."""
    content, _metadata = _memory_source_entry(
        target=target,
        source_scope=source_scope,
        source_content_hash=source_content_hash,
        source_owner_principal_id=source_owner_principal_id,
        agent_instance_id=agent_instance_id,
    )
    sanitized, changed = _sanitize_text(content)
    approved_hash = MemoryStore._entry_hash(sanitized)
    return PreparedPromotion(
        subject_kind="memory",
        subject_key=f"{target}:{source_content_hash}",
        source_content_hash=source_content_hash,
        approved_content_hash=approved_hash,
        sanitized=changed,
    )


def _candidate_dir(candidate_id: str) -> Path:
    if (
        type(candidate_id) is not str
        or not candidate_id.startswith("sha256:")
        or len(candidate_id) != 71
        or any(char not in "0123456789abcdef" for char in candidate_id[7:])
    ):
        raise FleetPromotionMutationError("skill candidate ID is invalid")
    root = _candidate_root()
    candidate = root / candidate_id.removeprefix("sha256:")
    try:
        resolved_root = root.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(resolved_root)
    except (OSError, ValueError) as error:
        raise FleetPromotionMutationError("skill candidate is unavailable") from error
    if not resolved.is_dir():
        raise FleetPromotionMutationError("skill candidate is unavailable")
    return resolved


def _learning_binding(metadata: Mapping[str, Any]) -> FleetSkillLearningBinding:
    principal = metadata.get("principal")
    scope = metadata.get("scope")
    provenance = metadata.get("provenance")
    network = metadata.get("network_needs")
    filesystem = metadata.get("filesystem_needs")
    tools = metadata.get("tools")
    secret_needs = metadata.get("secret_needs")
    if type(principal) is not dict:
        raise FleetPromotionMutationError("skill candidate principal is malformed")
    if type(scope) is not dict:
        raise FleetPromotionMutationError("skill candidate scope is malformed")
    if type(provenance) is not dict or type(network) is not dict:
        raise FleetPromotionMutationError("skill candidate provenance is malformed")
    if type(filesystem) is not list or type(tools) is not list or type(secret_needs) is not list:
        raise FleetPromotionMutationError("skill candidate capability manifest is malformed")
    try:
        return FleetSkillLearningBinding(
            principal_id=principal["principal_id"],
            principal_kind=principal["kind"],
            principal_generation=principal["generation"],
            principal_binding_hash=principal["binding_hash"],
            agent_instance_id=metadata["agent_instance_id"],
            source_run=metadata["source_run"],
            scope_kind=scope["kind"],
            scope_id=scope["scope_id"],
            run_authority_hash=provenance["run_authority_hash"],
            recipe_hash=provenance["recipe_hash"],
            resolved_recipe_hash=provenance["resolved_recipe_hash"],
            plan_fingerprint=provenance["plan_fingerprint"],
            capabilities_hash=provenance["capabilities_hash"],
            target_digest=provenance["target_digest"],
            toolsets=tuple(tools),
            filesystem_needs=tuple(
                FleetSkillFilesystemNeed.from_request(item) for item in filesystem
            ),
            network_mode=network["mode"],
            network_policy_hash=network["policy_hash"],
            secret_need_fingerprints=tuple(secret_needs),
        )
    except (KeyError, TypeError, ValueError, RuntimeError) as error:
        raise FleetPromotionMutationError("skill candidate binding cannot be reconstructed") from error


def _sanitized_skill_manifest(candidate_dir: Path) -> tuple[list[dict[str, object]], str, bool]:
    files: list[dict[str, object]] = []
    total = 0
    changed = False
    for path in sorted(candidate_dir.rglob("*")):
        if path.name == "candidate.json":
            continue
        try:
            info = path.lstat()
        except OSError as error:
            raise FleetPromotionMutationError("skill candidate bundle cannot be inspected") from error
        if stat.S_ISLNK(info.st_mode):
            raise FleetPromotionMutationError("skill promotion bundle contains a symlink")
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode):
            raise FleetPromotionMutationError("skill promotion bundle contains an unsafe entry")
        try:
            payload = path.read_bytes()
        except OSError as error:
            raise FleetPromotionMutationError("skill candidate bundle cannot be read") from error
        total += len(payload)
        if len(files) >= _MAX_SKILL_FILES or total > _MAX_SKILL_BYTES:
            raise FleetPromotionMutationError("skill promotion bundle exceeds supported bounds")
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError as error:
            raise FleetPromotionMutationError(
                "skill promotion cannot sanitize opaque binary content"
            ) from error
        sanitized_text, item_changed = _sanitize_text(text)
        changed = changed or item_changed
        sanitized_payload = sanitized_text.encode("utf-8")
        files.append(
            {
                "path": path.relative_to(candidate_dir).as_posix(),
                "sha256": _sha256(sanitized_payload),
                "bytes": len(sanitized_payload),
            }
        )
    if not any(item["path"] == "SKILL.md" for item in files):
        raise FleetPromotionMutationError("skill candidate bundle is missing SKILL.md")
    return files, _sha256(_canonical(files)), changed


def prepare_skill_promotion(
    *,
    candidate_id: str,
    source_owner_principal_id: str,
    agent_instance_id: str,
) -> PreparedPromotion:
    """Re-verify and sanitize one exact Phase 17 skill candidate."""
    candidate_dir = _candidate_dir(candidate_id)
    try:
        metadata = _load_existing_metadata(candidate_dir)
        if metadata is None:
            raise FleetPromotionMutationError("skill candidate metadata is missing")
        if metadata.get("candidate_id") != candidate_id:
            raise FleetPromotionMutationError("skill candidate identity changed")
        principal = metadata.get("principal")
        if type(principal) is not dict or principal.get("principal_id") != source_owner_principal_id:
            raise FleetPromotionMutationError("skill candidate owner changed")
        if metadata.get("agent_instance_id") != agent_instance_id:
            raise FleetPromotionMutationError("skill candidate Agent Instance changed")
        binding = _learning_binding(metadata)
        verification = verify_skill_candidate(candidate_dir, expected_binding=binding)
        if not verification.verified:
            raise FleetPromotionMutationError("skill candidate is not Phase 17 verified")
        _files, observed_hash = _bundle_manifest(candidate_dir)
        if observed_hash != verification.content_hash:
            raise FleetPromotionMutationError("skill candidate changed after verification")
    except (FleetSkillCandidateError, FleetSkillVerificationError) as error:
        raise FleetPromotionMutationError("skill candidate cannot be re-verified") from error

    _sanitized_files, approved_hash, changed = _sanitized_skill_manifest(candidate_dir)
    return PreparedPromotion(
        subject_kind="skill",
        subject_key=candidate_id,
        source_content_hash=observed_hash,
        approved_content_hash=approved_hash,
        sanitized=changed,
        verification_digest=verification.verification_digest,
    )


def validate_commit_authorization(
    prepared: PreparedPromotion,
    authorization: FleetPromotionAuthorization,
) -> None:
    """Bind a freshly prepared exact source to the short-lived Fleet decision."""
    if prepared.subject_kind != authorization.subject_kind:
        raise FleetPromotionError("promotion subject kind changed after authorization")
    if prepared.source_content_hash != authorization.source_content_hash:
        raise FleetPromotionError("promotion source changed after authorization")
    if prepared.approved_content_hash != authorization.approved_content_hash:
        raise FleetPromotionError("promotion sanitized content changed after authorization")
    if prepared.verification_digest != authorization.verification_digest:
        raise FleetPromotionError("promotion verification evidence changed after authorization")


@dataclass(frozen=True, slots=True)
class PromotionCommitResult:
    promotion_id: str
    subject_kind: str
    subject_key: str
    target_scope: dict[str, str]
    approved_content_hash: str
    previous_promotion_id: str | None
    current_promotion_id: str
    operation: str
    idempotent: bool = False

    def to_document(self) -> dict[str, object]:
        return {
            "promotion_id": self.promotion_id,
            "subject_kind": self.subject_kind,
            "subject_key": self.subject_key,
            "target_scope": self.target_scope,
            "approved_content_hash": self.approved_content_hash,
            "previous_promotion_id": self.previous_promotion_id,
            "current_promotion_id": self.current_promotion_id,
            "operation": self.operation,
            "idempotent": self.idempotent,
            "authority": "none",
        }


def _private_directory(path: Path) -> Path:
    """Create/check a private directory without following symlink ancestors."""
    home = get_hermes_home().absolute()
    candidate = path.absolute()
    try:
        relative = candidate.relative_to(home)
    except ValueError as error:
        raise FleetPromotionMutationError(
            "promotion state directory escaped Hermes home"
        ) from error

    cursor = home
    try:
        home_info = cursor.lstat()
    except OSError as error:
        raise FleetPromotionMutationError("Hermes home is unavailable") from error
    if stat.S_ISLNK(home_info.st_mode) or not stat.S_ISDIR(home_info.st_mode):
        raise FleetPromotionMutationError("Hermes home is unsafe")

    for part in relative.parts:
        cursor = cursor / part
        try:
            info = cursor.lstat()
        except FileNotFoundError:
            try:
                cursor.mkdir()
                info = cursor.lstat()
            except OSError as error:
                raise FleetPromotionMutationError(
                    "promotion state directory is unavailable"
                ) from error
        except OSError as error:
            raise FleetPromotionMutationError(
                "promotion state directory is unavailable"
            ) from error
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise FleetPromotionMutationError("promotion state directory is unsafe")
        if os.name != "nt":
            try:
                cursor.chmod(0o700)
            except OSError as error:
                raise FleetPromotionMutationError(
                    "promotion state directory permissions are unsafe"
                ) from error
    return candidate


def _promotion_root() -> Path:
    return _private_directory(get_hermes_home() / ".fleet" / "promotions-v1")


@contextmanager
def _promotion_lock() -> Iterator[None]:
    root = _promotion_root()
    path = root / ".lock"
    try:
        if path.exists() or path.is_symlink():
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise FleetPromotionMutationError("promotion lock path is unsafe")
        handle = path.open("a+b")
        opened = path.lstat()
        descriptor = os.fstat(handle.fileno())
    except OSError as error:
        raise FleetPromotionMutationError("promotion lock is unavailable") from error
    if (
        stat.S_ISLNK(opened.st_mode)
        or not stat.S_ISREG(opened.st_mode)
        or opened.st_dev != descriptor.st_dev
        or opened.st_ino != descriptor.st_ino
        or descriptor.st_nlink != 1
    ):
        handle.close()
        raise FleetPromotionMutationError("promotion lock path is unsafe")
    try:
        if os.name != "nt":
            os.fchmod(handle.fileno(), 0o600)
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        else:
            import msvcrt

            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"0")
                handle.flush()
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
        yield
    finally:
        try:
            if os.name != "nt":
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            else:
                import msvcrt

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        finally:
            handle.close()


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        info = path.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or (os.name != "nt" and stat.S_IMODE(info.st_mode) != 0o600)
        ):
            raise FleetPromotionMutationError("promotion state file is unsafe")
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FleetPromotionMutationError("promotion state file is unreadable") from error
    if type(value) is not dict:
        raise FleetPromotionMutationError("promotion state document is invalid")
    return value


def _write_json(path: Path, document: Mapping[str, object]) -> None:
    _private_directory(path.parent)
    atomic_write_text(
        path,
        json.dumps(document, ensure_ascii=True, allow_nan=False, sort_keys=True, indent=2) + "\n",
    )
    if os.name != "nt":
        path.chmod(0o600)


def _state_identity_document(
    *,
    subject_kind: str,
    subject_key: str,
    source_owner_principal_id: str,
    agent_instance_id: str,
    source_scope: Mapping[str, str],
    target_scope: Mapping[str, str],
) -> dict[str, object]:
    return {
        "schema": "fleet.promotion-subject.v1",
        "subject_kind": subject_kind,
        "subject_key": subject_key,
        "source_owner_principal_id": source_owner_principal_id,
        "agent_instance_id": agent_instance_id,
        "source_scope": dict(source_scope),
        "target_scope": dict(target_scope),
    }


def _state_id(authorization: FleetPromotionAuthorization) -> str:
    return _sha256(
        _canonical(
            _state_identity_document(
                subject_kind=authorization.subject_kind,
                subject_key=authorization.subject_key,
                source_owner_principal_id=authorization.source_owner_principal_id,
                agent_instance_id=authorization.agent_instance_id,
                source_scope=authorization.source_scope.to_request(),
                target_scope=authorization.target_scope.to_request(),
            )
        )
    )


def _state_path(authorization: FleetPromotionAuthorization) -> Path:
    return _promotion_root() / "subjects" / f"{_state_id(authorization)[7:]}.json"


def _record_path(promotion_id: str) -> Path:
    return _promotion_root() / "records" / f"{promotion_id[7:]}.json"


def _load_state(authorization: FleetPromotionAuthorization) -> dict[str, Any]:
    path = _state_path(authorization)
    current = _read_json(path)
    expected_base = _state_identity_document(
        subject_kind=authorization.subject_kind,
        subject_key=authorization.subject_key,
        source_owner_principal_id=authorization.source_owner_principal_id,
        agent_instance_id=authorization.agent_instance_id,
        source_scope=authorization.source_scope.to_request(),
        target_scope=authorization.target_scope.to_request(),
    )
    if current is None:
        return {**expected_base, "current_promotion_id": None, "history": []}
    if (
        current.get("schema") != expected_base["schema"]
        or current.get("subject_kind") != expected_base["subject_kind"]
        or current.get("subject_key") != expected_base["subject_key"]
        or current.get("source_owner_principal_id")
        != expected_base["source_owner_principal_id"]
        or current.get("agent_instance_id") != expected_base["agent_instance_id"]
        or current.get("source_scope") != expected_base["source_scope"]
        or current.get("target_scope") != expected_base["target_scope"]
        or type(current.get("history")) is not list
    ):
        raise FleetPromotionMutationError("promotion subject state identity changed")
    current_id = current.get("current_promotion_id")
    if current_id is not None and (type(current_id) is not str or not current_id.startswith("sha256:")):
        raise FleetPromotionMutationError("promotion current version is invalid")
    return current


def _assert_expected_current(
    state: Mapping[str, Any], authorization: FleetPromotionAuthorization
) -> str | None:
    current = state.get("current_promotion_id")
    expected = authorization.expected_current_promotion_id
    if current != expected:
        raise FleetPromotionMutationError("promotion conflict: current version changed")
    return current if type(current) is str else None


def _promotion_provenance(source_hash: str) -> str:
    """Stable durable-source provenance independent of approval-event identity."""
    return f"fleet-promotion-v1/{source_hash[7:]}"


def _write_memory_metadata(
    store: MemoryStore,
    *,
    target: str,
    scope: FleetMemoryScopeRef,
    metadata: Mapping[str, Mapping[str, Any]],
) -> None:
    document = {
        "schema": "fleet.memory-entry-metadata.v1",
        "scope": scope.to_request(),
        "entries": sorted((dict(item) for item in metadata.values()), key=lambda item: item["content_hash"]),
    }
    path = store._metadata_path(target, scope)
    atomic_write_text(path, json.dumps(document, sort_keys=True, separators=(",", ":")))
    if os.name != "nt":
        path.chmod(0o600)


def _commit_memory(
    *,
    target: str,
    prepared: PreparedPromotion,
    authorization: FleetPromotionAuthorization,
    previous_record: Mapping[str, Any] | None,
) -> None:
    source_scope = FleetMemoryScopeRef(
        authorization.source_scope.kind,
        authorization.source_scope.scope_id,
    )
    content, source_metadata = _memory_source_entry(
        target=target,
        source_scope=source_scope,
        source_content_hash=authorization.source_content_hash,
        source_owner_principal_id=authorization.source_owner_principal_id,
        agent_instance_id=authorization.agent_instance_id,
    )
    sanitized, _changed = _sanitize_text(content)
    if MemoryStore._entry_hash(sanitized) != prepared.approved_content_hash:
        raise FleetPromotionMutationError("memory sanitized content changed before commit")

    target_scope = FleetMemoryScopeRef(
        authorization.target_scope.kind,
        authorization.target_scope.scope_id,
    )
    store = MemoryStore(memory_char_limit=64 * 1024, user_char_limit=64 * 1024)
    store._ensure_scope_descriptor(target_scope)
    scope_dir = store._scope_dir(target_scope)
    path = scope_dir / store._target_filename(target)
    entries = store._read_file(path) if path.exists() else []
    metadata = store._read_fleet_metadata(target, target_scope)
    now_ms = int(time.time() * 1000)

    if previous_record is not None:
        previous_hash = previous_record.get("approved_content_hash")
        if type(previous_hash) is str and previous_hash in metadata:
            metadata[previous_hash]["revoked_at_ms"] = now_ms
            metadata[previous_hash]["updated_at_ms"] = now_ms

    existing = metadata.get(prepared.approved_content_hash)
    provenance = _promotion_provenance(authorization.source_content_hash)
    if existing is not None:
        if existing.get("provenance") != provenance:
            raise FleetPromotionMutationError("promotion conflict: approved memory hash has different provenance")
        existing["revoked_at_ms"] = None
        existing["updated_at_ms"] = now_ms
    else:
        if sanitized not in entries:
            entries.append(sanitized)
        metadata[prepared.approved_content_hash] = {
            "content_hash": prepared.approved_content_hash,
            "owner_principal_id": authorization.source_owner_principal_id,
            "owner_principal_kind": source_metadata["owner_principal_kind"],
            "scope_kind": target_scope.kind,
            "scope_id": target_scope.scope_id,
            "source_run": source_metadata["source_run"],
            "agent_instance_id": authorization.agent_instance_id,
            "sensitivity": "shared" if target_scope.kind in {"network", "owner"} else "internal",
            "trust": "promoted",
            "promotion_state": "promoted",
            "retention_until_ms": source_metadata.get("retention_until_ms"),
            "provenance": provenance,
            "created_at_ms": now_ms,
            "updated_at_ms": now_ms,
            "revoked_at_ms": None,
        }
    store._write_file(path, entries)
    _write_memory_metadata(store, target=target, scope=target_scope, metadata=metadata)


def _materialize_sanitized_skill_bundle(candidate_dir: Path, destination: Path) -> None:
    if destination.exists():
        return
    _private_directory(destination)
    for path in sorted(candidate_dir.rglob("*")):
        if path.name == "candidate.json":
            continue
        try:
            info = path.lstat()
        except OSError as error:
            raise FleetPromotionMutationError("skill bundle changed before commit") from error
        if stat.S_ISLNK(info.st_mode):
            raise FleetPromotionMutationError("skill bundle contains a symlink")
        relative = path.relative_to(candidate_dir)
        target = destination / relative
        if stat.S_ISDIR(info.st_mode):
            _private_directory(target)
            continue
        if not stat.S_ISREG(info.st_mode):
            raise FleetPromotionMutationError("skill bundle contains an unsafe entry")
        payload = path.read_bytes()
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError as error:
            raise FleetPromotionMutationError(
                "skill promotion cannot sanitize opaque binary content"
            ) from error
        sanitized_text, _changed = _sanitize_text(text)
        sanitized_payload = sanitized_text.encode("utf-8")
        _private_directory(target.parent)
        target.write_bytes(sanitized_payload)
        if os.name != "nt":
            target.chmod(0o600)


def _skill_version_dir(promotion_id: str) -> Path:
    return _promotion_root() / "skill-bundles" / promotion_id[7:] / "bundle"


def _assert_no_promoted_skill_name_collision(
    *,
    skill_name: str,
    authorization: FleetPromotionAuthorization,
) -> None:
    subjects = _promotion_root() / "subjects"
    if not subjects.exists():
        return
    current_identity = _state_identity_document(
        subject_kind=authorization.subject_kind,
        subject_key=authorization.subject_key,
        source_owner_principal_id=authorization.source_owner_principal_id,
        agent_instance_id=authorization.agent_instance_id,
        source_scope=authorization.source_scope.to_request(),
        target_scope=authorization.target_scope.to_request(),
    )
    for state_path in sorted(subjects.glob("*.json")):
        state = _read_json(state_path)
        if state is None or state.get("subject_kind") != "skill":
            continue
        if state.get("target_scope") != authorization.target_scope.to_request():
            continue
        observed_identity = {
            key: state.get(key) for key in current_identity
        }
        if observed_identity == current_identity:
            continue
        current_id = state.get("current_promotion_id")
        if type(current_id) is not str:
            continue
        record = _read_json(_record_path(current_id))
        detail = None if record is None else record.get("subject_detail")
        if type(detail) is dict and detail.get("name") == skill_name:
            raise FleetPromotionMutationError(
                "skill promotion conflict: promoted skill name already exists in target scope"
            )


def _commit_skill(
    *,
    prepared: PreparedPromotion,
    authorization: FleetPromotionAuthorization,
) -> str:
    candidate_dir = _candidate_dir(authorization.subject_key)
    metadata = _load_existing_metadata(candidate_dir)
    if metadata is None or type(metadata.get("name")) is not str:
        raise FleetPromotionMutationError("skill candidate name is unavailable")
    skill_name = metadata["name"]
    _assert_no_promoted_skill_name_collision(
        skill_name=skill_name,
        authorization=authorization,
    )

    # Phase 18 does not silently shadow an immutable/native active skill. Base
    # plus learned-overlay reconciliation belongs to Phase 24; until then a
    # collision is an explicit conflict rather than an implicit precedence rule.
    try:
        from tools.skills_tool import _find_all_skills

        if any(item.get("name") == skill_name for item in _find_all_skills()):
            raise FleetPromotionMutationError(
                "skill promotion conflict: active skill name already exists"
            )
    except FleetPromotionMutationError:
        raise
    except Exception as error:
        raise FleetPromotionMutationError(
            "skill promotion conflict check is unavailable"
        ) from error

    materialized = _skill_version_dir(authorization.promotion_id)
    if not materialized.exists():
        parent = materialized.parent
        _private_directory(parent)
        staging = parent / ".staging"
        if staging.exists():
            shutil.rmtree(staging)
        _materialize_sanitized_skill_bundle(candidate_dir, staging)
        _files, observed_hash, _changed = _sanitized_skill_manifest(staging)
        if observed_hash != prepared.approved_content_hash:
            shutil.rmtree(staging)
            raise FleetPromotionMutationError("materialized skill hash changed before activation")
        os.replace(staging, materialized)
    return skill_name


def _record_document(
    *,
    prepared: PreparedPromotion,
    authorization: FleetPromotionAuthorization,
    previous_promotion_id: str | None,
    subject_detail: Mapping[str, object],
) -> dict[str, object]:
    return {
        "schema": "fleet.promotion-record.v1",
        "promotion_id": authorization.promotion_id,
        "authorization": authorization.unsigned_document(),
        "prepared": prepared.to_document(),
        "subject_detail": dict(subject_detail),
        "previous_promotion_id": previous_promotion_id,
        "approved_content_hash": prepared.approved_content_hash,
        "source_content_hash": prepared.source_content_hash,
        "committed_at_ms": int(time.time() * 1000),
        "authority": "none",
    }


def commit_memory_promotion(
    *,
    target: str,
    authorization: FleetPromotionAuthorization,
) -> PromotionCommitResult:
    if authorization.subject_kind != "memory" or authorization.operation != "promote":
        raise FleetPromotionMutationError("memory commit requires a normal memory promotion")
    expected_key = f"{target}:{authorization.source_content_hash}"
    if authorization.subject_key != expected_key:
        raise FleetPromotionMutationError("memory promotion subject key changed")
    prepared = prepare_memory_promotion(
        target=target,
        source_scope=FleetMemoryScopeRef(
            authorization.source_scope.kind, authorization.source_scope.scope_id
        ),
        source_content_hash=authorization.source_content_hash,
        source_owner_principal_id=authorization.source_owner_principal_id,
        agent_instance_id=authorization.agent_instance_id,
    )
    validate_commit_authorization(prepared, authorization)

    with _promotion_lock():
        state = _load_state(authorization)
        existing_record = _read_json(_record_path(authorization.promotion_id))
        if existing_record is not None:
            if state.get("current_promotion_id") != authorization.promotion_id:
                raise FleetPromotionMutationError("promotion record exists outside current subject state")
            return PromotionCommitResult(
                promotion_id=authorization.promotion_id,
                subject_kind="memory",
                subject_key=authorization.subject_key,
                target_scope=authorization.target_scope.to_request(),
                approved_content_hash=authorization.approved_content_hash,
                previous_promotion_id=existing_record.get("previous_promotion_id"),
                current_promotion_id=authorization.promotion_id,
                operation="promote",
                idempotent=True,
            )
        previous_id = _assert_expected_current(state, authorization)
        previous_record = _read_json(_record_path(previous_id)) if previous_id else None
        _commit_memory(
            target=target,
            prepared=prepared,
            authorization=authorization,
            previous_record=previous_record,
        )
        record = _record_document(
            prepared=prepared,
            authorization=authorization,
            previous_promotion_id=previous_id,
            subject_detail={"target": target},
        )
        _write_json(_record_path(authorization.promotion_id), record)
        history = list(state["history"])
        history.append(authorization.promotion_id)
        state = {**state, "current_promotion_id": authorization.promotion_id, "history": history}
        _write_json(_state_path(authorization), state)
    return PromotionCommitResult(
        promotion_id=authorization.promotion_id,
        subject_kind="memory",
        subject_key=authorization.subject_key,
        target_scope=authorization.target_scope.to_request(),
        approved_content_hash=authorization.approved_content_hash,
        previous_promotion_id=previous_id,
        current_promotion_id=authorization.promotion_id,
        operation="promote",
    )


def commit_skill_promotion(
    *,
    authorization: FleetPromotionAuthorization,
) -> PromotionCommitResult:
    if authorization.subject_kind != "skill" or authorization.operation != "promote":
        raise FleetPromotionMutationError("skill commit requires a normal skill promotion")
    prepared = prepare_skill_promotion(
        candidate_id=authorization.subject_key,
        source_owner_principal_id=authorization.source_owner_principal_id,
        agent_instance_id=authorization.agent_instance_id,
    )
    validate_commit_authorization(prepared, authorization)
    with _promotion_lock():
        state = _load_state(authorization)
        existing_record = _read_json(_record_path(authorization.promotion_id))
        if existing_record is not None:
            if state.get("current_promotion_id") != authorization.promotion_id:
                raise FleetPromotionMutationError("promotion record exists outside current subject state")
            return PromotionCommitResult(
                promotion_id=authorization.promotion_id,
                subject_kind="skill",
                subject_key=authorization.subject_key,
                target_scope=authorization.target_scope.to_request(),
                approved_content_hash=authorization.approved_content_hash,
                previous_promotion_id=existing_record.get("previous_promotion_id"),
                current_promotion_id=authorization.promotion_id,
                operation="promote",
                idempotent=True,
            )
        previous_id = _assert_expected_current(state, authorization)
        skill_name = _commit_skill(prepared=prepared, authorization=authorization)
        record = _record_document(
            prepared=prepared,
            authorization=authorization,
            previous_promotion_id=previous_id,
            subject_detail={
                "name": skill_name,
                "bundle": str(_skill_version_dir(authorization.promotion_id)),
            },
        )
        _write_json(_record_path(authorization.promotion_id), record)
        history = list(state["history"])
        history.append(authorization.promotion_id)
        state = {**state, "current_promotion_id": authorization.promotion_id, "history": history}
        _write_json(_state_path(authorization), state)
    return PromotionCommitResult(
        promotion_id=authorization.promotion_id,
        subject_kind="skill",
        subject_key=authorization.subject_key,
        target_scope=authorization.target_scope.to_request(),
        approved_content_hash=authorization.approved_content_hash,
        previous_promotion_id=previous_id,
        current_promotion_id=authorization.promotion_id,
        operation="promote",
    )


def _rollback_memory(
    *,
    authorization: FleetPromotionAuthorization,
    current_record: Mapping[str, Any],
    rollback_record: Mapping[str, Any],
) -> None:
    current_detail = current_record.get("subject_detail")
    rollback_detail = rollback_record.get("subject_detail")
    if type(current_detail) is not dict or type(rollback_detail) is not dict:
        raise FleetPromotionMutationError("memory rollback history is malformed")
    target = rollback_detail.get("target")
    if target not in {"memory", "user"} or current_detail.get("target") != target:
        raise FleetPromotionMutationError("memory rollback target changed")
    target_scope = FleetMemoryScopeRef(
        authorization.target_scope.kind,
        authorization.target_scope.scope_id,
    )
    store = MemoryStore(memory_char_limit=64 * 1024, user_char_limit=64 * 1024)
    metadata = store._read_fleet_metadata(target, target_scope)
    current_hash = current_record.get("approved_content_hash")
    rollback_hash = rollback_record.get("approved_content_hash")
    if type(current_hash) is not str or type(rollback_hash) is not str:
        raise FleetPromotionMutationError("memory rollback hashes are malformed")
    if current_hash not in metadata or rollback_hash not in metadata:
        raise FleetPromotionMutationError("memory rollback version is no longer materialized")
    now_ms = int(time.time() * 1000)
    metadata[current_hash]["revoked_at_ms"] = now_ms
    metadata[current_hash]["updated_at_ms"] = now_ms
    metadata[rollback_hash]["revoked_at_ms"] = None
    metadata[rollback_hash]["updated_at_ms"] = now_ms
    _write_memory_metadata(store, target=target, scope=target_scope, metadata=metadata)


def rollback_promotion(
    *, authorization: FleetPromotionAuthorization
) -> PromotionCommitResult:
    """Rollback one promoted subject to an exact prior version under new Fleet approval."""
    if authorization.operation != "rollback":
        raise FleetPromotionMutationError("rollback requires a rollback authorization")
    rollback_to = authorization.rollback_to_promotion_id
    if rollback_to is None:
        raise FleetPromotionMutationError("rollback target is missing")
    with _promotion_lock():
        state = _load_state(authorization)
        existing_event = _read_json(_record_path(authorization.promotion_id))
        if existing_event is not None:
            if state.get("current_promotion_id") != authorization.promotion_id:
                raise FleetPromotionMutationError("rollback record exists outside current subject state")
            return PromotionCommitResult(
                promotion_id=authorization.promotion_id,
                subject_kind=authorization.subject_kind,
                subject_key=authorization.subject_key,
                target_scope=authorization.target_scope.to_request(),
                approved_content_hash=authorization.approved_content_hash,
                previous_promotion_id=existing_event.get("previous_promotion_id"),
                current_promotion_id=authorization.promotion_id,
                operation="rollback",
                idempotent=True,
            )
        current_id = _assert_expected_current(state, authorization)
        if current_id is None:
            raise FleetPromotionMutationError("rollback requires an existing current promotion")
        history = state.get("history")
        if type(history) is not list or rollback_to not in history:
            raise FleetPromotionMutationError("rollback target is not in subject history")
        current_record = _read_json(_record_path(current_id))
        target_record = _read_json(_record_path(rollback_to))
        if current_record is None or target_record is None:
            raise FleetPromotionMutationError("rollback history record is unavailable")
        target_auth = target_record.get("authorization")
        target_prepared = target_record.get("prepared")
        if type(target_auth) is not dict or type(target_prepared) is not dict:
            raise FleetPromotionMutationError("rollback target record is malformed")
        if (
            target_auth.get("subject_kind") != authorization.subject_kind
            or target_auth.get("subject_key") != authorization.subject_key
            or target_auth.get("target_scope") != authorization.target_scope.to_request()
            or target_prepared.get("source_content_hash") != authorization.source_content_hash
            or target_prepared.get("approved_content_hash") != authorization.approved_content_hash
            or target_prepared.get("verification_digest") != authorization.verification_digest
        ):
            raise FleetPromotionMutationError("rollback authorization does not match the exact target version")
        subject_detail = target_record.get("subject_detail")
        if type(subject_detail) is not dict:
            raise FleetPromotionMutationError("rollback subject detail is malformed")
        if authorization.subject_kind == "memory":
            _rollback_memory(
                authorization=authorization,
                current_record=current_record,
                rollback_record=target_record,
            )
        elif authorization.subject_kind == "skill":
            bundle_value = subject_detail.get("bundle")
            if type(bundle_value) is not str:
                raise FleetPromotionMutationError("skill rollback bundle is unavailable")
            source_bundle = Path(bundle_value)
            _source_files, source_hash, source_changed = _sanitized_skill_manifest(source_bundle)
            if source_changed or source_hash != authorization.approved_content_hash:
                raise FleetPromotionMutationError("skill rollback bundle changed after approval")
            destination = _skill_version_dir(authorization.promotion_id)
            if not destination.exists():
                parent = destination.parent
                _private_directory(parent)
                staging = parent / ".staging"
                if staging.exists():
                    shutil.rmtree(staging)
                _materialize_sanitized_skill_bundle(source_bundle, staging)
                _files, observed_hash, changed = _sanitized_skill_manifest(staging)
                if changed or observed_hash != authorization.approved_content_hash:
                    shutil.rmtree(staging)
                    raise FleetPromotionMutationError("skill rollback materialization changed content")
                os.replace(staging, destination)
            subject_detail = {**subject_detail, "bundle": str(destination)}
        else:
            raise FleetPromotionMutationError("rollback subject kind is invalid")

        rollback_event = _record_document(
            prepared=PreparedPromotion(
                subject_kind=authorization.subject_kind,
                subject_key=authorization.subject_key,
                source_content_hash=authorization.source_content_hash,
                approved_content_hash=authorization.approved_content_hash,
                sanitized=bool(target_prepared.get("sanitized")),
                verification_digest=authorization.verification_digest,
            ),
            authorization=authorization,
            previous_promotion_id=current_id,
            subject_detail=subject_detail,
        )
        rollback_event["rollback_to_promotion_id"] = rollback_to
        _write_json(_record_path(authorization.promotion_id), rollback_event)
        next_history = list(history)
        next_history.append(authorization.promotion_id)
        next_state = {
            **state,
            "current_promotion_id": authorization.promotion_id,
            "history": next_history,
        }
        _write_json(_state_path(authorization), next_state)
    return PromotionCommitResult(
        promotion_id=authorization.promotion_id,
        subject_kind=authorization.subject_kind,
        subject_key=authorization.subject_key,
        target_scope=authorization.target_scope.to_request(),
        approved_content_hash=authorization.approved_content_hash,
        previous_promotion_id=current_id,
        current_promotion_id=authorization.promotion_id,
        operation="rollback",
    )


def _state_path_for_identity(
    *,
    subject_kind: str,
    subject_key: str,
    source_owner_principal_id: str,
    agent_instance_id: str,
    source_scope: Mapping[str, str],
    target_scope: Mapping[str, str],
) -> Path:
    if subject_kind not in {"memory", "skill"}:
        raise FleetPromotionMutationError("promotion history subject kind is invalid")
    if type(subject_key) is not str or not subject_key:
        raise FleetPromotionMutationError("promotion history subject key is invalid")
    if type(source_owner_principal_id) is not str or not source_owner_principal_id.startswith(
        "sha256:"
    ):
        raise FleetPromotionMutationError("promotion history source owner is invalid")
    if type(agent_instance_id) is not str or not agent_instance_id.startswith("sha256:"):
        raise FleetPromotionMutationError("promotion history Agent Instance is invalid")
    try:
        source = FleetPromotionScopeRef.from_request(dict(source_scope))
        target = FleetPromotionScopeRef.from_request(dict(target_scope))
    except (FleetPromotionError, TypeError, ValueError) as error:
        raise FleetPromotionMutationError("promotion history scope is invalid") from error
    identity = _state_identity_document(
        subject_kind=subject_kind,
        subject_key=subject_key,
        source_owner_principal_id=source_owner_principal_id,
        agent_instance_id=agent_instance_id,
        source_scope=source.to_request(),
        target_scope=target.to_request(),
    )
    state_id = _sha256(_canonical(identity))
    return _promotion_root() / "subjects" / f"{state_id[7:]}.json"


def promotion_history(
    *,
    subject_kind: str,
    subject_key: str,
    source_owner_principal_id: str,
    agent_instance_id: str,
    source_scope: Mapping[str, str],
    target_scope: Mapping[str, str],
) -> dict[str, object]:
    """Return non-content promotion history for one exact scoped subject identity."""
    path = _state_path_for_identity(
        subject_kind=subject_kind,
        subject_key=subject_key,
        source_owner_principal_id=source_owner_principal_id,
        agent_instance_id=agent_instance_id,
        source_scope=source_scope,
        target_scope=target_scope,
    )
    state = _read_json(path)
    if state is None:
        return {
            "current_promotion_id": None,
            "history": [],
            "records": [],
            "authority": "none",
        }
    current = state.get("current_promotion_id")
    records: list[dict[str, object]] = []
    for promotion_id in state.get("history", []):
        if type(promotion_id) is not str:
            raise FleetPromotionMutationError("promotion history is malformed")
        record = _read_json(_record_path(promotion_id))
        if record is None:
            raise FleetPromotionMutationError("promotion history record is unavailable")
        prepared = record.get("prepared")
        authorization = record.get("authorization")
        if type(prepared) is not dict or type(authorization) is not dict:
            raise FleetPromotionMutationError("promotion history record is malformed")
        records.append(
            {
                "promotion_id": promotion_id,
                "operation": authorization.get("operation"),
                "source_content_hash": prepared.get("source_content_hash"),
                "approved_content_hash": prepared.get("approved_content_hash"),
                "verification_digest": prepared.get("verification_digest"),
                "previous_promotion_id": record.get("previous_promotion_id"),
                "rollback_to_promotion_id": record.get("rollback_to_promotion_id"),
                "committed_at_ms": record.get("committed_at_ms"),
            }
        )
    return {
        "current_promotion_id": current if type(current) is str else None,
        "history": list(state.get("history", [])),
        "records": records,
        "authority": "none",
    }


def current_promotion_id(
    *,
    subject_kind: str,
    subject_key: str,
    source_owner_principal_id: str,
    agent_instance_id: str,
    source_scope: Mapping[str, str],
    target_scope: Mapping[str, str],
) -> str | None:
    path = _state_path_for_identity(
        subject_kind=subject_kind,
        subject_key=subject_key,
        source_owner_principal_id=source_owner_principal_id,
        agent_instance_id=agent_instance_id,
        source_scope=source_scope,
        target_scope=target_scope,
    )
    state = _read_json(path)
    if state is None:
        return None
    current = state.get("current_promotion_id")
    return current if type(current) is str else None


def visible_promoted_skill_files() -> list[Path]:
    """Return current promoted SKILL.md files authorized by this Fleet run's read scopes."""
    from agent.fleet_memory_scope import get_fleet_memory

    binding = get_fleet_memory()
    if binding is None:
        return []
    allowed = {(scope.kind, scope.scope_id) for scope in binding.read_scopes if scope.kind != "principal"}
    subjects = _promotion_root() / "subjects"
    if not subjects.exists():
        return []
    result: list[Path] = []
    for path in sorted(subjects.glob("*.json")):
        state = _read_json(path)
        if state is None or state.get("subject_kind") != "skill":
            continue
        scope = state.get("target_scope")
        if type(scope) is not dict or (scope.get("kind"), scope.get("scope_id")) not in allowed:
            continue
        current = state.get("current_promotion_id")
        if type(current) is not str:
            continue
        record = _read_json(_record_path(current))
        if record is None or record.get("promotion_id") != current:
            raise FleetPromotionMutationError("current promoted skill record is unavailable")
        authorization = record.get("authorization")
        prepared = record.get("prepared")
        detail = record.get("subject_detail")
        if type(authorization) is not dict or type(prepared) is not dict or type(detail) is not dict:
            raise FleetPromotionMutationError("current promoted skill record is malformed")
        if (
            authorization.get("subject_kind") != "skill"
            or authorization.get("subject_key") != state.get("subject_key")
            or authorization.get("source_owner_principal_id") != state.get("source_owner_principal_id")
            or authorization.get("agent_instance_id") != state.get("agent_instance_id")
            or authorization.get("source_scope") != state.get("source_scope")
            or authorization.get("target_scope") != state.get("target_scope")
        ):
            raise FleetPromotionMutationError("current promoted skill identity changed")
        expected_bundle = _skill_version_dir(current)
        if detail.get("bundle") != str(expected_bundle):
            raise FleetPromotionMutationError("current promoted skill bundle path changed")
        _files, observed_hash, changed = _sanitized_skill_manifest(expected_bundle)
        if changed or observed_hash != prepared.get("approved_content_hash"):
            raise FleetPromotionMutationError("current promoted skill bundle changed after approval")
        skill_md = expected_bundle / "SKILL.md"
        try:
            info = skill_md.lstat()
        except OSError as error:
            raise FleetPromotionMutationError("current promoted skill SKILL.md is unavailable") from error
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise FleetPromotionMutationError("current promoted skill SKILL.md is unsafe")
        result.append(skill_md)
    return result


__all__ = [
    "FleetPromotionMutationError",
    "PreparedPromotion",
    "PromotionCommitResult",
    "commit_memory_promotion",
    "commit_skill_promotion",
    "current_promotion_id",
    "prepare_memory_promotion",
    "prepare_skill_promotion",
    "promotion_history",
    "rollback_promotion",
    "validate_commit_authorization",
    "visible_promoted_skill_files",
]
