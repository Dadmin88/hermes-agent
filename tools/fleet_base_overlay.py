"""Phase 24 Agency-base / promoted-skill overlay compatibility.

Hermes owns the durable promoted-skill bodies. Fleet may ask Hermes to assess
those exact current promoted bundles against one exact immutable Agency base.
The resulting record is authority-free and is used only to quarantine learned
skills that fail exact revalidation or collide with the new immutable base.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from pathlib import Path
from typing import Any, Mapping

from hermes_constants import get_hermes_home

_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_REPORT_SCHEMA = "fleet.base-overlay-compatibility.v1"
_MAX_BASE_SKILLS = 512
_MAX_REPORT_BYTES = 256 * 1024


class FleetBaseOverlayError(ValueError):
    """The exact base/overlay compatibility record cannot be trusted."""


def _hash(value: object, label: str) -> str:
    if type(value) is not str or _HASH_RE.fullmatch(value) is None:
        raise FleetBaseOverlayError(f"{label} is invalid")
    return value


def _name(value: object, label: str) -> str:
    if type(value) is not str or _NAME_RE.fullmatch(value) is None:
        raise FleetBaseOverlayError(f"{label} is invalid")
    return value


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise FleetBaseOverlayError("base overlay value is not canonical JSON") from error


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _report_root() -> Path:
    root = get_hermes_home() / ".fleet" / "base-overlay-compatibility-v1"
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if root.is_symlink() or not root.is_dir():
        raise FleetBaseOverlayError("base overlay report root is unsafe")
    if os.name != "nt":
        root.chmod(0o700)
    return root


def _report_path(agent_instance_id: str, base_manifest_digest: str) -> Path:
    agent = _hash(agent_instance_id, "Agent Instance ID").removeprefix("sha256:")
    base = _hash(base_manifest_digest, "base manifest digest").removeprefix("sha256:")
    directory = _report_root() / agent
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if directory.is_symlink() or not directory.is_dir():
        raise FleetBaseOverlayError("base overlay report directory is unsafe")
    if os.name != "nt":
        directory.chmod(0o700)
    return directory / f"{base}.json"


def _atomic_write(path: Path, value: Mapping[str, Any]) -> None:
    payload = _canonical(dict(value)) + b"\n"
    if len(payload) > _MAX_REPORT_BYTES:
        raise FleetBaseOverlayError("base overlay report exceeds its bound")
    temporary = path.with_name(f".{path.name}.tmp-{uuid.uuid4().hex}")
    descriptor = -1
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        if os.name != "nt":
            path.chmod(0o600)
    except OSError as error:
        raise FleetBaseOverlayError("base overlay report write failed") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def _base_skills(value: object) -> tuple[dict[str, str], ...]:
    if type(value) is not list or len(value) > _MAX_BASE_SKILLS:
        raise FleetBaseOverlayError("base skill inventory is invalid")
    result: list[dict[str, str]] = []
    seen_names: set[str] = set()
    seen_paths: set[str] = set()
    for item in value:
        if type(item) is not dict or set(item) != {"name", "path", "sha256"}:
            raise FleetBaseOverlayError("base skill inventory is invalid")
        name = _name(item["name"], "base skill name")
        path = item["path"]
        if (
            type(path) is not str
            or not path.startswith("skills/")
            or not path.endswith("/SKILL.md")
            or ".." in Path(path).parts
            or Path(path).is_absolute()
            or "\\" in path
        ):
            raise FleetBaseOverlayError("base skill path is invalid")
        digest = _hash(item["sha256"], "base skill hash")
        if name in seen_names or path in seen_paths:
            raise FleetBaseOverlayError("base skill inventory is ambiguous")
        seen_names.add(name)
        seen_paths.add(path)
        result.append({"name": name, "path": path, "sha256": digest})
    canonical = tuple(sorted(result, key=lambda item: (item["name"], item["path"])))
    if list(canonical) != result:
        raise FleetBaseOverlayError("base skill inventory is not canonical")
    return canonical


def _current_promoted_skills(agent_instance_id: str) -> tuple[dict[str, Any], ...]:
    from tools.fleet_promotion import (
        _promotion_root,
        _read_json,
        _validated_current_skill_record,
    )

    subjects = _promotion_root() / "subjects"
    if not subjects.exists():
        return ()
    by_subject: dict[str, dict[str, Any]] = {}
    for state_path in sorted(subjects.glob("*.json")):
        state = _read_json(state_path)
        if (
            state is None
            or state.get("subject_kind") != "skill"
            or state.get("agent_instance_id") != agent_instance_id
        ):
            continue
        subject_key = state.get("subject_key")
        if type(subject_key) is not str or not subject_key:
            raise FleetBaseOverlayError("promoted skill subject is invalid")
        record, _skill_md, skill_name = _validated_current_skill_record(state)
        prepared = record.get("prepared")
        current_promotion_id = state.get("current_promotion_id")
        if type(prepared) is not dict or type(current_promotion_id) is not str:
            raise FleetBaseOverlayError("promoted skill record is malformed")
        approved_hash = _hash(
            prepared.get("approved_content_hash"), "promoted skill content hash"
        )
        verification_digest = _hash(
            prepared.get("verification_digest"), "promoted skill verification digest"
        )
        previous = by_subject.get(subject_key)
        if previous is None:
            source_owner = state.get("source_owner_principal_id")
            if type(source_owner) is not str or not source_owner:
                raise FleetBaseOverlayError("promoted skill owner is invalid")
            by_subject[subject_key] = {
                "subject_key": subject_key,
                "source_owner_principal_id": source_owner,
                "name": _name(skill_name, "promoted skill name"),
                "approved_content_hash": approved_hash,
                "verification_digest": verification_digest,
                "promotion_ids": [current_promotion_id],
            }
            continue
        if (
            previous["source_owner_principal_id"]
            != state.get("source_owner_principal_id")
            or previous["name"] != skill_name
            or previous["approved_content_hash"] != approved_hash
            or previous["verification_digest"] != verification_digest
        ):
            raise FleetBaseOverlayError(
                "promoted skill differs across current visible scopes"
            )
        previous["promotion_ids"].append(current_promotion_id)

    from tools.fleet_promotion import (
        FleetPromotionMutationError,
        prepare_skill_promotion,
    )

    result: list[dict[str, Any]] = []
    for subject_key in sorted(by_subject):
        item = by_subject[subject_key]
        item["promotion_ids"] = sorted(set(item["promotion_ids"]))
        reverified = False
        revalidation_reason: str | None = None
        try:
            prepared = prepare_skill_promotion(
                candidate_id=subject_key,
                source_owner_principal_id=item["source_owner_principal_id"],
                agent_instance_id=agent_instance_id,
            )
            reverified = (
                prepared.approved_content_hash == item["approved_content_hash"]
                and prepared.verification_digest == item["verification_digest"]
            )
            if not reverified:
                revalidation_reason = "phase17-reverification-mismatch"
        except FleetPromotionMutationError:
            revalidation_reason = "phase17-reverification-failed"
        result.append(
            {
                **item,
                "reverified": reverified,
                "revalidation_reason": revalidation_reason,
            }
        )
    return tuple(result)


def assess_base_overlay_compatibility(
    *,
    agent_instance_id: str,
    base_manifest_digest: str,
    base_skills: object,
) -> dict[str, Any]:
    """Bind current promoted skill overlays to one exact Agency base.

    Existing exact promoted bundles are revalidated for content integrity by
    ``_validated_current_skill_record``. A learned skill whose Agent-visible
    name collides with the immutable base is quarantined for this exact base;
    unaffected learned skills retain their existing Phase 17 verification.
    """

    agent_instance_id = _hash(agent_instance_id, "Agent Instance ID")
    base_manifest_digest = _hash(base_manifest_digest, "base manifest digest")
    normalized_base_skills = _base_skills(base_skills)
    base_names = {item["name"] for item in normalized_base_skills}
    base_skills_digest = _digest(list(normalized_base_skills))

    skills: list[dict[str, Any]] = []
    for promoted in _current_promoted_skills(agent_instance_id):
        conflict = promoted["name"] in base_names
        reasons: list[str] = []
        if conflict:
            reasons.append("immutable-base-skill-name-conflict")
        if not promoted["reverified"]:
            reason = promoted.get("revalidation_reason")
            reasons.append(
                reason if type(reason) is str else "phase17-reverification-failed"
            )
        skills.append(
            {
                **promoted,
                "status": "quarantined" if reasons else "compatible",
                "reason_codes": reasons,
            }
        )

    body: dict[str, Any] = {
        "schema": _REPORT_SCHEMA,
        "agent_instance_id": agent_instance_id,
        "base_manifest_digest": base_manifest_digest,
        "base_skills_digest": base_skills_digest,
        "base_skills": list(normalized_base_skills),
        "skills": skills,
        "authority": "none",
    }
    report = {**body, "report_digest": _digest(body)}
    path = _report_path(agent_instance_id, base_manifest_digest)
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise FleetBaseOverlayError("base overlay report is unreadable") from error
        if existing != report:
            raise FleetBaseOverlayError(
                "base overlay compatibility changed for the same immutable base"
            )
        return report
    _atomic_write(path, report)
    return report


def load_base_overlay_compatibility(
    *,
    agent_instance_id: str,
    base_manifest_digest: str,
) -> dict[str, Any] | None:
    path = _report_path(agent_instance_id, base_manifest_digest)
    if not path.exists():
        return None
    try:
        payload = path.read_bytes()
        if len(payload) > _MAX_REPORT_BYTES:
            raise FleetBaseOverlayError("base overlay report exceeds its bound")
        value = json.loads(payload)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise FleetBaseOverlayError("base overlay report is unreadable") from error
    if type(value) is not dict or value.get("schema") != _REPORT_SCHEMA:
        raise FleetBaseOverlayError("base overlay report is invalid")
    report_digest = value.get("report_digest")
    if type(report_digest) is not str:
        raise FleetBaseOverlayError("base overlay report is invalid")
    body = dict(value)
    body.pop("report_digest", None)
    if _digest(body) != report_digest:
        raise FleetBaseOverlayError("base overlay report digest changed")
    if value.get("agent_instance_id") != agent_instance_id:
        raise FleetBaseOverlayError("base overlay Agent Instance changed")
    if value.get("base_manifest_digest") != base_manifest_digest:
        raise FleetBaseOverlayError("base overlay base manifest changed")
    return value


def quarantined_promoted_skill_names() -> set[str]:
    """Return exact Phase 24 quarantines for the current Fleet run/base."""

    from agent.fleet_context_scope import get_fleet_context

    context = get_fleet_context()
    if context is None:
        return set()
    report = load_base_overlay_compatibility(
        agent_instance_id=context.agent_instance_id,
        base_manifest_digest=context.base_manifest_digest,
    )
    if report is None:
        return set()
    result: set[str] = set()
    for item in report.get("skills", []):
        if type(item) is not dict:
            raise FleetBaseOverlayError("base overlay report skill is invalid")
        if item.get("status") == "quarantined":
            result.add(_name(item.get("name"), "quarantined skill name"))
    return result


__all__ = [
    "FleetBaseOverlayError",
    "assess_base_overlay_compatibility",
    "load_base_overlay_compatibility",
    "quarantined_promoted_skill_names",
]
