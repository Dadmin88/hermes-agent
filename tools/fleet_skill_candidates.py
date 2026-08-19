from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import stat
from pathlib import Path
from typing import Any

from agent.fleet_skill_learning_scope import FleetSkillLearningBinding
from utils import atomic_write_text

_CANDIDATE_SCHEMA = "fleet-skill-candidate-v1"
_CANDIDATE_ROOT = ".fleet"
_CANDIDATES_DIR = "candidates"
_METADATA_FILE = "candidate.json"
_MAX_COMMANDS = 64
_MAX_FILES = 128
_MAX_BUNDLE_BYTES = 4 * 1024 * 1024
_SHELL_FENCE_RE = re.compile(
    r"```(?:bash|sh|shell|zsh)\s*\n(?P<body>.*?)```", re.IGNORECASE | re.DOTALL
)
_SHELL_CONTROL = frozenset(
    {
        "if",
        "then",
        "else",
        "elif",
        "fi",
        "for",
        "while",
        "until",
        "do",
        "done",
        "case",
        "esac",
        "function",
        "time",
        "exec",
        "export",
        "readonly",
        "local",
    }
)


class FleetSkillCandidateError(RuntimeError):
    """A Fleet-scoped learned-skill candidate cannot be persisted safely."""


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
        raise FleetSkillCandidateError("candidate metadata is not canonical JSON") from error


def _sha256(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _candidate_id(binding: FleetSkillLearningBinding, name: str) -> str:
    return _sha256(
        _canonical(
            {
                "version": _CANDIDATE_SCHEMA,
                "principal_id": binding.principal_id,
                "agent_instance_id": binding.agent_instance_id,
                "source_run": binding.source_run,
                "run_authority_hash": binding.run_authority_hash,
                "plan_fingerprint": binding.plan_fingerprint,
                "name": name,
            }
        )
    )


def _private_dir(path: Path, *, create: bool = False) -> Path:
    try:
        if create:
            path.mkdir(parents=False, exist_ok=True)
        info = path.lstat()
    except OSError as error:
        raise FleetSkillCandidateError("candidate directory is unavailable") from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise FleetSkillCandidateError("candidate directory is unsafe")
    try:
        path.chmod(0o700)
    except OSError as error:
        raise FleetSkillCandidateError("candidate directory permissions are unsafe") from error
    return path


def _private_file(path: Path) -> None:
    try:
        info = path.lstat()
    except OSError as error:
        raise FleetSkillCandidateError("candidate file is unavailable") from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise FleetSkillCandidateError("candidate file is unsafe")
    try:
        path.chmod(0o600)
    except OSError as error:
        raise FleetSkillCandidateError("candidate file permissions are unsafe") from error


def _candidate_root() -> Path:
    from tools import skill_manager_tool as sm

    skills = sm._skills_dir()
    if not skills.exists():
        try:
            skills.mkdir(parents=True, exist_ok=True)
        except OSError as error:
            raise FleetSkillCandidateError("skills directory is unavailable") from error
    fleet = skills / _CANDIDATE_ROOT
    if not fleet.exists() and not fleet.is_symlink():
        _private_dir(fleet, create=True)
    else:
        _private_dir(fleet)
    candidates = fleet / _CANDIDATES_DIR
    if not candidates.exists() and not candidates.is_symlink():
        _private_dir(candidates, create=True)
    else:
        _private_dir(candidates)
    return candidates


def _candidate_dir(binding: FleetSkillLearningBinding, name: str) -> Path:
    return _candidate_root() / _candidate_id(binding, name).removeprefix("sha256:")


def _safe_regular_file(path: Path, *, root: Path) -> os.stat_result:
    try:
        resolved_root = root.resolve()
        resolved = path.resolve()
        resolved.relative_to(resolved_root)
        info = path.lstat()
    except (OSError, ValueError) as error:
        raise FleetSkillCandidateError("candidate file path is unsafe") from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise FleetSkillCandidateError("candidate bundle contains a non-regular file")
    return info


def _copy_active_skill(source: Path, destination: Path) -> str:
    try:
        source_root = source.resolve()
    except OSError as error:
        raise FleetSkillCandidateError("source skill cannot be resolved") from error
    if not (source_root / "SKILL.md").is_file():
        raise FleetSkillCandidateError("source skill is missing SKILL.md")
    _private_dir(destination, create=True)
    source_files: list[dict[str, object]] = []
    total = 0
    for entry in sorted(source_root.rglob("*")):
        try:
            rel = entry.relative_to(source_root)
            info = entry.lstat()
        except OSError as error:
            raise FleetSkillCandidateError("source skill cannot be inspected") from error
        if stat.S_ISLNK(info.st_mode):
            raise FleetSkillCandidateError("source skill contains a path redirect")
        target = destination / rel
        if stat.S_ISDIR(info.st_mode):
            target.mkdir(parents=True, exist_ok=True)
            _private_dir(target)
            continue
        if not stat.S_ISREG(info.st_mode):
            raise FleetSkillCandidateError("source skill contains a non-regular file")
        payload = entry.read_bytes()
        total += len(payload)
        if len(source_files) >= _MAX_FILES or total > _MAX_BUNDLE_BYTES:
            raise FleetSkillCandidateError("source skill exceeds candidate bundle bounds")
        target.parent.mkdir(parents=True, exist_ok=True)
        _private_dir(target.parent)
        target.write_bytes(payload)
        _private_file(target)
        source_files.append(
            {
                "path": rel.as_posix(),
                "sha256": _sha256(payload),
                "bytes": len(payload),
            }
        )
    return _sha256(_canonical(source_files))


def _bundle_manifest(candidate_dir: Path) -> tuple[list[dict[str, object]], str]:
    files: list[dict[str, object]] = []
    total = 0
    for path in sorted(candidate_dir.rglob("*")):
        if path.name == _METADATA_FILE:
            continue
        try:
            info = path.lstat()
        except OSError as error:
            raise FleetSkillCandidateError("candidate bundle cannot be inspected") from error
        if stat.S_ISDIR(info.st_mode):
            continue
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise FleetSkillCandidateError("candidate bundle contains an unsafe entry")
        payload = path.read_bytes()
        total += len(payload)
        if len(files) >= _MAX_FILES or total > _MAX_BUNDLE_BYTES:
            raise FleetSkillCandidateError("candidate bundle exceeds supported bounds")
        files.append(
            {
                "path": path.relative_to(candidate_dir).as_posix(),
                "sha256": _sha256(payload),
                "bytes": len(payload),
            }
        )
    if not any(item["path"] == "SKILL.md" for item in files):
        raise FleetSkillCandidateError("candidate bundle is missing SKILL.md")
    return files, _sha256(_canonical(files))


def _command_inventory(candidate_dir: Path) -> list[str]:
    commands: set[str] = set()
    skill_md = candidate_dir / "SKILL.md"
    try:
        text = skill_md.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise FleetSkillCandidateError("candidate SKILL.md is unreadable") from error
    snippets = [match.group("body") for match in _SHELL_FENCE_RE.finditer(text)]
    scripts = candidate_dir / "scripts"
    if scripts.is_dir():
        for path in sorted(scripts.rglob("*.sh")):
            _safe_regular_file(path, root=candidate_dir)
            try:
                snippets.append(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError) as error:
                raise FleetSkillCandidateError("candidate shell script is unreadable") from error
    for snippet in snippets:
        for raw_line in snippet.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            line = re.sub(r"^[A-Za-z_][A-Za-z0-9_]*=[^\s]+\s+", "", line)
            try:
                words = shlex.split(line, comments=True, posix=True)
            except ValueError:
                continue
            if not words:
                continue
            index = 0
            while index < len(words) and words[index] in {"sudo", "env", "command", "builtin"}:
                index += 1
            if index >= len(words):
                continue
            token = words[index]
            if token in _SHELL_CONTROL or token.startswith(("$", "-")):
                continue
            command = Path(token).name
            if re.fullmatch(r"[A-Za-z0-9_.+-]{1,128}", command):
                commands.add(command)
            if len(commands) >= _MAX_COMMANDS:
                break
        if len(commands) >= _MAX_COMMANDS:
            break
    return sorted(commands)


def _metadata_document(
    *,
    binding: FleetSkillLearningBinding,
    name: str,
    category: str | None,
    candidate_dir: Path,
    proposed_action: str,
    source_skill_hash: str | None,
    absorbed_into: str | None,
) -> dict[str, object]:
    files, content_hash = _bundle_manifest(candidate_dir)
    return {
        "schema": _CANDIDATE_SCHEMA,
        "candidate_id": _candidate_id(binding, name),
        "name": name,
        "category": category,
        "state": "quarantined",
        "active": False,
        "authority": "none",
        "principal": {
            "principal_id": binding.principal_id,
            "kind": binding.principal_kind,
            "generation": binding.principal_generation,
            "binding_hash": binding.principal_binding_hash,
        },
        "scope": {"kind": binding.scope_kind, "scope_id": binding.scope_id},
        "source_run": binding.source_run,
        "agent_instance_id": binding.agent_instance_id,
        "provenance": {
            "origin": "background_review",
            "run_authority_hash": binding.run_authority_hash,
            "recipe_hash": binding.recipe_hash,
            "resolved_recipe_hash": binding.resolved_recipe_hash,
            "plan_fingerprint": binding.plan_fingerprint,
            "capabilities_hash": binding.capabilities_hash,
            "target_digest": binding.target_digest,
            "source_skill_hash": source_skill_hash,
            "proposed_action": proposed_action,
            "absorbed_into": absorbed_into,
        },
        "commands": _command_inventory(candidate_dir),
        "tools": list(binding.toolsets),
        "filesystem_needs": [
            item.to_request() for item in binding.filesystem_needs
        ],
        "network_needs": {
            "mode": binding.network_mode,
            "policy_hash": binding.network_policy_hash,
        },
        "secret_needs": list(binding.secret_need_fingerprints),
        "risk": {"state": "unassessed", "next_phase": 16},
        "content_hash": content_hash,
        "files": files,
        "evidence": {
            "state": "source-run-bound",
            "run_authority_hash": binding.run_authority_hash,
        },
        "tests": {"state": "unverified", "results": [], "next_phase": 17},
    }


def _write_metadata(candidate_dir: Path, document: dict[str, object]) -> None:
    metadata_path = candidate_dir / _METADATA_FILE
    atomic_write_text(
        metadata_path,
        json.dumps(document, ensure_ascii=True, sort_keys=True, indent=2) + "\n",
    )
    _private_file(metadata_path)


def _load_existing_metadata(candidate_dir: Path) -> dict[str, Any] | None:
    path = candidate_dir / _METADATA_FILE
    if not path.exists():
        return None
    _safe_regular_file(path, root=candidate_dir)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FleetSkillCandidateError("candidate metadata is unreadable") from error
    if type(value) is not dict or value.get("schema") != _CANDIDATE_SCHEMA:
        raise FleetSkillCandidateError("candidate metadata schema is invalid")
    principal = value.get("principal")
    scope = value.get("scope")
    provenance = value.get("provenance")
    if (
        type(principal) is not dict
        or type(scope) is not dict
        or type(provenance) is not dict
        or value.get("state") != "quarantined"
        or value.get("active") is not False
        or value.get("authority") != "none"
    ):
        raise FleetSkillCandidateError("candidate metadata security state is invalid")
    return value


def _ensure_candidate(
    *,
    binding: FleetSkillLearningBinding,
    name: str,
    action: str,
    category: str | None,
) -> tuple[Path, str | None, str | None]:
    from tools import skill_manager_tool as sm

    candidate_dir = _candidate_dir(binding, name)
    _candidate_root()
    if candidate_dir.exists() or candidate_dir.is_symlink():
        _private_dir(candidate_dir)
    existing_metadata = _load_existing_metadata(candidate_dir) if candidate_dir.exists() else None
    if existing_metadata is not None:
        principal = existing_metadata["principal"]
        scope = existing_metadata["scope"]
        provenance = existing_metadata["provenance"]
        if (
            existing_metadata.get("candidate_id") != _candidate_id(binding, name)
            or existing_metadata.get("name") != name
            or principal.get("principal_id") != binding.principal_id
            or principal.get("kind") != binding.principal_kind
            or principal.get("generation") != binding.principal_generation
            or principal.get("binding_hash") != binding.principal_binding_hash
            or scope != {"kind": binding.scope_kind, "scope_id": binding.scope_id}
            or existing_metadata.get("source_run") != binding.source_run
            or existing_metadata.get("agent_instance_id") != binding.agent_instance_id
            or provenance.get("run_authority_hash") != binding.run_authority_hash
            or provenance.get("recipe_hash") != binding.recipe_hash
            or provenance.get("resolved_recipe_hash") != binding.resolved_recipe_hash
            or provenance.get("plan_fingerprint") != binding.plan_fingerprint
            or provenance.get("capabilities_hash") != binding.capabilities_hash
            or provenance.get("target_digest") != binding.target_digest
        ):
            raise FleetSkillCandidateError("candidate identity changed")
        return (
            candidate_dir,
            cast_optional_string(existing_metadata.get("category")),
            cast_optional_string(
                existing_metadata.get("provenance", {}).get("source_skill_hash")
                if isinstance(existing_metadata.get("provenance"), dict)
                else None
            ),
        )

    if action == "create":
        if sm._find_skill(name) is not None:
            raise FleetSkillCandidateError(
                f"an active skill named '{name}' already exists; propose an edit instead"
            )
        _private_dir(candidate_dir, create=True)
        return candidate_dir, category, None

    existing = sm._find_skill(name)
    if existing is None:
        raise FleetSkillCandidateError(f"active skill '{name}' was not found")
    source = Path(existing["path"])
    source_hash = _copy_active_skill(source, candidate_dir)
    try:
        relative = source.relative_to(sm._skills_dir())
        detected_category = relative.parts[-2] if len(relative.parts) > 1 else None
    except ValueError:
        detected_category = None
    return candidate_dir, detected_category, source_hash


def cast_optional_string(value: object) -> str | None:
    return value if type(value) is str else None


def _patch_text(
    text: str, old_string: str, new_string: str, replace_all: bool
) -> tuple[str, int]:
    count = text.count(old_string)
    if count == 0:
        raise FleetSkillCandidateError("patch target was not found in candidate")
    if count > 1 and not replace_all:
        raise FleetSkillCandidateError(
            "patch target appears multiple times; set replace_all=true to continue"
        )
    if replace_all:
        return text.replace(old_string, new_string), count
    return text.replace(old_string, new_string, 1), 1


def route_fleet_skill_candidate_write(
    *,
    action: str,
    name: str,
    content: str | None,
    category: str | None,
    file_path: str | None,
    file_content: str | None,
    old_string: str | None,
    new_string: str | None,
    replace_all: bool,
    absorbed_into: str | None,
) -> dict[str, object] | None:
    """Route Fleet-scoped autonomous learning into an inactive native skill candidate.

    Foreground/user-directed writes and non-Fleet background reviews return None
    and continue through the normal Hermes skill-management path.
    """
    from agent.fleet_skill_learning_scope import get_fleet_skill_learning
    from tools import skill_manager_tool as sm
    from tools.skill_provenance import is_background_review

    binding = get_fleet_skill_learning()
    if binding is None or not is_background_review():
        return None
    if action not in {"create", "edit", "patch", "delete", "write_file", "remove_file"}:
        return None

    name_error = sm._validate_name(name)
    if name_error:
        return {"success": False, "error": name_error}
    category_error = sm._validate_category(category)
    if category_error:
        return {"success": False, "error": category_error}

    candidate_dir: Path | None = None
    try:
        candidate_dir, candidate_category, source_skill_hash = _ensure_candidate(
            binding=binding,
            name=name,
            action=action,
            category=category,
        )
        skill_md = candidate_dir / "SKILL.md"
        if action == "create":
            if not content:
                raise FleetSkillCandidateError("content is required for candidate creation")
            validation = sm._validate_frontmatter(content, new_skill=True)
            if validation:
                raise FleetSkillCandidateError(validation)
            validation = sm._validate_content_size(content)
            if validation:
                raise FleetSkillCandidateError(validation)
            sensitive = sm._sensitive_skill_error(content, file_path="SKILL.md")
            if sensitive:
                raise FleetSkillCandidateError(sensitive)
            atomic_write_text(skill_md, content)
            _private_file(skill_md)
        elif action == "edit":
            if not content:
                raise FleetSkillCandidateError("content is required for candidate edit")
            validation = sm._validate_frontmatter(content, new_skill=False)
            if validation:
                raise FleetSkillCandidateError(validation)
            validation = sm._validate_content_size(content)
            if validation:
                raise FleetSkillCandidateError(validation)
            sensitive = sm._sensitive_skill_error(content, file_path="SKILL.md")
            if sensitive:
                raise FleetSkillCandidateError(sensitive)
            atomic_write_text(skill_md, content)
            _private_file(skill_md)
        elif action == "patch":
            if not old_string:
                raise FleetSkillCandidateError("old_string is required for candidate patch")
            if new_string is None:
                raise FleetSkillCandidateError("new_string is required for candidate patch")
            target_label = file_path or "SKILL.md"
            if file_path:
                validation = sm._validate_file_path(file_path)
                if validation:
                    raise FleetSkillCandidateError(validation)
                target, validation = sm._resolve_skill_target(candidate_dir, file_path)
                if validation or target is None:
                    raise FleetSkillCandidateError(validation or "candidate path is invalid")
            else:
                target = skill_md
            _safe_regular_file(target, root=candidate_dir)
            try:
                current = target.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as error:
                raise FleetSkillCandidateError("candidate patch target is unreadable") from error
            updated, match_count = _patch_text(
                current, old_string, new_string, replace_all
            )
            if target.name == "SKILL.md":
                validation = sm._validate_frontmatter(updated, new_skill=False)
                if validation:
                    raise FleetSkillCandidateError(validation)
                validation = sm._validate_content_size(updated)
                if validation:
                    raise FleetSkillCandidateError(validation)
            elif len(updated.encode("utf-8")) > sm.MAX_SKILL_FILE_BYTES:
                raise FleetSkillCandidateError("candidate supporting file exceeds size limit")
            sensitive = sm._sensitive_skill_error(updated, file_path=target_label)
            if sensitive:
                raise FleetSkillCandidateError(sensitive)
            atomic_write_text(target, updated)
            _private_file(target)
        elif action == "write_file":
            if not file_path:
                raise FleetSkillCandidateError("file_path is required for candidate write")
            if file_content is None:
                raise FleetSkillCandidateError("file_content is required for candidate write")
            validation = sm._validate_file_path(file_path)
            if validation:
                raise FleetSkillCandidateError(validation)
            if Path(file_path).name == "SKILL.md":
                raise FleetSkillCandidateError("use edit/patch for candidate SKILL.md")
            if len(file_content.encode("utf-8")) > sm.MAX_SKILL_FILE_BYTES:
                raise FleetSkillCandidateError("candidate supporting file exceeds size limit")
            sensitive = sm._sensitive_skill_error(file_content, file_path=file_path)
            if sensitive:
                raise FleetSkillCandidateError(sensitive)
            target, validation = sm._resolve_skill_target(candidate_dir, file_path)
            if validation or target is None:
                raise FleetSkillCandidateError(validation or "candidate path is invalid")
            target.parent.mkdir(parents=True, exist_ok=True)
            _private_dir(target.parent)
            atomic_write_text(target, file_content)
            _private_file(target)
        elif action == "remove_file":
            if not file_path:
                raise FleetSkillCandidateError("file_path is required for candidate removal")
            validation = sm._validate_file_path(file_path)
            if validation:
                raise FleetSkillCandidateError(validation)
            if Path(file_path).name == "SKILL.md":
                raise FleetSkillCandidateError("candidate SKILL.md cannot be removed")
            target, validation = sm._resolve_skill_target(candidate_dir, file_path)
            if validation or target is None:
                raise FleetSkillCandidateError(validation or "candidate path is invalid")
            _safe_regular_file(target, root=candidate_dir)
            target.unlink()
            parent = target.parent
            while parent != candidate_dir and parent.exists() and not any(parent.iterdir()):
                parent.rmdir()
                parent = parent.parent
        elif action == "delete":
            # Keep an immutable-enough native snapshot as the proposal body. Later
            # promotion policy decides whether an active skill can actually vanish.
            pass
        else:
            raise FleetSkillCandidateError("candidate action is unsupported")

        metadata = _metadata_document(
            binding=binding,
            name=name,
            category=candidate_category,
            candidate_dir=candidate_dir,
            proposed_action=action,
            source_skill_hash=source_skill_hash,
            absorbed_into=absorbed_into,
        )
        _write_metadata(candidate_dir, metadata)
        return {
            "success": True,
            "candidate": True,
            "candidate_id": metadata["candidate_id"],
            "state": "quarantined",
            "active": False,
            "scope": metadata["scope"],
            "content_hash": metadata["content_hash"],
            "message": (
                f"Skill candidate '{name}' recorded privately and quarantined; "
                "it is not active and grants no authority."
            ),
            "_change": {
                "kind": "candidate",
                "action": action,
                "description": "private quarantined skill candidate",
            },
        }
    except FleetSkillCandidateError as error:
        if candidate_dir is not None and not (candidate_dir / _METADATA_FILE).exists():
            # A newly seeded candidate that failed before metadata was committed is
            # not a valid candidate. Remove only the deterministic hidden directory.
            try:
                shutil.rmtree(candidate_dir)
            except OSError:
                pass
        return {"success": False, "error": str(error), "candidate": True}


__all__ = ["FleetSkillCandidateError", "route_fleet_skill_candidate_write"]
