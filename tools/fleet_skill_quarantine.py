from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

import yaml

from agent.fleet_skill_learning_scope import FleetSkillLearningBinding
from agent.sensitive_interception import classify_sensitive_text
from tools import skills_guard
from tools.fleet_skill_candidates import (
    _CANDIDATE_SCHEMA,
    _METADATA_FILE,
    _bundle_manifest,
    _candidate_root,
    _command_inventory,
    _private_file,
    _write_metadata,
)

_SCANNER_VERSION = "fleet-skill-quarantine-v1"
_MAX_REASONS = 256
_FINAL_STATES = frozenset({"rejected", "needs-review", "verification-ready"})
_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,511}$")
_ALLOWED_TOOL_SPLIT_RE = re.compile(r"[\s,]+")
_NETWORK_RE = re.compile(
    r"(?i)(?:https?://|\b(?:curl|wget)\b|\b(?:requests|httpx?)\.(?:get|post|put|patch|delete)\s*\(|"
    r"\bsocket\.(?:create_connection|socket)\s*\(|\bgit\s+clone\b|\bdocker\s+pull\b)"
)
_HOST_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])(?P<path>/(?:etc|root|home|proc|sys|dev|run|media|mnt)(?:/[^\s`\"'<>]*)?)"
)
_WINDOWS_HOST_PATH_RE = re.compile(
    r"(?i)(?P<path>[A-Z]:\\(?:Users|Windows|ProgramData)(?:\\[^\s`\"'<>]*)?)"
)
_DOCKER_SOCKET_RE = re.compile(r"(?i)(?:/var/run/docker\.sock|/run/docker\.sock|docker\.sock)")
_AUTHORITY_PATTERNS = (
    (
        re.compile(
            r"(?i)\b(?:modify|replace|override|widen|grant|change|patch|edit|rewrite|forge)\s+(?:the\s+)?RunAuthority\b"
        ),
        "authority_run_authority_mutation",
        "attempts to modify or widen RunAuthority",
    ),
    (
        re.compile(
            r"(?i)\b(?:run_authority_hash|approval_budget|host_broker_grants|filesystem_grants|network_grant)\s*="
        ),
        "authority_field_assignment",
        "assigns a Fleet authority/control field",
    ),
    (
        re.compile(r"(?i)\b(?:export\s+)?(?:FLEET_|HERMES_|API_SERVER_KEY)[A-Z0-9_]*\s*="),
        "authority_control_environment",
        "attempts to set Fleet/Hermes control environment",
    ),
)
_HERMES_TOOL_CALLS = frozenset(
    {
        "terminal",
        "browser",
        "web_search",
        "computer",
        "memory",
        "skill_manage",
        "delegate_task",
        "cron",
        "send_message",
        "read_file",
        "write_file",
        "patch_file",
    }
)
_TOOL_CALL_RE = re.compile(
    r"\b(" + "|".join(sorted(re.escape(name) for name in _HERMES_TOOL_CALLS)) + r")\s*\("
)
_CRITICAL_COMMANDS = frozenset(
    {"mkfs", "fdisk", "parted", "shutdown", "reboot", "poweroff", "halt", "nsenter", "chroot"}
)
_REVIEW_COMMANDS = frozenset(
    {
        "sudo",
        "su",
        "mount",
        "umount",
        "docker",
        "podman",
        "kubectl",
        "systemctl",
        "service",
        "iptables",
        "nft",
        "dd",
        "chmod",
        "chown",
    }
)


class FleetSkillQuarantineError(RuntimeError):
    """A learned-skill candidate cannot be quarantined safely."""


@dataclass(frozen=True, slots=True, order=True)
class QuarantineReason:
    severity: str
    category: str
    code: str
    file: str
    line: int
    message: str

    def to_document(self) -> dict[str, object]:
        return {
            "code": self.code,
            "severity": self.severity,
            "category": self.category,
            "file": self.file,
            "line": self.line,
            "message": self.message,
        }


@dataclass(frozen=True, slots=True)
class FleetSkillQuarantineResult:
    candidate_id: str
    name: str
    state: str
    content_hash: str
    quarantine_digest: str
    reasons: tuple[QuarantineReason, ...]


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
        raise FleetSkillQuarantineError("quarantine data is not canonical JSON") from error


def _sha256(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _reason(
    code: str,
    severity: str,
    category: str,
    message: str,
    *,
    file: str = "candidate.json",
    line: int = 0,
) -> QuarantineReason:
    return QuarantineReason(severity, category, code, file, line, message)


def _sorted_reasons(reasons: Iterable[QuarantineReason]) -> tuple[QuarantineReason, ...]:
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    unique = {
        reason.code
        + "\0"
        + reason.file
        + "\0"
        + str(reason.line)
        + "\0"
        + reason.message: reason
        for reason in reasons
    }
    return tuple(
        sorted(
            unique.values(),
            key=lambda item: (
                rank.get(item.severity, 9),
                item.category,
                item.code,
                item.file,
                item.line,
                item.message,
            ),
        )[:_MAX_REASONS]
    )


def _load_metadata(candidate_dir: Path) -> dict[str, Any]:
    metadata_path = candidate_dir / _METADATA_FILE
    try:
        if metadata_path.is_symlink() or not metadata_path.is_file():
            raise FleetSkillQuarantineError("candidate metadata file is unsafe")
        value = json.loads(metadata_path.read_text(encoding="utf-8"))
    except FleetSkillQuarantineError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FleetSkillQuarantineError("candidate metadata is unreadable") from error
    if type(value) is not dict:
        raise FleetSkillQuarantineError("candidate metadata must be an object")
    return value


def _candidate_identity_document(metadata: Mapping[str, Any]) -> dict[str, object] | None:
    principal = metadata.get("principal")
    provenance = metadata.get("provenance")
    if type(principal) is not dict or type(provenance) is not dict:
        return None
    values = {
        "version": _CANDIDATE_SCHEMA,
        "principal_id": principal.get("principal_id"),
        "agent_instance_id": metadata.get("agent_instance_id"),
        "source_run": metadata.get("source_run"),
        "run_authority_hash": provenance.get("run_authority_hash"),
        "plan_fingerprint": provenance.get("plan_fingerprint"),
        "name": metadata.get("name"),
    }
    if any(type(value) is not str for value in values.values()):
        return None
    return values


def _validate_security_shell(metadata: Mapping[str, Any]) -> None:
    if metadata.get("active") is not False:
        raise FleetSkillQuarantineError("refusing to mutate a candidate marked active")
    if metadata.get("authority") != "none":
        raise FleetSkillQuarantineError("refusing to quarantine a candidate carrying authority")


def _baseline_reasons(
    candidate_dir: Path,
    metadata: Mapping[str, Any],
    observed_files: list[dict[str, object]],
    observed_hash: str,
    expected_binding: FleetSkillLearningBinding | None,
) -> list[QuarantineReason]:
    reasons: list[QuarantineReason] = []
    if metadata.get("schema") != _CANDIDATE_SCHEMA:
        reasons.append(
            _reason("provenance_schema", "critical", "provenance", "candidate schema is unsupported")
        )
    if metadata.get("state") != "quarantined":
        reasons.append(
            _reason(
                "provenance_initial_state",
                "critical",
                "provenance",
                "candidate was not in the initial quarantined state",
            )
        )
    risk = metadata.get("risk")
    if type(risk) is not dict or risk.get("state") != "unassessed":
        reasons.append(
            _reason(
                "provenance_risk_state",
                "critical",
                "provenance",
                "candidate risk state was not unassessed before quarantine",
            )
        )
    tests = metadata.get("tests")
    if type(tests) is not dict or tests.get("state") != "unverified":
        reasons.append(
            _reason(
                "provenance_verification_state",
                "critical",
                "provenance",
                "candidate verification state is invalid for Phase 16",
            )
        )

    principal = metadata.get("principal")
    scope = metadata.get("scope")
    provenance = metadata.get("provenance")
    evidence = metadata.get("evidence")
    if type(principal) is not dict:
        reasons.append(_reason("provenance_principal", "critical", "provenance", "principal metadata is missing"))
        principal = {}
    if type(scope) is not dict:
        reasons.append(_reason("scope_shape", "critical", "scope", "candidate scope metadata is missing"))
        scope = {}
    if type(provenance) is not dict:
        reasons.append(_reason("provenance_shape", "critical", "provenance", "candidate provenance is missing"))
        provenance = {}
    if type(evidence) is not dict:
        reasons.append(_reason("provenance_evidence", "critical", "provenance", "source-run evidence binding is missing"))
        evidence = {}

    principal_id = principal.get("principal_id")
    if type(principal_id) is not str or _HASH_RE.fullmatch(principal_id) is None:
        reasons.append(_reason("scope_principal_id", "critical", "scope", "principal ID is invalid"))
    generation = principal.get("generation")
    if isinstance(generation, bool) or type(generation) is not int or generation < 1:
        reasons.append(_reason("scope_principal_generation", "critical", "scope", "principal generation is invalid"))
    binding_hash = principal.get("binding_hash")
    if type(binding_hash) is not str or _HASH_RE.fullmatch(binding_hash) is None:
        reasons.append(_reason("scope_principal_binding", "critical", "scope", "principal binding hash is invalid"))
    if scope.get("kind") != "principal" or scope.get("scope_id") != principal_id:
        reasons.append(
            _reason(
                "scope_not_private",
                "critical",
                "scope",
                "Phase 16 candidate scope is not exact principal-private scope",
            )
        )

    source_run = metadata.get("source_run")
    if type(source_run) is not str or _IDENTIFIER_RE.fullmatch(source_run) is None:
        reasons.append(_reason("provenance_source_run", "critical", "provenance", "source run is invalid"))
    agent_instance_id = metadata.get("agent_instance_id")
    if type(agent_instance_id) is not str or _HASH_RE.fullmatch(agent_instance_id) is None:
        reasons.append(_reason("provenance_agent_instance", "critical", "provenance", "Agent Instance ID is invalid"))

    for key in (
        "run_authority_hash",
        "recipe_hash",
        "resolved_recipe_hash",
        "plan_fingerprint",
        "capabilities_hash",
        "target_digest",
    ):
        value = provenance.get(key)
        if type(value) is not str or _HASH_RE.fullmatch(value) is None:
            reasons.append(
                _reason(
                    f"provenance_{key}",
                    "critical",
                    "provenance",
                    f"{key} is invalid",
                )
            )
    if evidence.get("state") != "source-run-bound" or evidence.get("run_authority_hash") != provenance.get("run_authority_hash"):
        reasons.append(
            _reason(
                "provenance_evidence_mismatch",
                "critical",
                "provenance",
                "source-run evidence does not bind the same RunAuthority",
            )
        )

    identity = _candidate_identity_document(metadata)
    if identity is None:
        reasons.append(_reason("provenance_candidate_identity", "critical", "provenance", "candidate identity cannot be reconstructed"))
    else:
        expected_id = _sha256(_canonical(identity))
        if metadata.get("candidate_id") != expected_id or candidate_dir.name != expected_id.removeprefix("sha256:"):
            reasons.append(
                _reason(
                    "provenance_candidate_id_mismatch",
                    "critical",
                    "provenance",
                    "candidate ID does not match exact principal/run/authority/plan identity",
                )
            )

    if metadata.get("files") != observed_files:
        reasons.append(
            _reason(
                "provenance_manifest_mismatch",
                "critical",
                "provenance",
                "candidate file manifest changed after Phase 15 persistence",
            )
        )
    if metadata.get("content_hash") != observed_hash:
        reasons.append(
            _reason(
                "provenance_content_hash_mismatch",
                "critical",
                "provenance",
                "candidate content hash changed after Phase 15 persistence",
            )
        )
    observed_commands = _command_inventory(candidate_dir)
    if metadata.get("commands") != observed_commands:
        reasons.append(
            _reason(
                "provenance_command_inventory_mismatch",
                "critical",
                "provenance",
                "candidate command inventory does not match the exact bundle",
            )
        )

    if expected_binding is not None:
        expected_principal = {
            "principal_id": expected_binding.principal_id,
            "kind": expected_binding.principal_kind,
            "generation": expected_binding.principal_generation,
            "binding_hash": expected_binding.principal_binding_hash,
        }
        expected_scope = {
            "kind": expected_binding.scope_kind,
            "scope_id": expected_binding.scope_id,
        }
        expected_provenance = {
            "run_authority_hash": expected_binding.run_authority_hash,
            "recipe_hash": expected_binding.recipe_hash,
            "resolved_recipe_hash": expected_binding.resolved_recipe_hash,
            "plan_fingerprint": expected_binding.plan_fingerprint,
            "capabilities_hash": expected_binding.capabilities_hash,
            "target_digest": expected_binding.target_digest,
        }
        if principal != expected_principal:
            reasons.append(
                _reason(
                    "provenance_principal_mismatch",
                    "critical",
                    "provenance",
                    "candidate principal metadata differs from the exact source-run binding",
                )
            )
        if scope != expected_scope:
            reasons.append(
                _reason(
                    "provenance_scope_mismatch",
                    "critical",
                    "provenance",
                    "candidate scope differs from the exact source-run binding",
                )
            )
        if metadata.get("source_run") != expected_binding.source_run:
            reasons.append(
                _reason(
                    "provenance_source_run_mismatch",
                    "critical",
                    "provenance",
                    "candidate source run differs from the exact source-run binding",
                )
            )
        if metadata.get("agent_instance_id") != expected_binding.agent_instance_id:
            reasons.append(
                _reason(
                    "provenance_agent_instance_mismatch",
                    "critical",
                    "provenance",
                    "candidate Agent Instance differs from the exact source-run binding",
                )
            )
        for key, expected_value in expected_provenance.items():
            if provenance.get(key) != expected_value:
                reasons.append(
                    _reason(
                        f"provenance_binding_{key}_mismatch",
                        "critical",
                        "provenance",
                        f"candidate {key} differs from the exact source-run binding",
                    )
                )
        if metadata.get("tools") != list(expected_binding.toolsets):
            reasons.append(
                _reason(
                    "provenance_tools_mismatch",
                    "critical",
                    "provenance",
                    "candidate tool envelope differs from the exact source run",
                )
            )
        if metadata.get("filesystem_needs") != [
            item.to_request() for item in expected_binding.filesystem_needs
        ]:
            reasons.append(
                _reason(
                    "provenance_filesystem_mismatch",
                    "critical",
                    "provenance",
                    "candidate filesystem envelope differs from the exact source run",
                )
            )
        if metadata.get("network_needs") != {
            "mode": expected_binding.network_mode,
            "policy_hash": expected_binding.network_policy_hash,
        }:
            reasons.append(
                _reason(
                    "provenance_network_mismatch",
                    "critical",
                    "provenance",
                    "candidate network envelope differs from the exact source run",
                )
            )
        if metadata.get("secret_needs") != list(
            expected_binding.secret_need_fingerprints
        ):
            reasons.append(
                _reason(
                    "provenance_secret_needs_mismatch",
                    "critical",
                    "provenance",
                    "candidate protected-material need fingerprints differ from the exact source run",
                )
            )
    return reasons


def _text_files(candidate_dir: Path, observed_files: Iterable[Mapping[str, object]]) -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    for item in observed_files:
        rel = item.get("path")
        if type(rel) is not str:
            continue
        path = candidate_dir / rel
        if path.name != "SKILL.md" and path.suffix.lower() not in skills_guard.SCANNABLE_EXTENSIONS:
            continue
        try:
            result.append((rel, path.read_text(encoding="utf-8")))
        except (OSError, UnicodeDecodeError):
            continue
    return result


def _guard_reasons(candidate_dir: Path, observed_files: Iterable[Mapping[str, object]]) -> list[QuarantineReason]:
    reasons: list[QuarantineReason] = []
    file_count = 0
    total_bytes = 0
    for item in observed_files:
        rel = item.get("path")
        size = item.get("bytes")
        if type(rel) is not str or type(size) is not int:
            continue
        file_count += 1
        total_bytes += size
        suffix = Path(rel).suffix.lower()
        if suffix in skills_guard.SUSPICIOUS_BINARY_EXTENSIONS:
            reasons.append(
                _reason(
                    "guard_suspicious_binary",
                    "high",
                    "binary",
                    "candidate contains a suspicious executable/binary file type",
                    file=rel,
                )
            )
        remaining = max(0, _MAX_REASONS - len(reasons))
        guard_findings = skills_guard.scan_file(candidate_dir / rel, rel)
        for finding in guard_findings[:remaining]:
            reasons.append(
                _reason(
                    f"guard_{finding.pattern_id}",
                    finding.severity,
                    finding.category,
                    finding.description,
                    file=finding.file,
                    line=finding.line,
                )
            )
        if len(guard_findings) > remaining or len(reasons) >= _MAX_REASONS:
            reasons.append(
                _reason(
                    "guard_findings_overflow",
                    "critical",
                    "structure",
                    "candidate exceeded the bounded quarantine finding budget; exhaustive assessment is unavailable",
                    file=rel,
                )
            )
            break
    if file_count > skills_guard.MAX_FILE_COUNT:
        reasons.append(
            _reason(
                "guard_file_count",
                "high",
                "structure",
                "candidate exceeds the normal Hermes skill file-count threshold",
            )
        )
    if total_bytes > skills_guard.MAX_TOTAL_SIZE_KB * 1024:
        reasons.append(
            _reason(
                "guard_total_size",
                "high",
                "structure",
                "candidate exceeds the normal Hermes skill size threshold",
            )
        )
    return reasons


def _sensitive_reasons(text_files: Iterable[tuple[str, str]]) -> list[QuarantineReason]:
    reasons: list[QuarantineReason] = []
    for rel, text in text_files:
        findings, _redacted, uncertain = classify_sensitive_text(text)
        if uncertain:
            reasons.append(
                _reason(
                    "secret_classification_uncertain",
                    "critical",
                    "secret",
                    "sensitive-content classification was unavailable",
                    file=rel,
                )
            )
        for finding in findings:
            reasons.append(
                _reason(
                    f"secret_{finding.kind}",
                    "critical",
                    "secret",
                    "candidate contains sensitive material that must not become learned skill content",
                    file=rel,
                )
            )
    return reasons


def _frontmatter_allowed_tools(skill_text: str) -> tuple[tuple[str, ...], bool]:
    if not skill_text.startswith("---"):
        return (), False
    match = re.search(r"\n---\s*\n", skill_text[3:])
    if not match:
        return (), False
    try:
        parsed = yaml.safe_load(skill_text[3 : match.start() + 3])
    except yaml.YAMLError:
        return (), False
    if not isinstance(parsed, dict):
        return (), False
    raw = parsed.get("allowed-tools")
    if not isinstance(raw, str):
        return (), False
    raw_tokens = [token for token in _ALLOWED_TOOL_SPLIT_RE.split(raw.strip()) if token]
    overflow = len(raw_tokens) > _MAX_REASONS or any(
        len(token) > 128 for token in raw_tokens
    )
    return tuple(token[:128] for token in raw_tokens[:_MAX_REASONS]), overflow


def _tool_reasons(metadata: Mapping[str, Any], text_files: Iterable[tuple[str, str]]) -> list[QuarantineReason]:
    reasons: list[QuarantineReason] = []
    source_tools = metadata.get("tools")
    if type(source_tools) is not list or any(type(item) is not str for item in source_tools):
        return [
            _reason(
                "tool_source_envelope_invalid",
                "critical",
                "tool",
                "source-run tool envelope is invalid",
            )
        ]
    source = set(source_tools)
    filesystem = metadata.get("filesystem_needs")
    filesystem_items = filesystem if type(filesystem) is list else []
    has_read = bool(filesystem_items)
    has_write = any(type(item) is dict and item.get("mode") == "read-write" for item in filesystem_items)

    skill_text = next((text for rel, text in text_files if rel == "SKILL.md"), "")
    declared_tools, declaration_overflow = _frontmatter_allowed_tools(skill_text)
    if declaration_overflow:
        reasons.append(
            _reason(
                "tool_declaration_overflow",
                "critical",
                "tool",
                "allowed-tools declaration exceeds the bounded quarantine assessment surface",
            )
        )
    for declared in declared_tools:
        base = declared.split("(", 1)[0].strip().lower()
        if base in {"bash", "shell", "terminal", "fleet-terminal"}:
            if "fleet-terminal" not in source:
                reasons.append(
                    _reason("tool_terminal_undeclared", "high", "tool", "skill declares terminal access absent from the source run")
                )
        elif base in {"read"}:
            if not has_read:
                reasons.append(
                    _reason("tool_read_undeclared", "high", "tool", "skill declares file-read access absent from the source run")
                )
        elif base in {"write", "edit"}:
            if not has_write:
                reasons.append(
                    _reason("tool_write_undeclared", "high", "tool", "skill declares file-write access absent from the source run")
                )
        else:
            reasons.append(
                _reason(
                    "tool_unknown_declaration",
                    "high",
                    "tool",
                    f"skill declares tool '{base}' that is not present in the source-run envelope",
                )
            )

    for rel, text in text_files:
        for line_no, line in enumerate(text.splitlines(), start=1):
            if len(reasons) >= _MAX_REASONS:
                return reasons
            for match in _TOOL_CALL_RE.finditer(line):
                name = match.group(1)
                if name == "terminal" and "fleet-terminal" in source:
                    continue
                if name == "read_file" and has_read:
                    continue
                if name in {"write_file", "patch_file"} and has_write:
                    continue
                reasons.append(
                    _reason(
                        f"tool_call_{name}_undeclared",
                        "high",
                        "tool",
                        f"skill references Hermes tool '{name}' outside the source-run tool envelope",
                        file=rel,
                        line=line_no,
                    )
                )
    return reasons


def _network_reasons(metadata: Mapping[str, Any], text_files: Iterable[tuple[str, str]]) -> list[QuarantineReason]:
    network = metadata.get("network_needs")
    if type(network) is not dict or type(network.get("mode")) is not str or type(network.get("policy_hash")) is not str:
        return [_reason("network_envelope_invalid", "critical", "network", "source-run network envelope is invalid")]
    mode = network["mode"]
    if _HASH_RE.fullmatch(network["policy_hash"]) is None:
        return [_reason("network_policy_hash_invalid", "critical", "network", "source-run network policy hash is invalid")]
    reasons: list[QuarantineReason] = []
    for rel, text in text_files:
        for line_no, line in enumerate(text.splitlines(), start=1):
            if len(reasons) >= _MAX_REASONS:
                return reasons
            if _NETWORK_RE.search(line) is None:
                continue
            if mode == "none":
                severity = "high"
                code = "network_requirement_undeclared"
                message = "skill requires network behavior but the source run had no network grant"
            elif mode in {"provider-only", "project-allowlist"}:
                severity = "high"
                code = "network_requirement_needs_review"
                message = "skill contains network behavior whose destination cannot be proven from the opaque source-run policy hash"
            else:
                severity = "low"
                code = "network_requirement_declared"
                message = "skill contains network behavior under an explicitly approved source-run internet mode"
            reasons.append(_reason(code, severity, "network", message, file=rel, line=line_no))
    return reasons


def _host_path_reasons(text_files: Iterable[tuple[str, str]]) -> list[QuarantineReason]:
    reasons: list[QuarantineReason] = []
    for rel, text in text_files:
        for line_no, line in enumerate(text.splitlines(), start=1):
            if len(reasons) >= _MAX_REASONS:
                return reasons
            if _DOCKER_SOCKET_RE.search(line):
                reasons.append(
                    _reason(
                        "host_docker_socket",
                        "critical",
                        "host_path",
                        "skill references a Docker socket or equivalent host-control path",
                        file=rel,
                        line=line_no,
                    )
                )
            for pattern in (_HOST_PATH_RE, _WINDOWS_HOST_PATH_RE):
                if pattern.search(line):
                    reasons.append(
                        _reason(
                            "host_protected_path",
                            "high",
                            "host_path",
                            "skill references a protected host-style filesystem path",
                            file=rel,
                            line=line_no,
                        )
                    )
                    break
    return reasons


def _authority_reasons(text_files: Iterable[tuple[str, str]]) -> list[QuarantineReason]:
    reasons: list[QuarantineReason] = []
    for rel, text in text_files:
        for line_no, line in enumerate(text.splitlines(), start=1):
            if len(reasons) >= _MAX_REASONS:
                return reasons
            for pattern, code, message in _AUTHORITY_PATTERNS:
                if pattern.search(line):
                    reasons.append(
                        _reason(code, "critical", "authority", message, file=rel, line=line_no)
                    )
    return reasons


def _command_reasons(metadata: Mapping[str, Any]) -> list[QuarantineReason]:
    commands = metadata.get("commands")
    if type(commands) is not list or any(type(item) is not str for item in commands):
        return [_reason("command_inventory_invalid", "critical", "command", "candidate command inventory is invalid")]
    reasons: list[QuarantineReason] = []
    for command in sorted(set(commands)):
        lowered = command.lower()
        if lowered in _CRITICAL_COMMANDS:
            reasons.append(
                _reason(
                    f"command_{lowered}",
                    "critical",
                    "command",
                    f"candidate uses dangerous command '{lowered}'",
                    file="SKILL.md",
                )
            )
        elif lowered in _REVIEW_COMMANDS:
            reasons.append(
                _reason(
                    f"command_{lowered}",
                    "high",
                    "command",
                    f"candidate uses privileged or host-affecting command '{lowered}'",
                    file="SKILL.md",
                )
            )
    return reasons


def _classification(reasons: Iterable[QuarantineReason]) -> str:
    severities = {reason.severity for reason in reasons}
    if "critical" in severities:
        return "rejected"
    if "high" in severities:
        return "needs-review"
    return "verification-ready"


def _existing_result(metadata: Mapping[str, Any], observed_hash: str) -> FleetSkillQuarantineResult:
    state = metadata.get("state")
    risk = metadata.get("risk")
    quarantine = metadata.get("quarantine")
    if state not in _FINAL_STATES or type(risk) is not dict or type(quarantine) is not dict:
        raise FleetSkillQuarantineError("candidate quarantine state is invalid")
    if quarantine.get("scanner") != _SCANNER_VERSION or quarantine.get("immutable") is not True:
        raise FleetSkillQuarantineError("candidate quarantine record is unsupported")
    if (
        quarantine.get("content_hash") != observed_hash
        or quarantine.get("bundle_id") != observed_hash
    ):
        raise FleetSkillQuarantineError("immutable quarantined candidate content changed")
    if risk.get("state") != state or risk.get("scanner") != _SCANNER_VERSION:
        raise FleetSkillQuarantineError("candidate quarantine risk record is inconsistent")
    raw_reasons = risk.get("reasons")
    if type(raw_reasons) is not list:
        raise FleetSkillQuarantineError("candidate quarantine reasons are invalid")
    reasons: list[QuarantineReason] = []
    for item in raw_reasons:
        if type(item) is not dict:
            raise FleetSkillQuarantineError("candidate quarantine reason shape is invalid")
        try:
            reasons.append(
                QuarantineReason(
                    severity=item["severity"],
                    category=item["category"],
                    code=item["code"],
                    file=item["file"],
                    line=item["line"],
                    message=item["message"],
                )
            )
        except KeyError as error:
            raise FleetSkillQuarantineError("candidate quarantine reason is incomplete") from error
    ordered = _sorted_reasons(reasons)
    reason_documents = [reason.to_document() for reason in ordered]
    if reason_documents != raw_reasons:
        raise FleetSkillQuarantineError("candidate quarantine reason order/content changed")
    reason_digest = _sha256(_canonical(reason_documents))
    if risk.get("reason_digest") != reason_digest:
        raise FleetSkillQuarantineError("candidate quarantine reason digest changed")
    digest = quarantine.get("digest")
    if type(digest) is not str or _HASH_RE.fullmatch(digest) is None:
        raise FleetSkillQuarantineError("candidate quarantine digest is invalid")
    expected_digest = _sha256(
        _canonical(
            {
                "scanner": _SCANNER_VERSION,
                "candidate_id": metadata.get("candidate_id"),
                "content_hash": observed_hash,
                "state": state,
                "reason_digest": reason_digest,
            }
        )
    )
    if digest != expected_digest:
        raise FleetSkillQuarantineError("candidate quarantine seal changed")
    return FleetSkillQuarantineResult(
        candidate_id=str(metadata.get("candidate_id", "")),
        name=str(metadata.get("name", "")),
        state=state,
        content_hash=observed_hash,
        quarantine_digest=digest,
        reasons=tuple(reasons),
    )


def quarantine_skill_candidate(
    candidate_dir: Path,
    *,
    expected_binding: FleetSkillLearningBinding | None = None,
) -> FleetSkillQuarantineResult:
    """Classify and freeze one Phase 15 candidate without touching active skills."""
    metadata = _load_metadata(candidate_dir)
    _validate_security_shell(metadata)
    observed_files, observed_hash = _bundle_manifest(candidate_dir)
    if metadata.get("state") in _FINAL_STATES:
        return _existing_result(metadata, observed_hash)

    text_files = _text_files(candidate_dir, observed_files)
    reasons = _baseline_reasons(
        candidate_dir,
        metadata,
        observed_files,
        observed_hash,
        expected_binding,
    )
    reasons.extend(_guard_reasons(candidate_dir, observed_files))
    reasons.extend(_sensitive_reasons(text_files))
    reasons.extend(_command_reasons(metadata))
    reasons.extend(_tool_reasons(metadata, text_files))
    reasons.extend(_network_reasons(metadata, text_files))
    reasons.extend(_host_path_reasons(text_files))
    reasons.extend(_authority_reasons(text_files))
    ordered = _sorted_reasons(reasons)
    state = _classification(ordered)
    reason_documents = [reason.to_document() for reason in ordered]
    reason_digest = _sha256(_canonical(reason_documents))
    quarantine_digest = _sha256(
        _canonical(
            {
                "scanner": _SCANNER_VERSION,
                "candidate_id": metadata.get("candidate_id"),
                "content_hash": observed_hash,
                "state": state,
                "reason_digest": reason_digest,
            }
        )
    )

    updated = dict(metadata)
    updated["state"] = state
    updated["risk"] = {
        "state": state,
        "scanner": _SCANNER_VERSION,
        "reason_digest": reason_digest,
        "reasons": reason_documents,
    }
    updated["quarantine"] = {
        "scanner": _SCANNER_VERSION,
        "bundle_id": observed_hash,
        "content_hash": observed_hash,
        "digest": quarantine_digest,
        "immutable": True,
    }
    _write_metadata(candidate_dir, updated)
    _private_file(candidate_dir / _METADATA_FILE)
    return FleetSkillQuarantineResult(
        candidate_id=str(updated.get("candidate_id", "")),
        name=str(updated.get("name", "")),
        state=state,
        content_hash=observed_hash,
        quarantine_digest=quarantine_digest,
        reasons=ordered,
    )


def _matches_binding(metadata: Mapping[str, Any], binding: FleetSkillLearningBinding) -> bool:
    principal = metadata.get("principal")
    provenance = metadata.get("provenance")
    return (
        type(principal) is dict
        and type(provenance) is dict
        and principal.get("principal_id") == binding.principal_id
        and principal.get("kind") == binding.principal_kind
        and principal.get("generation") == binding.principal_generation
        and principal.get("binding_hash") == binding.principal_binding_hash
        and metadata.get("agent_instance_id") == binding.agent_instance_id
        and metadata.get("source_run") == binding.source_run
        and provenance.get("run_authority_hash") == binding.run_authority_hash
        and provenance.get("plan_fingerprint") == binding.plan_fingerprint
    )


def quarantine_candidates_for_binding(
    binding: FleetSkillLearningBinding,
) -> tuple[FleetSkillQuarantineResult, ...]:
    """Freeze all candidates authored under one exact Fleet learning binding."""
    if type(binding) is not FleetSkillLearningBinding:
        raise FleetSkillQuarantineError("Fleet skill-learning binding is invalid")
    root = _candidate_root()
    results: list[FleetSkillQuarantineResult] = []
    for candidate_dir in sorted(path for path in root.iterdir() if path.is_dir() and not path.is_symlink()):
        try:
            metadata = _load_metadata(candidate_dir)
        except FleetSkillQuarantineError:
            # Unknown/corrupt candidates remain hidden and inactive. They are not
            # eligible for verification or promotion and therefore fail closed.
            continue
        if not _matches_binding(metadata, binding):
            continue
        results.append(
            quarantine_skill_candidate(candidate_dir, expected_binding=binding)
        )
    return tuple(results)


__all__ = [
    "FleetSkillQuarantineError",
    "FleetSkillQuarantineResult",
    "QuarantineReason",
    "quarantine_candidates_for_binding",
    "quarantine_skill_candidate",
]
