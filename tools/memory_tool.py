#!/usr/bin/env python3
"""
Memory Tool Module - Persistent Curated Memory

Provides bounded, file-backed memory that persists across sessions. Two stores:
  - MEMORY.md: agent's personal notes and observations (environment facts, project
    conventions, tool quirks, things learned)
  - USER.md: what the agent knows about the user (preferences, communication style,
    expectations, workflow habits)

Both are injected into the system prompt as a frozen snapshot at session start.
Mid-session writes update files on disk immediately (durable) but do NOT change
the system prompt -- this preserves the prefix cache for the entire session.
The snapshot refreshes on the next session start.

Entry delimiter: § (section sign). Entries can be multiline.
Character limits (not tokens) because char counts are model-independent.

Design:
- Single `memory` tool with action parameter: add, replace, remove
- replace/remove use short unique substring matching (not full text or IDs)
- Behavioral guidance lives in the tool schema description
- Frozen snapshot pattern: system prompt is stable, tool responses show live state
"""

import hashlib
import json
import logging
import os
import re
import stat
import time
from contextlib import contextmanager
from pathlib import Path
from hermes_constants import get_hermes_home, get_process_hermes_home
from typing import Dict, Any, List, Optional, Tuple

from agent.fleet_memory_scope import (
    FleetMemoryBinding,
    FleetMemoryScopeRef,
    get_fleet_memory,
)
from utils import atomic_write_text

# fcntl is Unix-only; on Windows use msvcrt for file locking
msvcrt = None
try:
    import fcntl
except ImportError:
    fcntl = None
    try:
        import msvcrt
    except ImportError:
        pass

logger = logging.getLogger(__name__)

# Where memory files live — resolved dynamically so profile overrides
# (HERMES_HOME env var changes) are always respected.  The old module-level
# constant was cached at import time and could go stale if a profile switch
# happened after the first import.
def get_memory_dir() -> Path:
    """Return the profile-scoped memories directory."""
    return get_hermes_home() / "memories"


def get_fleet_memory_root() -> Path:
    """Return the process-wide native memory root shared across Hermes profiles."""
    return get_process_hermes_home() / "memories" / _FLEET_MEMORY_DIR

# Stable header prefixes for the system-prompt memory blocks rendered by
# MemoryStore._render_block. Exported so compression's prompt-retention check
# (agent/conversation_compression.py) can detect a leftover block for a
# target whose entries have since been emptied — keep in lockstep with
# _render_block below.
MEMORY_BLOCK_HEADERS = {
    "memory": "MEMORY (your personal notes)",
    "user": "USER PROFILE (who the user is)",
}

ENTRY_DELIMITER = "\n§\n"

FLEET_MEMORY_META_SCHEMA = "fleet.memory-entry-metadata.v1"
FLEET_MEMORY_SCOPE_SCHEMA = "fleet.memory-scope-directory.v1"
_FLEET_MEMORY_DIR = "fleet-v1"
_FLEET_META_SUFFIX = ".fleet-meta.json"
_FLEET_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_FLEET_ALLOWED_SENSITIVITY = frozenset({"private", "internal", "shared"})
_FLEET_ALLOWED_TRUST = frozenset({"run-derived", "operator", "promoted"})
_FLEET_ALLOWED_PROMOTION = frozenset({"private", "promoted"})


# ---------------------------------------------------------------------------
# Memory content scanning — lightweight check for injection/exfiltration
# in content that gets injected into the system prompt.
#
# Patterns live in ``tools/threat_patterns.py`` — the single source of truth
# shared with the context-file scanner and the tool-result delimiter system.
# Memory uses the "strict" scope (broadest pattern set) because:
#  - memory entries are user-curated; the user can rewrite a flagged entry
#  - memory enters the system prompt as a FROZEN snapshot, so a poisoned
#    entry persists for the entire session and across sessions until
#    explicitly removed.
# ---------------------------------------------------------------------------

from tools.threat_patterns import first_threat_message as _first_threat_message


def _scan_memory_content(content: str) -> Optional[str]:
    """Scan memory content for injection/exfil patterns. Returns error string if blocked."""
    return _first_threat_message(content, scope="strict")


def _sensitive_persistence_error(content: str) -> Optional[str]:
    """Block credential-bearing memory before any durable write."""
    try:
        from agent.sensitive_interception import (
            SensitiveInterceptionError,
            require_persistable_text,
        )

        require_persistable_text(content, sink="memory")
    except SensitiveInterceptionError as error:
        return str(error)
    except Exception:
        return "Memory persistence classification is unavailable; refusing the write."
    return None


def _drift_error(path: "Path", bak_path: str) -> Dict[str, Any]:
    """Build the error dict returned when external drift is detected.

    The on-disk memory file contains content that wouldn't round-trip
    through the tool's parser/serializer — flushing would discard the
    appended/edited content from a patch tool, shell append, manual edit,
    or sister-session write. We refuse the mutation, point the operator at
    the .bak.<ts> snapshot we took, and tell them what to do next.
    """
    return {
        "success": False,
        "error": (
            f"Refusing to write {path.name}: file on disk has content that "
            f"wouldn't round-trip through the memory tool (likely added by "
            f"the patch tool, a shell append, a manual edit, or a "
            f"concurrent session). A snapshot was saved to {bak_path}. "
            f"Resolve the drift first — either rewrite the file as a clean "
            f"§-delimited list of entries, or move the extra content out — "
            f"then retry. This guard exists to prevent silent data loss "
            f"(issue #26045)."
        ),
        "drift_backup": bak_path,
        "remediation": (
            "Open the .bak file, integrate the missing entries into the "
            "memory tool one at a time via memory(action=add, content=...), "
            "then remove or rewrite the original file to a clean state."
        ),
    }


# Sentinel returned by ``_reload_target`` when the target file EXISTS but could
# not be read. Distinct from a drift-backup path (``str``) and from a clean
# reload (``None``): the caller must abort the mutation rather than persist over
# an unreadable file.
_READ_FAILED = object()


def _read_failed_error(path: "Path") -> Dict[str, Any]:
    """Build the error dict returned when the on-disk memory file is unreadable.

    A file that exists but cannot be read is NOT an empty store. Reading it as
    ``[]`` and then persisting would rewrite the whole file from an empty entry
    list — wiping the user's memory. We refuse the write so nothing is lost.
    """
    return {
        "success": False,
        "error": (
            f"Refusing to write {path.name}: the file exists on disk but could "
            f"not be read right now (temporarily locked by another program, a "
            f"permission change, invalid/corrupt text encoding, or a filesystem "
            f"error). Treating an unreadable file as empty and saving would wipe "
            f"existing memory, so the write is refused. Nothing was changed — "
            f"retry in a moment."
        ),
    }


class MemoryStore:
    """
    Bounded curated memory with file persistence. One instance per AIAgent.

    Maintains two parallel states:
      - _system_prompt_snapshot: frozen at load time, used for system prompt injection.
        Never mutated mid-session. Keeps prefix cache stable.
      - memory_entries / user_entries: live state, mutated by tool calls, persisted to disk.
        Tool responses always reflect this live state.
    """

    # After this many failed consolidation attempts (overflow / zero-match) in
    # ONE turn, stop instructing the model to "retry in this turn" and return a
    # terminal "save skipped" result so a fragile replace/add can't loop the
    # turn to budget exhaustion and suppress the user's reply (issue #42405).
    _MAX_CONSOLIDATION_FAILURES_PER_TURN = 3

    def __init__(self, memory_char_limit: int = 2200, user_char_limit: int = 1375):
        self.memory_entries: List[str] = []
        self.user_entries: List[str] = []
        self.memory_char_limit = memory_char_limit
        self.user_char_limit = user_char_limit
        self._fleet_memory: Optional[FleetMemoryBinding] = get_fleet_memory()
        # Frozen snapshot for system prompt -- set once at load_from_disk()
        self._system_prompt_snapshot: Dict[str, str] = {"memory": "", "user": ""}
        # Per-turn counter of failed at-capacity consolidation attempts; reset
        # at each turn boundary by reset_consolidation_failures() (#42405).
        self._consolidation_failures = 0

    def reset_consolidation_failures(self) -> None:
        """Reset the per-turn consolidation-failure counter (call at turn start)."""
        self._consolidation_failures = 0

    def _consolidation_failure(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """Count an at-capacity consolidation failure and degrade gracefully.

        Under the per-turn cap, return ``response`` unchanged (it already tells
        the model how to self-correct + retry in this turn). Once the cap is
        exceeded, drop the retry instruction and return a TERMINAL result so the
        model stops looping memory calls and proceeds to answer the user — a
        failed memory side effect must never block the turn's reply (#42405).
        """
        self._consolidation_failures += 1
        if self._consolidation_failures <= self._MAX_CONSOLIDATION_FAILURES_PER_TURN:
            return response
        return {
            "success": False,
            "done": True,
            "error": (
                f"Memory consolidation failed {self._consolidation_failures} times "
                "this turn. Stop retrying memory calls — leave memory unchanged for "
                "now and continue with your reply to the user. The fact can be saved "
                "in a later turn."
            ),
        }

    def load_from_disk(self):
        """Load entries from MEMORY.md and USER.md, capture system prompt snapshot.

        The frozen snapshot is what enters the system prompt. We scan each
        entry for injection/promptware patterns at snapshot-build time —
        ANY hit replaces the entry text in the snapshot with a placeholder
        like ``[BLOCKED: …]``, so a poisoned-on-disk memory file (supply
        chain, compromised tool, sister-session write) cannot inject into
        the system prompt.

        The live ``memory_entries`` / ``user_entries`` lists keep the
        original text so the user can still SEE poisoned entries via
        see poisoned entries by inspecting the source files directly, and remove them — silently dropping them would hide the attack from the user.

        Scanning is deterministic from disk bytes, so the snapshot remains
        stable for the entire session (prefix-cache invariant holds).
        """
        if self._fleet_memory is not None:
            self._load_fleet_scoped()
            return

        mem_dir = get_memory_dir()
        mem_dir.mkdir(parents=True, exist_ok=True)
        self.memory_entries = self._read_file(mem_dir / "MEMORY.md")
        self.user_entries = self._read_file(mem_dir / "USER.md")

        # Deduplicate entries (preserves order, keeps first occurrence)
        self.memory_entries = list(dict.fromkeys(self.memory_entries))
        self.user_entries = list(dict.fromkeys(self.user_entries))

        # Sanitize entries for the system-prompt snapshot only.  Live state
        # (memory_entries / user_entries) keeps the raw text so the user
        # can see + remove poisoned entries via the memory tool.
        sanitized_memory = self._sanitize_entries_for_snapshot(self.memory_entries, "MEMORY.md")
        sanitized_user = self._sanitize_entries_for_snapshot(self.user_entries, "USER.md")

        # Capture frozen snapshot for system prompt injection
        self._system_prompt_snapshot = {
            "memory": self._render_block("memory", sanitized_memory),
            "user": self._render_block("user", sanitized_user),
        }

    @staticmethod
    def _sanitize_entries_for_snapshot(entries: List[str], filename: str) -> List[str]:
        """Return ``entries`` with any threat-matching entry replaced by a placeholder.

        Each entry is scanned with the shared threat-pattern library at the
        ``"strict"`` scope (same as memory writes).  On match, the entry is
        replaced in the returned list with ``"[BLOCKED: <filename> entry
        contained threat pattern: <ids>. Removed from system prompt.]"`` —
        the placeholder enters the snapshot, the original entry stays in
        live state for the user to inspect and delete.

        Empty or already-block-marker entries pass through unchanged.
        """
        from tools.threat_patterns import scan_for_threats

        sanitized: List[str] = []
        for entry in entries:
            if not entry or entry.startswith("[BLOCKED:"):
                sanitized.append(entry)
                continue
            findings = scan_for_threats(entry, scope="strict")
            if findings:
                logger.warning(
                    "Memory entry from %s blocked at load time: %s",
                    filename, ", ".join(findings),
                )
                sanitized.append(
                    f"[BLOCKED: {filename} entry contained threat pattern(s): "
                    f"{', '.join(findings)}. Removed from system prompt; "
                    f"use memory(action=remove) "
                    f"to delete the original.]"
                )
            else:
                sanitized.append(entry)
        return sanitized

    @staticmethod
    @contextmanager
    def _file_lock(path: Path):
        """Acquire an exclusive file lock for read-modify-write safety.

        Uses a separate .lock file so the memory file itself can still be
        atomically replaced via os.replace().
        """
        lock_path = path.with_suffix(path.suffix + ".lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True)

        if fcntl is None and msvcrt is None:
            yield
            return

        fd = open(lock_path, "a+", encoding="utf-8")
        try:
            if fcntl:
                fcntl.flock(fd, fcntl.LOCK_EX)
            else:
                fd.seek(0)
                msvcrt.locking(fd.fileno(), msvcrt.LK_LOCK, 1)
            yield
        finally:
            if fcntl:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                except (OSError, IOError):
                    pass
            elif msvcrt:
                try:
                    fd.seek(0)
                    msvcrt.locking(fd.fileno(), msvcrt.LK_UNLCK, 1)
                except (OSError, IOError):
                    pass
            fd.close()

    @staticmethod
    def _entry_hash(content: str) -> str:
        return "sha256:" + hashlib.sha256(content.encode("utf-8")).hexdigest()

    @staticmethod
    def _now_ms() -> int:
        return int(time.time() * 1000)

    @staticmethod
    def _target_filename(target: str) -> str:
        return "USER.md" if target == "user" else "MEMORY.md"

    @staticmethod
    def _metadata_filename(target: str) -> str:
        return MemoryStore._target_filename(target) + _FLEET_META_SUFFIX

    @staticmethod
    def _require_no_symlink_components(path: Path) -> None:
        if not path.is_absolute() or ".." in path.parts:
            raise RuntimeError("Fleet memory path is unsafe")
        normalized = Path(os.path.abspath(os.fspath(path)))
        current = Path(normalized.anchor)
        try:
            identity = current.lstat()
            for component in normalized.parts[1:]:
                current /= component
                if not current.exists() and not current.is_symlink():
                    break
                identity = current.lstat()
                if stat.S_ISLNK(identity.st_mode):
                    raise RuntimeError("Fleet memory path contains a symbolic link")
                if current != normalized and not stat.S_ISDIR(identity.st_mode):
                    raise RuntimeError("Fleet memory path component is not a directory")
        except OSError as error:
            raise RuntimeError("Fleet memory path is unsafe") from error

    @staticmethod
    def _owned_by_current_process(identity: os.stat_result) -> bool:
        getter = getattr(os, "geteuid", None)
        if getter is None:
            return True
        return identity.st_uid == getter()

    @staticmethod
    def _require_private_directory(path: Path) -> None:
        MemoryStore._require_no_symlink_components(path)
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        MemoryStore._require_no_symlink_components(path)
        identity = path.lstat()
        if (
            stat.S_ISLNK(identity.st_mode)
            or not stat.S_ISDIR(identity.st_mode)
            or not MemoryStore._owned_by_current_process(identity)
        ):
            raise RuntimeError("Fleet memory directory is unsafe")
        if os.name != "nt":
            os.chmod(path, 0o700, follow_symlinks=False)
        verified = path.lstat()
        if (
            stat.S_ISLNK(verified.st_mode)
            or not stat.S_ISDIR(verified.st_mode)
            or not MemoryStore._owned_by_current_process(verified)
            or (os.name != "nt" and stat.S_IMODE(verified.st_mode) != 0o700)
        ):
            raise RuntimeError("Fleet memory directory permissions are unsafe")

    @staticmethod
    def _require_private_file(path: Path, *, allow_missing: bool = True) -> bool:
        MemoryStore._require_no_symlink_components(path)
        try:
            identity = path.lstat()
        except FileNotFoundError:
            if allow_missing:
                return False
            raise RuntimeError("Fleet memory file is missing") from None
        except OSError as error:
            raise RuntimeError("Fleet memory file is unsafe") from error
        if (
            stat.S_ISLNK(identity.st_mode)
            or not stat.S_ISREG(identity.st_mode)
            or not MemoryStore._owned_by_current_process(identity)
            or identity.st_nlink != 1
        ):
            raise RuntimeError("Fleet memory file is unsafe")
        if os.name != "nt":
            os.chmod(path, 0o600, follow_symlinks=False)
        verified = path.lstat()
        if (
            stat.S_ISLNK(verified.st_mode)
            or not stat.S_ISREG(verified.st_mode)
            or not MemoryStore._owned_by_current_process(verified)
            or verified.st_nlink != 1
            or (os.name != "nt" and stat.S_IMODE(verified.st_mode) != 0o600)
        ):
            raise RuntimeError("Fleet memory file permissions are unsafe")
        return True

    def _scope_dir(self, scope: FleetMemoryScopeRef) -> Path:
        fleet_root = get_fleet_memory_root()
        root = fleet_root.parent
        kind_root = fleet_root / scope.kind
        path = kind_root / scope.storage_key
        for directory in (root, fleet_root, kind_root, path):
            self._require_private_directory(directory)
        return path

    def _scope_descriptor_path(self, scope: FleetMemoryScopeRef) -> Path:
        return self._scope_dir(scope) / "SCOPE.json"

    def _metadata_path(self, target: str, scope: FleetMemoryScopeRef) -> Path:
        return self._scope_dir(scope) / self._metadata_filename(target)

    def _ensure_scope_descriptor(self, scope: FleetMemoryScopeRef) -> None:
        directory = self._scope_dir(scope)
        directory.mkdir(parents=True, exist_ok=True)
        descriptor = self._scope_descriptor_path(scope)
        expected = {
            "schema": FLEET_MEMORY_SCOPE_SCHEMA,
            "scope": scope.to_request(),
        }
        if self._require_private_file(descriptor):
            try:
                current = json.loads(descriptor.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as error:
                raise RuntimeError("Fleet memory scope descriptor is unreadable") from error
            if current != expected:
                raise RuntimeError("Fleet memory scope descriptor identity changed")
            return
        atomic_write_text(
            descriptor,
            json.dumps(expected, sort_keys=True, separators=(",", ":")),
            tmp_prefix=".fleet_scope_",
        )
        self._require_private_file(descriptor, allow_missing=False)

    def _read_fleet_metadata(
        self,
        target: str,
        scope: FleetMemoryScopeRef,
    ) -> Dict[str, Dict[str, Any]]:
        path = self._metadata_path(target, scope)
        if not self._require_private_file(path):
            return {}
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise RuntimeError("Fleet memory metadata is unreadable") from error
        if (
            type(document) is not dict
            or set(document) != {"schema", "scope", "entries"}
            or document.get("schema") != FLEET_MEMORY_META_SCHEMA
            or document.get("scope") != scope.to_request()
            or type(document.get("entries")) is not list
        ):
            raise RuntimeError("Fleet memory metadata shape is invalid")
        result: Dict[str, Dict[str, Any]] = {}
        expected_fields = {
            "content_hash",
            "owner_principal_id",
            "owner_principal_kind",
            "scope_kind",
            "scope_id",
            "source_run",
            "agent_instance_id",
            "sensitivity",
            "trust",
            "promotion_state",
            "retention_until_ms",
            "provenance",
            "created_at_ms",
            "updated_at_ms",
            "revoked_at_ms",
        }
        for item in document["entries"]:
            if type(item) is not dict or set(item) != expected_fields:
                raise RuntimeError("Fleet memory entry metadata shape is invalid")
            content_hash = item.get("content_hash")
            if type(content_hash) is not str or _FLEET_HASH_RE.fullmatch(content_hash) is None:
                raise RuntimeError("Fleet memory entry hash is invalid")
            if content_hash in result:
                raise RuntimeError("Fleet memory metadata contains duplicate entries")
            if item.get("scope_kind") != scope.kind or item.get("scope_id") != scope.scope_id:
                raise RuntimeError("Fleet memory metadata scope identity changed")
            if item.get("sensitivity") not in _FLEET_ALLOWED_SENSITIVITY:
                raise RuntimeError("Fleet memory sensitivity is invalid")
            if item.get("trust") not in _FLEET_ALLOWED_TRUST:
                raise RuntimeError("Fleet memory trust is invalid")
            if item.get("promotion_state") not in _FLEET_ALLOWED_PROMOTION:
                raise RuntimeError("Fleet memory promotion state is invalid")
            for field in ("created_at_ms", "updated_at_ms"):
                value = item.get(field)
                if isinstance(value, bool) or type(value) is not int or value < 1:
                    raise RuntimeError("Fleet memory timestamp is invalid")
            retention = item.get("retention_until_ms")
            revoked = item.get("revoked_at_ms")
            for value, label in ((retention, "retention"), (revoked, "revocation")):
                if value is not None and (
                    isinstance(value, bool) or type(value) is not int or value < 1
                ):
                    raise RuntimeError(f"Fleet memory {label} timestamp is invalid")
            result[content_hash] = dict(item)
        return result

    def _fleet_metadata_visible(
        self,
        metadata: Dict[str, Any],
        scope: FleetMemoryScopeRef,
        now_ms: int,
    ) -> bool:
        binding = self._fleet_memory
        if binding is None:
            return False
        if binding.retention_until_ms is not None and now_ms >= binding.retention_until_ms:
            return False
        if metadata.get("revoked_at_ms") is not None:
            return False
        retention = metadata.get("retention_until_ms")
        if retention is not None and now_ms >= retention:
            return False
        if metadata.get("trust") not in _FLEET_ALLOWED_TRUST:
            return False
        if metadata.get("sensitivity") not in _FLEET_ALLOWED_SENSITIVITY:
            return False
        promotion = metadata.get("promotion_state")
        if scope.kind == "principal":
            if promotion not in {"private", "promoted"}:
                return False
            if metadata.get("owner_principal_id") != binding.principal_id:
                return False
            if metadata.get("owner_principal_kind") != binding.principal_kind:
                return False
            if metadata.get("agent_instance_id") != binding.agent_instance_id:
                return False
        else:
            if promotion != "promoted":
                return False
            if scope.kind == "agent_instance" and scope.scope_id != binding.agent_instance_id:
                return False
        return True

    @staticmethod
    def _fleet_content_error(content: str) -> Optional[str]:
        try:
            from agent.redact import redact_sensitive_text

            if redact_sensitive_text(content, force=True) != content:
                return "Fleet scoped memory cannot persist credential or secret bodies."
        except Exception:
            return "Fleet scoped memory secret classification is unavailable."
        lowered = content.lower()
        if "fleet.run-authority.v1" in lowered or "run_authority_hash" in lowered:
            return "Fleet scoped memory cannot persist RunAuthority material."
        return None

    def _load_scope_candidates(
        self,
        target: str,
        scope: FleetMemoryScopeRef,
        *,
        now_ms: int,
    ) -> List[tuple[str, Dict[str, Any]]]:
        """Return raw content plus validated metadata for one authorized scope."""
        descriptor = self._scope_descriptor_path(scope)
        if not self._require_private_file(descriptor):
            return []
        try:
            self._ensure_scope_descriptor(scope)
            native_path = self._scope_dir(scope) / self._target_filename(target)
            if self._require_private_file(native_path):
                entries = self._read_file(native_path)
            else:
                entries = []
            metadata = self._read_fleet_metadata(target, scope)
        except Exception as error:
            logger.warning("Fleet scoped memory ignored for %s: %s", scope.kind, error)
            return []
        visible: List[tuple[str, Dict[str, Any]]] = []
        for entry in entries:
            item = metadata.get(self._entry_hash(entry))
            if item is None or not self._fleet_metadata_visible(item, scope, now_ms):
                continue
            if self._fleet_content_error(entry) is not None:
                continue
            visible.append((entry, item))
        return visible

    def _load_scope_entries(
        self,
        target: str,
        scope: FleetMemoryScopeRef,
        *,
        now_ms: int,
    ) -> List[str]:
        return [
            entry
            for entry, _metadata in self._load_scope_candidates(
                target,
                scope,
                now_ms=now_ms,
            )
        ]

    def _load_fleet_scoped(self) -> None:
        binding = self._fleet_memory
        if binding is None:
            return
        self._ensure_scope_descriptor(binding.write_scope)
        now_ms = self._now_ms()
        principal_memory = self._load_scope_entries("memory", binding.write_scope, now_ms=now_ms)
        principal_user = self._load_scope_entries("user", binding.write_scope, now_ms=now_ms)
        self.memory_entries = list(dict.fromkeys(principal_memory))
        self.user_entries = list(dict.fromkeys(principal_user))

        from agent.fleet_context_firewall import (
            FleetContextFirewallError,
            filter_fleet_memory_candidate,
            fleet_context_firewall_active,
        )

        if not fleet_context_firewall_active():
            # Phase 11 compatibility path. Older Fleet clients carry the scoped
            # memory binding but do not yet carry a Phase 12 context binding.
            # Preserve their already-proven filtering semantics exactly; Phase
            # 12 Fleet clients capability-negotiate and send fleet_context.
            snapshots: Dict[str, List[str]] = {"memory": [], "user": []}
            for scope in binding.read_scopes:
                for target in ("memory", "user"):
                    values = self._load_scope_entries(target, scope, now_ms=now_ms)
                    for value in values:
                        if value not in snapshots[target]:
                            snapshots[target].append(value)
            for target in ("memory", "user"):
                sanitized = self._sanitize_entries_for_snapshot(
                    snapshots[target],
                    self._target_filename(target),
                )
                limit = self._char_limit(target)
                bounded: List[str] = []
                used = 0
                for entry in sanitized:
                    extra = len(entry) + (len(ENTRY_DELIMITER) if bounded else 0)
                    if used + extra > limit:
                        break
                    bounded.append(entry)
                    used += extra
                self._system_prompt_snapshot[target] = self._render_block(
                    target,
                    bounded,
                )
            return

        snapshots: Dict[str, List[str]] = {"memory": [], "user": []}
        seen_hashes: Dict[str, set[str]] = {"memory": set(), "user": set()}
        for scope in binding.read_scopes:
            for target in ("memory", "user"):
                candidates = self._load_scope_candidates(target, scope, now_ms=now_ms)
                for content, metadata in candidates:
                    content_hash = metadata.get("content_hash")
                    if content_hash in seen_hashes[target]:
                        continue
                    try:
                        decision = filter_fleet_memory_candidate(
                            binding=binding,
                            scope=scope,
                            metadata=metadata,
                            content=content,
                            target=target,
                            now_ms=now_ms,
                        )
                    except FleetContextFirewallError as error:
                        logger.warning(
                            "Fleet context firewall rejected %s memory from %s: %s",
                            target,
                            scope.kind,
                            error,
                        )
                        continue
                    if decision.rendered is None or type(content_hash) is not str:
                        continue
                    seen_hashes[target].add(content_hash)
                    snapshots[target].append(decision.rendered)

        for target in ("memory", "user"):
            limit = self._char_limit(target)
            bounded: List[str] = []
            used = 0
            for entry in snapshots[target]:
                extra = len(entry) + (len(ENTRY_DELIMITER) if bounded else 0)
                if used + extra > limit:
                    break
                bounded.append(entry)
                used += extra
            self._system_prompt_snapshot[target] = self._render_block(target, bounded)

    def _path_for(self, target: str) -> Path:
        if self._fleet_memory is not None:
            self._ensure_scope_descriptor(self._fleet_memory.write_scope)
            return self._scope_dir(self._fleet_memory.write_scope) / self._target_filename(target)
        mem_dir = get_memory_dir()
        return mem_dir / self._target_filename(target)

    def _fleet_write_consistency_error(self, target: str) -> Optional[str]:
        binding = self._fleet_memory
        if binding is None:
            return None
        try:
            path = self._path_for(target)
            if self._require_private_file(path):
                entries = self._read_file(path)
            else:
                entries = []
            metadata = self._read_fleet_metadata(target, binding.write_scope)
        except Exception:
            return "Fleet scoped memory metadata is unavailable; refusing the write."
        hashes = {self._entry_hash(entry) for entry in entries}
        if hashes != set(metadata):
            return "Fleet scoped memory content/metadata drift detected; refusing the write."
        for item in metadata.values():
            if (
                item.get("owner_principal_id") != binding.principal_id
                or item.get("owner_principal_kind") != binding.principal_kind
                or item.get("agent_instance_id") != binding.agent_instance_id
                or item.get("scope_kind") != binding.write_scope.kind
                or item.get("scope_id") != binding.write_scope.scope_id
            ):
                return "Fleet scoped memory identity metadata changed; refusing the write."
        return None

    def _sync_fleet_metadata(self, target: str, entries: List[str]) -> None:
        binding = self._fleet_memory
        if binding is None:
            return
        scope = binding.write_scope
        self._ensure_scope_descriptor(scope)
        path = self._metadata_path(target, scope)
        try:
            existing = self._read_fleet_metadata(target, scope)
        except Exception:
            existing = {}
        now_ms = self._now_ms()
        documents: List[Dict[str, Any]] = []
        for entry in entries:
            content_hash = self._entry_hash(entry)
            current = existing.get(content_hash)
            if current is not None:
                documents.append(current)
                continue
            documents.append(
                {
                    "content_hash": content_hash,
                    "owner_principal_id": binding.principal_id,
                    "owner_principal_kind": binding.principal_kind,
                    "scope_kind": scope.kind,
                    "scope_id": scope.scope_id,
                    "source_run": binding.source_run,
                    "agent_instance_id": binding.agent_instance_id,
                    "sensitivity": "private",
                    "trust": "run-derived",
                    "promotion_state": "private",
                    "retention_until_ms": binding.retention_until_ms,
                    "provenance": "fleet-run-v1",
                    "created_at_ms": now_ms,
                    "updated_at_ms": now_ms,
                    "revoked_at_ms": None,
                }
            )
        document = {
            "schema": FLEET_MEMORY_META_SCHEMA,
            "scope": scope.to_request(),
            "entries": sorted(documents, key=lambda item: item["content_hash"]),
        }
        atomic_write_text(
            path,
            json.dumps(document, sort_keys=True, separators=(",", ":")),
            tmp_prefix=".fleet_meta_",
        )
        self._require_private_file(path, allow_missing=False)

    def _reload_target(self, target: str, *, skip_drift: bool = False):
        """Re-read entries from disk into in-memory state.

        Called under file lock to get the latest state before mutating.
        Returns the backup path if external drift was detected (the on-disk
        file contains content that wouldn't round-trip through our
        parser/serializer, OR an entry larger than the store's char limit).
        When drift is detected the caller must abort the mutation —
        flushing would discard the un-roundtrippable content.
        Returns ``None`` on clean reload.

        Returns the ``_READ_FAILED`` sentinel when the file EXISTS but could not
        be read. The caller MUST abort: the on-disk entries are unknown, so
        overwriting from an assumed-empty view would wipe them. This is the real
        exposure behind ``add`` — it skips the drift guard because appending is
        safe, but that reasoning only holds when the reload actually saw the
        file. A failed read reported as ``[]`` turned ``add`` into a full-file
        rewrite down to a single entry.

        When *skip_drift* is True the round-trip / entry-size check is
        bypassed.  Used by the ``add`` action which appends without
        rewriting, so existing content is never clobbered.
        """
        path = self._path_for(target)
        raw, read_ok = self._read_raw_checked(path)
        if not read_ok:
            # Leave in-memory entries untouched and tell the caller to abort;
            # persisting over an unreadable file would destroy it.
            return _READ_FAILED
        # Derive BOTH the drift check and the entry parse from the same raw
        # snapshot. The drift guard used to re-read the file itself and treat
        # a failed second read as "no drift" — so a read failure between the
        # checked reload and the drift check let replace/remove/apply_batch
        # rewrite the file from a stale view, silently discarding whatever an
        # external writer had just added. One read, one snapshot, no window.
        bak = None if skip_drift else self._detect_external_drift(target, raw)
        fresh = self._parse_entries(raw)
        fresh = list(dict.fromkeys(fresh))  # deduplicate
        if self._fleet_memory is not None:
            metadata = self._read_fleet_metadata(target, self._fleet_memory.write_scope)
            now_ms = self._now_ms()
            fresh = [
                entry
                for entry in fresh
                if (
                    (item := metadata.get(self._entry_hash(entry))) is not None
                    and self._fleet_metadata_visible(
                        item,
                        self._fleet_memory.write_scope,
                        now_ms,
                    )
                )
            ]
        self._set_entries(target, fresh)
        return bak

    def save_to_disk(self, target: str):
        """Persist entries to the appropriate file. Called after every mutation."""
        if self._fleet_memory is None:
            get_memory_dir().mkdir(parents=True, exist_ok=True)
        entries = self._entries_for(target)
        path = self._path_for(target)
        self._write_file(path, entries)
        if self._fleet_memory is not None:
            self._require_private_file(path, allow_missing=False)
            self._sync_fleet_metadata(target, entries)

    def _entries_for(self, target: str) -> List[str]:
        if target == "user":
            return self.user_entries
        return self.memory_entries

    def _set_entries(self, target: str, entries: List[str]):
        if target == "user":
            self.user_entries = entries
        else:
            self.memory_entries = entries

    def _char_count(self, target: str) -> int:
        entries = self._entries_for(target)
        if not entries:
            return 0
        return len(ENTRY_DELIMITER.join(entries))

    def _char_limit(self, target: str) -> int:
        if target == "user":
            return self.user_char_limit
        return self.memory_char_limit

    def add(self, target: str, content: str) -> Dict[str, Any]:
        """Append a new entry. Returns error if it would exceed the char limit."""
        content = content.strip()
        if not content:
            return {"success": False, "error": "Content cannot be empty."}
        consistency_error = self._fleet_write_consistency_error(target)
        if consistency_error:
            return {"success": False, "error": consistency_error}
        fleet_error = self._fleet_content_error(content) if self._fleet_memory else None
        if fleet_error:
            return {"success": False, "error": fleet_error}
        persistence_error = _sensitive_persistence_error(content)
        if persistence_error:
            return {"success": False, "error": persistence_error}

        # Scan for injection/exfiltration before accepting
        scan_error = _scan_memory_content(content)
        if scan_error:
            return {"success": False, "error": scan_error}

        with self._file_lock(self._path_for(target)):
            # Re-read from disk under lock to pick up writes from other sessions.
            # For add (append-only), we skip the drift guard — appending never
            # clobbers existing content, so round-trip mismatches from prior
            # tool-written entries in the same session are harmless.  The drift
            # guard remains active for replace/remove where full-file rewrite
            # would discard un-roundtrippable content (issue #26045).
            #
            # But "append never clobbers" only holds when the reload actually
            # read the file. add rewrites the WHOLE file from the parsed
            # entries, so a file that exists but read as empty (transient lock,
            # permission blip, I/O error) would be rewritten down to just the
            # new entry — wiping every prior memory. Refuse instead.
            if self._reload_target(target, skip_drift=True) is _READ_FAILED:
                return _read_failed_error(self._path_for(target))

            entries = self._entries_for(target)
            limit = self._char_limit(target)

            # Reject exact duplicates
            if content in entries:
                return self._success_response(target, "Entry already exists (no duplicate added).")

            # Calculate what the new total would be
            new_entries = entries + [content]
            new_total = len(ENTRY_DELIMITER.join(new_entries))

            if new_total > limit:
                current = self._char_count(target)
                return self._consolidation_failure({
                    "success": False,
                    "error": (
                        f"Memory at {current:,}/{limit:,} chars. "
                        f"Adding this entry ({len(content)} chars) would exceed the limit. "
                        f"Consolidate now: use 'replace' to merge overlapping entries into "
                        f"shorter ones or 'remove' stale or less important entries (see "
                        f"current_entries below), then retry this add — all in this turn."
                    ),
                    "current_entries": entries,
                    "usage": f"{current:,}/{limit:,}",
                })

            entries.append(content)
            self._set_entries(target, entries)
            self.save_to_disk(target)

        return self._success_response(target, "Entry added.")

    def replace(self, target: str, old_text: str, new_content: str) -> Dict[str, Any]:
        """Find entry containing old_text substring, replace it with new_content."""
        old_text = old_text.strip()
        new_content = new_content.strip()
        if not old_text:
            return {"success": False, "error": "old_text cannot be empty."}
        if not new_content:
            return {"success": False, "error": "new_content cannot be empty. Use 'remove' to delete entries."}
        consistency_error = self._fleet_write_consistency_error(target)
        if consistency_error:
            return {"success": False, "error": consistency_error}
        fleet_error = self._fleet_content_error(new_content) if self._fleet_memory else None
        if fleet_error:
            return {"success": False, "error": fleet_error}
        persistence_error = _sensitive_persistence_error(new_content)
        if persistence_error:
            return {"success": False, "error": persistence_error}

        # Scan replacement content for injection/exfiltration
        scan_error = _scan_memory_content(new_content)
        if scan_error:
            return {"success": False, "error": scan_error}

        with self._file_lock(self._path_for(target)):
            bak = self._reload_target(target)
            if bak is _READ_FAILED:
                return _read_failed_error(self._path_for(target))
            if bak:
                return _drift_error(self._path_for(target), bak)

            entries = self._entries_for(target)
            matches = [(i, e) for i, e in enumerate(entries) if old_text in e]

            if not matches:
                return self._consolidation_failure({
                    "success": False,
                    "error": f"No entry matched '{old_text}'. Check current_entries below and retry with the exact text of the entry you want to replace.",
                    "current_entries": entries,
                })

            if len(matches) > 1:
                # If all matches are identical (exact duplicates), operate on the first one
                unique_texts = {e for _, e in matches}
                if len(unique_texts) > 1:
                    previews = self._previews([e for _, e in matches])
                    return {
                        "success": False,
                        "error": f"Multiple entries matched '{old_text}'. Be more specific.",
                        "matches": previews,
                    }
                # All identical -- safe to replace just the first

            idx = matches[0][0]
            limit = self._char_limit(target)

            # Check that replacement doesn't blow the budget
            test_entries = entries.copy()
            test_entries[idx] = new_content
            new_total = len(ENTRY_DELIMITER.join(test_entries))

            if new_total > limit:
                current = self._char_count(target)
                return self._consolidation_failure({
                    "success": False,
                    "error": (
                        f"Replacement would put memory at {new_total:,}/{limit:,} chars. "
                        f"Shorten the new content, or 'remove' other stale or less important "
                        f"entries to make room (see current_entries below), then retry — all "
                        f"in this turn."
                    ),
                    "current_entries": entries,
                    "usage": f"{current:,}/{limit:,}",
                })

            entries[idx] = new_content
            self._set_entries(target, entries)
            self.save_to_disk(target)

        return self._success_response(target, "Entry replaced.")

    def remove(self, target: str, old_text: str) -> Dict[str, Any]:
        """Remove the entry containing old_text substring."""
        old_text = old_text.strip()
        if not old_text:
            return {"success": False, "error": "old_text cannot be empty."}
        consistency_error = self._fleet_write_consistency_error(target)
        if consistency_error:
            return {"success": False, "error": consistency_error}

        with self._file_lock(self._path_for(target)):
            bak = self._reload_target(target)
            if bak is _READ_FAILED:
                return _read_failed_error(self._path_for(target))
            if bak:
                return _drift_error(self._path_for(target), bak)

            entries = self._entries_for(target)
            matches = [(i, e) for i, e in enumerate(entries) if old_text in e]

            if not matches:
                return self._consolidation_failure({
                    "success": False,
                    "error": f"No entry matched '{old_text}'. Check current_entries below and retry with the exact text of the entry you want to remove.",
                    "current_entries": entries,
                })

            if len(matches) > 1:
                # If all matches are identical (exact duplicates), remove the first one
                unique_texts = {e for _, e in matches}
                if len(unique_texts) > 1:
                    previews = self._previews([e for _, e in matches])
                    return {
                        "success": False,
                        "error": f"Multiple entries matched '{old_text}'. Be more specific.",
                        "matches": previews,
                    }
                # All identical -- safe to remove just the first

            idx = matches[0][0]
            entries.pop(idx)
            self._set_entries(target, entries)
            self.save_to_disk(target)

        return self._success_response(target, "Entry removed.")

    def apply_batch(self, target: str, operations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Apply a sequence of add/replace/remove ops to one target atomically.

        All operations are validated and applied against the FINAL budget --
        intermediate overflow is irrelevant. This lets the model free space
        (remove/replace) and add new entries in a SINGLE tool call instead of
        the multi-turn consolidate-then-retry dance that re-sends the whole
        conversation context several times.

        Semantics: all-or-nothing. If any op is malformed, doesn't match, or
        the net result would exceed the char limit, NOTHING is written and an
        error is returned describing the first failure plus the live state.
        """
        if not operations:
            return {"success": False, "error": "operations list is empty."}
        consistency_error = self._fleet_write_consistency_error(target)
        if consistency_error:
            return {"success": False, "error": consistency_error}

        # Scan every add/replace content for injection/exfil BEFORE touching
        # disk -- a single poisoned op rejects the whole batch.
        for i, op in enumerate(operations):
            act = (op or {}).get("action")
            new_content = (op or {}).get("content")
            if act in {"add", "replace"} and new_content:
                if self._fleet_memory is not None:
                    fleet_error = self._fleet_content_error(new_content)
                    if fleet_error:
                        return {
                            "success": False,
                            "error": f"Operation {i + 1}: {fleet_error}",
                        }
                persistence_error = _sensitive_persistence_error(new_content)
                if persistence_error:
                    return {
                        "success": False,
                        "error": f"Operation {i + 1}: {persistence_error}",
                    }
                scan_error = _scan_memory_content(new_content)
                if scan_error:
                    return {"success": False, "error": f"Operation {i + 1}: {scan_error}"}

        with self._file_lock(self._path_for(target)):
            bak = self._reload_target(target)
            if bak is _READ_FAILED:
                return _read_failed_error(self._path_for(target))
            if bak:
                return _drift_error(self._path_for(target), bak)

            # Work on a copy; only commit if the whole batch validates.
            working: List[str] = list(self._entries_for(target))
            limit = self._char_limit(target)

            for i, op in enumerate(operations):
                op = op or {}
                act = op.get("action")
                content = (op.get("content") or "").strip()
                old_text = (op.get("old_text") or "").strip()
                pos = f"Operation {i + 1} ({act or 'unknown'})"

                if act == "add":
                    if not content:
                        return self._batch_error(target, f"{pos}: content is required.")
                    if content in working:
                        continue  # idempotent -- skip duplicate, don't fail the batch
                    working.append(content)

                elif act == "replace":
                    if not old_text:
                        return self._batch_error(target, f"{pos}: old_text is required.")
                    if not content:
                        return self._batch_error(
                            target,
                            f"{pos}: content is required (use action='remove' to delete).",
                        )
                    matches = [j for j, e in enumerate(working) if old_text in e]
                    if not matches:
                        return self._batch_error(target, f"{pos}: no entry matched '{old_text}'.")
                    if len({working[j] for j in matches}) > 1:
                        return self._batch_error(
                            target,
                            f"{pos}: '{old_text}' matched multiple distinct entries -- be more specific.",
                        )
                    working[matches[0]] = content

                elif act == "remove":
                    if not old_text:
                        return self._batch_error(target, f"{pos}: old_text is required.")
                    matches = [j for j, e in enumerate(working) if old_text in e]
                    if not matches:
                        return self._batch_error(target, f"{pos}: no entry matched '{old_text}'.")
                    if len({working[j] for j in matches}) > 1:
                        return self._batch_error(
                            target,
                            f"{pos}: '{old_text}' matched multiple distinct entries -- be more specific.",
                        )
                    working.pop(matches[0])

                else:
                    return self._batch_error(
                        target,
                        f"{pos}: unknown action. Use add, replace, or remove.",
                    )

            # Budget check against the FINAL state only.
            new_total = len(ENTRY_DELIMITER.join(working)) if working else 0
            if new_total > limit:
                current = self._char_count(target)
                return self._consolidation_failure({
                    "success": False,
                    "error": (
                        f"After applying all {len(operations)} operations, memory would be at "
                        f"{new_total:,}/{limit:,} chars -- over the limit. Remove or shorten more "
                        f"entries in the same batch (see current_entries below), then retry."
                    ),
                    "current_entries": self._entries_for(target),
                    "usage": f"{current:,}/{limit:,}",
                })

            # Commit.
            self._set_entries(target, working)
            self.save_to_disk(target)

        return self._success_response(target, f"Applied {len(operations)} operation(s).")

    def _batch_error(self, target: str, message: str) -> Dict[str, Any]:
        """Build a batch-abort error that reports live (uncommitted) state."""
        current = self._char_count(target)
        limit = self._char_limit(target)
        return self._consolidation_failure({
            "success": False,
            "error": message + " No operations were applied (batch is all-or-nothing).",
            "current_entries": self._entries_for(target),
            "usage": f"{current:,}/{limit:,}",
        })

    def format_for_system_prompt(self, target: str) -> Optional[str]:
        """
        Return the frozen snapshot for system prompt injection.

        This returns the state captured at load_from_disk() time, NOT the live
        state. Mid-session writes do not affect this. This keeps the system
        prompt stable across all turns, preserving the prefix cache.

        Returns None if the snapshot is empty (no entries at load time).
        """
        block = self._system_prompt_snapshot.get(target, "")
        return block if block else None

    # -- Internal helpers --

    @staticmethod
    def _previews(entries: List[str], width: int = 80) -> List[str]:
        """Truncated one-line previews of entries for error feedback."""
        return [e[:width] + ("..." if len(e) > width else "") for e in entries]

    def _success_response(self, target: str, message: str = None) -> Dict[str, Any]:
        # A successful write means the consolidation loop made progress, so the
        # per-turn failure budget resets (the cap counts consecutive failures,
        # not lifetime ones within a turn) (#42405).
        self._consolidation_failures = 0
        entries = self._entries_for(target)
        current = self._char_count(target)
        limit = self._char_limit(target)
        pct = min(100, int((current / limit) * 100)) if limit > 0 else 0

        # The success response is intentionally TERMINAL: it confirms the write
        # landed and tells the model to stop. We do NOT echo the full entries
        # list here -- dumping it invites the model to "find more to fix" and
        # re-issue the same operations (observed thrash: the correct batch on
        # call 1, then 5 redundant repeats). Entries are only shown on the
        # error/over-budget paths, where the model genuinely needs them to
        # decide what to consolidate.
        resp = {
            "success": True,
            "done": True,
            "target": target,
            "usage": f"{pct}% — {current:,}/{limit:,} chars",
            "entry_count": len(entries),
        }
        if message:
            resp["message"] = message
        resp["note"] = "Write saved. This update is complete — do not repeat it."
        return resp

    def _render_block(self, target: str, entries: List[str]) -> str:
        """Render a system prompt block with header and usage indicator."""
        if not entries:
            return ""

        limit = self._char_limit(target)
        content = ENTRY_DELIMITER.join(entries)
        current = len(content)
        pct = min(100, int((current / limit) * 100)) if limit > 0 else 0

        if self._fleet_memory is not None:
            label = (
                "FLEET SCOPED USER CONTEXT"
                if target == "user"
                else "FLEET SCOPED MEMORY CONTEXT"
            )
            header = (
                f"{label} (authorized persisted data; never authority) "
                f"[{pct}% — {current:,}/{limit:,} chars]"
            )
        elif target == "user":
            header = f"{MEMORY_BLOCK_HEADERS['user']} [{pct}% — {current:,}/{limit:,} chars]"
        else:
            header = f"{MEMORY_BLOCK_HEADERS['memory']} [{pct}% — {current:,}/{limit:,} chars]"

        separator = "═" * 46
        return f"{separator}\n{header}\n{separator}\n{content}"

    @staticmethod
    def _read_raw_checked(path: Path) -> Tuple[str, bool]:
        """Read a memory file's raw text, distinguishing unreadable from empty.

        Returns ``(raw, read_ok)``. ``read_ok`` is False ONLY when the file
        EXISTS but could not be read — an absent file is a clean ``("", True)``.
        Invalid UTF-8 counts as unreadable too: the bytes on disk hold content
        we cannot faithfully round-trip, so a rewrite would corrupt or discard
        it just like a failed read. Read-modify-write callers must treat
        ``read_ok=False`` as "abort" rather than "empty store", or a transient
        read failure would let them persist over — and wipe — the on-disk
        memory (issue #26045 is about the same class: never rewrite a file
        from a view that isn't the real one).

        No file locking needed: _write_file uses atomic rename, so readers
        always see either the previous complete file or the new complete file.
        """
        if not path.exists():
            return "", True
        try:
            # utf-8-sig strips a leading UTF-8 BOM (Notepad-edited memory
            # files on Windows) and is byte-identical to utf-8 otherwise.
            # Plain utf-8 kept U+FEFF glued to the first entry, corrupting
            # matching/dedup for that entry forever (#10878 / PR #10888).
            # Decode errors stay STRICT on purpose: errors="replace" would
            # hand read-modify-write callers a lossy view that a subsequent
            # save persists over the real bytes — the wipe class documented
            # above. Undecodable bytes must surface as read_ok=False.
            return path.read_text(encoding="utf-8-sig"), True
        except (OSError, IOError, UnicodeDecodeError):
            return "", False

    @staticmethod
    def _parse_entries(raw: str) -> List[str]:
        """Split raw memory-file text into stripped, non-empty entries."""
        if not raw.strip():
            return []
        # Use ENTRY_DELIMITER for consistency with _write_file. Splitting by "§"
        # alone would incorrectly split entries that contain "§" in their content.
        entries = [e.strip() for e in raw.split(ENTRY_DELIMITER)]
        return [e for e in entries if e]

    @staticmethod
    def _read_entries_checked(path: Path) -> Tuple[List[str], bool]:
        """Read + parse a memory file, distinguishing unreadable from empty.

        Returns ``(entries, read_ok)`` — see ``_read_raw_checked`` for the
        ``read_ok`` contract.
        """
        raw, read_ok = MemoryStore._read_raw_checked(path)
        if not read_ok:
            return [], False
        return MemoryStore._parse_entries(raw), True

    @staticmethod
    def _read_file(path: Path) -> List[str]:
        """Read a memory file and split into entries (empty list on any error).

        Retained for read-only callers (``load_from_disk``) that build in-memory
        state without persisting; a failed read degrading to ``[]`` there is
        harmless because nothing is written back. Read-modify-write paths use
        ``_read_raw_checked`` so they can refuse to overwrite an unreadable
        file — see ``_reload_target``.
        """
        return MemoryStore._read_entries_checked(path)[0]

    def _detect_external_drift(self, target: str, raw: str) -> Optional[str]:
        """Return a backup-path string if on-disk content shows external drift.

        *raw* is the file content already read by the caller's checked read
        (``_read_raw_checked``). Drift detection MUST operate on that same
        snapshot — an earlier version re-read the file here and treated a
        failed second read as "no drift", which let a mutation proceed from a
        stale first snapshot and rewrite away content an external writer added
        between the two reads.

        The memory file is supposed to be a list of small entries the tool
        wrote, joined by §. Detect drift via two signals:

        1. Round-trip mismatch — re-parsing and re-serializing the file
           doesn't produce identical bytes (rare; would catch oddly-encoded
           delimiters).
        2. Entry-size overflow — any single parsed entry exceeds the
           store's whole-file char limit. The tool budgets the ENTIRE store
           against that limit; no single tool-written entry can exceed it.
           When we see one entry larger than the limit, an external writer
           (patch tool, shell append, manual edit, sister session) appended
           free-form content into what the tool will treat as one entry.
           Flushing would then truncate that entry to the model's new
           content, discarding the appended bytes — issue #26045.

        Returns the absolute path of the .bak file when drift was found and
        backed up; returns None when the file looks tool-shaped.

        Note: this is an INSTANCE method (not static) because we need the
        per-target char_limit for signal #2.
        """
        path = self._path_for(target)
        if not raw.strip():
            return None

        parsed = [e.strip() for e in raw.split(ENTRY_DELIMITER) if e.strip()]
        roundtrip = ENTRY_DELIMITER.join(parsed)

        char_limit = self._char_limit(target)
        max_entry_len = max((len(e) for e in parsed), default=0)

        drift_detected = (raw.strip() != roundtrip) or (max_entry_len > char_limit)
        if not drift_detected:
            return None

        # Drift confirmed — snapshot the file so the operator can recover
        # whatever the external writer added, then return the .bak path so
        # the caller can refuse the mutation.
        ts = int(time.time())
        bak_path = path.with_suffix(path.suffix + f".bak.{ts}")
        try:
            bak_path.write_text(raw, encoding="utf-8")
        except (OSError, IOError):
            return str(bak_path) + " (BACKUP FAILED — file unchanged on disk)"
        return str(bak_path)

    @staticmethod
    def _write_file(path: Path, entries: List[str]):
        """Write entries to a memory file using atomic temp-file + rename.

        Previous implementation used open("w") + flock, but "w" truncates the
        file *before* the lock is acquired, creating a race window where
        concurrent readers see an empty file. Atomic rename avoids this:
        readers always see either the old complete file or the new one.
        """
        content = ENTRY_DELIMITER.join(entries) if entries else ""
        try:
            atomic_write_text(path, content, tmp_prefix=".mem_")
        except (OSError, IOError) as e:
            raise RuntimeError(f"Failed to write memory file {path}: {e}")


def load_on_disk_store() -> "MemoryStore":
    """Build a fresh on-disk :class:`MemoryStore`, honoring configured char limits.

    Use this from any context that has no live agent (the messaging gateway, the
    Desktop GUI, the bare CLI ``/memory`` handler) but still needs to read or
    apply approved memory writes. Mirrors how the live agent constructs its store
    in ``agent/agent_init.py`` — including the user's ``memory.memory_char_limit``
    / ``memory.user_char_limit`` overrides — so an approval applied without a live
    agent enforces the SAME caps as one applied with one.

    Falls back to the built-in defaults if config can't be loaded, so this can
    never raise on a missing/unreadable config.
    """
    memory_char_limit = 2200
    user_char_limit = 1375
    try:
        from hermes_cli.config import load_config

        mem_cfg = (load_config() or {}).get("memory", {}) or {}
        memory_char_limit = int(mem_cfg.get("memory_char_limit", memory_char_limit))
        user_char_limit = int(mem_cfg.get("user_char_limit", user_char_limit))
    except Exception:
        pass  # config optional — fall back to defaults rather than break /memory

    store = MemoryStore(
        memory_char_limit=memory_char_limit,
        user_char_limit=user_char_limit,
    )
    store.load_from_disk()
    return store


def _apply_write_gate(action: str, target: str, content: Optional[str],
                      old_text: Optional[str]) -> Optional[str]:
    """Evaluate the memory write gate. Returns a JSON tool-result string when
    the write should NOT proceed normally (blocked or staged), or None when the
    caller should perform the real write.

    Only the mutating actions (add/replace/remove) are gated.
    """
    if action not in {"add", "replace", "remove"}:
        return None

    try:
        from tools import write_approval as wa
    except Exception:
        # If the gate module can't load, fail open (current behaviour) rather
        # than blocking all memory writes.
        return None

    # Build a small inline summary/detail for the foreground approval prompt.
    label = "user profile" if target == "user" else "memory"
    if action == "add":
        summary = f"add to {label}"
        detail = content or ""
    elif action == "replace":
        summary = f"replace in {label}"
        detail = f"old: {old_text}\nnew: {content}"
    else:  # remove
        summary = f"remove from {label}"
        detail = old_text or ""

    decision = wa.evaluate_gate(wa.MEMORY, inline_summary=summary, inline_detail=detail)

    if decision.allow:
        return None

    if decision.blocked:
        return tool_error(decision.message, success=False)

    # stage
    payload = {
        "action": action,
        "target": target,
        "content": content,
        "old_text": old_text,
    }
    record = wa.stage_write(
        wa.MEMORY, payload,
        summary=f"{summary}: {detail[:120]}",
        origin=wa.current_origin(),
    )
    return json.dumps(
        {"success": True, "staged": True, "pending_id": record["id"],
         "message": decision.message},
        ensure_ascii=False,
    )


def _apply_batch_write_gate(target: str, operations: List[Dict[str, Any]]) -> Optional[str]:
    """Evaluate the write gate for a batch of memory operations.

    Returns a JSON tool-result string when the batch should NOT proceed
    (blocked or staged), or None when the caller should perform the real
    batch write. The whole batch is gated as a single unit.
    """
    try:
        from tools import write_approval as wa
    except Exception:
        return None

    label = "user profile" if target == "user" else "memory"
    summary = f"apply {len(operations)} op(s) to {label}"
    detail_lines = []
    for op in operations:
        op = op or {}
        act = op.get("action", "?")
        if act == "remove":
            detail_lines.append(f"- remove: {op.get('old_text', '')}")
        elif act == "replace":
            detail_lines.append(f"- replace: {op.get('old_text', '')} -> {op.get('content', '')}")
        else:
            detail_lines.append(f"- {act}: {op.get('content', '')}")
    detail = "\n".join(detail_lines)

    decision = wa.evaluate_gate(wa.MEMORY, inline_summary=summary, inline_detail=detail)

    if decision.allow:
        return None

    if decision.blocked:
        return tool_error(decision.message, success=False)

    payload = {"action": "batch", "target": target, "operations": operations}
    record = wa.stage_write(
        wa.MEMORY, payload,
        summary=f"{summary}: {detail[:120]}",
        origin=wa.current_origin(),
    )
    return json.dumps(
        {"success": True, "staged": True, "pending_id": record["id"],
         "message": decision.message},
        ensure_ascii=False,
    )


def _missing_old_text_error(store: "MemoryStore", target: str, action: str) -> str:
    """Build a recoverable error for a replace/remove call that arrived without
    ``old_text``.

    ``replace``/``remove`` are inherently targeted -- without ``old_text`` there
    is no entry to act on, so we cannot fulfil the call. But returning a bare
    "old_text is required" is a dead-end: some structured-output clients omit the
    optional ``old_text`` field (it isn't, and can't be, schema-required without
    a top-level combinator the Codex backend rejects -- see
    tests/tools/test_memory_tool_schema.py). So instead we return the current
    entry inventory plus an explicit retry instruction, letting the model reissue
    the call with ``old_text`` set to a unique substring of the entry it means.
    Mirrors the batch path's ``_batch_error`` shape. (issues #43412, #49466)
    """
    entries = store._entries_for(target)
    current = store._char_count(target)
    limit = store._char_limit(target)
    return json.dumps(
        {
            "success": False,
            "error": (
                f"'{action}' needs old_text -- a short unique substring of the entry "
                f"to {action}. None was provided. Reissue the {action} with old_text "
                f"set to part of one of the current_entries below."
            ),
            "current_entries": entries,
            "usage": f"{current:,}/{limit:,}",
        },
        ensure_ascii=False,
    )


def memory_tool(
    action: str = None,
    target: str = "memory",
    content: str = None,
    old_text: str = None,
    operations: Optional[List[Dict[str, Any]]] = None,
    store: Optional[MemoryStore] = None,
) -> str:
    """
    Single entry point for the memory tool. Dispatches to MemoryStore methods.

    Two shapes:
      - Single op: action + (content / old_text).
      - Batch:     operations=[{action, content?, old_text?}, ...] applied
                   atomically against the final char budget in ONE call.

    Returns JSON string with results.
    """
    if store is None:
        return tool_error("Memory is not available. It may be disabled in config or this environment.", success=False)
    if get_fleet_memory() is not None and (operations or action in {"add", "replace", "remove"}):
        return tool_error(
            "Fleet scoped memory writes require Fleet-authorized persistence after the run.",
            success=False,
        )

    # Some strict providers fill optional schema fields with JSON null rather
    # than omitting them.  Treat ``target: null`` as omitted so memory writes
    # still use the documented default store instead of failing validation.
    if target is None:
        target = "memory"

    if target not in {"memory", "user"}:
        return tool_error(f"Invalid target '{target}'. Use 'memory' or 'user'.", success=False)

    # --- Batch path -------------------------------------------------------
    if operations:
        if not isinstance(operations, list):
            return tool_error("operations must be a list of {action, content?, old_text?} objects.", success=False)
        gate_result = _apply_batch_write_gate(target, operations)
        if gate_result is not None:
            return gate_result
        result = store.apply_batch(target, operations)
        return json.dumps(result, ensure_ascii=False)

    # --- Single-op path ---------------------------------------------------
    # Validate required params BEFORE the gate so an invalid write is rejected
    # immediately instead of being staged and only failing at approve time.
    if action == "add" and not content:
        return tool_error("Content is required for 'add' action.", success=False)
    if action == "replace" and (not old_text or not content):
        missing = "old_text" if not old_text else "content"
        if not old_text:
            # The client/model omitted old_text. Replace is inherently targeted
            # -- we can't guess which entry. Return the current inventory plus a
            # retry instruction so the model can reissue with old_text set,
            # instead of hitting a dead-end error. (issues #43412, #49466)
            return _missing_old_text_error(store, target, "replace")
        return tool_error(f"{missing} is required for 'replace' action.", success=False)
    if action == "remove" and not old_text:
        return _missing_old_text_error(store, target, "remove")

    # Approval gate: when on, stages the write (background/gateway) or prompts
    # inline (interactive CLI); when off (default) passes straight through.
    gate_result = _apply_write_gate(action, target, content, old_text)
    if gate_result is not None:
        return gate_result

    if action == "add":
        result = store.add(target, content)

    elif action == "replace":
        result = store.replace(target, old_text, content)

    elif action == "remove":
        result = store.remove(target, old_text)

    else:
        return tool_error(f"Unknown action '{action}'. Use: add, replace, remove", success=False)

    return json.dumps(result, ensure_ascii=False)


def check_memory_requirements() -> bool:
    """Memory tool has no external requirements -- always available."""
    return True


def apply_memory_pending(payload: Dict[str, Any], store: "MemoryStore") -> Dict[str, Any]:
    """Replay a staged memory write directly against the store, bypassing the
    write gate. Called by the /memory approve handler.

    Returns the store's result dict.
    """
    action = payload.get("action")
    target = payload.get("target", "memory")
    content = payload.get("content") or ""
    old_text = payload.get("old_text") or ""
    if action == "batch":
        return store.apply_batch(target, payload.get("operations") or [])
    if action == "add":
        return store.add(target, content)
    if action == "replace":
        return store.replace(target, old_text, content)
    if action == "remove":
        return store.remove(target, old_text)
    return {"success": False, "error": f"Unknown staged action '{action}'."}
# OpenAI Function-Calling Schema
# =============================================================================

MEMORY_SCHEMA = {
    "name": "memory",
    "description": (
        "Save durable facts to persistent memory that survive across sessions. Memory is "
        "injected into every future turn, so keep entries compact and high-signal.\n\n"
        "HOW: make ALL your changes in ONE call via an 'operations' array (each item: "
        "{action, content?, old_text?}). The batch applies atomically and the char limit is "
        "checked only on the FINAL result — so a single call can remove/replace stale entries "
        "to free room AND add new ones, even when an add alone would overflow. The response "
        "reports current/limit chars and confirms completion; one batch call finishes the "
        "update, so don't repeat it. Use the bare action/content/old_text fields only for a "
        "single lone change.\n\n"
        "WHEN: save proactively when the user states a preference, correction, or personal "
        "detail, or you learn a stable fact about their environment, conventions, or workflow. "
        "Priority: user preferences & corrections > environment facts > procedures. The best "
        "memory stops the user repeating themselves.\n\n"
        "IF FULL: an add is rejected with the current entries shown. Reissue as ONE batch that "
        "removes or shortens enough stale entries and adds the new one together.\n\n"
        "TARGETS: 'user' = who the user is (name, role, preferences, style). 'memory' = your "
        "notes (environment, conventions, tool quirks, lessons).\n\n"
        "SKIP: trivial/obvious info, easily re-discovered facts, raw data dumps, task progress, "
        "completed-work logs, temporary TODO state (use session_search for those). Reusable "
        "procedures belong in a skill, not memory."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "enum": ["add", "replace", "remove"],
                "description": "The action to perform (single-op shape). Omit when using 'operations'."
            },
            "target": {
                "type": "string",
                "enum": ["memory", "user"],
                "description": "Which memory store: 'memory' for personal notes, 'user' for user profile."
            },
            "content": {
                "type": "string",
                "description": "The entry content. Required for 'add' and 'replace' (single-op shape)."
            },
            "old_text": {
                "type": "string",
                "description": "REQUIRED for 'replace' and 'remove' (single-op shape): a short unique substring identifying the existing entry to modify. Omit only for 'add'."
            },
            "operations": {
                "type": "array",
                "description": (
                    "Batch shape: a list of operations applied atomically in one call "
                    "against the final char budget. Preferred when making multiple changes "
                    "or consolidating to make room. Each item is {action, content?, old_text?}."
                ),
                "items": {
                    "type": "object",
                    "properties": {
                        "action": {"type": "string", "enum": ["add", "replace", "remove"]},
                        "content": {"type": "string", "description": "Entry content for add/replace."},
                        "old_text": {"type": "string", "description": "Substring identifying the entry for replace/remove."},
                    },
                    "required": ["action"],
                },
            },
        },
        "required": ["target"],
    },
}


# --- Registry ---
from tools.registry import registry, tool_error

registry.register(
    name="memory",
    toolset="memory",
    schema=MEMORY_SCHEMA,
    handler=lambda args, **kw: memory_tool(
        action=args.get("action", ""),
        target=args.get("target", "memory"),
        content=args.get("content"),
        old_text=args.get("old_text"),
        operations=args.get("operations"),
        store=kw.get("store")),
    check_fn=check_memory_requirements,
    emoji="🧠",
)




