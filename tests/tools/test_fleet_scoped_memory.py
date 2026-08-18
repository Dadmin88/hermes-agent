from __future__ import annotations

import json
from pathlib import Path

import pytest

from hermes_constants import reset_hermes_home_override, set_hermes_home_override
from agent.fleet_memory_scope import (
    FleetMemoryBinding,
    FleetMemoryScopeRef,
    fleet_memory_scope,
)
from tools.memory_tool import (
    ENTRY_DELIMITER,
    FLEET_MEMORY_META_SCHEMA,
    MemoryStore,
    memory_tool,
)

P1 = "sha256:" + "1" * 64
P2 = "sha256:" + "2" * 64
B1 = "sha256:" + "3" * 64
B2 = "sha256:" + "4" * 64
AGENT = "sha256:" + "5" * 64


def binding(
    principal: str = P1,
    *,
    reads: tuple[FleetMemoryScopeRef, ...] | None = None,
    retention_until_ms: int | None = None,
) -> FleetMemoryBinding:
    private = FleetMemoryScopeRef("principal", principal)
    return FleetMemoryBinding(
        version="fleet-memory-v1",
        principal_id=principal,
        principal_kind="owner",
        principal_generation=1,
        principal_binding_hash=B1 if principal == P1 else B2,
        agent_instance_id=AGENT,
        source_run=f"run-{principal[-4:]}",
        read_scopes=reads or (private,),
        write_scope=private,
        retention_until_ms=retention_until_ms,
    )


def new_store(monkeypatch, tmp_path: Path, item: FleetMemoryBinding) -> MemoryStore:
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes"))
    with fleet_memory_scope(item):
        store = MemoryStore(memory_char_limit=10_000, user_char_limit=10_000)
        store.load_from_disk()
    return store


def test_two_principals_share_profile_without_memory_leakage(monkeypatch, tmp_path: Path) -> None:
    first = binding(P1)
    second = binding(P2)

    store = new_store(monkeypatch, tmp_path, first)
    result = store.add("memory", "alpha-private")
    assert result["success"] is True
    first_path = store._path_for("memory")
    assert first_path.read_text(encoding="utf-8") == "alpha-private"
    assert not (tmp_path / "hermes" / "memories" / "MEMORY.md").exists()

    store = new_store(monkeypatch, tmp_path, second)
    assert store.memory_entries == []
    assert store.format_for_system_prompt("memory") is None
    assert store.add("memory", "beta-private")["success"] is True
    second_path = store._path_for("memory")
    assert second_path != first_path

    first_reopened = new_store(monkeypatch, tmp_path, first)
    second_reopened = new_store(monkeypatch, tmp_path, second)
    first_prompt = first_reopened.format_for_system_prompt("memory") or ""
    second_prompt = second_reopened.format_for_system_prompt("memory") or ""
    assert "alpha-private" in first_prompt
    assert "beta-private" not in first_prompt
    assert "beta-private" in second_prompt
    assert "alpha-private" not in second_prompt


def test_scoped_memory_persists_across_fresh_store_instances(monkeypatch, tmp_path: Path) -> None:
    item = binding()
    first = new_store(monkeypatch, tmp_path, item)
    assert first.add("user", "prefers-short-replies")["success"] is True

    reopened = new_store(monkeypatch, tmp_path, item)
    assert reopened.user_entries == ["prefers-short-replies"]
    assert "prefers-short-replies" in (reopened.format_for_system_prompt("user") or "")


def test_revoked_or_expired_metadata_is_filtered_before_prompt(monkeypatch, tmp_path: Path) -> None:
    item = binding()
    store = new_store(monkeypatch, tmp_path, item)
    assert store.add("memory", "durable-fact")["success"] is True
    metadata_path = store._metadata_path("memory", item.write_scope)
    document = json.loads(metadata_path.read_text(encoding="utf-8"))
    document["entries"][0]["revoked_at_ms"] = store._now_ms()
    metadata_path.write_text(json.dumps(document), encoding="utf-8")

    revoked = new_store(monkeypatch, tmp_path, item)
    assert revoked.memory_entries == []
    assert revoked.format_for_system_prompt("memory") is None

    document["entries"][0]["revoked_at_ms"] = None
    document["entries"][0]["retention_until_ms"] = 1
    metadata_path.write_text(json.dumps(document), encoding="utf-8")
    expired = new_store(monkeypatch, tmp_path, item)
    assert expired.memory_entries == []
    assert expired.format_for_system_prompt("memory") is None
    assert expired.add("memory", "replacement-after-expiry")["success"] is True
    assert expired._path_for("memory").read_text(encoding="utf-8") == (
        "replacement-after-expiry"
    )
    refreshed = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert len(refreshed["entries"]) == 1
    assert refreshed["entries"][0]["content_hash"] == expired._entry_hash(
        "replacement-after-expiry"
    )


def test_content_without_matching_metadata_is_never_recalled_and_blocks_mutation(
    monkeypatch, tmp_path: Path
) -> None:
    item = binding()
    store = new_store(monkeypatch, tmp_path, item)
    assert store.add("memory", "known-entry")["success"] is True
    path = store._path_for("memory")
    path.write_text(ENTRY_DELIMITER.join(["known-entry", "untracked-entry"]), encoding="utf-8")

    reopened = new_store(monkeypatch, tmp_path, item)
    prompt = reopened.format_for_system_prompt("memory") or ""
    assert "known-entry" in prompt
    assert "untracked-entry" not in prompt
    result = reopened.add("memory", "new-entry")
    assert result["success"] is False
    assert "drift" in result["error"].lower()


def test_sensitive_or_authority_material_is_rejected_before_persistence(
    monkeypatch, tmp_path: Path
) -> None:
    item = binding()
    store = new_store(monkeypatch, tmp_path, item)

    import agent.redact as redact

    original = redact.redact_sensitive_text

    def fake_redactor(text: str, *, force: bool = False) -> str:
        if "credential-fixture" in text:
            return "[REDACTED]"
        return original(text, force=force)

    monkeypatch.setattr(redact, "redact_sensitive_text", fake_redactor)
    result = store.add("memory", "credential-fixture")
    assert result["success"] is False
    assert "credential or secret" in result["error"]

    result = store.add("memory", "schema=fleet.run-authority.v1")
    assert result["success"] is False
    assert "RunAuthority" in result["error"]
    assert not store._path_for("memory").exists()


def _seed_promoted_scope(
    store: MemoryStore,
    *,
    scope: FleetMemoryScopeRef,
    target: str,
    content: str,
    owner_principal_id: str = P1,
) -> None:
    store._ensure_scope_descriptor(scope)
    directory = store._scope_dir(scope)
    native_path = directory / store._target_filename(target)
    native_path.write_text(content, encoding="utf-8")
    now = store._now_ms()
    metadata = {
        "schema": FLEET_MEMORY_META_SCHEMA,
        "scope": scope.to_request(),
        "entries": [
            {
                "content_hash": store._entry_hash(content),
                "owner_principal_id": owner_principal_id,
                "owner_principal_kind": "owner",
                "scope_kind": scope.kind,
                "scope_id": scope.scope_id,
                "source_run": "promotion-fixture",
                "agent_instance_id": AGENT,
                "sensitivity": "shared",
                "trust": "promoted",
                "promotion_state": "promoted",
                "retention_until_ms": None,
                "provenance": "promotion-fixture",
                "created_at_ms": now,
                "updated_at_ms": now,
                "revoked_at_ms": None,
            }
        ],
    }
    store._metadata_path(target, scope).write_text(json.dumps(metadata), encoding="utf-8")


def test_explicit_promoted_shared_scope_is_read_only_and_opt_in(monkeypatch, tmp_path: Path) -> None:
    project = FleetMemoryScopeRef("project", "project-a")
    private = FleetMemoryScopeRef("principal", P1)
    item = binding(P1, reads=(private, project))
    store = new_store(monkeypatch, tmp_path, item)
    _seed_promoted_scope(store, scope=project, target="memory", content="project-shared")

    reopened = new_store(monkeypatch, tmp_path, item)
    assert "project-shared" in (reopened.format_for_system_prompt("memory") or "")
    assert reopened.memory_entries == []
    assert reopened._path_for("memory").parent != reopened._scope_dir(project)

    private_only = new_store(monkeypatch, tmp_path, binding(P1))
    assert "project-shared" not in (private_only.format_for_system_prompt("memory") or "")


def test_scoped_storage_is_private_and_symlink_scope_is_rejected(monkeypatch, tmp_path: Path) -> None:
    item = binding()
    store = new_store(monkeypatch, tmp_path, item)
    assert store.add('memory', 'private-mode-check')['success'] is True

    scope_dir = store._scope_dir(item.write_scope)
    metadata = store._metadata_path('memory', item.write_scope)
    descriptor = store._scope_descriptor_path(item.write_scope)
    native = store._path_for('memory')
    assert scope_dir.stat().st_mode & 0o777 == 0o700
    for path in (metadata, descriptor, native):
        assert path.stat().st_mode & 0o777 == 0o600

    other_root = tmp_path / 'other-scope'
    other_root.mkdir(mode=0o700)
    native.unlink()
    native.symlink_to(other_root / 'outside-memory')
    result = store.add('memory', 'must-not-follow-link')
    assert result['success'] is False
    assert 'metadata is unavailable' in result['error']
    assert not (other_root / 'outside-memory').exists()


def test_symlinked_scope_directory_fails_closed(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv('HERMES_HOME', str(tmp_path / 'hermes'))
    item = binding()
    root = tmp_path / 'hermes' / 'memories' / 'fleet-v1' / 'principal'
    root.mkdir(parents=True, mode=0o700)
    target = tmp_path / 'elsewhere'
    target.mkdir(mode=0o700)
    (root / item.write_scope.storage_key).symlink_to(target, target_is_directory=True)

    with fleet_memory_scope(item):
        store = MemoryStore(memory_char_limit=10_000, user_char_limit=10_000)
        with pytest.raises(RuntimeError, match='symbolic link'):
            store.load_from_disk()


def test_model_memory_tool_cannot_mutate_fleet_scoped_store(monkeypatch, tmp_path: Path) -> None:
    item = binding()
    store = new_store(monkeypatch, tmp_path, item)
    with fleet_memory_scope(item):
        result = json.loads(
            memory_tool(
                action='add',
                target='memory',
                content='model-must-not-persist',
                store=store,
            )
        )
    assert result['success'] is False
    assert 'Fleet-authorized persistence' in result['error']
    assert not store._path_for('memory').exists()


def test_promoted_project_scope_is_shared_across_profile_overrides(
    monkeypatch, tmp_path: Path
) -> None:
    process_home = tmp_path / 'process-home'
    monkeypatch.setenv('HERMES_HOME', str(process_home))
    project = FleetMemoryScopeRef('project', 'project-a')
    first_private = FleetMemoryScopeRef('principal', P1)
    first_binding = binding(P1, reads=(first_private, project))

    first_override = set_hermes_home_override(tmp_path / 'profile-a')
    try:
        with fleet_memory_scope(first_binding):
            first = MemoryStore(memory_char_limit=10_000, user_char_limit=10_000)
            first.load_from_disk()
            _seed_promoted_scope(
                first,
                scope=project,
                target='memory',
                content='cross-agent-project-memory',
            )
    finally:
        reset_hermes_home_override(first_override)

    second_private = FleetMemoryScopeRef('principal', P2)
    second_binding = FleetMemoryBinding(
        version='fleet-memory-v1',
        principal_id=P2,
        principal_kind='owner',
        principal_generation=1,
        principal_binding_hash=B2,
        agent_instance_id='sha256:' + '6' * 64,
        source_run='second-agent-run',
        read_scopes=(second_private, project),
        write_scope=second_private,
        retention_until_ms=None,
    )
    second_override = set_hermes_home_override(tmp_path / 'profile-b')
    try:
        with fleet_memory_scope(second_binding):
            second = MemoryStore(memory_char_limit=10_000, user_char_limit=10_000)
            second.load_from_disk()
    finally:
        reset_hermes_home_override(second_override)

    assert 'cross-agent-project-memory' in (
        second.format_for_system_prompt('memory') or ''
    )
    shared_root = process_home / 'memories' / 'fleet-v1' / 'project'
    assert list(shared_root.glob('*/MEMORY.md'))
    assert not (tmp_path / 'profile-a' / 'memories' / 'fleet-v1').exists()
    assert not (tmp_path / 'profile-b' / 'memories' / 'fleet-v1').exists()
