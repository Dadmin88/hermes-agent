from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

import pytest

from agent.fleet_promotion import FleetPromotionAuthorization
from agent.fleet_memory_scope import (
    FleetMemoryBinding,
    FleetMemoryScopeRef,
    fleet_memory_scope,
)
from hermes_constants import reset_hermes_home_override, set_hermes_home_override
from tools.fleet_promotion import (
    FleetPromotionMutationError,
    commit_memory_promotion,
    prepare_memory_promotion,
    promotion_history,
    rollback_promotion,
)
from tools.memory_tool import MemoryStore

P1 = "sha256:" + "1" * 64
P2 = "sha256:" + "9" * 64
B1 = "sha256:" + "2" * 64
AGENT = "sha256:" + "3" * 64


def binding() -> FleetMemoryBinding:
    private = FleetMemoryScopeRef("principal", P1)
    return FleetMemoryBinding(
        version="fleet-memory-v1",
        principal_id=P1,
        principal_kind="owner",
        principal_generation=1,
        principal_binding_hash=B1,
        agent_instance_id=AGENT,
        source_run="run-one",
        read_scopes=(private,),
        write_scope=private,
        retention_until_ms=None,
    )


@pytest.fixture(autouse=True)
def reset_home(tmp_path: Path) -> None:
    home = tmp_path / "hermes"
    home.mkdir()
    token = set_hermes_home_override(home)
    yield
    reset_hermes_home_override(token)


def seed(tmp_path: Path, content: str) -> tuple[FleetMemoryBinding, str]:
    item = binding()
    with fleet_memory_scope(item):
        store = MemoryStore(memory_char_limit=10_000, user_char_limit=10_000)
        store.load_from_disk()
        result = store.add("memory", content)
        assert result["success"] is True
    return item, MemoryStore._entry_hash(content)


def memory_authorization(
    item: FleetMemoryBinding,
    *,
    source_hash: str,
    approved_hash: str,
    expected_current: str | None = None,
    rollback_to: str | None = None,
    operation: str = "promote",
    issued_at_ms: int = 10_000,
) -> FleetPromotionAuthorization:
    unsigned: dict[str, object] = {
        "version": "fleet-promotion-v1",
        "policy_version": "phase18-v1",
        "subject_kind": "memory",
        "subject_key": "memory:" + source_hash,
        "source_owner_principal_id": P1,
        "agent_instance_id": AGENT,
        "source_scope": item.write_scope.to_request(),
        "target_scope": {"kind": "project", "scope_id": "fleet"},
        "source_content_hash": source_hash,
        "approved_content_hash": approved_hash,
        "administrator": {
            "principal_id": P1,
            "kind": "project",
            "generation": 1,
            "binding_hash": "sha256:" + "5" * 64,
        },
        "issued_at_ms": issued_at_ms,
        "expires_at_ms": issued_at_ms + 60_000,
        "verification_digest": None,
        "expected_current_promotion_id": expected_current,
        "rollback_to_promotion_id": rollback_to,
        "operation": operation,
        "authority": "none",
    }
    promotion_id = "sha256:" + hashlib.sha256(
        json.dumps(
            unsigned,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    return FleetPromotionAuthorization.from_request(
        {**unsigned, "promotion_id": promotion_id},
        now_ms=issued_at_ms + 1,
    )


def test_prepare_memory_promotion_sanitizes_private_data_before_approval(tmp_path: Path) -> None:
    item, source_hash = seed(tmp_path, "Contact dev@example.com for the release notes")
    prepared = prepare_memory_promotion(
        target="memory",
        source_scope=item.write_scope,
        source_content_hash=source_hash,
        source_owner_principal_id=P1,
        agent_instance_id=AGENT,
    )
    assert prepared.subject_kind == "memory"
    assert prepared.source_content_hash == source_hash
    assert prepared.approved_content_hash != source_hash
    assert prepared.sanitized is True
    assert prepared.to_document()["authority"] == "none"


def test_prepare_memory_promotion_is_deterministic_for_safe_content(tmp_path: Path) -> None:
    item, source_hash = seed(tmp_path, "Use deterministic release checks")
    first = prepare_memory_promotion(
        target="memory",
        source_scope=item.write_scope,
        source_content_hash=source_hash,
        source_owner_principal_id=P1,
        agent_instance_id=AGENT,
    )
    second = prepare_memory_promotion(
        target="memory",
        source_scope=item.write_scope,
        source_content_hash=source_hash,
        source_owner_principal_id=P1,
        agent_instance_id=AGENT,
    )
    assert first == second
    assert first.approved_content_hash == source_hash
    assert first.sanitized is False


def test_prepare_memory_promotion_rejects_wrong_owner_or_missing_hash(tmp_path: Path) -> None:
    item, source_hash = seed(tmp_path, "private durable fact")
    with pytest.raises(FleetPromotionMutationError, match="owner"):
        prepare_memory_promotion(
            target="memory",
            source_scope=item.write_scope,
            source_content_hash=source_hash,
            source_owner_principal_id="sha256:" + "9" * 64,
            agent_instance_id=AGENT,
        )
    with pytest.raises(FleetPromotionMutationError, match="hash"):
        prepare_memory_promotion(
            target="memory",
            source_scope=item.write_scope,
            source_content_hash="sha256:" + "8" * 64,
            source_owner_principal_id=P1,
            agent_instance_id=AGENT,
        )


def test_commit_memory_promotion_persists_only_sanitized_shared_content(tmp_path: Path) -> None:
    item, source_hash = seed(tmp_path, "Contact dev@example.com after release")
    prepared = prepare_memory_promotion(
        target="memory",
        source_scope=item.write_scope,
        source_content_hash=source_hash,
        source_owner_principal_id=P1,
        agent_instance_id=AGENT,
    )
    authorization = memory_authorization(
        item,
        source_hash=source_hash,
        approved_hash=prepared.approved_content_hash,
    )
    result = commit_memory_promotion(target="memory", authorization=authorization)
    assert result.current_promotion_id == authorization.promotion_id
    assert result.to_document()["authority"] == "none"

    project = FleetMemoryScopeRef("project", "fleet")
    reader = FleetMemoryBinding(
        version="fleet-memory-v1",
        principal_id=P1,
        principal_kind="owner",
        principal_generation=1,
        principal_binding_hash=B1,
        agent_instance_id=AGENT,
        source_run="later-run",
        read_scopes=(item.write_scope, project),
        write_scope=item.write_scope,
        retention_until_ms=None,
    )
    with fleet_memory_scope(reader):
        store = MemoryStore(memory_char_limit=10_000, user_char_limit=10_000)
        store.load_from_disk()
        project_path = store._scope_dir(project) / store._target_filename("memory")
        promoted_content = project_path.read_text(encoding="utf-8")
        prompt = store.format_for_system_prompt("memory") or ""
    assert "dev@example.com" not in promoted_content
    assert "[email]" in promoted_content
    assert "[email]" in prompt


def test_memory_promotion_replay_is_idempotent_and_stale_current_conflicts(tmp_path: Path) -> None:
    item, source_hash = seed(tmp_path, "safe shared release fact")
    prepared = prepare_memory_promotion(
        target="memory",
        source_scope=item.write_scope,
        source_content_hash=source_hash,
        source_owner_principal_id=P1,
        agent_instance_id=AGENT,
    )
    first_auth = memory_authorization(
        item,
        source_hash=source_hash,
        approved_hash=prepared.approved_content_hash,
    )
    first = commit_memory_promotion(target="memory", authorization=first_auth)
    replay = commit_memory_promotion(target="memory", authorization=first_auth)
    assert first.idempotent is False
    assert replay.idempotent is True

    stale = memory_authorization(
        item,
        source_hash=source_hash,
        approved_hash=prepared.approved_content_hash,
        expected_current=None,
        issued_at_ms=20_000,
    )
    with pytest.raises(FleetPromotionMutationError, match="conflict"):
        commit_memory_promotion(target="memory", authorization=stale)


def test_promotion_store_creates_fresh_hermes_home(tmp_path: Path) -> None:
    fresh_home = tmp_path / "fresh-hermes-home"
    token = set_hermes_home_override(fresh_home)
    try:
        assert not fresh_home.exists()
        history = promotion_history(
            subject_kind="memory",
            subject_key="memory:" + ("sha256:" + "e" * 64),
            source_owner_principal_id=P1,
            agent_instance_id=AGENT,
            source_scope={"kind": "principal", "scope_id": P1},
            target_scope={"kind": "project", "scope_id": "fleet"},
        )
        assert history["current_promotion_id"] is None
        assert history["history"] == []
        assert fresh_home.is_dir()
        if os.name != "nt":
            assert stat.S_IMODE(fresh_home.stat().st_mode) == 0o700
    finally:
        reset_hermes_home_override(token)


def test_promotion_store_rejects_symlinked_state_root(tmp_path: Path) -> None:
    home = tmp_path / "hermes"
    outside = tmp_path / "outside"
    outside.mkdir()
    fleet_link = home / ".fleet"
    fleet_link.symlink_to(outside, target_is_directory=True)

    with pytest.raises(FleetPromotionMutationError, match="unsafe"):
        promotion_history(
            subject_kind="memory",
            subject_key="memory:" + ("sha256:" + "f" * 64),
            source_owner_principal_id=P1,
            agent_instance_id=AGENT,
            source_scope={"kind": "principal", "scope_id": P1},
            target_scope={"kind": "project", "scope_id": "fleet"},
        )


def test_memory_promotion_history_and_rollback_are_append_only(tmp_path: Path) -> None:
    item, source_hash = seed(tmp_path, "stable shared release fact")
    prepared = prepare_memory_promotion(
        target="memory",
        source_scope=item.write_scope,
        source_content_hash=source_hash,
        source_owner_principal_id=P1,
        agent_instance_id=AGENT,
    )
    first_auth = memory_authorization(
        item,
        source_hash=source_hash,
        approved_hash=prepared.approved_content_hash,
        issued_at_ms=10_000,
    )
    first = commit_memory_promotion(target="memory", authorization=first_auth)
    second_auth = memory_authorization(
        item,
        source_hash=source_hash,
        approved_hash=prepared.approved_content_hash,
        expected_current=first.promotion_id,
        issued_at_ms=20_000,
    )
    second = commit_memory_promotion(target="memory", authorization=second_auth)
    assert second.previous_promotion_id == first.promotion_id

    before = promotion_history(
        subject_kind="memory",
        subject_key="memory:" + source_hash,
        source_owner_principal_id=P1,
        agent_instance_id=AGENT,
        source_scope=item.write_scope.to_request(),
        target_scope={"kind": "project", "scope_id": "fleet"},
    )
    assert before["current_promotion_id"] == second.promotion_id
    assert before["history"] == [first.promotion_id, second.promotion_id]

    other_principal = promotion_history(
        subject_kind="memory",
        subject_key="memory:" + source_hash,
        source_owner_principal_id=P2,
        agent_instance_id=AGENT,
        source_scope={"kind": "principal", "scope_id": P2},
        target_scope={"kind": "project", "scope_id": "fleet"},
    )
    assert other_principal["current_promotion_id"] is None
    assert other_principal["history"] == []

    rollback_auth = memory_authorization(
        item,
        source_hash=source_hash,
        approved_hash=prepared.approved_content_hash,
        expected_current=second.promotion_id,
        rollback_to=first.promotion_id,
        operation="rollback",
        issued_at_ms=30_000,
    )
    rolled_back = rollback_promotion(authorization=rollback_auth)
    assert rolled_back.operation == "rollback"
    assert rolled_back.previous_promotion_id == second.promotion_id
    assert rolled_back.current_promotion_id == rollback_auth.promotion_id
    assert rollback_promotion(authorization=rollback_auth).idempotent is True

    after = promotion_history(
        subject_kind="memory",
        subject_key="memory:" + source_hash,
        source_owner_principal_id=P1,
        agent_instance_id=AGENT,
        source_scope=item.write_scope.to_request(),
        target_scope={"kind": "project", "scope_id": "fleet"},
    )
    assert after["current_promotion_id"] == rollback_auth.promotion_id
    assert after["history"] == [
        first.promotion_id,
        second.promotion_id,
        rollback_auth.promotion_id,
    ]
    assert after["records"][-1]["rollback_to_promotion_id"] == first.promotion_id
    assert after["authority"] == "none"

    stale_rollback = memory_authorization(
        item,
        source_hash=source_hash,
        approved_hash=prepared.approved_content_hash,
        expected_current=second.promotion_id,
        rollback_to=first.promotion_id,
        operation="rollback",
        issued_at_ms=40_000,
    )
    with pytest.raises(FleetPromotionMutationError, match="conflict"):
        rollback_promotion(authorization=stale_rollback)
