from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import tools.fleet_skill_verification as verification_module
import tools.skill_manager_tool as sm
import tools.skills_tool as skills_tool
from agent.fleet_forget import FleetForgetAuthorization
from agent.fleet_memory_scope import (
    FleetMemoryBinding,
    FleetMemoryScopeRef,
    fleet_memory_scope,
)
from agent.fleet_promotion import FleetPromotionAuthorization
from hermes_constants import reset_hermes_home_override, set_hermes_home_override
from tests.tools.test_fleet_promotion_skills import (
    promotion_authorization as skill_promotion_authorization,
    verified_candidate,
)
from tests.tools.test_fleet_skill_verification import AGENT as SKILL_AGENT
from tests.tools.test_fleet_skill_verification import P1 as SKILL_OWNER
from tools.fleet_base_overlay import assess_base_overlay_compatibility, _report_root
from tools.fleet_forget import forget_fleet_learning
from tools.fleet_promotion import (
    _record_path,
    _skill_version_dir,
    commit_memory_promotion,
    commit_skill_promotion,
    prepare_memory_promotion,
    prepare_skill_promotion,
)
from tools.memory_tool import MemoryStore

P1 = "sha256:" + "1" * 64
B1 = "sha256:" + "2" * 64
AGENT = "sha256:" + "3" * 64


@pytest.fixture(autouse=True)
def reset_home(tmp_path: Path) -> None:
    home = tmp_path / "hermes"
    home.mkdir()
    token = set_hermes_home_override(home)
    yield
    reset_hermes_home_override(token)


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


def promotion_authorization(
    *,
    source_scope: FleetMemoryScopeRef,
    target_scope: FleetMemoryScopeRef,
    source_hash: str,
    approved_hash: str,
    expected_current: str | None = None,
    issued_at_ms: int,
) -> FleetPromotionAuthorization:
    unsigned: dict[str, object] = {
        "version": "fleet-promotion-v1",
        "policy_version": "phase18-v1",
        "subject_kind": "memory",
        "subject_key": "memory:" + source_hash,
        "source_owner_principal_id": P1,
        "agent_instance_id": AGENT,
        "source_scope": source_scope.to_request(),
        "target_scope": target_scope.to_request(),
        "source_content_hash": source_hash,
        "approved_content_hash": approved_hash,
        "administrator": {
            "principal_id": P1,
            "kind": target_scope.kind,
            "generation": 1,
            "binding_hash": "sha256:" + "5" * 64,
        },
        "issued_at_ms": issued_at_ms,
        "expires_at_ms": issued_at_ms + 60_000,
        "verification_digest": None,
        "expected_current_promotion_id": expected_current,
        "rollback_to_promotion_id": None,
        "operation": "promote",
        "authority": "none",
    }
    promotion_id = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(
                unsigned,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
    )
    return FleetPromotionAuthorization.from_request(
        {**unsigned, "promotion_id": promotion_id},
        now_ms=issued_at_ms + 1,
    )


def forget_authorization(source_hash: str) -> FleetForgetAuthorization:
    unsigned = {
        "version": "fleet-forget-v1",
        "policy_version": "phase25-v1",
        "subject_kind": "memory",
        "subject_key": "memory:" + source_hash,
        "source_owner_principal_id": P1,
        "agent_instance_id": AGENT,
        "administrator": {
            "principal_id": P1,
            "kind": "owner",
            "generation": 1,
            "binding_hash": B1,
        },
        "issued_at_ms": 50_000,
        "expires_at_ms": 110_000,
        "authority": "none",
    }
    forget_id = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(
                unsigned,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
    )
    return FleetForgetAuthorization.from_request(
        {**unsigned, "forget_id": forget_id}, now_ms=50_001
    )


def scope_entries(scope: FleetMemoryScopeRef) -> list[str]:
    store = MemoryStore(memory_char_limit=64 * 1024, user_char_limit=64 * 1024)
    path = store._scope_dir(scope) / store._target_filename("memory")
    return store._read_file(path) if path.exists() else []


def test_forget_memory_cascades_multi_hop_promotions_and_survives_restart(
    tmp_path: Path,
) -> None:
    item = binding()
    source = "Contact dev@example.com for the release procedure"
    unrelated = "Keep this unrelated memory"
    with fleet_memory_scope(item):
        store = MemoryStore(memory_char_limit=10_000, user_char_limit=10_000)
        store.load_from_disk()
        assert store.add("memory", source)["success"] is True
        assert store.add("memory", unrelated)["success"] is True
    source_hash = MemoryStore._entry_hash(source)

    project = FleetMemoryScopeRef("project", "project-alpha")
    prepared_project = prepare_memory_promotion(
        target="memory",
        source_scope=item.write_scope,
        source_content_hash=source_hash,
        source_owner_principal_id=P1,
        agent_instance_id=AGENT,
    )
    assert prepared_project.approved_content_hash != source_hash
    project_auth = promotion_authorization(
        source_scope=item.write_scope,
        target_scope=project,
        source_hash=source_hash,
        approved_hash=prepared_project.approved_content_hash,
        issued_at_ms=10_000,
    )
    project_result = commit_memory_promotion(
        target="memory", authorization=project_auth
    )

    network = FleetMemoryScopeRef("network", "network-alpha")
    prepared_network = prepare_memory_promotion(
        target="memory",
        source_scope=project,
        source_content_hash=prepared_project.approved_content_hash,
        source_owner_principal_id=P1,
        agent_instance_id=AGENT,
    )
    network_auth = promotion_authorization(
        source_scope=project,
        target_scope=network,
        source_hash=prepared_project.approved_content_hash,
        approved_hash=prepared_network.approved_content_hash,
        expected_current=None,
        issued_at_ms=20_000,
    )
    network_result = commit_memory_promotion(
        target="memory", authorization=network_auth
    )

    assert source in scope_entries(item.write_scope)
    assert prepared_project.evaluation_material["text"] in scope_entries(project)
    assert prepared_network.evaluation_material["text"] in scope_entries(network)

    authorization = forget_authorization(source_hash)
    result = forget_fleet_learning(authorization)
    assert result.memory_entries == 3
    assert result.promotion_records == 2
    assert result.promotion_states == 2
    assert result.idempotent is False

    assert source not in scope_entries(item.write_scope)
    assert unrelated in scope_entries(item.write_scope)
    assert prepared_project.evaluation_material["text"] not in scope_entries(project)
    assert prepared_network.evaluation_material["text"] not in scope_entries(network)

    home = tmp_path / "hermes"
    regular_payloads = [
        path.read_bytes()
        for path in home.rglob("*")
        if path.is_file() and not path.is_symlink()
    ]
    assert all(source.encode() not in payload for payload in regular_payloads)
    assert all(
        str(prepared_project.evaluation_material["text"]).encode() not in payload
        for payload in regular_payloads
    )
    assert all(
        project_result.promotion_id.encode() not in payload
        for payload in regular_payloads
    )
    assert all(
        network_result.promotion_id.encode() not in payload
        for payload in regular_payloads
    )

    repeated = forget_fleet_learning(authorization)
    assert repeated.idempotent is True
    assert repeated.memory_entries == 3
    assert unrelated in scope_entries(item.write_scope)


def skill_forget_authorization(candidate_id: str) -> FleetForgetAuthorization:
    unsigned = {
        "version": "fleet-forget-v1",
        "policy_version": "phase25-v1",
        "subject_kind": "skill",
        "subject_key": candidate_id,
        "source_owner_principal_id": SKILL_OWNER,
        "agent_instance_id": SKILL_AGENT,
        "administrator": {
            "principal_id": SKILL_OWNER,
            "kind": "owner",
            "generation": 1,
            "binding_hash": B1,
        },
        "issued_at_ms": 60_000,
        "expires_at_ms": 120_000,
        "authority": "none",
    }
    forget_id = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(
                unsigned,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
    )
    return FleetForgetAuthorization.from_request(
        {**unsigned, "forget_id": forget_id}, now_ms=60_001
    )


def test_forget_skill_erases_candidate_promoted_bundle_reports_and_caches(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "skills"
    root.mkdir()
    monkeypatch.setattr(sm, "SKILLS_DIR", root)
    monkeypatch.setattr(skills_tool, "SKILLS_DIR", root)
    monkeypatch.setattr("agent.skill_utils.get_all_skills_dirs", lambda: [root])
    sm._reset_background_review_read_marks()
    skills_tool._SKILLS_CACHE.clear()

    candidate, metadata = verified_candidate(root, monkeypatch)
    candidate_id = metadata["candidate_id"]
    prepared = prepare_skill_promotion(
        candidate_id=candidate_id,
        source_owner_principal_id=SKILL_OWNER,
        agent_instance_id=SKILL_AGENT,
    )
    promotion = skill_promotion_authorization(
        candidate_id=candidate_id,
        source_hash=prepared.source_content_hash,
        approved_hash=prepared.approved_content_hash,
        verification_digest=prepared.verification_digest or "",
    )
    committed = commit_skill_promotion(authorization=promotion)
    bundle = _skill_version_dir(committed.promotion_id)
    assert bundle.exists()
    assert _record_path(committed.promotion_id).exists()

    base_digest = "sha256:" + "a" * 64
    assess_base_overlay_compatibility(
        agent_instance_id=SKILL_AGENT,
        base_manifest_digest=base_digest,
        base_skills=[],
    )
    report_dir = _report_root() / SKILL_AGENT.removeprefix("sha256:")
    assert report_dir.exists()

    skills_tool._SKILLS_CACHE["sentinel"] = ((), 0.0, ["stale"])
    snapshot = tmp_path / "hermes" / ".skills_prompt_snapshot.json"
    snapshot.write_text("stale skill prompt", encoding="utf-8")

    authorization = skill_forget_authorization(candidate_id)
    result = forget_fleet_learning(authorization)
    assert result.skill_candidate is True
    assert result.skill_bundles == 1
    assert result.promotion_records == 1
    assert result.promotion_states == 1
    assert result.base_overlay_reports == 1

    assert not candidate.exists()
    assert not bundle.exists()
    assert not _record_path(committed.promotion_id).exists()
    assert not report_dir.exists()
    assert skills_tool._SKILLS_CACHE == {}
    assert not snapshot.exists()

    regular_payloads = [
        path.read_bytes()
        for parent in (tmp_path / "hermes", root)
        for path in parent.rglob("*")
        if path.is_file() and not path.is_symlink()
    ]
    assert all(b"# Safe helper" not in payload for payload in regular_payloads)

    repeated = forget_fleet_learning(authorization)
    assert repeated.idempotent is True
    assert repeated.skill_candidate is True
