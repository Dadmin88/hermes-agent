from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

import tools.fleet_skill_verification as verification_module
import tools.skill_manager_tool as sm
import tools.skills_tool as skills_tool
from agent.fleet_memory_scope import (
    FleetMemoryBinding,
    FleetMemoryScopeRef,
    fleet_memory_scope,
)
from agent.fleet_promotion import FleetPromotionAuthorization
from hermes_constants import reset_hermes_home_override, set_hermes_home_override
from tests.tools.test_fleet_skill_verification import (
    AGENT,
    B1,
    P1,
    SAFE_SKILL,
    binding as learning_binding,
    create_candidate,
    mocked_runtime_checks,
)
from tools.fleet_promotion import (
    FleetPromotionMutationError,
    _sanitized_skill_manifest,
    commit_skill_promotion,
    prepare_skill_promotion,
    promotion_history,
    rollback_promotion,
    visible_promoted_skill_files,
)
from tools.fleet_skill_quarantine import quarantine_skill_candidate
from tools.fleet_skill_verification import verify_skill_candidate

ADMIN = P1
ADMIN_BINDING = "sha256:" + "e" * 64


@pytest.fixture(autouse=True)
def isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    home = tmp_path / "hermes"
    home.mkdir()
    token = set_hermes_home_override(home)
    root = tmp_path / "skills"
    root.mkdir()
    monkeypatch.setattr(sm, "SKILLS_DIR", root)
    monkeypatch.setattr(skills_tool, "SKILLS_DIR", root)
    monkeypatch.setattr("agent.skill_utils.get_all_skills_dirs", lambda: [root])
    sm._reset_background_review_read_marks()
    skills_tool._SKILLS_CACHE.clear()
    try:
        yield root
    finally:
        skills_tool._SKILLS_CACHE.clear()
        reset_hermes_home_override(token)


def promotion_authorization(
    *,
    candidate_id: str,
    source_hash: str,
    approved_hash: str,
    verification_digest: str,
    source_scope: dict[str, str] | None = None,
    target_scope: dict[str, str] | None = None,
    administrator_principal_id: str = ADMIN,
    administrator_binding_hash: str = ADMIN_BINDING,
    expected_current: str | None = None,
    rollback_to: str | None = None,
    operation: str = "promote",
    issued_at_ms: int = 10_000,
) -> FleetPromotionAuthorization:
    source_scope = source_scope or {"kind": "principal", "scope_id": P1}
    target_scope = target_scope or {"kind": "project", "scope_id": "project-one"}
    unsigned: dict[str, object] = {
        "version": "fleet-promotion-v1",
        "policy_version": "phase18-v1",
        "subject_kind": "skill",
        "subject_key": candidate_id,
        "source_owner_principal_id": P1,
        "agent_instance_id": AGENT,
        "source_scope": source_scope,
        "target_scope": target_scope,
        "source_content_hash": source_hash,
        "approved_content_hash": approved_hash,
        "administrator": {
            "principal_id": administrator_principal_id,
            "kind": target_scope["kind"],
            "generation": 1,
            "binding_hash": administrator_binding_hash,
        },
        "issued_at_ms": issued_at_ms,
        "expires_at_ms": issued_at_ms + 60_000,
        "verification_digest": verification_digest,
        "expected_current_promotion_id": expected_current,
        "rollback_to_promotion_id": rollback_to,
        "operation": operation,
        "authority": "none",
    }
    payload = json.dumps(
        unsigned,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return FleetPromotionAuthorization.from_request(
        {
            **unsigned,
            "promotion_id": "sha256:" + hashlib.sha256(payload).hexdigest(),
        },
        now_ms=issued_at_ms + 1,
    )


def scoped_reader(
    *, include_project: bool, include_network: bool = False
) -> FleetMemoryBinding:
    private = FleetMemoryScopeRef("principal", P1)
    reads = [private]
    if include_project:
        reads.append(FleetMemoryScopeRef("project", "project-one"))
    if include_network:
        reads.append(FleetMemoryScopeRef("network", "network-one"))
    return FleetMemoryBinding(
        version="fleet-memory-v1",
        principal_id=P1,
        principal_kind="owner",
        principal_generation=1,
        principal_binding_hash=B1,
        agent_instance_id=AGENT,
        source_run="later-run",
        read_scopes=tuple(reads),
        write_scope=private,
        retention_until_ms=None,
    )


def verified_candidate(
    root: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, dict[str, object]]:
    bound = learning_binding()
    _bound, candidate = create_candidate(root, content=SAFE_SKILL, bound=bound)
    quarantine = quarantine_skill_candidate(candidate, expected_binding=bound)
    assert quarantine.state == "verification-ready"
    monkeypatch.setattr(verification_module, "_runtime_checks", mocked_runtime_checks)
    verification = verify_skill_candidate(candidate, expected_binding=bound)
    assert verification.verified is True
    metadata = json.loads((candidate / "candidate.json").read_text(encoding="utf-8"))
    return candidate, metadata


def test_verified_skill_promotion_is_visible_only_in_authorized_scope(
    isolated_home: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, metadata = verified_candidate(isolated_home, monkeypatch)
    candidate_id = metadata["candidate_id"]
    prepared = prepare_skill_promotion(
        candidate_id=candidate_id,
        source_owner_principal_id=P1,
        agent_instance_id=AGENT,
    )
    material = prepared.to_document()["evaluation_material"]
    assert material["schema"] == "fleet.promotion-evaluation-material.v1"
    assert material["kind"] == "skill"
    assert material["content_hash"] == prepared.approved_content_hash
    assert any(item["path"] == "SKILL.md" for item in material["files"])
    assert all(
        item["bytes"] == len(item["text"].encode("utf-8"))
        for item in material["files"]
    )
    authorization = promotion_authorization(
        candidate_id=candidate_id,
        source_hash=prepared.source_content_hash,
        approved_hash=prepared.approved_content_hash,
        verification_digest=prepared.verification_digest or "",
    )
    committed = commit_skill_promotion(authorization=authorization)
    assert committed.subject_kind == "skill"
    assert committed.to_document()["authority"] == "none"
    assert metadata["active"] is False
    assert metadata["authority"] == "none"

    with fleet_memory_scope(scoped_reader(include_project=False)):
        assert visible_promoted_skill_files() == []
        names = {item["name"] for item in skills_tool._find_all_skills()}
        assert "safe-helper" not in names

    with fleet_memory_scope(scoped_reader(include_project=True)):
        visible = visible_promoted_skill_files()
        assert len(visible) == 1
        assert visible[0].name == "SKILL.md"
        names = {item["name"] for item in skills_tool._find_all_skills()}
        assert "safe-helper" in names
        viewed = json.loads(skills_tool.skill_view("safe-helper", preprocess=False))
        assert viewed["success"] is True
        assert "# Safe helper" in viewed["content"]

    # The original Phase 15/17 candidate remains quarantined and inactive.
    persisted = json.loads((candidate / "candidate.json").read_text(encoding="utf-8"))
    assert persisted["state"] == "verification-ready"
    assert persisted["active"] is False
    assert persisted["authority"] == "none"


def test_skill_multi_hop_requires_current_source_promotion(
    isolated_home: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _candidate, metadata = verified_candidate(isolated_home, monkeypatch)
    candidate_id = metadata["candidate_id"]
    prepared = prepare_skill_promotion(
        candidate_id=candidate_id,
        source_owner_principal_id=P1,
        agent_instance_id=AGENT,
    )
    authorization = promotion_authorization(
        candidate_id=candidate_id,
        source_hash=prepared.source_content_hash,
        approved_hash=prepared.approved_content_hash,
        verification_digest=prepared.verification_digest or "",
        source_scope={"kind": "project", "scope_id": "project-one"},
        target_scope={"kind": "network", "scope_id": "network-one"},
    )
    with pytest.raises(
        FleetPromotionMutationError,
        match="source scope is not currently promoted",
    ):
        commit_skill_promotion(authorization=authorization)


def test_skill_multi_hop_prefers_broadest_visible_exact_version(
    isolated_home: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _candidate, metadata = verified_candidate(isolated_home, monkeypatch)
    candidate_id = metadata["candidate_id"]
    prepared = prepare_skill_promotion(
        candidate_id=candidate_id,
        source_owner_principal_id=P1,
        agent_instance_id=AGENT,
    )
    project_authorization = promotion_authorization(
        candidate_id=candidate_id,
        source_hash=prepared.source_content_hash,
        approved_hash=prepared.approved_content_hash,
        verification_digest=prepared.verification_digest or "",
    )
    project_result = commit_skill_promotion(
        authorization=project_authorization
    )
    assert project_result.operation == "promote"

    network_authorization = promotion_authorization(
        candidate_id=candidate_id,
        source_hash=prepared.source_content_hash,
        approved_hash=prepared.approved_content_hash,
        verification_digest=prepared.verification_digest or "",
        source_scope={"kind": "project", "scope_id": "project-one"},
        target_scope={"kind": "network", "scope_id": "network-one"},
        issued_at_ms=20_000,
    )
    network_result = commit_skill_promotion(
        authorization=network_authorization
    )
    assert network_result.operation == "promote"

    with fleet_memory_scope(
        scoped_reader(include_project=True, include_network=True)
    ):
        visible = visible_promoted_skill_files()
        assert len(visible) == 1
        assert network_authorization.promotion_id.removeprefix("sha256:") in str(
            visible[0]
        )
        viewed = json.loads(
            skills_tool.skill_view("safe-helper", preprocess=False)
        )
        assert viewed["success"] is True
        assert "# Safe helper" in viewed["content"]


def test_promoted_skill_tamper_invalidates_visibility(
    isolated_home: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _candidate, metadata = verified_candidate(isolated_home, monkeypatch)
    candidate_id = metadata["candidate_id"]
    prepared = prepare_skill_promotion(
        candidate_id=candidate_id,
        source_owner_principal_id=P1,
        agent_instance_id=AGENT,
    )
    authorization = promotion_authorization(
        candidate_id=candidate_id,
        source_hash=prepared.source_content_hash,
        approved_hash=prepared.approved_content_hash,
        verification_digest=prepared.verification_digest or "",
    )
    commit_skill_promotion(authorization=authorization)

    with fleet_memory_scope(scoped_reader(include_project=True)):
        visible = visible_promoted_skill_files()
        assert len(visible) == 1
        visible[0].write_text(SAFE_SKILL + "\nTampered after approval.\n", encoding="utf-8")
        with pytest.raises(FleetPromotionMutationError, match="changed after approval"):
            visible_promoted_skill_files()
        skills_tool._SKILLS_CACHE.clear()
        names = {item["name"] for item in skills_tool._find_all_skills()}
        assert "safe-helper" not in names


def test_skill_rollback_materializes_fresh_exact_bundle(
    isolated_home: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _candidate, metadata = verified_candidate(isolated_home, monkeypatch)
    candidate_id = metadata["candidate_id"]
    prepared = prepare_skill_promotion(
        candidate_id=candidate_id,
        source_owner_principal_id=P1,
        agent_instance_id=AGENT,
    )
    first_auth = promotion_authorization(
        candidate_id=candidate_id,
        source_hash=prepared.source_content_hash,
        approved_hash=prepared.approved_content_hash,
        verification_digest=prepared.verification_digest or "",
        issued_at_ms=10_000,
    )
    first = commit_skill_promotion(authorization=first_auth)
    second_auth = promotion_authorization(
        candidate_id=candidate_id,
        source_hash=prepared.source_content_hash,
        approved_hash=prepared.approved_content_hash,
        verification_digest=prepared.verification_digest or "",
        expected_current=first.promotion_id,
        issued_at_ms=20_000,
    )
    second = commit_skill_promotion(authorization=second_auth)

    rollback_auth = promotion_authorization(
        candidate_id=candidate_id,
        source_hash=prepared.source_content_hash,
        approved_hash=prepared.approved_content_hash,
        verification_digest=prepared.verification_digest or "",
        expected_current=second.promotion_id,
        rollback_to=first.promotion_id,
        operation="rollback",
        issued_at_ms=30_000,
    )
    rolled_back = rollback_promotion(authorization=rollback_auth)
    assert rolled_back.current_promotion_id == rollback_auth.promotion_id
    assert rolled_back.operation == "rollback"

    history = promotion_history(
        subject_kind="skill",
        subject_key=candidate_id,
        source_owner_principal_id=P1,
        agent_instance_id=AGENT,
        source_scope={"kind": "principal", "scope_id": P1},
        target_scope={"kind": "project", "scope_id": "project-one"},
    )
    assert history["current_promotion_id"] == rollback_auth.promotion_id
    assert history["history"] == [
        first.promotion_id,
        second.promotion_id,
        rollback_auth.promotion_id,
    ]

    with fleet_memory_scope(scoped_reader(include_project=True)):
        visible = visible_promoted_skill_files()
        assert len(visible) == 1
        assert rollback_auth.promotion_id.removeprefix("sha256:") in str(visible[0])
        assert "# Safe helper" in visible[0].read_text(encoding="utf-8")


def test_skill_promotion_rejects_opaque_binary_content(tmp_path: Path) -> None:
    bundle = tmp_path / "opaque-skill"
    bundle.mkdir()
    (bundle / "SKILL.md").write_text(SAFE_SKILL, encoding="utf-8")
    assets = bundle / "assets"
    assets.mkdir()
    (assets / "opaque.bin").write_bytes(b"\xff\xfe\x00\x01")
    with pytest.raises(FleetPromotionMutationError, match="opaque binary"):
        _sanitized_skill_manifest(bundle)


def test_skill_promotion_rejects_promoted_name_collision(
    isolated_home: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _first_candidate, first_metadata = verified_candidate(isolated_home, monkeypatch)
    first_id = first_metadata["candidate_id"]
    first_prepared = prepare_skill_promotion(
        candidate_id=first_id,
        source_owner_principal_id=P1,
        agent_instance_id=AGENT,
    )
    first_auth = promotion_authorization(
        candidate_id=first_id,
        source_hash=first_prepared.source_content_hash,
        approved_hash=first_prepared.approved_content_hash,
        verification_digest=first_prepared.verification_digest or "",
    )
    commit_skill_promotion(authorization=first_auth)

    second_binding = replace(learning_binding(), source_run="run-second")
    _bound, _candidate_hint = create_candidate(
        isolated_home,
        content=SAFE_SKILL,
        bound=second_binding,
    )
    second_candidate = None
    candidate_root = isolated_home / ".fleet" / "candidates"
    for candidate in candidate_root.iterdir():
        if not candidate.is_dir():
            continue
        metadata = json.loads(
            (candidate / "candidate.json").read_text(encoding="utf-8")
        )
        if metadata.get("source_run") == second_binding.source_run:
            second_candidate = candidate
            break
    assert second_candidate is not None
    quarantine = quarantine_skill_candidate(
        second_candidate,
        expected_binding=second_binding,
    )
    assert quarantine.state == "verification-ready"
    verification = verify_skill_candidate(
        second_candidate,
        expected_binding=second_binding,
    )
    assert verification.verified is True
    second_metadata = json.loads(
        (second_candidate / "candidate.json").read_text(encoding="utf-8")
    )
    second_id = second_metadata["candidate_id"]
    assert second_id != first_id
    second_prepared = prepare_skill_promotion(
        candidate_id=second_id,
        source_owner_principal_id=P1,
        agent_instance_id=AGENT,
    )
    second_auth = promotion_authorization(
        candidate_id=second_id,
        source_hash=second_prepared.source_content_hash,
        approved_hash=second_prepared.approved_content_hash,
        verification_digest=second_prepared.verification_digest or "",
        issued_at_ms=20_000,
    )
    with pytest.raises(FleetPromotionMutationError, match="promoted skill name"):
        commit_skill_promotion(authorization=second_auth)


def test_skill_promotion_rejects_native_name_collision(
    isolated_home: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _candidate, metadata = verified_candidate(isolated_home, monkeypatch)
    candidate_id = metadata["candidate_id"]
    prepared = prepare_skill_promotion(
        candidate_id=candidate_id,
        source_owner_principal_id=P1,
        agent_instance_id=AGENT,
    )

    native = isolated_home / "native" / "safe-helper"
    native.mkdir(parents=True)
    (native / "SKILL.md").write_text(SAFE_SKILL, encoding="utf-8")
    skills_tool._SKILLS_CACHE.clear()

    authorization = promotion_authorization(
        candidate_id=candidate_id,
        source_hash=prepared.source_content_hash,
        approved_hash=prepared.approved_content_hash,
        verification_digest=prepared.verification_digest or "",
    )
    with pytest.raises(FleetPromotionMutationError, match="conflict"):
        commit_skill_promotion(authorization=authorization)
