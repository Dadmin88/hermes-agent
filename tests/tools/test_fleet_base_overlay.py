from __future__ import annotations

import shutil
from pathlib import Path

import pytest

import tools.fleet_skill_verification as verification_module
import tools.skill_manager_tool as sm
import tools.skills_tool as skills_tool
from agent.fleet_context_scope import FleetContextBinding, fleet_context_scope
from agent.fleet_memory_scope import fleet_memory_scope
from hermes_constants import reset_hermes_home_override, set_hermes_home_override
from tests.tools.test_fleet_promotion_skills import (
    AGENT,
    B1,
    P1,
    promotion_authorization,
    scoped_reader,
    verified_candidate,
)
from tests.tools.test_fleet_skill_verification import mocked_runtime_checks
from tools.fleet_base_overlay import (
    FleetBaseOverlayError,
    assess_base_overlay_compatibility,
    load_base_overlay_compatibility,
    quarantined_promoted_skill_names,
)
from tools.fleet_promotion import commit_skill_promotion, prepare_skill_promotion

BASE_ONE = "sha256:" + "1" * 64
BASE_TWO = "sha256:" + "2" * 64
BASE_SKILL_HASH = "sha256:" + "3" * 64
RUN_AUTHORITY = "sha256:" + "4" * 64


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


def _context(base_manifest_digest: str) -> FleetContextBinding:
    return FleetContextBinding(
        version="fleet-context-v1",
        principal_id=P1,
        principal_kind="owner",
        principal_generation=1,
        principal_binding_hash=B1,
        agent_instance_id=AGENT,
        base_manifest_digest=base_manifest_digest,
        run_authority_hash=RUN_AUTHORITY,
    )


def _promote_verified_skill(
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, str]:
    candidate, metadata = verified_candidate(root, monkeypatch)
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
    return candidate, candidate_id


def test_promoted_skill_is_reverified_and_remains_visible_when_base_does_not_conflict(
    isolated_home: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _candidate, candidate_id = _promote_verified_skill(isolated_home, monkeypatch)
    monkeypatch.setattr(verification_module, "_runtime_checks", mocked_runtime_checks)

    report = assess_base_overlay_compatibility(
        agent_instance_id=AGENT,
        base_manifest_digest=BASE_ONE,
        base_skills=[
            {
                "name": "different-base-skill",
                "path": "skills/different-base-skill/SKILL.md",
                "sha256": BASE_SKILL_HASH,
            }
        ],
    )

    assert report["authority"] == "none"
    assert report["skills"] == [
        {
            "subject_key": candidate_id,
            "source_owner_principal_id": P1,
            "name": "safe-helper",
            "approved_content_hash": report["skills"][0]["approved_content_hash"],
            "verification_digest": report["skills"][0]["verification_digest"],
            "promotion_ids": report["skills"][0]["promotion_ids"],
            "reverified": True,
            "revalidation_reason": None,
            "status": "compatible",
            "reason_codes": [],
        }
    ]
    assert load_base_overlay_compatibility(
        agent_instance_id=AGENT,
        base_manifest_digest=BASE_ONE,
    ) == report

    with fleet_memory_scope(scoped_reader(include_project=True)):
        with fleet_context_scope(_context(BASE_ONE)):
            assert quarantined_promoted_skill_names() == set()
            names = {item["name"] for item in skills_tool._find_all_skills()}
            assert "safe-helper" in names


def test_new_base_name_collision_quarantines_but_does_not_delete_promoted_skill(
    isolated_home: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _candidate, _candidate_id = _promote_verified_skill(isolated_home, monkeypatch)
    monkeypatch.setattr(verification_module, "_runtime_checks", mocked_runtime_checks)

    report = assess_base_overlay_compatibility(
        agent_instance_id=AGENT,
        base_manifest_digest=BASE_TWO,
        base_skills=[
            {
                "name": "safe-helper",
                "path": "skills/safe-helper/SKILL.md",
                "sha256": BASE_SKILL_HASH,
            }
        ],
    )
    assert report["skills"][0]["reverified"] is True
    assert report["skills"][0]["status"] == "quarantined"
    assert report["skills"][0]["reason_codes"] == [
        "immutable-base-skill-name-conflict"
    ]

    with fleet_memory_scope(scoped_reader(include_project=True)):
        # The same promoted bundle remains usable under the previous exact base.
        with fleet_context_scope(_context(BASE_ONE)):
            assert "safe-helper" in {
                item["name"] for item in skills_tool._find_all_skills()
            }
        # The Phase 24 compatibility record hides it only under the new base.
        with fleet_context_scope(_context(BASE_TWO)):
            assert quarantined_promoted_skill_names() == {"safe-helper"}
            assert "safe-helper" not in {
                item["name"] for item in skills_tool._find_all_skills()
            }


def test_missing_original_candidate_quarantines_promoted_bundle_on_revalidation_failure(
    isolated_home: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate, _candidate_id = _promote_verified_skill(isolated_home, monkeypatch)
    shutil.rmtree(candidate)

    report = assess_base_overlay_compatibility(
        agent_instance_id=AGENT,
        base_manifest_digest=BASE_TWO,
        base_skills=[],
    )

    skill = report["skills"][0]
    assert skill["reverified"] is False
    assert skill["revalidation_reason"] == "phase17-reverification-failed"
    assert skill["status"] == "quarantined"
    assert skill["reason_codes"] == ["phase17-reverification-failed"]


def test_same_exact_base_report_cannot_be_redefined_after_persistence(
    isolated_home: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _promote_verified_skill(isolated_home, monkeypatch)
    monkeypatch.setattr(verification_module, "_runtime_checks", mocked_runtime_checks)
    assess_base_overlay_compatibility(
        agent_instance_id=AGENT,
        base_manifest_digest=BASE_ONE,
        base_skills=[],
    )

    with pytest.raises(FleetBaseOverlayError, match="changed for the same immutable base"):
        assess_base_overlay_compatibility(
            agent_instance_id=AGENT,
            base_manifest_digest=BASE_ONE,
            base_skills=[
                {
                    "name": "different",
                    "path": "skills/different/SKILL.md",
                    "sha256": BASE_SKILL_HASH,
                }
            ],
        )
