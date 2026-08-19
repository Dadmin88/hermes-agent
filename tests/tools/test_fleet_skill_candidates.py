from __future__ import annotations

import json
import os
import stat
from dataclasses import replace
from pathlib import Path

import pytest

import tools.skill_manager_tool as sm
from agent.fleet_skill_learning_scope import (
    FleetSkillFilesystemNeed,
    FleetSkillLearningBinding,
    fleet_skill_learning_scope,
)
from agent.skill_utils import is_excluded_skill_path
from tools.skill_provenance import (
    BACKGROUND_REVIEW,
    reset_current_write_origin,
    set_current_write_origin,
)

P1 = "sha256:" + "1" * 64
P2 = "sha256:" + "2" * 64
B1 = "sha256:" + "3" * 64
B2 = "sha256:" + "4" * 64
AGENT = "sha256:" + "5" * 64
AUTH = "sha256:" + "6" * 64
RECIPE = "sha256:" + "7" * 64
RESOLVED = "sha256:" + "8" * 64
PLAN = "sha256:" + "9" * 64
CAP = "sha256:" + "a" * 64
TARGET = "sha256:" + "b" * 64
NET = "sha256:" + "c" * 64
SECRET_FP = "sha256:" + "d" * 64

SKILL = """---
name: deploy-helper
description: Repeatable deploy helper
---

# Deploy helper

Use the approved workspace and run:

```bash
python build.py
curl https://example.invalid/health
```
"""


def binding(principal: str = P1) -> FleetSkillLearningBinding:
    return FleetSkillLearningBinding(
        principal_id=principal,
        principal_kind="owner",
        principal_generation=1,
        principal_binding_hash=B1 if principal == P1 else B2,
        agent_instance_id=AGENT,
        source_run=f"run-{principal[-4:]}",
        scope_kind="principal",
        scope_id=principal,
        run_authority_hash=AUTH,
        recipe_hash=RECIPE,
        resolved_recipe_hash=RESOLVED,
        plan_fingerprint=PLAN,
        capabilities_hash=CAP,
        target_digest=TARGET,
        toolsets=("fleet-terminal",),
        filesystem_needs=(
            FleetSkillFilesystemNeed(
                project_id="project-one",
                relative_path="src",
                target="/workspace/src",
                mode="read-only",
                max_bytes=4096,
            ),
        ),
        network_mode="project-allowlist",
        network_policy_hash=NET,
        secret_need_fingerprints=(SECRET_FP,),
    )


@pytest.fixture
def skills_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "skills"
    root.mkdir()
    monkeypatch.setattr(sm, "SKILLS_DIR", root)
    monkeypatch.setattr("agent.skill_utils.get_all_skills_dirs", lambda: [root])
    sm._reset_background_review_read_marks()
    return root


def background_skill_manage(bound: FleetSkillLearningBinding, **kwargs):
    token = set_current_write_origin(BACKGROUND_REVIEW)
    try:
        with fleet_skill_learning_scope(bound):
            return json.loads(sm.skill_manage(**kwargs))
    finally:
        reset_current_write_origin(token)


def candidate_dirs(root: Path) -> list[Path]:
    base = root / ".fleet" / "candidates"
    return sorted(path for path in base.iterdir() if path.is_dir()) if base.exists() else []


def test_background_create_becomes_private_quarantined_inactive_native_candidate(
    skills_root: Path,
) -> None:
    result = background_skill_manage(
        binding(), action="create", name="deploy-helper", content=SKILL
    )

    assert result["success"] is True
    assert result["candidate"] is True
    assert result["state"] == "quarantined"
    assert result["active"] is False
    assert sm._find_skill("deploy-helper") is None

    candidates = candidate_dirs(skills_root)
    assert len(candidates) == 1
    candidate = candidates[0]
    skill_md = candidate / "SKILL.md"
    metadata = json.loads((candidate / "candidate.json").read_text(encoding="utf-8"))

    assert skill_md.read_text(encoding="utf-8") == SKILL
    assert is_excluded_skill_path(skill_md) is True
    assert metadata["schema"] == "fleet-skill-candidate-v1"
    assert metadata["candidate_id"] == result["candidate_id"]
    assert metadata["principal"]["principal_id"] == P1
    assert metadata["scope"] == {"kind": "principal", "scope_id": P1}
    assert metadata["source_run"] == binding().source_run
    assert metadata["agent_instance_id"] == AGENT
    assert metadata["state"] == "quarantined"
    assert metadata["active"] is False
    assert metadata["authority"] == "none"
    assert metadata["provenance"]["run_authority_hash"] == AUTH
    assert metadata["commands"] == ["curl", "python"]
    assert metadata["tools"] == ["fleet-terminal"]
    assert metadata["filesystem_needs"] == [
        {
            "project_id": "project-one",
            "relative_path": "src",
            "target": "/workspace/src",
            "mode": "read-only",
            "max_bytes": 4096,
        }
    ]
    assert metadata["network_needs"] == {
        "mode": "project-allowlist",
        "policy_hash": NET,
    }
    assert metadata["secret_needs"] == [SECRET_FP]
    assert metadata["risk"] == {"state": "unassessed", "next_phase": 16}
    assert metadata["tests"] == {
        "state": "unverified",
        "results": [],
        "next_phase": 17,
    }
    assert metadata["content_hash"] == result["content_hash"]
    assert metadata["provenance"]["proposed_action"] == "create"
    if os.name != "nt":
        assert stat.S_IMODE((skills_root / ".fleet").stat().st_mode) == 0o700
        assert stat.S_IMODE((skills_root / ".fleet" / "candidates").stat().st_mode) == 0o700
        assert stat.S_IMODE(candidate.stat().st_mode) == 0o700
        assert stat.S_IMODE(skill_md.stat().st_mode) == 0o600
        assert stat.S_IMODE((candidate / "candidate.json").stat().st_mode) == 0o600


def test_candidate_root_rejects_path_redirect(skills_root: Path) -> None:
    if os.name == "nt":
        pytest.skip("symlink creation is privilege-dependent on Windows")
    redirected = skills_root / "redirected"
    redirected.mkdir()
    (skills_root / ".fleet").symlink_to(redirected, target_is_directory=True)

    result = background_skill_manage(
        binding(), action="create", name="deploy-helper", content=SKILL
    )

    assert result["success"] is False
    assert result["candidate"] is True
    assert "unsafe" in result["error"]
    assert list(redirected.iterdir()) == []


def test_foreground_user_write_remains_active_even_with_fleet_binding(
    skills_root: Path,
) -> None:
    with fleet_skill_learning_scope(binding()):
        result = json.loads(
            sm.skill_manage(action="create", name="deploy-helper", content=SKILL)
        )

    assert result["success"] is True
    assert result.get("candidate") is not True
    active = sm._find_skill("deploy-helper")
    assert active is not None
    assert (active["path"] / "SKILL.md").read_text(encoding="utf-8") == SKILL
    assert candidate_dirs(skills_root) == []


def test_background_edit_does_not_bypass_existing_user_owned_skill_guard(
    skills_root: Path,
) -> None:
    active_dir = skills_root / "deploy-helper"
    active_dir.mkdir()
    active_md = active_dir / "SKILL.md"
    active_md.write_text(SKILL, encoding="utf-8")
    token = set_current_write_origin(BACKGROUND_REVIEW)
    try:
        sm.mark_background_review_skill_read(active_md)
    finally:
        reset_current_write_origin(token)
    updated = SKILL.replace("Repeatable deploy helper", "Safer deploy helper")

    result = background_skill_manage(
        binding(), action="edit", name="deploy-helper", content=updated
    )

    assert result["success"] is False
    assert "not curator-managed" in result["error"]
    assert active_md.read_text(encoding="utf-8") == SKILL
    assert candidate_dirs(skills_root) == []


def test_background_delete_does_not_bypass_existing_user_owned_skill_guard(
    skills_root: Path,
) -> None:
    active_dir = skills_root / "deploy-helper"
    active_dir.mkdir()
    active_md = active_dir / "SKILL.md"
    active_md.write_text(SKILL, encoding="utf-8")
    token = set_current_write_origin(BACKGROUND_REVIEW)
    try:
        sm.mark_background_review_skill_read(active_md)
    finally:
        reset_current_write_origin(token)

    result = background_skill_manage(
        binding(),
        action="delete",
        name="deploy-helper",
        absorbed_into="umbrella-skill",
    )

    assert result["success"] is False
    assert "not curator-managed" in result["error"]
    assert active_md.exists()
    assert candidate_dirs(skills_root) == []


def test_background_can_refine_its_own_quarantined_candidate_without_activation(
    skills_root: Path,
) -> None:
    bound = binding()
    created = background_skill_manage(
        bound, action="create", name="deploy-helper", content=SKILL
    )
    updated = SKILL.replace("Repeatable deploy helper", "Safer deploy helper")
    edited = background_skill_manage(
        bound, action="edit", name="deploy-helper", content=updated
    )

    assert created["success"] is True
    assert edited["success"] is True
    assert edited["candidate"] is True
    candidate = candidate_dirs(skills_root)[0]
    assert (candidate / "SKILL.md").read_text(encoding="utf-8") == updated
    metadata = json.loads((candidate / "candidate.json").read_text(encoding="utf-8"))
    assert metadata["provenance"]["proposed_action"] == "edit"
    assert metadata["state"] == "quarantined"
    assert metadata["active"] is False
    assert sm._find_skill("deploy-helper") is None


def test_candidate_support_files_update_bundle_hash_without_becoming_active(
    skills_root: Path,
) -> None:
    bound = binding()
    created = background_skill_manage(
        bound, action="create", name="deploy-helper", content=SKILL
    )
    written = background_skill_manage(
        bound,
        action="write_file",
        name="deploy-helper",
        file_path="references/checklist.md",
        file_content="# Checklist\n- verify health\n",
    )

    assert created["content_hash"] != written["content_hash"]
    candidate = candidate_dirs(skills_root)[0]
    assert (candidate / "references" / "checklist.md").is_file()
    assert sm._find_skill("deploy-helper") is None


def test_phase13_sensitive_interception_blocks_candidate_and_cleans_partial_tree(
    skills_root: Path,
) -> None:
    sensitive = SKILL + "\n```bash\nexport OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwx\n```\n"

    result = background_skill_manage(
        binding(), action="create", name="deploy-helper", content=sensitive
    )

    assert result["success"] is False
    assert result["candidate"] is True
    assert candidate_dirs(skills_root) == []
    assert sm._find_skill("deploy-helper") is None


def test_candidate_identity_tampering_fails_closed_before_mutation(
    skills_root: Path,
) -> None:
    bound = binding()
    created = background_skill_manage(
        bound, action="create", name="deploy-helper", content=SKILL
    )
    assert created["success"] is True
    candidate = candidate_dirs(skills_root)[0]
    metadata_path = candidate / "candidate.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["provenance"]["run_authority_hash"] = "sha256:" + "e" * 64
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

    result = background_skill_manage(
        bound,
        action="write_file",
        name="deploy-helper",
        file_path="references/should-not-exist.md",
        file_content="blocked\n",
    )

    assert result["success"] is False
    assert result["candidate"] is True
    assert "identity changed" in result["error"]
    assert not (candidate / "references" / "should-not-exist.md").exists()
    assert sm._find_skill("deploy-helper") is None


def test_same_skill_name_from_two_principals_produces_isolated_candidates(
    skills_root: Path,
) -> None:
    first = background_skill_manage(
        binding(P1), action="create", name="deploy-helper", content=SKILL
    )
    second = background_skill_manage(
        binding(P2), action="create", name="deploy-helper", content=SKILL
    )

    assert first["success"] is True
    assert second["success"] is True
    assert first["candidate_id"] != second["candidate_id"]
    candidates = candidate_dirs(skills_root)
    assert len(candidates) == 2
    scopes = {
        json.loads((candidate / "candidate.json").read_text(encoding="utf-8"))["scope"][
            "scope_id"
        ]
        for candidate in candidates
    }
    assert scopes == {P1, P2}
    assert sm._find_skill("deploy-helper") is None
