from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

import tools.fleet_skill_quarantine as quarantine_module
import tools.skill_manager_tool as sm
from agent.fleet_skill_learning_scope import (
    FleetSkillFilesystemNeed,
    FleetSkillLearningBinding,
    fleet_skill_learning_scope,
)
from tools.fleet_skill_quarantine import (
    FleetSkillQuarantineError,
    quarantine_candidates_for_binding,
    quarantine_skill_candidate,
)
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

SAFE_SKILL = """---
name: safe-helper
description: Safe repeatable helper
allowed-tools: Bash
---

# Safe helper

```bash
python build.py
```
"""

SUDO_SKILL = SAFE_SKILL.replace("safe-helper", "sudo-helper").replace(
    "python build.py", "sudo systemctl restart demo"
)

BROWSER_SKILL = SAFE_SKILL.replace("safe-helper", "browser-helper").replace(
    "allowed-tools: Bash", "allowed-tools: Browser"
)

NETWORK_SKILL = SAFE_SKILL.replace("safe-helper", "network-helper").replace(
    "python build.py", "curl https://example.invalid/health"
)

AUTHORITY_SKILL = SAFE_SKILL.replace("safe-helper", "authority-helper").replace(
    "python build.py", "echo modify the RunAuthority before execution"
)

HOST_PATH_SKILL = SAFE_SKILL.replace("safe-helper", "hostpath-helper").replace(
    "python build.py", "cat /etc/passwd"
)


def binding(principal: str = P1, *, network_mode: str = "none") -> FleetSkillLearningBinding:
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
                mode="read-write",
                max_bytes=4096,
            ),
        ),
        network_mode=network_mode,
        network_policy_hash=NET,
        secret_need_fingerprints=(),
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


def create_candidate(
    root: Path,
    content: str = SAFE_SKILL,
    *,
    bound: FleetSkillLearningBinding | None = None,
) -> tuple[FleetSkillLearningBinding, Path]:
    active_binding = bound or binding()
    name = content.split("name: ", 1)[1].splitlines()[0]
    result = background_skill_manage(
        active_binding,
        action="create",
        name=name,
        content=content,
    )
    assert result["success"] is True, result
    base = root / ".fleet" / "candidates"
    candidates = [path for path in base.iterdir() if path.is_dir()]
    match = None
    for candidate in candidates:
        metadata = json.loads((candidate / "candidate.json").read_text(encoding="utf-8"))
        if metadata["candidate_id"] == result["candidate_id"]:
            match = candidate
            break
    assert match is not None
    return active_binding, match


def metadata(candidate: Path) -> dict:
    return json.loads((candidate / "candidate.json").read_text(encoding="utf-8"))


def reason_codes(candidate: Path) -> set[str]:
    return {item["code"] for item in metadata(candidate)["risk"]["reasons"]}


def test_safe_candidate_becomes_verification_ready_and_immutable(skills_root: Path) -> None:
    bound, candidate = create_candidate(skills_root)

    result = quarantine_skill_candidate(candidate)

    assert result.state == "verification-ready"
    saved = metadata(candidate)
    assert saved["state"] == "verification-ready"
    assert saved["active"] is False
    assert saved["authority"] == "none"
    assert saved["risk"]["state"] == "verification-ready"
    assert saved["quarantine"]["immutable"] is True
    assert saved["quarantine"]["bundle_id"] == saved["content_hash"]
    assert saved["quarantine"]["content_hash"] == saved["content_hash"]
    assert saved["tests"]["state"] == "unverified"
    assert sm._find_skill("safe-helper") is None

    again = quarantine_skill_candidate(candidate)
    assert again == result

    attempted = background_skill_manage(
        bound,
        action="write_file",
        name="safe-helper",
        file_path="references/later.md",
        file_content="late mutation",
    )
    assert attempted["success"] is False
    assert "immutable" in attempted["error"]
    assert not (candidate / "references" / "later.md").exists()


def test_high_risk_privileged_command_needs_review(skills_root: Path) -> None:
    _bound, candidate = create_candidate(skills_root, SUDO_SKILL)

    result = quarantine_skill_candidate(candidate)

    assert result.state == "needs-review"
    codes = reason_codes(candidate)
    assert "command_sudo" in codes or "guard_sudo_usage" in codes


def test_undeclared_native_tool_needs_review(skills_root: Path) -> None:
    _bound, candidate = create_candidate(skills_root, BROWSER_SKILL)

    result = quarantine_skill_candidate(candidate)

    assert result.state == "needs-review"
    assert "tool_unknown_declaration" in reason_codes(candidate)


def test_network_requirement_without_network_grant_needs_review(skills_root: Path) -> None:
    _bound, candidate = create_candidate(skills_root, NETWORK_SKILL)

    result = quarantine_skill_candidate(candidate)

    assert result.state == "needs-review"
    assert "network_requirement_undeclared" in reason_codes(candidate)


def test_protected_host_path_needs_review(skills_root: Path) -> None:
    _bound, candidate = create_candidate(skills_root, HOST_PATH_SKILL)

    result = quarantine_skill_candidate(candidate)

    assert result.state == "rejected"
    assert "host_protected_path" in reason_codes(candidate)


def test_authority_manipulation_is_rejected(skills_root: Path) -> None:
    _bound, candidate = create_candidate(skills_root, AUTHORITY_SKILL)

    result = quarantine_skill_candidate(candidate)

    assert result.state == "rejected"
    assert "authority_run_authority_mutation" in reason_codes(candidate)


def test_phase13_defense_in_depth_rejects_sensitive_postwrite_tamper(skills_root: Path) -> None:
    _bound, candidate = create_candidate(skills_root)
    skill_md = candidate / "SKILL.md"
    skill_md.write_text(
        skill_md.read_text(encoding="utf-8") + "\npassword=definitely-sensitive-value\n",
        encoding="utf-8",
    )

    result = quarantine_skill_candidate(candidate)

    assert result.state == "rejected"
    codes = reason_codes(candidate)
    assert "secret_password" in codes
    assert "provenance_content_hash_mismatch" in codes
    serialized = json.dumps(metadata(candidate))
    assert "definitely-sensitive-value" not in serialized


def test_content_manifest_tamper_is_rejected_and_frozen(skills_root: Path) -> None:
    _bound, candidate = create_candidate(skills_root)
    (candidate / "SKILL.md").write_text(
        SAFE_SKILL.replace("python build.py", "python changed.py"), encoding="utf-8"
    )

    result = quarantine_skill_candidate(candidate)

    assert result.state == "rejected"
    assert "provenance_manifest_mismatch" in reason_codes(candidate)
    assert "provenance_content_hash_mismatch" in reason_codes(candidate)
    with pytest.raises(FleetSkillQuarantineError, match="immutable"):
        (candidate / "SKILL.md").write_text(SAFE_SKILL, encoding="utf-8")
        quarantine_skill_candidate(candidate)


def test_scope_tamper_is_rejected(skills_root: Path) -> None:
    _bound, candidate = create_candidate(skills_root)
    saved = metadata(candidate)
    saved["scope"] = {"kind": "network", "scope_id": "network-one"}
    (candidate / "candidate.json").write_text(json.dumps(saved), encoding="utf-8")

    result = quarantine_skill_candidate(candidate)

    assert result.state == "rejected"
    assert "scope_not_private" in reason_codes(candidate)


def test_candidate_marked_active_is_never_mutated_by_quarantine(skills_root: Path) -> None:
    _bound, candidate = create_candidate(skills_root)
    saved = metadata(candidate)
    saved["active"] = True
    path = candidate / "candidate.json"
    path.write_text(json.dumps(saved), encoding="utf-8")
    before = path.read_bytes()

    with pytest.raises(FleetSkillQuarantineError, match="marked active"):
        quarantine_skill_candidate(candidate)

    assert path.read_bytes() == before


def test_quarantine_does_not_mutate_active_skill_tree(skills_root: Path) -> None:
    active = skills_root / "active-user-skill"
    active.mkdir()
    active_md = active / "SKILL.md"
    active_md.write_text("---\nname: active-user-skill\ndescription: User skill\n---\n\nKeep me.\n")
    before = active_md.read_bytes()
    _bound, candidate = create_candidate(skills_root)

    quarantine_skill_candidate(candidate)

    assert active_md.read_bytes() == before
    assert active_md.exists()


def test_binding_quarantine_only_freezes_exact_run_candidates(skills_root: Path) -> None:
    first, first_candidate = create_candidate(skills_root, SAFE_SKILL, bound=binding(P1))
    second_skill = SAFE_SKILL.replace("safe-helper", "second-helper")
    second, second_candidate = create_candidate(skills_root, second_skill, bound=binding(P2))

    results = quarantine_candidates_for_binding(first)

    assert [item.name for item in results] == ["safe-helper"]
    assert metadata(first_candidate)["state"] == "verification-ready"
    assert metadata(second_candidate)["state"] == "quarantined"

    second_results = quarantine_candidates_for_binding(second)
    assert [item.name for item in second_results] == ["second-helper"]
    assert metadata(second_candidate)["state"] == "verification-ready"


def test_deterministic_reasons_and_digest_are_stable(skills_root: Path) -> None:
    _bound, candidate = create_candidate(skills_root, SUDO_SKILL)

    first = quarantine_skill_candidate(candidate)
    second = quarantine_skill_candidate(candidate)

    assert first.reasons == second.reasons
    assert first.quarantine_digest == second.quarantine_digest
    saved = metadata(candidate)
    reasons = saved["risk"]["reasons"]
    assert reasons == sorted(
        reasons,
        key=lambda item: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3}[item["severity"]],
            item["category"],
            item["code"],
            item["file"],
            item["line"],
            item["message"],
        ),
    )


def test_source_run_envelope_tamper_is_rejected_against_exact_binding(
    skills_root: Path,
) -> None:
    bound, candidate = create_candidate(skills_root)
    saved = metadata(candidate)
    saved["tools"] = ["fleet-terminal", "browser"]
    (candidate / "candidate.json").write_text(json.dumps(saved), encoding="utf-8")

    results = quarantine_candidates_for_binding(bound)

    assert [item.state for item in results] == ["rejected"]
    assert "provenance_tools_mismatch" in reason_codes(candidate)


def test_quarantine_seal_detects_metadata_tamper(skills_root: Path) -> None:
    _bound, candidate = create_candidate(skills_root)
    quarantine_skill_candidate(candidate)
    saved = metadata(candidate)
    saved["risk"]["reasons"][0]["message"] = "tampered reason"
    (candidate / "candidate.json").write_text(json.dumps(saved), encoding="utf-8")

    with pytest.raises(FleetSkillQuarantineError, match="reason"):
        quarantine_skill_candidate(candidate)


def test_wrong_binding_does_not_claim_candidate(skills_root: Path) -> None:
    first, candidate = create_candidate(skills_root)
    wrong = replace(first, plan_fingerprint="sha256:" + "f" * 64)

    assert quarantine_candidates_for_binding(wrong) == ()
    assert metadata(candidate)["state"] == "quarantined"


def test_guard_finding_overflow_fails_closed(
    skills_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _bound, candidate = create_candidate(skills_root)
    finding = quarantine_module.skills_guard.Finding(
        pattern_id="noise",
        severity="medium",
        category="structure",
        file="SKILL.md",
        line=1,
        match="noise",
        description="bounded scanner noise",
    )
    monkeypatch.setattr(
        quarantine_module.skills_guard,
        "scan_file",
        lambda _path, _rel="": [finding] * 257,
    )

    result = quarantine_skill_candidate(candidate)

    assert result.state == "rejected"
    assert "guard_findings_overflow" in reason_codes(candidate)


def test_allowed_tools_overflow_fails_closed(skills_root: Path) -> None:
    declarations = ", ".join(f"Tool{i}" for i in range(257))
    content = SAFE_SKILL.replace("safe-helper", "tool-overflow-helper").replace(
        "allowed-tools: Bash", f"allowed-tools: {declarations}"
    )
    _bound, candidate = create_candidate(skills_root, content)

    result = quarantine_skill_candidate(candidate)

    assert result.state == "rejected"
    assert "tool_declaration_overflow" in reason_codes(candidate)
