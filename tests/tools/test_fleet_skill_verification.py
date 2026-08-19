from __future__ import annotations

import json
import shutil
import sys
from dataclasses import replace
from pathlib import Path

import pytest

import tools.fleet_skill_verification as verification_module
import tools.skill_manager_tool as sm
from agent.fleet_skill_learning_scope import (
    FleetSkillFilesystemNeed,
    FleetSkillLearningBinding,
    fleet_skill_learning_scope,
)
from tools.fleet_skill_quarantine import quarantine_skill_candidate
from tools.fleet_skill_verification import (
    FleetSkillVerificationError,
    VerificationCheck,
    verify_candidates_for_binding,
    verify_skill_candidate,
)
from tools.skill_provenance import (
    BACKGROUND_REVIEW,
    reset_current_write_origin,
    set_current_write_origin,
)
from tools.skills_guard import Finding

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
                mode="read-write",
                max_bytes=4096,
            ),
        ),
        network_mode="none",
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
    *,
    content: str = SAFE_SKILL,
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
    match = None
    for candidate in base.iterdir():
        if not candidate.is_dir():
            continue
        metadata = json.loads((candidate / "candidate.json").read_text(encoding="utf-8"))
        if metadata["name"] == name and metadata["principal"]["principal_id"] == active_binding.principal_id:
            match = candidate
            break
    assert match is not None
    return active_binding, match


def quarantine_ready(
    root: Path,
    *,
    content: str = SAFE_SKILL,
    bound: FleetSkillLearningBinding | None = None,
) -> tuple[FleetSkillLearningBinding, Path]:
    active_binding, candidate = create_candidate(root, content=content, bound=bound)
    result = quarantine_skill_candidate(candidate, expected_binding=active_binding)
    assert result.state == "verification-ready", result
    return active_binding, candidate


def mocked_runtime_checks(*_args, **_kwargs) -> list[VerificationCheck]:
    return [
        VerificationCheck("broker-denial", "broker-sockets", True, "broker paths absent"),
        VerificationCheck("broker-denial", "docker-socket", True, "Docker socket absent"),
        VerificationCheck("filesystem-denial", "host-path:/etc/passwd", True, "host path absent"),
        VerificationCheck("network-denial", "internet", True, "unreachable"),
        VerificationCheck("network-denial", "management-network", True, "unreachable"),
        VerificationCheck("positive-test", "bundle-readable", True, "files=1"),
        VerificationCheck("positive-test", "scratch-write", True, "isolated tmpfs"),
        VerificationCheck("privilege-denial", "effective-capabilities", True, "CapEff=0"),
        VerificationCheck("privilege-denial", "non-root-uid", True, "euid=65534"),
        VerificationCheck("resource-bound", "address-space", True, "bounded"),
        VerificationCheck("resource-bound", "cpu", True, "bounded"),
        VerificationCheck("resource-bound", "file-size", True, "bounded"),
        VerificationCheck("resource-bound", "open-files", True, "bounded"),
        VerificationCheck("resource-bound", "processes", True, "bounded"),
        VerificationCheck("secret-denial", "environment", True, "sensitive_names=0"),
    ]


def read_metadata(candidate: Path) -> dict:
    return json.loads((candidate / "candidate.json").read_text(encoding="utf-8"))


def test_safe_candidate_verifies_without_activation_or_authority(
    skills_root: Path, monkeypatch: pytest.MonkeyPatch
):
    bound, candidate = quarantine_ready(skills_root)
    monkeypatch.setattr(verification_module, "_runtime_checks", mocked_runtime_checks)

    result = verify_skill_candidate(candidate, expected_binding=bound)

    assert result.verified is True
    assert result.state == "verified"
    metadata = read_metadata(candidate)
    assert metadata["state"] == "verification-ready"
    assert metadata["active"] is False
    assert metadata["authority"] == "none"
    assert metadata["tests"]["state"] == "verified"
    assert metadata["tests"]["next_phase"] == 18
    assert metadata["tests"]["content_hash"] == result.content_hash
    assert metadata["tests"]["quarantine_digest"] == result.quarantine_digest
    assert metadata["tests"]["verification_digest"] == result.verification_digest
    assert all(check.passed for check in result.checks)


def test_verification_requires_exact_learning_binding(
    skills_root: Path, monkeypatch: pytest.MonkeyPatch
):
    bound, candidate = quarantine_ready(skills_root)
    monkeypatch.setattr(verification_module, "_runtime_checks", mocked_runtime_checks)

    with pytest.raises(FleetSkillVerificationError, match="exact Fleet learning binding"):
        verify_skill_candidate(candidate)

    wrong = replace(bound, plan_fingerprint="sha256:" + "d" * 64)
    with pytest.raises(FleetSkillVerificationError, match="capability manifest"):
        verify_skill_candidate(candidate, expected_binding=wrong)


def test_non_verification_ready_candidate_is_refused(skills_root: Path):
    bound, candidate = create_candidate(skills_root, content=SUDO_SKILL)
    quarantine = quarantine_skill_candidate(candidate, expected_binding=bound)
    assert quarantine.state == "needs-review"

    with pytest.raises(FleetSkillVerificationError, match="verification-ready"):
        verify_skill_candidate(candidate, expected_binding=bound)


def test_static_analysis_failure_is_recorded_without_granting_authority(
    skills_root: Path, monkeypatch: pytest.MonkeyPatch
):
    bound, candidate = quarantine_ready(skills_root)
    monkeypatch.setattr(verification_module, "_runtime_checks", mocked_runtime_checks)
    original_scan = verification_module.skills_guard.scan_file

    def unsafe_scan(path: Path, rel: str = ""):
        if rel == "SKILL.md":
            return [
                Finding(
                    pattern_id="phase17-test",
                    severity="high",
                    category="injection",
                    file=rel,
                    line=1,
                    match="test",
                    description="test finding",
                )
            ]
        return original_scan(path, rel)

    monkeypatch.setattr(verification_module.skills_guard, "scan_file", unsafe_scan)
    result = verify_skill_candidate(candidate, expected_binding=bound)

    assert result.state == "failed"
    assert any(
        check.category == "static-analysis" and not check.passed
        for check in result.checks
    )
    metadata = read_metadata(candidate)
    assert metadata["active"] is False
    assert metadata["authority"] == "none"
    assert metadata["tests"]["next_phase"] == 17


def test_secret_scan_failure_is_recorded_fail_closed(
    skills_root: Path, monkeypatch: pytest.MonkeyPatch
):
    bound, candidate = quarantine_ready(skills_root)
    monkeypatch.setattr(verification_module, "_runtime_checks", mocked_runtime_checks)
    monkeypatch.setattr(
        verification_module,
        "classify_sensitive_text",
        lambda text: ([object()], text, False),
    )

    result = verify_skill_candidate(candidate, expected_binding=bound)

    assert result.state == "failed"
    check = next(check for check in result.checks if check.category == "secret-scan")
    assert check.passed is False
    assert "findings=" in check.detail


def test_capability_manifest_tamper_is_refused(
    skills_root: Path, monkeypatch: pytest.MonkeyPatch
):
    bound, candidate = quarantine_ready(skills_root)
    monkeypatch.setattr(verification_module, "_runtime_checks", mocked_runtime_checks)
    metadata = read_metadata(candidate)
    metadata["tools"] = []
    (candidate / "candidate.json").write_text(
        json.dumps(metadata, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )

    with pytest.raises(FleetSkillVerificationError, match="capability manifest"):
        verify_skill_candidate(candidate, expected_binding=bound)


def test_changed_skill_invalidates_prior_verification(
    skills_root: Path, monkeypatch: pytest.MonkeyPatch
):
    bound, candidate = quarantine_ready(skills_root)
    monkeypatch.setattr(verification_module, "_runtime_checks", mocked_runtime_checks)
    first = verify_skill_candidate(candidate, expected_binding=bound)
    assert first.verified is True

    skill = candidate / "SKILL.md"
    skill.write_text(skill.read_text(encoding="utf-8") + "\nchanged\n", encoding="utf-8")

    with pytest.raises(FleetSkillVerificationError, match="quarantine seal"):
        verify_skill_candidate(candidate, expected_binding=bound)


def test_verified_attestation_reuse_is_idempotent(
    skills_root: Path, monkeypatch: pytest.MonkeyPatch
):
    bound, candidate = quarantine_ready(skills_root)
    monkeypatch.setattr(verification_module, "_runtime_checks", mocked_runtime_checks)
    first = verify_skill_candidate(candidate, expected_binding=bound)

    def should_not_run(*_args, **_kwargs):
        pytest.fail("verified candidate should reuse exact attestation")

    monkeypatch.setattr(verification_module, "_runtime_checks", should_not_run)
    second = verify_skill_candidate(candidate, expected_binding=bound)

    assert second == first


def test_verification_attestation_tamper_is_refused(
    skills_root: Path, monkeypatch: pytest.MonkeyPatch
):
    bound, candidate = quarantine_ready(skills_root)
    monkeypatch.setattr(verification_module, "_runtime_checks", mocked_runtime_checks)
    verify_skill_candidate(candidate, expected_binding=bound)
    metadata = read_metadata(candidate)
    metadata["tests"]["results"][0]["detail"] = "tampered"
    (candidate / "candidate.json").write_text(
        json.dumps(metadata, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )

    with pytest.raises(FleetSkillVerificationError, match="attestation|digest|order/content"):
        verify_skill_candidate(candidate, expected_binding=bound)


def test_verify_candidates_for_binding_filters_other_principals(
    skills_root: Path, monkeypatch: pytest.MonkeyPatch
):
    first = binding(P1)
    second = binding(P2)
    _first_binding, first_candidate = quarantine_ready(skills_root, bound=first)
    second_content = SAFE_SKILL.replace("safe-helper", "other-helper")
    _second_binding, second_candidate = quarantine_ready(
        skills_root,
        content=second_content,
        bound=second,
    )
    monkeypatch.setattr(verification_module, "_runtime_checks", mocked_runtime_checks)

    results = verify_candidates_for_binding(first)

    assert [result.name for result in results] == ["safe-helper"]
    assert read_metadata(first_candidate)["tests"]["state"] == "verified"
    assert read_metadata(second_candidate)["tests"]["state"] == "unverified"


@pytest.mark.skipif(
    not sys.platform.startswith("linux") or shutil.which("bwrap") is None,
    reason="Bubblewrap disposable runtime is required",
)
def test_disposable_runtime_enforces_phase17_denials_and_bounds(skills_root: Path):
    bound, candidate = quarantine_ready(skills_root)

    result = verify_skill_candidate(candidate, expected_binding=bound)

    assert result.verified is True
    checks = {(check.category, check.name): check for check in result.checks}
    required = {
        ("positive-test", "bundle-readable"),
        ("positive-test", "scratch-write"),
        ("network-denial", "internet"),
        ("network-denial", "management-network"),
        ("filesystem-denial", "host-path:/etc/passwd"),
        ("secret-denial", "environment"),
        ("broker-denial", "broker-sockets"),
        ("broker-denial", "docker-socket"),
        ("privilege-denial", "non-root-uid"),
        ("privilege-denial", "effective-capabilities"),
        ("resource-bound", "cpu"),
        ("resource-bound", "address-space"),
        ("resource-bound", "file-size"),
        ("resource-bound", "open-files"),
        ("resource-bound", "processes"),
    }
    assert required <= set(checks)
    assert all(checks[key].passed for key in required)


def test_missing_disposable_runtime_fails_closed_without_attestation(
    skills_root: Path, monkeypatch: pytest.MonkeyPatch
):
    bound, candidate = quarantine_ready(skills_root)
    monkeypatch.setattr(verification_module.shutil, "which", lambda _name: None)

    with pytest.raises(FleetSkillVerificationError, match="Bubblewrap is required"):
        verify_skill_candidate(candidate, expected_binding=bound)

    metadata = read_metadata(candidate)
    assert metadata["state"] == "verification-ready"
    assert metadata["active"] is False
    assert metadata["authority"] == "none"
    assert metadata["tests"] == {
        "state": "unverified",
        "results": [],
        "next_phase": 17,
    }


def test_failed_verification_reuse_is_idempotent(
    skills_root: Path, monkeypatch: pytest.MonkeyPatch
):
    bound, candidate = quarantine_ready(skills_root)

    def failed_runtime(*_args, **_kwargs):
        checks = mocked_runtime_checks()
        return [
            VerificationCheck(
                check.category,
                check.name,
                False if check.name == "management-network" else check.passed,
                check.detail,
            )
            for check in checks
        ]

    monkeypatch.setattr(verification_module, "_runtime_checks", failed_runtime)
    first = verify_skill_candidate(candidate, expected_binding=bound)
    assert first.state == "failed"

    monkeypatch.setattr(
        verification_module,
        "_runtime_checks",
        lambda *_args, **_kwargs: pytest.fail("failed attestation should be reused"),
    )
    second = verify_skill_candidate(candidate, expected_binding=bound)
    assert second == first
