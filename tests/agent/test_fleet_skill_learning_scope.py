from __future__ import annotations

import asyncio
from dataclasses import replace

import pytest

from agent.fleet_skill_learning_scope import (
    FleetSkillFilesystemNeed,
    FleetSkillLearningBinding,
    FleetSkillLearningScopeError,
    fleet_skill_learning_scope,
    get_fleet_skill_learning,
)

P = "sha256:" + "1" * 64
B = "sha256:" + "2" * 64
A = "sha256:" + "3" * 64
R = "sha256:" + "4" * 64
RR = "sha256:" + "5" * 64
PLAN = "sha256:" + "6" * 64
CAP = "sha256:" + "7" * 64
TARGET = "sha256:" + "8" * 64
AUTH = "sha256:" + "9" * 64
NET = "sha256:" + "a" * 64
SECRET = "sha256:" + "b" * 64


def binding() -> FleetSkillLearningBinding:
    return FleetSkillLearningBinding(
        principal_id=P,
        principal_kind="owner",
        principal_generation=1,
        principal_binding_hash=B,
        agent_instance_id=A,
        source_run="fleet-run-one",
        scope_kind="principal",
        scope_id=P,
        run_authority_hash=AUTH,
        recipe_hash=R,
        resolved_recipe_hash=RR,
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
        network_mode="none",
        network_policy_hash=NET,
        secret_need_fingerprints=(SECRET,),
    )


def test_skill_learning_binding_round_trips_exact_closed_wire_shape() -> None:
    bound = binding()
    payload = bound.to_request()

    assert FleetSkillLearningBinding.from_request(payload) == bound
    assert payload["scope"] == {"kind": "principal", "scope_id": P}
    assert payload["needs"]["tools"] == ["fleet-terminal"]
    assert payload["needs"]["secret_fingerprints"] == [SECRET]


def test_phase15_scope_is_principal_private_only() -> None:
    with pytest.raises(FleetSkillLearningScopeError, match="principal-private"):
        replace(binding(), scope_kind="project", scope_id="project-one")


def test_malformed_skill_learning_wire_types_fail_closed() -> None:
    payload = binding().to_request()
    payload["principal"] = dict(payload["principal"])
    payload["principal"]["kind"] = []
    with pytest.raises(FleetSkillLearningScopeError, match="principal kind"):
        FleetSkillLearningBinding.from_request(payload)

    payload = binding().to_request()
    payload["needs"] = dict(payload["needs"])
    payload["needs"]["tools"] = [123]
    with pytest.raises(FleetSkillLearningScopeError, match="toolsets"):
        FleetSkillLearningBinding.from_request(payload)

    payload = binding().to_request()
    payload["needs"] = dict(payload["needs"])
    payload["needs"]["network"] = {
        "mode": [],
        "policy_hash": NET,
    }
    with pytest.raises(FleetSkillLearningScopeError, match="network mode"):
        FleetSkillLearningBinding.from_request(payload)


def test_skill_learning_context_is_nested_and_task_local() -> None:
    first = binding()
    second = replace(first, source_run="fleet-run-two")

    assert get_fleet_skill_learning() is None
    with fleet_skill_learning_scope(first):
        assert get_fleet_skill_learning() is first
        with fleet_skill_learning_scope(second):
            assert get_fleet_skill_learning() is second
        assert get_fleet_skill_learning() is first
    assert get_fleet_skill_learning() is None

    async def child() -> FleetSkillLearningBinding | None:
        await asyncio.sleep(0)
        return get_fleet_skill_learning()

    async def run() -> FleetSkillLearningBinding | None:
        with fleet_skill_learning_scope(first):
            return await asyncio.create_task(child())

    assert asyncio.run(run()) is first
    assert get_fleet_skill_learning() is None
