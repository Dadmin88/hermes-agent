from __future__ import annotations

import os

from agent.fleet_runtime_scope import FleetRuntimeBinding, fleet_runtime_scope
from tools import terminal_tool as terminal_mod
from tools.environments import docker as docker_mod

CONTAINER = "a" * 64
PLAN = "sha256:" + "b" * 64
IMAGE = "debian@sha256:" + "c" * 64


def runtime() -> FleetRuntimeBinding:
    return FleetRuntimeBinding(
        version="fleet-run-v1",
        container_id=CONTAINER,
        plan_fingerprint=PLAN,
        image=IMAGE,
        toolsets=("fleet-terminal",),
        max_iterations=7,
    )


def test_fleet_runtime_forces_attach_only_environment_without_generic_config(
    monkeypatch,
) -> None:
    captured = {}

    class FakeFleetWorkshopEnvironment:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr(
        docker_mod,
        "FleetWorkshopEnvironment",
        FakeFleetWorkshopEnvironment,
    )
    before = dict(os.environ)
    malicious_container_config = {
        "docker_volumes": ["host:/workspace"],
        "docker_env": {"SHOULD_NOT_EXIST": "value"},
        "docker_extra_args": ["--privileged"],
        "docker_network": True,
        "docker_run_as_host_user": True,
    }

    with fleet_runtime_scope(runtime()):
        environment = terminal_mod._create_environment(
            env_type="local",
            image="ignored:latest",
            cwd="/some/host/path",
            timeout=11,
            container_config=malicious_container_config,
            task_id="run-1",
            host_cwd="/host/path",
        )

    assert isinstance(environment, FakeFleetWorkshopEnvironment)
    assert captured == {
        "container_id": CONTAINER,
        "plan_fingerprint": PLAN,
        "timeout": 11,
        "expected_image": IMAGE,
    }
    assert dict(os.environ) == before


def test_without_fleet_runtime_normal_environment_selection_is_unchanged(monkeypatch) -> None:
    class FakeLocalEnvironment:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    monkeypatch.setattr(terminal_mod, "_LocalEnvironment", FakeLocalEnvironment)
    environment = terminal_mod._create_environment(
        env_type="local",
        image="ignored",
        cwd="/workspace",
        timeout=9,
    )
    assert isinstance(environment, FakeLocalEnvironment)
    assert environment.kwargs == {"cwd": "/workspace", "timeout": 9}
