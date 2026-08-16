from __future__ import annotations

import platform
import shutil
import subprocess

import pytest

from agent.fleet_runtime_scope import FleetRuntimeBinding, fleet_runtime_scope
from tools import terminal_tool as terminal_mod

BASE_IMAGE = (
    "debian@sha256:3a39a0592364683e6bab97937b72cad5a8fa6dcbbee90edb3bb48c7f8e94f258"
)
PLAN = "sha256:" + "b" * 64


@pytest.mark.skipif(shutil.which("docker") is None, reason="Docker is unavailable")
@pytest.mark.skipif(platform.machine() != "x86_64", reason="pinned base image is amd64")
def test_contextvar_selects_exact_live_fleet_workshop_without_lifecycle_ownership() -> None:
    probe = subprocess.run(
        ["docker", "image", "inspect", BASE_IMAGE],
        capture_output=True,
        check=False,
        timeout=10,
    )
    if probe.returncode != 0:
        pytest.skip("pinned base image is unavailable locally")

    create = subprocess.run(
        [
            "docker",
            "create",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--network",
            "none",
            "--pids-limit",
            "16",
            "--memory",
            "33554432",
            "--memory-swap",
            "33554432",
            "--cpus",
            "0.100",
            "--log-driver",
            "none",
            "--init",
            "--user",
            "65532:65532",
            "--workdir",
            "/workspace",
            "--tmpfs",
            (
                "/workspace:rw,nosuid,nodev,exec,size=33554432,"
                "uid=65532,gid=65532,mode=0711"
            ),
            "--tmpfs",
            (
                "/workspace/inputs:rw,nosuid,nodev,exec,size=16777216,"
                "uid=65533,gid=65533,mode=0755"
            ),
            "--tmpfs",
            (
                "/tmp:rw,nosuid,nodev,exec,size=16777216,"
                "uid=65532,gid=65532,mode=0700"
            ),
            "--tmpfs",
            (
                "/home/fleet:rw,nosuid,nodev,exec,size=16777216,"
                "uid=65532,gid=65532,mode=0700"
            ),
            "--env",
            "HOME=/home/fleet",
            "--env",
            "TMPDIR=/tmp",
            "--label",
            "dev.hermes.fleet.backend=fleet.dev/docker-oci",
            "--label",
            f"dev.hermes.fleet.plan={PLAN}",
            "--label",
            "dev.hermes.fleet.role=workshop",
            "--label",
            "dev.hermes.fleet.deadline_ms=4102444800000",
            "--label",
            "hermes-agent=1",
            "--label",
            "hermes-egress=off",
            BASE_IMAGE,
            "sleep",
            "infinity",
        ],
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )
    assert create.returncode == 0, create.stderr
    container_id = create.stdout.strip()
    try:
        started = subprocess.run(
            ["docker", "start", container_id],
            capture_output=True,
            check=False,
            timeout=10,
        )
        assert started.returncode == 0
        binding = FleetRuntimeBinding(
            version="fleet-run-v1",
            container_id=container_id,
            plan_fingerprint=PLAN,
            image=BASE_IMAGE,
            toolsets=("fleet-terminal",),
            max_iterations=6,
        )
        with fleet_runtime_scope(binding):
            environment = terminal_mod._create_environment(
                env_type="local",
                image="ignored:latest",
                cwd="/host/path/is/not/used",
                timeout=10,
                container_config={"docker_extra_args": ["--privileged"]},
            )
            result = environment.execute("printf phase7-ok")
            environment.cleanup()
        assert result["returncode"] == 0
        assert "phase7-ok" in result["output"]

        state = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Status}}", container_id],
            capture_output=True,
            check=False,
            text=True,
            timeout=10,
        )
        assert state.returncode == 0
        assert state.stdout.strip() == "running"
    finally:
        subprocess.run(
            ["docker", "rm", "--force", container_id],
            capture_output=True,
            check=False,
            timeout=10,
        )
