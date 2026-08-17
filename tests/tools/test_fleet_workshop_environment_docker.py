from __future__ import annotations

import json
import platform
import shutil
import subprocess
import time

import pytest

from tools.environments.docker import FleetWorkshopEnvironment

BASE_IMAGE = (
    "debian@sha256:3a39a0592364683e6bab97937b72cad5a8fa6dcbbee90edb3bb48c7f8e94f258"
)
PLAN = "sha256:" + "b" * 64


@pytest.mark.skipif(shutil.which("docker") is None, reason="Docker is unavailable")
@pytest.mark.skipif(platform.machine() != "x86_64", reason="pinned base image is amd64")
def test_hermes_enters_exact_fleet_workshop_without_lifecycle_authority() -> None:
    probe = subprocess.run(
        ["docker", "image", "inspect", BASE_IMAGE],
        capture_output=True,
        check=False,
        timeout=10,
    )
    if probe.returncode != 0:
        pytest.skip("pinned base image is unavailable locally")

    deadline_ms = int(time.time() * 1_000) + 30_000
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
            "/workspace:rw,nosuid,nodev,exec,size=33554432,uid=65532,gid=65532,mode=0700",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,exec,size=16777216,uid=65532,gid=65532,mode=0700",
            "--tmpfs",
            "/home/fleet:rw,nosuid,nodev,exec,size=16777216,uid=65532,gid=65532,mode=0700",
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
            f"dev.hermes.fleet.deadline_ms={deadline_ms}",
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
    if create.returncode != 0:
        pytest.fail("failed to create Fleet workshop fixture")
    container_id = create.stdout.strip()
    environment = None
    try:
        started = subprocess.run(
            ["docker", "start", container_id],
            capture_output=True,
            check=False,
            timeout=10,
        )
        assert started.returncode == 0
        environment = FleetWorkshopEnvironment(
            container_id=container_id,
            plan_fingerprint=PLAN,
            timeout=10,
        )
        result = environment.execute("printf 'uid='; id -u; printf '\ncwd='; pwd")
        assert result["returncode"] == 0
        assert "uid=65532" in result["output"]
        assert "cwd=/workspace" in result["output"]

        inspected = subprocess.run(
            ["docker", "inspect", container_id],
            capture_output=True,
            check=False,
            text=True,
            timeout=10,
        )
        assert inspected.returncode == 0
        document = json.loads(inspected.stdout)[0]
        assert document["State"]["Status"] == "running"
        environment.cleanup()
        environment = None

        still_running = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Status}}", container_id],
            capture_output=True,
            check=False,
            text=True,
            timeout=10,
        )
        assert still_running.returncode == 0
        assert still_running.stdout.strip() == "running"
    finally:
        if environment is not None:
            environment.cleanup()
        subprocess.run(
            ["docker", "rm", "--force", container_id],
            capture_output=True,
            check=False,
            timeout=10,
        )
