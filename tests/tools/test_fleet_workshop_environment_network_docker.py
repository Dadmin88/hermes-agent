from __future__ import annotations

import platform
import shutil
import subprocess
import time
import uuid

import pytest

from tools.environments.docker import FleetWorkshopEnvironment

BASE_IMAGE = (
    "debian@sha256:3a39a0592364683e6bab97937b72cad5a8fa6dcbbee90edb3bb48c7f8e94f258"
)
PLAN = "sha256:" + "b" * 64


@pytest.mark.skipif(shutil.which("docker") is None, reason="Docker is unavailable")
@pytest.mark.skipif(platform.machine() != "x86_64", reason="pinned base image is amd64")
def test_hermes_enters_exact_mediated_fleet_workshop() -> None:
    probe = subprocess.run(
        ["docker", "image", "inspect", BASE_IMAGE],
        capture_output=True,
        check=False,
        timeout=10,
    )
    if probe.returncode != 0:
        pytest.skip("pinned base image is unavailable locally")

    network_name = f"hermes-fleet-egress-{uuid.uuid4().hex[:24]}"
    network_policy = "sha256:" + "d" * 64
    network_authority = "sha256:" + "e" * 64
    gateway_id = "f" * 64
    gateway_ip = "172.25.0.2"
    proxy = f"http://{gateway_ip}:8080"
    network = subprocess.run(
        ["docker", "network", "create", "--internal", network_name],
        capture_output=True,
        check=False,
        text=True,
        timeout=10,
    )
    assert network.returncode == 0
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
            network_name,
            "--dns",
            "127.0.0.1",
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
            "--env",
            f"HTTP_PROXY={proxy}",
            "--env",
            f"HTTPS_PROXY={proxy}",
            "--env",
            f"http_proxy={proxy}",
            "--env",
            f"https_proxy={proxy}",
            "--env",
            "NO_PROXY=",
            "--env",
            "no_proxy=",
            "--label",
            "dev.hermes.fleet.backend=fleet.dev/docker-oci",
            "--label",
            f"dev.hermes.fleet.plan={PLAN}",
            "--label",
            "dev.hermes.fleet.role=workshop",
            "--label",
            f"dev.hermes.fleet.deadline_ms={deadline_ms}",
            "--label",
            "dev.hermes.fleet.network_mode=project-allowlist",
            "--label",
            f"dev.hermes.fleet.network_policy={network_policy}",
            "--label",
            f"dev.hermes.fleet.network_authority={network_authority}",
            "--label",
            f"dev.hermes.fleet.network_gateway={gateway_id}",
            "--label",
            "hermes-agent=1",
            "--label",
            "hermes-egress=proxy",
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
        subprocess.run(
            ["docker", "network", "rm", network_name],
            capture_output=True,
            check=False,
            timeout=10,
        )
        pytest.fail("failed to create mediated Fleet workshop fixture")
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
            expected_network_mode="project-allowlist",
            expected_network_name=network_name,
            expected_network_policy=network_policy,
            expected_network_authority=network_authority,
            expected_gateway_id=gateway_id,
            expected_gateway_ip=gateway_ip,
        )
        result = environment.execute("printf phase4-ok")
        assert result["returncode"] == 0
        assert "phase4-ok" in result["output"]
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
        subprocess.run(
            ["docker", "network", "rm", network_name],
            capture_output=True,
            check=False,
            timeout=10,
        )
