from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from tools.environments import docker as docker_mod
from tools.environments.docker import (
    FleetWorkshopEnvironment,
    verify_fleet_workshop_document,
)

CONTAINER_ID = "a" * 64
PLAN = "sha256:" + "b" * 64
DEADLINE_MS = 2_000_000_000_000


def workshop_document() -> dict:
    return {
        "Id": CONTAINER_ID,
        "Config": {
            "Labels": {
                "dev.hermes.fleet.backend": "fleet.dev/docker-oci",
                "dev.hermes.fleet.plan": PLAN,
                "dev.hermes.fleet.role": "workshop",
                "dev.hermes.fleet.deadline_ms": str(DEADLINE_MS),
                "hermes-agent": "1",
                "hermes-egress": "off",
            },
            "User": "65532:65532",
            "WorkingDir": "/workspace",
            "Env": [
                "HOME=/home/fleet",
                "TMPDIR=/tmp",
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            ],
        },
        "HostConfig": {
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "Privileged": False,
            "CapDrop": ["ALL"],
            "CapAdd": None,
            "SecurityOpt": ["no-new-privileges:true"],
            "PidsLimit": 32,
            "Memory": 67_108_864,
            "NanoCpus": 500_000_000,
            "Binds": None,
            "Devices": None,
            "DeviceRequests": None,
            "Tmpfs": {
                "/workspace": (
                    "rw,nosuid,nodev,exec,size=268435456,"
                    "uid=65532,gid=65532,mode=0711"
                ),
                "/workspace/inputs": (
                    "rw,nosuid,nodev,exec,size=134217728,"
                    "uid=65533,gid=65533,mode=0755"
                ),
                "/tmp": (
                    "rw,nosuid,nodev,exec,size=67108864,"
                    "uid=65532,gid=65532,mode=0700"
                ),
                "/home/fleet": (
                    "rw,nosuid,nodev,exec,size=67108864,"
                    "uid=65532,gid=65532,mode=0700"
                ),
            },
        },
        "State": {"Status": "running"},
        "Mounts": [],
    }


def test_fleet_workshop_verifier_accepts_exact_hardened_container() -> None:
    verify_fleet_workshop_document(
        workshop_document(),
        container_id=CONTAINER_ID,
        plan_fingerprint=PLAN,
        now_ms=DEADLINE_MS - 1,
    )


@pytest.mark.parametrize(
    ("section", "key", "unsafe"),
    [
        ("Config", "User", "0:0"),
        ("Config", "User", "65532:0"),
        ("Config", "WorkingDir", "/root"),
        ("HostConfig", "NetworkMode", "bridge"),
        ("HostConfig", "ReadonlyRootfs", False),
        ("HostConfig", "Privileged", True),
        ("HostConfig", "CapDrop", []),
        ("HostConfig", "CapAdd", ["SYS_ADMIN"]),
        ("HostConfig", "SecurityOpt", []),
        ("HostConfig", "PidsLimit", 0),
        ("HostConfig", "Memory", 0),
        ("HostConfig", "NanoCpus", 0),
        ("HostConfig", "Binds", ["/home:/workspace"]),
        ("HostConfig", "Devices", [{"PathOnHost": "/dev/kvm"}]),
        ("HostConfig", "DeviceRequests", [{"Capabilities": [["gpu"]]}]),
        ("HostConfig", "Tmpfs", {"/tmp": "rw"}),
        ("State", "Status", "exited"),
    ],
)
def test_fleet_workshop_verifier_rejects_security_drift(section, key, unsafe) -> None:
    document = workshop_document()
    document[section][key] = unsafe
    with pytest.raises(RuntimeError):
        verify_fleet_workshop_document(
            document,
            container_id=CONTAINER_ID,
            plan_fingerprint=PLAN,
            now_ms=DEADLINE_MS - 1,
        )


def test_fleet_workshop_verifier_rejects_workspace_identity_drift() -> None:
    document = workshop_document()
    document["HostConfig"]["Tmpfs"]["/workspace/inputs"] = (
        "rw,nosuid,nodev,exec,size=134217728,uid=65532,gid=65532,mode=0755"
    )
    with pytest.raises(RuntimeError, match="input staging"):
        verify_fleet_workshop_document(
            document,
            container_id=CONTAINER_ID,
            plan_fingerprint=PLAN,
            now_ms=DEADLINE_MS - 1,
        )

    document = workshop_document()
    document["HostConfig"]["Tmpfs"]["/workspace"] = (
        "rw,nosuid,nodev,exec,size=268435456,uid=65532,gid=65532,mode=0700"
    )
    with pytest.raises(RuntimeError, match="workspace"):
        verify_fleet_workshop_document(
            document,
            container_id=CONTAINER_ID,
            plan_fingerprint=PLAN,
            now_ms=DEADLINE_MS - 1,
        )

    document = workshop_document()
    document["HostConfig"]["Tmpfs"]["/tmp"] = (
        "rw,nosuid,nodev,exec,size=134217728,uid=65532,gid=65532,mode=0700"
    )
    with pytest.raises(RuntimeError, match="temporary directory"):
        verify_fleet_workshop_document(
            document,
            container_id=CONTAINER_ID,
            plan_fingerprint=PLAN,
            now_ms=DEADLINE_MS - 1,
        )

    document = workshop_document()
    document["HostConfig"]["Tmpfs"]["/home/fleet"] = (
        "rw,nosuid,nodev,exec,size=67108864,uid=0,gid=0,mode=0700"
    )
    with pytest.raises(RuntimeError, match="disposable home"):
        verify_fleet_workshop_document(
            document,
            container_id=CONTAINER_ID,
            plan_fingerprint=PLAN,
            now_ms=DEADLINE_MS - 1,
        )


def test_fleet_workshop_verifier_rejects_identity_mount_and_deadline_drift() -> None:
    document = workshop_document()
    document["Config"]["Labels"]["dev.hermes.fleet.plan"] = "sha256:" + "c" * 64
    with pytest.raises(RuntimeError, match="ownership proof"):
        verify_fleet_workshop_document(
            document,
            container_id=CONTAINER_ID,
            plan_fingerprint=PLAN,
            now_ms=DEADLINE_MS - 1,
        )

    document = workshop_document()
    document["Mounts"] = [
        {"Type": "bind", "Source": "/var/run/docker.sock", "Destination": "/sock"}
    ]
    with pytest.raises(RuntimeError, match="persistent mounts"):
        verify_fleet_workshop_document(
            document,
            container_id=CONTAINER_ID,
            plan_fingerprint=PLAN,
            now_ms=DEADLINE_MS - 1,
        )

    with pytest.raises(RuntimeError, match="deadline has expired"):
        verify_fleet_workshop_document(
            workshop_document(),
            container_id=CONTAINER_ID,
            plan_fingerprint=PLAN,
            now_ms=DEADLINE_MS,
        )


@pytest.mark.parametrize(
    "extra_environment",
    [
        "SSH_AUTH_SOCK=/tmp/agent.sock",
        "KERYX_NODE_TOKEN=opaque",
        "FLEET_CONTROL_SOCKET=/run/fleet.sock",
        "NODESCALE_SOCKET=/run/nodescale.sock",
        "DOCKER_HOST=unix:///var/run/docker.sock",
        "DOCKER_CONTEXT=host-control",
        "HERMES_HOME=/host/hermes",
        "OPENAI_API_KEY=opaque",
        "AWS_ACCESS_KEY_ID=opaque",
    ],
)
def test_fleet_workshop_verifier_rejects_forbidden_environment_authority(
    extra_environment,
) -> None:
    document = workshop_document()
    document["Config"]["Env"].append(extra_environment)
    with pytest.raises(RuntimeError, match="forbidden authority"):
        verify_fleet_workshop_document(
            document,
            container_id=CONTAINER_ID,
            plan_fingerprint=PLAN,
            now_ms=DEADLINE_MS - 1,
        )


def test_fleet_workshop_verifier_rejects_missing_or_duplicate_required_environment() -> None:
    document = workshop_document()
    document["Config"]["Env"].remove("HOME=/home/fleet")
    with pytest.raises(RuntimeError, match="environment is invalid"):
        verify_fleet_workshop_document(
            document,
            container_id=CONTAINER_ID,
            plan_fingerprint=PLAN,
            now_ms=DEADLINE_MS - 1,
        )

    document = workshop_document()
    document["Config"]["Env"].append("HOME=/different")
    with pytest.raises(RuntimeError, match="environment is invalid"):
        verify_fleet_workshop_document(
            document,
            container_id=CONTAINER_ID,
            plan_fingerprint=PLAN,
            now_ms=DEADLINE_MS - 1,
        )


def test_fleet_workshop_environment_missing_exact_container_fails_without_fallback(
    monkeypatch,
) -> None:
    calls: list[list[str]] = []

    def run(argv, **_kwargs):
        calls.append(list(argv))
        assert argv == ["/usr/bin/docker", "inspect", CONTAINER_ID]
        return SimpleNamespace(returncode=1, stdout="", stderr="No such container")

    monkeypatch.setattr(docker_mod, "find_docker", lambda: "/usr/bin/docker")
    monkeypatch.setattr(docker_mod.subprocess, "run", run)

    with pytest.raises(RuntimeError, match="container is unavailable"):
        FleetWorkshopEnvironment(
            container_id=CONTAINER_ID,
            plan_fingerprint=PLAN,
            timeout=30,
        )

    assert calls == [["/usr/bin/docker", "inspect", CONTAINER_ID]]


def test_fleet_workshop_environment_is_attach_only(monkeypatch) -> None:
    calls: list[list[str]] = []
    document = workshop_document()

    def run(argv, **_kwargs):
        calls.append(list(argv))
        assert argv == ["/usr/bin/docker", "inspect", CONTAINER_ID]
        return SimpleNamespace(returncode=0, stdout=json.dumps([document]), stderr="")

    popen_calls: list[tuple[list[str], str | None]] = []

    def popen(argv, stdin_data=None):
        popen_calls.append((list(argv), stdin_data))
        return object()

    monkeypatch.setattr(docker_mod, "find_docker", lambda: "/usr/bin/docker")
    monkeypatch.setattr(docker_mod.subprocess, "run", run)
    monkeypatch.setattr(docker_mod, "_popen_bash", popen)
    monkeypatch.setattr(docker_mod.BaseEnvironment, "init_session", lambda self: None)
    monkeypatch.setattr(docker_mod.time, "time", lambda: (DEADLINE_MS - 1_000) / 1_000)

    environment = FleetWorkshopEnvironment(
        container_id=CONTAINER_ID,
        plan_fingerprint=PLAN,
        timeout=30,
    )
    environment._before_execute()
    environment._run_bash("printf ok", stdin_data=None)
    environment.cleanup()

    assert calls == [
        ["/usr/bin/docker", "inspect", CONTAINER_ID],
        ["/usr/bin/docker", "inspect", CONTAINER_ID],
    ]
    assert popen_calls == [
        (["/usr/bin/docker", "exec", CONTAINER_ID, "bash", "-c", "printf ok"], None)
    ]
    assert all(
        not any(operation in call for operation in ("start", "stop", "rm", "run", "create"))
        for call in calls
    )
