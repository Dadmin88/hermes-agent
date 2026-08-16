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
NETWORK_NAME = "hermes-fleet-egress-" + "c" * 24
NETWORK_POLICY = "sha256:" + "d" * 64
NETWORK_AUTHORITY = "sha256:" + "e" * 64
GATEWAY_ID = "f" * 64
GATEWAY_IP = "172.25.0.2"


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
                "/tmp": "rw,nosuid,nodev,exec,size=67108864",
                "/home/fleet": "rw,nosuid,nodev,exec,size=67108864",
            },
        },
        "State": {"Status": "running"},
        "Mounts": [],
    }


def direct_workshop_document() -> dict:
    document = workshop_document()
    proxy = f"http://{GATEWAY_IP}:8080"
    document["Config"]["Labels"].update(
        {
            "dev.hermes.fleet.network_mode": "project-allowlist",
            "dev.hermes.fleet.network_policy": NETWORK_POLICY,
            "dev.hermes.fleet.network_authority": NETWORK_AUTHORITY,
            "dev.hermes.fleet.network_gateway": GATEWAY_ID,
            "hermes-egress": "proxy",
        }
    )
    document["Config"]["Env"] = [
        f"HTTP_PROXY={proxy}",
        f"HTTPS_PROXY={proxy}",
        f"http_proxy={proxy}",
        f"https_proxy={proxy}",
        "NO_PROXY=",
        "no_proxy=",
    ]
    document["HostConfig"]["NetworkMode"] = NETWORK_NAME
    document["HostConfig"]["Dns"] = ["127.0.0.1"]
    document["NetworkSettings"] = {
        "Networks": {NETWORK_NAME: {"IPAddress": "172.25.0.3"}}
    }
    return document


def test_fleet_workshop_verifier_accepts_exact_hardened_container() -> None:
    verify_fleet_workshop_document(
        workshop_document(),
        container_id=CONTAINER_ID,
        plan_fingerprint=PLAN,
        now_ms=DEADLINE_MS - 1,
    )


def test_fleet_workshop_verifier_accepts_exact_mediated_network_binding() -> None:
    verify_fleet_workshop_document(
        direct_workshop_document(),
        container_id=CONTAINER_ID,
        plan_fingerprint=PLAN,
        now_ms=DEADLINE_MS - 1,
        expected_network_mode="project-allowlist",
        expected_network_name=NETWORK_NAME,
        expected_network_policy=NETWORK_POLICY,
        expected_network_authority=NETWORK_AUTHORITY,
        expected_gateway_id=GATEWAY_ID,
        expected_gateway_ip=GATEWAY_IP,
    )


def test_fleet_workshop_verifier_accepts_provider_only_as_offline_container() -> None:
    document = workshop_document()
    document["Config"]["Labels"].update(
        {
            "dev.hermes.fleet.network_mode": "provider-only",
            "dev.hermes.fleet.network_policy": NETWORK_POLICY,
            "dev.hermes.fleet.network_authority": NETWORK_AUTHORITY,
        }
    )
    verify_fleet_workshop_document(
        document,
        container_id=CONTAINER_ID,
        plan_fingerprint=PLAN,
        now_ms=DEADLINE_MS - 1,
        expected_network_mode="provider-only",
        expected_network_policy=NETWORK_POLICY,
        expected_network_authority=NETWORK_AUTHORITY,
    )


@pytest.mark.parametrize(
    ("mutator", "match"),
    [
        (
            lambda value: value["Config"]["Labels"].__setitem__(
                "dev.hermes.fleet.network_policy", "sha256:" + "1" * 64
            ),
            "network policy",
        ),
        (
            lambda value: value["Config"]["Labels"].__setitem__(
                "dev.hermes.fleet.network_gateway", "1" * 64
            ),
            "network gateway",
        ),
        (
            lambda value: value["HostConfig"].__setitem__("NetworkMode", "bridge"),
            "network isolation",
        ),
        (
            lambda value: value["HostConfig"].__setitem__("Dns", ["8.8.8.8"]),
            "direct DNS",
        ),
        (
            lambda value: value["NetworkSettings"]["Networks"].__setitem__(
                "bridge", {"IPAddress": "172.17.0.3"}
            ),
            "network membership",
        ),
        (
            lambda value: value["Config"]["Env"].append(
                "ALL_PROXY=http://1.2.3.4:1080"
            ),
            "proxy binding",
        ),
    ],
)
def test_fleet_workshop_verifier_rejects_mediated_network_drift(
    mutator, match
) -> None:
    document = direct_workshop_document()
    mutator(document)
    with pytest.raises(RuntimeError, match=match):
        verify_fleet_workshop_document(
            document,
            container_id=CONTAINER_ID,
            plan_fingerprint=PLAN,
            now_ms=DEADLINE_MS - 1,
            expected_network_mode="project-allowlist",
            expected_network_name=NETWORK_NAME,
            expected_network_policy=NETWORK_POLICY,
            expected_network_authority=NETWORK_AUTHORITY,
            expected_gateway_id=GATEWAY_ID,
            expected_gateway_ip=GATEWAY_IP,
        )


@pytest.mark.parametrize(
    ("section", "key", "unsafe"),
    [
        ("Config", "User", "0:0"),
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
    with pytest.raises(RuntimeError, match="input staging ownership"):
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
    with pytest.raises(RuntimeError, match="workspace ownership"):
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
