from __future__ import annotations

import subprocess

import pytest

import agent.fleet_runtime_material as runtime_material
import tools.environments.docker as docker_module
from tools.environments.docker import FleetWorkshopEnvironment


def bare_environment() -> FleetWorkshopEnvironment:
    environment = object.__new__(FleetWorkshopEnvironment)
    environment._docker_exe = "/usr/bin/docker"
    environment._container_id = "a" * 64
    return environment


def test_env_material_crosses_only_stdin_not_docker_argv(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    protected = "provider-runtime-value-1234567890"
    captured: dict[str, object] = {}

    monkeypatch.setattr(
        runtime_material,
        "redeem_environment_material",
        lambda: {"PROVIDER_KEY": protected},
    )

    def fake_popen(cmd, stdin_data=None, **_kwargs):
        captured["cmd"] = list(cmd)
        captured["stdin"] = stdin_data
        return object()

    monkeypatch.setattr(docker_module, "_popen_bash", fake_popen)
    environment = bare_environment()

    token = docker_module._FLEET_RUNTIME_MATERIAL_COMMAND.set(True)
    try:
        process = environment._run_bash(
            "printf '%s' \"$PROVIDER_KEY\"; cat",
            stdin_data="caller-input",
        )
    finally:
        docker_module._FLEET_RUNTIME_MATERIAL_COMMAND.reset(token)

    assert process is not None
    command = captured["cmd"]
    assert isinstance(command, list)
    assert protected not in repr(command)
    assert "PROVIDER_KEY" in command[-1]
    assert command[:4] == ["/usr/bin/docker", "exec", "-i", "a" * 64]
    assert captured["stdin"] == protected + "\x00caller-input"


def test_env_material_is_not_redeemed_during_snapshot_or_noncommand_spawn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = []
    monkeypatch.setattr(
        runtime_material,
        "redeem_environment_material",
        lambda: calls.append("redeem") or {"PROVIDER_KEY": "protected"},
    )
    captured = {}

    def fake_popen(cmd, stdin_data=None, **_kwargs):
        captured["cmd"] = list(cmd)
        captured["stdin"] = stdin_data
        return object()

    monkeypatch.setattr(docker_module, "_popen_bash", fake_popen)
    environment = bare_environment()
    environment._run_bash("snapshot bootstrap", login=True)

    assert calls == []
    assert captured["stdin"] is None
    assert captured["cmd"][-2:] == ["-c", "snapshot bootstrap"]


def test_file_material_crosses_only_stdin_to_disposable_tmpfs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    protected = b"-----BEGIN MATERIAL-----\nprivate-body\n-----END MATERIAL-----"
    captured: list[dict[str, object]] = []
    monkeypatch.setattr(
        runtime_material,
        "redeem_file_material",
        lambda: {"provider.pem": protected},
    )

    def fake_run(args, **kwargs):
        captured.append({"args": list(args), **kwargs})
        return subprocess.CompletedProcess(args=args, returncode=0, stdout=b"")

    monkeypatch.setattr(docker_module.subprocess, "run", fake_run)
    environment = bare_environment()
    environment._stage_fleet_file_material()

    assert len(captured) == 1
    call = captured[0]
    args = call["args"]
    assert isinstance(args, list)
    assert protected.decode() not in repr(args)
    assert args[:4] == ["/usr/bin/docker", "exec", "-i", "a" * 64]
    script = args[-1]
    assert "/tmp/hermes-secrets/provider.pem" in script
    assert "chmod 700 /tmp/hermes-secrets" in script
    assert "chmod 600" in script
    assert call["input"] == protected
    assert call["check"] is False


def test_file_injection_failure_never_includes_protected_body_in_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    protected = b"private-file-body"
    monkeypatch.setattr(
        runtime_material,
        "redeem_file_material",
        lambda: {"provider.pem": protected},
    )

    def fake_run(args, **kwargs):
        return subprocess.CompletedProcess(args=args, returncode=23, stdout=protected)

    monkeypatch.setattr(docker_module.subprocess, "run", fake_run)
    environment = bare_environment()

    with pytest.raises(RuntimeError) as caught:
        environment._stage_fleet_file_material()
    assert protected.decode() not in str(caught.value)
