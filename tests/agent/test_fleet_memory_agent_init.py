from __future__ import annotations

from unittest.mock import MagicMock

from agent.fleet_memory_scope import (
    FleetMemoryBinding,
    FleetMemoryScopeRef,
    fleet_memory_scope,
)
from agent.fleet_runtime_scope import FleetRuntimeBinding, fleet_runtime_scope
from run_agent import AIAgent

P1 = "sha256:" + "1" * 64
B1 = "sha256:" + "2" * 64
AGENT = "sha256:" + "3" * 64
IMAGE = "debian@sha256:" + "e" * 64


class _FakeOpenAI:
    def __init__(self, **kw):
        self.api_key = kw.get("api_key", "test")
        self.base_url = kw.get("base_url", "http://test")

    def close(self):
        pass


def runtime() -> FleetRuntimeBinding:
    return FleetRuntimeBinding(
        version="fleet-run-v1",
        container_id="a" * 64,
        plan_fingerprint="sha256:" + "b" * 64,
        image=IMAGE,
        toolsets=("fleet-terminal",),
        max_iterations=8,
    )


def memory() -> FleetMemoryBinding:
    private = FleetMemoryScopeRef("principal", P1)
    return FleetMemoryBinding(
        version="fleet-memory-v1",
        principal_id=P1,
        principal_kind="owner",
        principal_generation=1,
        principal_binding_hash=B1,
        agent_instance_id=AGENT,
        source_run="fleet-init-test",
        read_scopes=(private,),
        write_scope=private,
        retention_until_ms=None,
    )


def configure(monkeypatch, tmp_path, provider_loader=None) -> None:
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "profile"))
    monkeypatch.setattr("run_agent.get_tool_definitions", lambda **kw: [])
    monkeypatch.setattr("run_agent.check_toolset_requirements", lambda: {})
    monkeypatch.setattr("run_agent.OpenAI", _FakeOpenAI)
    monkeypatch.setattr(
        "hermes_cli.config.load_config_readonly",
        lambda: {
            "memory": {
                "memory_enabled": False,
                "user_profile_enabled": False,
                "provider": "fixture-provider",
            }
        },
    )
    if provider_loader is not None:
        monkeypatch.setattr("plugins.memory.load_memory_provider", provider_loader)


def make_agent() -> AIAgent:
    return AIAgent(
        api_key="test-key",
        base_url="http://test",
        provider="openrouter",
        api_mode="chat_completions",
        max_iterations=1,
        quiet_mode=True,
        skip_context_files=True,
        skip_memory=False,
        enabled_toolsets=["fleet-terminal"],
    )


def test_fleet_runtime_without_memory_scope_fails_closed_to_no_persistent_memory(
    monkeypatch, tmp_path
) -> None:
    loader = MagicMock()
    configure(monkeypatch, tmp_path, loader)

    with fleet_runtime_scope(runtime()):
        agent = make_agent()

    assert agent._memory_store is None
    assert agent._memory_manager is None
    loader.assert_not_called()


def test_fleet_runtime_with_memory_scope_uses_scoped_native_store_and_no_external_provider(
    monkeypatch, tmp_path
) -> None:
    loader = MagicMock()
    configure(monkeypatch, tmp_path, loader)

    with fleet_runtime_scope(runtime()), fleet_memory_scope(memory()):
        agent = make_agent()

    assert agent._memory_store is not None
    assert agent._memory_store._fleet_memory == memory()
    assert agent._memory_enabled is True
    assert agent._user_profile_enabled is True
    assert agent._memory_manager is None
    loader.assert_not_called()
    assert not (tmp_path / "profile" / "memories" / "MEMORY.md").exists()
