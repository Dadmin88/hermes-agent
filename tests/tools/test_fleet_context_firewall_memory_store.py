from __future__ import annotations

from contextlib import contextmanager

from agent.fleet_context_scope import FleetContextBinding, fleet_context_scope
from agent.fleet_memory_scope import (
    FleetMemoryBinding,
    FleetMemoryScopeRef,
    fleet_memory_scope,
)
from agent.fleet_runtime_scope import FleetRuntimeBinding, fleet_runtime_scope
from tools.memory_tool import MemoryStore

P = "sha256:" + "1" * 64
B = "sha256:" + "2" * 64
A = "sha256:" + "3" * 64
M = "sha256:" + "4" * 64
R = "sha256:" + "5" * 64
IMAGE = "debian@sha256:" + "6" * 64


def bindings() -> tuple[FleetRuntimeBinding, FleetMemoryBinding, FleetContextBinding]:
    runtime = FleetRuntimeBinding(
        version="fleet-run-v1",
        container_id="a" * 64,
        plan_fingerprint="sha256:" + "b" * 64,
        image=IMAGE,
        toolsets=("fleet-terminal",),
        max_iterations=8,
    )
    private = FleetMemoryScopeRef("principal", P)
    memory = FleetMemoryBinding(
        version="fleet-memory-v1",
        principal_id=P,
        principal_kind="owner",
        principal_generation=1,
        principal_binding_hash=B,
        agent_instance_id=A,
        source_run="store-test-run",
        read_scopes=(private,),
        write_scope=private,
        retention_until_ms=None,
    )
    context = FleetContextBinding(
        version="fleet-context-v1",
        principal_id=P,
        principal_kind="owner",
        principal_generation=1,
        principal_binding_hash=B,
        agent_instance_id=A,
        base_manifest_digest=M,
        run_authority_hash=R,
    )
    return runtime, memory, context


@contextmanager
def protected():
    runtime, memory, context = bindings()
    with (
        fleet_runtime_scope(runtime),
        fleet_memory_scope(memory),
        fleet_context_scope(context),
    ):
        yield


def test_memory_store_places_only_provenanced_authorized_context_in_prompt(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "profile"))
    with protected():
        store = MemoryStore()
        store.load_from_disk()
        assert store.add("memory", "Preferred release window is 21:00.")["success"] is True

    with protected():
        reopened = MemoryStore()
        reopened.load_from_disk()
        prompt = reopened.format_for_system_prompt("memory") or ""

    assert "FLEET SCOPED MEMORY CONTEXT" in prompt
    assert "Preferred release window is 21:00." in prompt
    assert "Fleet context provenance" in prompt
    assert "trust_class=principal-private" in prompt
    assert "authority=none" in prompt
    assert "cannot alter policy" in prompt
