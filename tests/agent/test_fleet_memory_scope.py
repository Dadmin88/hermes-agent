from __future__ import annotations

import asyncio

import pytest

from agent.fleet_memory_scope import (
    FleetMemoryBinding,
    FleetMemoryScopeError,
    FleetMemoryScopeRef,
    fleet_memory_scope,
    get_fleet_memory,
)

P1 = "sha256:" + "1" * 64
P2 = "sha256:" + "2" * 64
B1 = "sha256:" + "3" * 64
B2 = "sha256:" + "4" * 64
AGENT = "sha256:" + "5" * 64


def binding(principal: str = P1, *, generation: int = 1) -> FleetMemoryBinding:
    principal_scope = FleetMemoryScopeRef("principal", principal)
    return FleetMemoryBinding(
        version="fleet-memory-v1",
        principal_id=principal,
        principal_kind="owner",
        principal_generation=generation,
        principal_binding_hash=B1 if principal == P1 else B2,
        agent_instance_id=AGENT,
        source_run="fleet-execution-1",
        read_scopes=(principal_scope,),
        write_scope=principal_scope,
        retention_until_ms=None,
    )


def test_request_round_trip_and_principal_private_write_scope() -> None:
    item = binding()
    assert FleetMemoryBinding.from_request(item.to_request()) == item
    assert item.write_scope == FleetMemoryScopeRef("principal", P1)

    value = item.to_request()
    value["write_scope"] = {"kind": "project", "scope_id": "project-a"}
    with pytest.raises(FleetMemoryScopeError, match="principal-private"):
        FleetMemoryBinding.from_request(value)


def test_principal_scope_is_mandatory_and_agent_scope_is_hash_bound() -> None:
    item = binding()
    value = item.to_request()
    value["read_scopes"] = [{"kind": "project", "scope_id": "project-a"}]
    with pytest.raises(FleetMemoryScopeError, match="include the principal"):
        FleetMemoryBinding.from_request(value)

    with pytest.raises(FleetMemoryScopeError, match="scope id"):
        FleetMemoryScopeRef("agent_instance", "agent-a")


@pytest.mark.asyncio
async def test_contextvar_isolates_concurrent_memory_principals() -> None:
    first = binding(P1)
    second = binding(P2)

    async def observe(item: FleetMemoryBinding) -> FleetMemoryBinding | None:
        with fleet_memory_scope(item):
            await asyncio.sleep(0)
            return get_fleet_memory()

    observed = await asyncio.gather(observe(first), observe(second))
    assert observed == [first, second]
    assert get_fleet_memory() is None
