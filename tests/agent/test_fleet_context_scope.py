from __future__ import annotations

import pytest

from agent.fleet_context_scope import (
    FleetContextBinding,
    FleetContextScopeError,
    fleet_context_scope,
    get_fleet_context,
)

P = "sha256:" + "1" * 64
B = "sha256:" + "2" * 64
A = "sha256:" + "3" * 64
M = "sha256:" + "4" * 64
R = "sha256:" + "5" * 64


def binding() -> FleetContextBinding:
    return FleetContextBinding(
        version="fleet-context-v1",
        principal_id=P,
        principal_kind="owner",
        principal_generation=1,
        principal_binding_hash=B,
        agent_instance_id=A,
        base_manifest_digest=M,
        run_authority_hash=R,
    )


def test_fleet_context_round_trips_exact_shape_and_restores_context() -> None:
    item = binding()
    request = item.to_request()
    assert FleetContextBinding.from_request(request) == item
    assert get_fleet_context() is None
    with fleet_context_scope(item):
        assert get_fleet_context() is item
    assert get_fleet_context() is None


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.update(extra=True),
        lambda value: value.__setitem__("version", "fleet-context-v2"),
        lambda value: value.__setitem__("base_manifest_digest", "bad"),
        lambda value: value.__setitem__("run_authority_hash", "bad"),
        lambda value: value["principal"].__setitem__("generation", 0),
        lambda value: value["principal"].__setitem__("kind", "unknown"),
    ],
)
def test_fleet_context_rejects_malformed_or_ambiguous_binding(mutate) -> None:
    value = binding().to_request()
    mutate(value)
    with pytest.raises(FleetContextScopeError):
        FleetContextBinding.from_request(value)
