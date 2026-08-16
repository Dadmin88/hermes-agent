from __future__ import annotations

import asyncio
from contextvars import copy_context

import pytest

from agent.fleet_runtime_scope import (
    FleetRuntimeBinding,
    FleetRuntimeScopeError,
    fleet_runtime_scope,
    get_fleet_runtime,
)

CONTAINER_A = "a" * 64
CONTAINER_B = "b" * 64
PLAN_A = "sha256:" + "c" * 64
PLAN_B = "sha256:" + "d" * 64
IMAGE = "debian@sha256:" + "e" * 64


def binding(
    *,
    container_id: str = CONTAINER_A,
    plan_fingerprint: str = PLAN_A,
    max_iterations: int = 8,
) -> FleetRuntimeBinding:
    return FleetRuntimeBinding(
        version="fleet-run-v1",
        container_id=container_id,
        plan_fingerprint=plan_fingerprint,
        image=IMAGE,
        toolsets=("fleet-terminal",),
        max_iterations=max_iterations,
    )


def test_request_shape_is_exact_and_cannot_carry_generic_runtime_power() -> None:
    value = binding().to_request()
    assert FleetRuntimeBinding.from_request(value) == binding()

    for extra in (
        "mounts",
        "env",
        "network",
        "docker_flags",
        "persistent",
    ):
        changed = {**value, extra: True}
        with pytest.raises(FleetRuntimeScopeError, match="invalid shape"):
            FleetRuntimeBinding.from_request(changed)


def test_binding_requires_exact_container_digest_image_toolset_and_budget() -> None:
    valid = binding().to_request()
    invalid_values = (
        {**valid, "container_id": "short"},
        {**valid, "plan_fingerprint": "sha256:bad"},
        {**valid, "image": "debian:latest"},
        {**valid, "toolsets": ["terminal"]},
        {**valid, "toolsets": ["fleet-terminal", "web"]},
        {**valid, "max_iterations": 0},
        {**valid, "max_iterations": 33},
        {**valid, "max_iterations": True},
    )
    for value in invalid_values:
        with pytest.raises(FleetRuntimeScopeError):
            FleetRuntimeBinding.from_request(value)


def test_context_scope_restores_exact_prior_value() -> None:
    assert get_fleet_runtime() is None
    first = binding()
    second = binding(
        container_id=CONTAINER_B,
        plan_fingerprint=PLAN_B,
    )
    with fleet_runtime_scope(first):
        assert get_fleet_runtime() == first
        with fleet_runtime_scope(second):
            assert get_fleet_runtime() == second
        assert get_fleet_runtime() == first
    assert get_fleet_runtime() is None


@pytest.mark.asyncio
async def test_concurrent_tasks_and_executor_threads_keep_distinct_bindings() -> None:
    first = binding()
    second = binding(
        container_id=CONTAINER_B,
        plan_fingerprint=PLAN_B,
        max_iterations=5,
    )

    async def observe(expected: FleetRuntimeBinding):
        await asyncio.sleep(0)
        task_value = get_fleet_runtime()
        executor_context = copy_context()
        thread_value = await asyncio.get_running_loop().run_in_executor(
            None,
            executor_context.run,
            get_fleet_runtime,
        )
        return task_value, thread_value, expected

    with fleet_runtime_scope(first):
        first_task = asyncio.create_task(observe(first))
    with fleet_runtime_scope(second):
        second_task = asyncio.create_task(observe(second))

    first_values, second_values = await asyncio.gather(first_task, second_task)
    assert first_values == (first, first, first)
    assert second_values == (second, second, second)
    assert get_fleet_runtime() is None
