from __future__ import annotations

import asyncio
import threading
from unittest.mock import MagicMock

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from agent.fleet_context_scope import FleetContextBinding, get_fleet_context
from agent.fleet_memory_scope import FleetMemoryBinding, FleetMemoryScopeRef
from agent.fleet_runtime_scope import FleetRuntimeBinding
from gateway.config import PlatformConfig
from gateway.platforms.api_server import APIServerAdapter

P1 = "sha256:" + "1" * 64
P2 = "sha256:" + "2" * 64
B1 = "sha256:" + "3" * 64
B2 = "sha256:" + "4" * 64
AGENT = "sha256:" + "5" * 64
BASE = "sha256:" + "6" * 64
AUTH1 = "sha256:" + "7" * 64
AUTH2 = "sha256:" + "8" * 64
IMAGE = "debian@sha256:" + "9" * 64


def runtime(container: str, plan: str) -> FleetRuntimeBinding:
    return FleetRuntimeBinding(
        version="fleet-run-v1",
        container_id=container * 64,
        plan_fingerprint="sha256:" + plan * 64,
        image=IMAGE,
        toolsets=("fleet-terminal",),
        max_iterations=8,
    )


def memory(principal: str) -> FleetMemoryBinding:
    private = FleetMemoryScopeRef("principal", principal)
    return FleetMemoryBinding(
        version="fleet-memory-v1",
        principal_id=principal,
        principal_kind="owner",
        principal_generation=1,
        principal_binding_hash=B1 if principal == P1 else B2,
        agent_instance_id=AGENT,
        source_run=f"run-{principal[-4:]}",
        read_scopes=(private,),
        write_scope=private,
        retention_until_ms=None,
    )


def context(mem: FleetMemoryBinding, authority: str) -> FleetContextBinding:
    return FleetContextBinding(
        version="fleet-context-v1",
        principal_id=mem.principal_id,
        principal_kind=mem.principal_kind,
        principal_generation=mem.principal_generation,
        principal_binding_hash=mem.principal_binding_hash,
        agent_instance_id=mem.agent_instance_id,
        base_manifest_digest=BASE,
        run_authority_hash=authority,
    )


def app_for(adapter: APIServerAdapter) -> web.Application:
    app = web.Application()
    app.router.add_post("/v1/runs", adapter._handle_runs)
    app.router.add_get("/v1/runs/{run_id}", adapter._handle_get_run)
    return app


@pytest.mark.asyncio
async def test_fleet_context_requires_runtime_memory_and_exact_identity_before_run_state() -> None:
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={}))
    adapter._create_agent = MagicMock()
    app = app_for(adapter)
    mem = memory(P1)
    ctx = context(mem, AUTH1)

    async with TestClient(TestServer(app)) as client:
        for payload in (
            {"input": "hello", "fleet_context": ctx.to_request()},
            {
                "input": "hello",
                "fleet_runtime": runtime("a", "b").to_request(),
                "fleet_context": ctx.to_request(),
            },
        ):
            response = await client.post("/v1/runs", json=payload)
            body = await response.json()
            assert response.status == 400
            assert body["error"]["code"] == "invalid_fleet_context"

        mismatched = ctx.to_request()
        mismatched["principal"] = dict(mismatched["principal"])
        mismatched["principal"]["principal_id"] = P2
        response = await client.post(
            "/v1/runs",
            json={
                "input": "hello",
                "fleet_runtime": runtime("a", "b").to_request(),
                "fleet_memory": mem.to_request(),
                "fleet_context": mismatched,
            },
        )
        body = await response.json()
        assert response.status == 400
        assert body["error"]["code"] == "invalid_fleet_context"

    assert adapter._run_statuses == {}
    assert adapter._run_streams == {}
    adapter._create_agent.assert_not_called()
    assert get_fleet_context() is None


@pytest.mark.asyncio
async def test_concurrent_runs_keep_fleet_context_isolated_in_task_and_executor() -> None:
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={}))
    app = app_for(adapter)
    first_memory = memory(P1)
    second_memory = memory(P2)
    first = context(first_memory, AUTH1)
    second = context(second_memory, AUTH2)
    created: list[FleetContextBinding | None] = []
    executed: list[FleetContextBinding | None] = []
    ready = [threading.Event(), threading.Event()]
    release = threading.Event()
    lock = threading.Lock()

    def fake_create_agent(**_kwargs):
        current = get_fleet_context()
        with lock:
            index = len(created)
            created.append(current)
        agent = MagicMock()

        def run_conversation(**_run_kwargs):
            executed.append(get_fleet_context())
            ready[index].set()
            release.wait(timeout=10)
            return {"final_response": "done"}

        agent.run_conversation.side_effect = run_conversation
        agent.session_prompt_tokens = 0
        agent.session_completion_tokens = 0
        agent.session_total_tokens = 0
        return agent

    adapter._create_agent = fake_create_agent

    async with TestClient(TestServer(app)) as client:
        run_ids = []
        for text, rt, mem, ctx in (
            ("first", runtime("a", "b"), first_memory, first),
            ("second", runtime("c", "d"), second_memory, second),
        ):
            response = await client.post(
                "/v1/runs",
                json={
                    "input": text,
                    "fleet_runtime": rt.to_request(),
                    "fleet_memory": mem.to_request(),
                    "fleet_context": ctx.to_request(),
                },
            )
            assert response.status == 202
            run_ids.append((await response.json())["run_id"])
            assert get_fleet_context() is None

        for _ in range(100):
            if all(event.is_set() for event in ready):
                break
            await asyncio.sleep(0.02)
        assert all(event.is_set() for event in ready)
        release.set()

        for run_id in run_ids:
            for _ in range(100):
                response = await client.get(f"/v1/runs/{run_id}")
                status = await response.json()
                if status["status"] == "completed":
                    break
                await asyncio.sleep(0.02)
            assert status["status"] == "completed"

    assert set(created) == {first, second}
    assert set(executed) == {first, second}
    assert created == executed
    assert get_fleet_context() is None
