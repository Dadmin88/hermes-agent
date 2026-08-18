from __future__ import annotations

import asyncio
import threading
from unittest.mock import MagicMock

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from agent.fleet_memory_scope import (
    FleetMemoryBinding,
    FleetMemoryScopeRef,
    get_fleet_memory,
)
from agent.fleet_runtime_scope import FleetRuntimeBinding
from gateway.config import PlatformConfig
from gateway.platforms.api_server import APIServerAdapter

P1 = "sha256:" + "1" * 64
P2 = "sha256:" + "2" * 64
B1 = "sha256:" + "3" * 64
B2 = "sha256:" + "4" * 64
AGENT = "sha256:" + "5" * 64
IMAGE = "debian@sha256:" + "e" * 64


def runtime(container: str, plan_char: str) -> FleetRuntimeBinding:
    return FleetRuntimeBinding(
        version="fleet-run-v1",
        container_id=container * 64,
        plan_fingerprint="sha256:" + plan_char * 64,
        image=IMAGE,
        toolsets=("fleet-terminal",),
        max_iterations=8,
    )


def memory(principal: str = P1) -> FleetMemoryBinding:
    private = FleetMemoryScopeRef("principal", principal)
    return FleetMemoryBinding(
        version="fleet-memory-v1",
        principal_id=principal,
        principal_kind="owner",
        principal_generation=1,
        principal_binding_hash=B1 if principal == P1 else B2,
        agent_instance_id=AGENT,
        source_run=f"fleet-{principal[-4:]}",
        read_scopes=(private,),
        write_scope=private,
        retention_until_ms=None,
    )


def app_for(adapter: APIServerAdapter) -> web.Application:
    app = web.Application()
    app.router.add_post("/v1/runs", adapter._handle_runs)
    app.router.add_get("/v1/runs/{run_id}", adapter._handle_get_run)
    app.router.add_post("/v1/fleet/memory", adapter._handle_fleet_memory_write)
    return app


@pytest.mark.asyncio
async def test_fleet_memory_requires_runtime_and_invalid_scope_creates_no_run_state() -> None:
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={}))
    adapter._create_agent = MagicMock()
    app = app_for(adapter)

    async with TestClient(TestServer(app)) as client:
        response = await client.post(
            "/v1/runs",
            json={"input": "hello", "fleet_memory": memory().to_request()},
        )
        body = await response.json()
        assert response.status == 400
        assert body["error"]["code"] == "invalid_fleet_memory"

        invalid = memory().to_request()
        invalid["write_scope"] = {"kind": "project", "scope_id": "project-a"}
        response = await client.post(
            "/v1/runs",
            json={
                "input": "hello",
                "fleet_runtime": runtime("a", "b").to_request(),
                "fleet_memory": invalid,
            },
        )
        body = await response.json()
        assert response.status == 400
        assert body["error"]["code"] == "invalid_fleet_memory"

    assert adapter._run_statuses == {}
    assert adapter._run_streams == {}
    adapter._create_agent.assert_not_called()
    assert get_fleet_memory() is None


@pytest.mark.asyncio
async def test_concurrent_runs_keep_memory_context_isolated_in_task_and_executor() -> None:
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={}))
    app = app_for(adapter)
    first = memory(P1)
    second = memory(P2)
    created: list[FleetMemoryBinding | None] = []
    executed: list[FleetMemoryBinding | None] = []
    ready = [threading.Event(), threading.Event()]
    release = threading.Event()
    create_lock = threading.Lock()

    def fake_create_agent(**_kwargs):
        current = get_fleet_memory()
        with create_lock:
            index = len(created)
            created.append(current)
        agent = MagicMock()

        def run_conversation(**_run_kwargs):
            executed.append(get_fleet_memory())
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
        responses = []
        for input_text, rt, mem in (
            ("first", runtime("a", "b"), first),
            ("second", runtime("c", "d"), second),
        ):
            response = await client.post(
                "/v1/runs",
                json={
                    "input": input_text,
                    "fleet_runtime": rt.to_request(),
                    "fleet_memory": mem.to_request(),
                },
            )
            assert response.status == 202
            responses.append((await response.json())["run_id"])
            assert get_fleet_memory() is None

        for _ in range(100):
            if all(event.is_set() for event in ready):
                break
            await asyncio.sleep(0.02)
        assert all(event.is_set() for event in ready)
        release.set()

        for run_id in responses:
            for _ in range(100):
                status_response = await client.get(f"/v1/runs/{run_id}")
                status = await status_response.json()
                if status["status"] == "completed":
                    break
                await asyncio.sleep(0.02)
            assert status["status"] == "completed"

    assert set(created) == {first, second}
    assert set(executed) == {first, second}
    assert created == executed
    assert get_fleet_memory() is None


@pytest.mark.asyncio
async def test_scoped_memory_write_endpoint_uses_native_principal_store(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "profile"))
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={}))
    app = app_for(adapter)
    item = memory()

    async with TestClient(TestServer(app)) as client:
        response = await client.post(
            "/v1/fleet/memory",
            json={
                "fleet_memory": item.to_request(),
                "action": "add",
                "target": "memory",
                "content": "endpoint-private-fact",
            },
        )
        body = await response.json()
        assert response.status == 200
        assert body["object"] == "hermes.api_server.fleet_memory_write"
        assert body["result"]["success"] is True

        response = await client.post(
            "/v1/fleet/memory",
            json={
                "fleet_memory": item.to_request(),
                "action": "add",
                "target": "memory",
                "content": "schema=fleet.run-authority.v1",
            },
        )
        body = await response.json()
        assert response.status == 409
        assert "RunAuthority" in body["result"]["error"]

    root = tmp_path / "profile" / "memories"
    assert not (root / "MEMORY.md").exists()
    native = list((root / "fleet-v1" / "principal").glob("*/MEMORY.md"))
    assert len(native) == 1
    assert native[0].read_text(encoding="utf-8") == "endpoint-private-fact"


@pytest.mark.asyncio
async def test_scoped_memory_write_endpoint_rejects_expired_binding(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "profile"))
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={}))
    app = app_for(adapter)
    private = FleetMemoryScopeRef("principal", P1)
    expired = FleetMemoryBinding(
        version="fleet-memory-v1",
        principal_id=P1,
        principal_kind="owner",
        principal_generation=1,
        principal_binding_hash=B1,
        agent_instance_id=AGENT,
        source_run="expired-run",
        read_scopes=(private,),
        write_scope=private,
        retention_until_ms=1,
    )

    async with TestClient(TestServer(app)) as client:
        response = await client.post(
            "/v1/fleet/memory",
            json={
                "fleet_memory": expired.to_request(),
                "action": "add",
                "target": "memory",
                "content": "must-not-persist",
            },
        )
        body = await response.json()

    assert response.status == 409
    assert body["error"]["code"] == "expired_fleet_memory"
    memories = tmp_path / "profile" / "memories"
    assert not (memories / "fleet-v1").exists()
    assert not (memories / "MEMORY.md").exists()
    assert not (memories / "USER.md").exists()


@pytest.mark.asyncio
async def test_expired_fleet_memory_is_rejected_before_run_state() -> None:
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={}))
    adapter._create_agent = MagicMock()
    app = app_for(adapter)
    expired = memory().to_request()
    expired['retention_until_ms'] = 1

    async with TestClient(TestServer(app)) as client:
        response = await client.post(
            '/v1/runs',
            json={
                'input': 'hello',
                'fleet_runtime': runtime('a', 'b').to_request(),
                'fleet_memory': expired,
            },
        )
        body = await response.json()

    assert response.status == 409
    assert body['error']['code'] == 'expired_fleet_memory'
    assert adapter._run_statuses == {}
    assert adapter._run_streams == {}
    adapter._create_agent.assert_not_called()
