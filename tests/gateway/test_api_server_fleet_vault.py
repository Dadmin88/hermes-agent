from __future__ import annotations

import asyncio
import threading
from unittest.mock import MagicMock

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from agent.fleet_runtime_material import (
    FleetRuntimeMaterialHandle,
    FleetVaultBinding,
    get_fleet_vault,
)
from gateway.config import PlatformConfig
from gateway.platforms.api_server import APIServerAdapter
from tests.gateway.test_api_server_fleet_context import (
    AUTH1,
    AUTH2,
    P1,
    P2,
    context,
    memory,
    runtime,
)

FUTURE = 9_999_999_999_999


def vault(
    *,
    run_id: str,
    authority: str,
    suffix: str,
    target: str = "PROVIDER_KEY",
    expires: int = FUTURE,
) -> FleetVaultBinding:
    return FleetVaultBinding(
        run_id=run_id,
        run_authority_hash=authority,
        handles=(
            FleetRuntimeMaterialHandle(
                handle="hvh1_" + suffix * 32,
                injection_kind="env",
                injection_target=target,
                version=1,
                expires_at_ms=expires,
            ),
        ),
    )


def app_for(adapter: APIServerAdapter) -> web.Application:
    app = web.Application()
    app.router.add_post("/v1/runs", adapter._handle_runs)
    app.router.add_get("/v1/runs/{run_id}", adapter._handle_get_run)
    return app


@pytest.mark.asyncio
async def test_fleet_vault_requires_full_binding_and_exact_run_authority_before_state() -> (
    None
):
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={}))
    adapter._create_agent = MagicMock()
    app = app_for(adapter)
    mem = memory(P1)
    ctx = context(mem, AUTH1)
    bound = vault(run_id=mem.source_run, authority=AUTH1, suffix="a")

    async with TestClient(TestServer(app)) as client:
        response = await client.post(
            "/v1/runs",
            json={"input": "hello", "fleet_vault": bound.to_request()},
        )
        body = await response.json()
        assert response.status == 400
        assert body["error"]["code"] == "invalid_fleet_vault"

        mismatch_authority = bound.to_request()
        mismatch_authority["run_authority_hash"] = AUTH2
        response = await client.post(
            "/v1/runs",
            json={
                "input": "hello",
                "fleet_runtime": runtime("a", "b").to_request(),
                "fleet_memory": mem.to_request(),
                "fleet_context": ctx.to_request(),
                "fleet_vault": mismatch_authority,
            },
        )
        body = await response.json()
        assert response.status == 400
        assert body["error"]["code"] == "invalid_fleet_vault"

        mismatch_run = bound.to_request()
        mismatch_run["run_id"] = "different-run"
        response = await client.post(
            "/v1/runs",
            json={
                "input": "hello",
                "fleet_runtime": runtime("a", "b").to_request(),
                "fleet_memory": mem.to_request(),
                "fleet_context": ctx.to_request(),
                "fleet_vault": mismatch_run,
            },
        )
        body = await response.json()
        assert response.status == 400
        assert body["error"]["code"] == "invalid_fleet_vault"

        expired = bound.to_request()
        expired["handles"] = [dict(expired["handles"][0])]
        expired["handles"][0]["expires_at_ms"] = 1
        response = await client.post(
            "/v1/runs",
            json={
                "input": "hello",
                "fleet_runtime": runtime("a", "b").to_request(),
                "fleet_memory": mem.to_request(),
                "fleet_context": ctx.to_request(),
                "fleet_vault": expired,
            },
        )
        body = await response.json()
        assert response.status == 400
        assert body["error"]["code"] == "invalid_fleet_vault"

    assert adapter._run_statuses == {}
    assert adapter._run_streams == {}
    adapter._create_agent.assert_not_called()
    assert get_fleet_vault() is None


@pytest.mark.asyncio
async def test_concurrent_runs_keep_fleet_vault_binding_isolated_in_task_and_executor() -> (
    None
):
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={}))
    app = app_for(adapter)
    first_memory = memory(P1)
    second_memory = memory(P2)
    first_context = context(first_memory, AUTH1)
    second_context = context(second_memory, AUTH2)
    first = vault(run_id=first_memory.source_run, authority=AUTH1, suffix="a")
    second = vault(
        run_id=second_memory.source_run,
        authority=AUTH2,
        suffix="b",
        target="SECOND_PROVIDER_KEY",
    )
    created: list[FleetVaultBinding | None] = []
    executed: list[FleetVaultBinding | None] = []
    ready = [threading.Event(), threading.Event()]
    release = threading.Event()
    lock = threading.Lock()

    def fake_create_agent(**_kwargs):
        current = get_fleet_vault()
        with lock:
            index = len(created)
            created.append(current)
        agent = MagicMock()

        def run_conversation(**_run_kwargs):
            executed.append(get_fleet_vault())
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
        for text, rt, mem, ctx, bound in (
            ("first", runtime("a", "b"), first_memory, first_context, first),
            ("second", runtime("c", "d"), second_memory, second_context, second),
        ):
            response = await client.post(
                "/v1/runs",
                json={
                    "input": text,
                    "fleet_runtime": rt.to_request(),
                    "fleet_memory": mem.to_request(),
                    "fleet_context": ctx.to_request(),
                    "fleet_vault": bound.to_request(),
                },
            )
            assert response.status == 202
            run_ids.append((await response.json())["run_id"])
            assert get_fleet_vault() is None

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
    assert get_fleet_vault() is None
