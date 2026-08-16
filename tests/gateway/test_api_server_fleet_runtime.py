from __future__ import annotations

import asyncio
import threading
from unittest.mock import MagicMock

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from agent.fleet_runtime_scope import (
    FleetRuntimeBinding,
    fleet_runtime_scope,
    get_fleet_runtime,
)
from gateway.config import PlatformConfig
from gateway.platforms.api_server import APIServerAdapter

IMAGE = "debian@sha256:" + "e" * 64


def binding(container: str, plan_char: str, iterations: int = 8) -> FleetRuntimeBinding:
    return FleetRuntimeBinding(
        version="fleet-run-v1",
        container_id=container * 64,
        plan_fingerprint="sha256:" + plan_char * 64,
        image=IMAGE,
        toolsets=("fleet-terminal",),
        max_iterations=iterations,
    )


def app_for(adapter: APIServerAdapter) -> web.Application:
    app = web.Application()
    app.router.add_post("/v1/runs", adapter._handle_runs)
    app.router.add_get("/v1/runs/{run_id}", adapter._handle_get_run)
    return app


def patch_create_agent_runtime(monkeypatch) -> None:
    monkeypatch.setattr(
        "gateway.run._resolve_runtime_agent_kwargs",
        lambda: {
            "provider": "openrouter",
            "api_key": "test-key",
            "base_url": "https://provider.invalid/v1",
            "api_mode": "chat_completions",
        },
    )
    monkeypatch.setattr("gateway.run._resolve_gateway_model", lambda: "global/model")
    monkeypatch.setattr("gateway.run._load_gateway_config", lambda: {})
    monkeypatch.setattr(
        "gateway.run.GatewayRunner._load_reasoning_config",
        staticmethod(lambda model="": {}),
    )
    monkeypatch.setattr(
        "gateway.run.GatewayRunner._load_fallback_model",
        staticmethod(lambda: None),
    )
    monkeypatch.setattr("gateway.run._current_max_iterations", lambda: 90)
    monkeypatch.setattr(
        "hermes_cli.tools_config._get_platform_tools",
        lambda *_args: {"web", "terminal"},
    )


def test_create_agent_uses_only_run_scoped_toolset_and_iteration_budget(
    monkeypatch,
) -> None:
    patch_create_agent_runtime(monkeypatch)
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={}))
    adapter._session_db = MagicMock()
    captured: list[dict] = []

    class FakeAgent:
        model = "global/model"
        provider = "openrouter"

        def __init__(self, **kwargs):
            captured.append(kwargs)

    monkeypatch.setattr("run_agent.AIAgent", FakeAgent)

    runtime = binding("a", "b", iterations=6)
    with fleet_runtime_scope(runtime):
        adapter._create_agent(session_id="fleet-run")
    adapter._create_agent(session_id="normal-run")

    assert captured[0]["enabled_toolsets"] == ["fleet-terminal"]
    assert captured[0]["max_iterations"] == 6
    assert captured[1]["enabled_toolsets"] == ["terminal", "web"]
    assert captured[1]["max_iterations"] == 90
    assert get_fleet_runtime() is None


@pytest.mark.asyncio
async def test_invalid_fleet_runtime_rejected_before_run_state_or_agent_creation() -> None:
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={}))
    adapter._create_agent = MagicMock()
    app = app_for(adapter)
    value = binding("a", "b").to_request()
    value["network"] = "bridge"

    async with TestClient(TestServer(app)) as client:
        response = await client.post(
            "/v1/runs",
            json={"input": "hello", "fleet_runtime": value},
        )
        body = await response.json()

    assert response.status == 400
    assert body["error"]["code"] == "invalid_fleet_runtime"
    assert adapter._run_statuses == {}
    assert adapter._run_streams == {}
    adapter._create_agent.assert_not_called()
    assert get_fleet_runtime() is None


@pytest.mark.asyncio
async def test_concurrent_runs_keep_task_and_executor_runtime_bindings_isolated() -> None:
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={}))
    app = app_for(adapter)
    first = binding("a", "b", iterations=4)
    second = binding("c", "d", iterations=5)
    created: list[FleetRuntimeBinding | None] = []
    executed: list[FleetRuntimeBinding | None] = []
    ready = [threading.Event(), threading.Event()]
    release = threading.Event()
    create_lock = threading.Lock()

    def fake_create_agent(**_kwargs):
        current = get_fleet_runtime()
        with create_lock:
            index = len(created)
            created.append(current)
        agent = MagicMock()

        def run_conversation(**_run_kwargs):
            executed.append(get_fleet_runtime())
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
        first_response = await client.post(
            "/v1/runs",
            json={"input": "first", "fleet_runtime": first.to_request()},
        )
        assert first_response.status == 202
        first_id = (await first_response.json())["run_id"]
        assert get_fleet_runtime() is None

        second_response = await client.post(
            "/v1/runs",
            json={"input": "second", "fleet_runtime": second.to_request()},
        )
        assert second_response.status == 202
        second_id = (await second_response.json())["run_id"]
        assert get_fleet_runtime() is None

        for _ in range(100):
            if all(event.is_set() for event in ready):
                break
            await asyncio.sleep(0.02)
        assert all(event.is_set() for event in ready)
        release.set()

        for run_id in (first_id, second_id):
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
    assert get_fleet_runtime() is None
