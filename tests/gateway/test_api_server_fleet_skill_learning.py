from __future__ import annotations

import asyncio
import threading
from unittest.mock import MagicMock

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from agent.fleet_skill_learning_scope import (
    FleetSkillLearningBinding,
    get_fleet_skill_learning,
)
from gateway.config import PlatformConfig
from gateway.platforms.api_server import APIServerAdapter
from tests.gateway.test_api_server_fleet_context import (
    AGENT,
    AUTH1,
    AUTH2,
    B1,
    B2,
    P1,
    P2,
    context,
    memory,
    runtime,
)

R = "sha256:" + "a" * 64
RR = "sha256:" + "b" * 64
CAP = "sha256:" + "d" * 64
TARGET = "sha256:" + "e" * 64
NET = "sha256:" + "f" * 64


def learning(
    principal: str, authority: str, plan_fingerprint: str
) -> FleetSkillLearningBinding:
    mem = memory(principal)
    return FleetSkillLearningBinding(
        principal_id=principal,
        principal_kind="owner",
        principal_generation=1,
        principal_binding_hash=B1 if principal == P1 else B2,
        agent_instance_id=AGENT,
        source_run=mem.source_run,
        scope_kind="principal",
        scope_id=principal,
        run_authority_hash=authority,
        recipe_hash=R,
        resolved_recipe_hash=RR,
        plan_fingerprint=plan_fingerprint,
        capabilities_hash=CAP,
        target_digest=TARGET,
        toolsets=("fleet-terminal",),
        filesystem_needs=(),
        network_mode="none",
        network_policy_hash=NET,
        secret_need_fingerprints=(),
    )


def app_for(adapter: APIServerAdapter) -> web.Application:
    app = web.Application()
    app.router.add_post("/v1/runs", adapter._handle_runs)
    app.router.add_get("/v1/runs/{run_id}", adapter._handle_get_run)
    return app


@pytest.mark.asyncio
async def test_fleet_skill_learning_requires_full_exact_run_identity_before_state() -> None:
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={}))
    adapter._create_agent = MagicMock()
    app = app_for(adapter)
    mem = memory(P1)
    ctx = context(mem, AUTH1)
    bound = learning(P1, AUTH1, "sha256:" + "b" * 64)

    async with TestClient(TestServer(app)) as client:
        response = await client.post(
            "/v1/runs",
            json={"input": "hello", "fleet_skill_learning": bound.to_request()},
        )
        body = await response.json()
        assert response.status == 400
        assert body["error"]["code"] == "invalid_fleet_skill_learning"

        mismatch = bound.to_request()
        mismatch["source_run"] = "different-run"
        response = await client.post(
            "/v1/runs",
            json={
                "input": "hello",
                "fleet_runtime": runtime("a", "b").to_request(),
                "fleet_memory": mem.to_request(),
                "fleet_context": ctx.to_request(),
                "fleet_skill_learning": mismatch,
            },
        )
        body = await response.json()
        assert response.status == 400
        assert body["error"]["code"] == "invalid_fleet_skill_learning"

        mismatch = bound.to_request()
        mismatch["run_authority_hash"] = AUTH2
        response = await client.post(
            "/v1/runs",
            json={
                "input": "hello",
                "fleet_runtime": runtime("a", "b").to_request(),
                "fleet_memory": mem.to_request(),
                "fleet_context": ctx.to_request(),
                "fleet_skill_learning": mismatch,
            },
        )
        body = await response.json()
        assert response.status == 400
        assert body["error"]["code"] == "invalid_fleet_skill_learning"

        mismatch = bound.to_request()
        mismatch["provenance"] = dict(mismatch["provenance"])
        mismatch["provenance"]["plan_fingerprint"] = "sha256:" + "c" * 64
        response = await client.post(
            "/v1/runs",
            json={
                "input": "hello",
                "fleet_runtime": runtime("a", "b").to_request(),
                "fleet_memory": mem.to_request(),
                "fleet_context": ctx.to_request(),
                "fleet_skill_learning": mismatch,
            },
        )
        body = await response.json()
        assert response.status == 400
        assert body["error"]["code"] == "invalid_fleet_skill_learning"

    assert adapter._run_statuses == {}
    assert adapter._run_streams == {}
    adapter._create_agent.assert_not_called()
    assert get_fleet_skill_learning() is None


@pytest.mark.asyncio
async def test_concurrent_runs_keep_skill_learning_binding_isolated_in_task_and_executor() -> None:
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={}))
    app = app_for(adapter)
    first_memory = memory(P1)
    second_memory = memory(P2)
    first_context = context(first_memory, AUTH1)
    second_context = context(second_memory, AUTH2)
    first = learning(P1, AUTH1, "sha256:" + "b" * 64)
    second = learning(P2, AUTH2, "sha256:" + "d" * 64)
    created: list[FleetSkillLearningBinding | None] = []
    executed: list[FleetSkillLearningBinding | None] = []
    ready = [threading.Event(), threading.Event()]
    release = threading.Event()
    lock = threading.Lock()

    def fake_create_agent(**_kwargs):
        current = get_fleet_skill_learning()
        with lock:
            index = len(created)
            created.append(current)
        agent = MagicMock()

        def run_conversation(**_run_kwargs):
            executed.append(get_fleet_skill_learning())
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
                    "fleet_skill_learning": bound.to_request(),
                },
            )
            assert response.status == 202
            run_ids.append((await response.json())["run_id"])
            assert get_fleet_skill_learning() is None

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
    assert get_fleet_skill_learning() is None
