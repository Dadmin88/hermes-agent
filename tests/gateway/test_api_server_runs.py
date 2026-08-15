"""Tests for /v1/runs endpoints: start, status, events, steer, and stop.

Covers:
- POST /v1/runs — start a run (202)
- GET /v1/runs/{run_id} — poll run status
- GET /v1/runs/{run_id}/events — SSE event stream
- POST /v1/runs/{run_id}/steer — inject guidance into a running agent
- POST /v1/runs/{run_id}/stop — interrupt a running agent
- Auth, error handling, and cleanup
"""

import asyncio
import json
import threading
import time
from unittest.mock import MagicMock, patch

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from gateway.config import PlatformConfig
from gateway.platforms.api_server import (
    APIServerAdapter,
    _api_request_profile,
    _approval_event_choices,
    cors_middleware,
    security_headers_middleware,
)
from tools import approval as approval_mod


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("smart_denied", "allow_permanent", "expected"),
    [
        (False, True, ["once", "session", "always", "deny"]),
        (False, False, ["once", "session", "deny"]),
        (True, True, ["once", "deny"]),
        (True, False, ["once", "deny"]),
    ],
)
def test_approval_event_choices_follow_backend_capabilities(
    smart_denied, allow_permanent, expected
):
    assert _approval_event_choices(
        smart_denied=smart_denied,
        allow_permanent=allow_permanent,
    ) == expected


def _make_adapter(api_key: str = "") -> APIServerAdapter:
    """Create an adapter with optional API key."""
    extra = {}
    if api_key:
        extra["key"] = api_key
    config = PlatformConfig(enabled=True, extra=extra)
    adapter = APIServerAdapter(config)
    return adapter


def _create_runs_app(adapter: APIServerAdapter) -> web.Application:
    """Create an aiohttp app with /v1/runs routes registered."""
    mws = [mw for mw in (cors_middleware, security_headers_middleware) if mw is not None]
    app = web.Application(middlewares=mws)
    app["api_server_adapter"] = adapter
    app.router.add_post("/v1/runs", adapter._handle_runs)
    app.router.add_get("/v1/runs/{run_id}", adapter._handle_get_run)
    app.router.add_get("/v1/runs/{run_id}/events", adapter._handle_run_events)
    app.router.add_post("/v1/runs/{run_id}/approval", adapter._handle_run_approval)
    app.router.add_post("/v1/runs/{run_id}/steer", adapter._handle_steer_run)
    app.router.add_post("/v1/runs/{run_id}/finalize", adapter._handle_finalize_run)
    app.router.add_post("/v1/runs/{run_id}/stop", adapter._handle_stop_run)
    return app


def _make_slow_agent(**kwargs):
    """Create a mock agent that blocks in run_conversation until interrupted.

    Returns (mock_agent, agent_ready_event, interrupt_event) where
    agent_ready_event is set once run_conversation starts, and
    interrupt_event is set when interrupt() is called.
    """
    ready = threading.Event()
    interrupted = threading.Event()

    mock_agent = MagicMock()

    def _do_interrupt(message=None):
        interrupted.set()

    mock_agent.interrupt = MagicMock(side_effect=_do_interrupt)

    def _slow_run(user_message=None, conversation_history=None, task_id=None):
        ready.set()
        # Block until interrupt() is called
        interrupted.wait(timeout=10)
        return {"final_response": "interrupted"}

    mock_agent.run_conversation.side_effect = _slow_run
    mock_agent.session_prompt_tokens = 0
    mock_agent.session_completion_tokens = 0
    mock_agent.session_total_tokens = 0

    return mock_agent, ready, interrupted


@pytest.fixture
def adapter():
    return _make_adapter()


@pytest.fixture
def auth_adapter():
    return _make_adapter(api_key="sk-secret")


# ---------------------------------------------------------------------------
# POST /v1/runs — start a run
# ---------------------------------------------------------------------------


class TestStartRun:
    @pytest.mark.asyncio
    async def test_start_returns_202(self, adapter):
        app = _create_runs_app(adapter)
        async with TestClient(TestServer(app)) as cli:
            with patch.object(adapter, "_create_agent") as mock_create:
                mock_agent = MagicMock()
                mock_agent.run_conversation.return_value = {"final_response": "done"}
                mock_agent.session_prompt_tokens = 10
                mock_agent.session_completion_tokens = 5
                mock_agent.session_total_tokens = 15
                mock_create.return_value = mock_agent

                resp = await cli.post("/v1/runs", json={"input": "hello"})
                assert resp.status == 202
                data = await resp.json()
                assert data["status"] == "started"
                assert data["run_id"].startswith("run_")

                status_resp = await cli.get(f"/v1/runs/{data['run_id']}")
                assert status_resp.status == 200
                status = await status_resp.json()
                assert status["run_id"] == data["run_id"]
                assert status["status"] in {"queued", "running", "completed"}
                assert status["object"] == "hermes.run"

    @pytest.mark.asyncio
    async def test_start_rejects_invalid_approval_budget(self, adapter):
        app = _create_runs_app(adapter)
        async with TestClient(TestServer(app)) as cli:
            resp = await cli.post(
                "/v1/runs",
                json={"input": "hello", "approval_budget": 0},
            )
            data = await resp.json()

        assert resp.status == 400
        assert data["error"]["code"] == "invalid_approval_budget"
        assert adapter._run_streams == {}
        assert adapter._run_approval_budgets == {}

    @pytest.mark.asyncio
    async def test_start_binds_chat_id_for_delegation_wake_target(self, adapter):
        """/v1/runs must bind the raw session id as the api_server chat_id
        (like every other agent-entry route does via _run_agent): the async
        delegation dispatch reads HERMES_SESSION_CHAT_ID to pick its wake
        self-post target, and an empty binding forces background delegations
        on this route back to synchronous execution."""
        app = _create_runs_app(adapter)
        captured = {}

        async with TestClient(TestServer(app)) as cli:
            with patch.object(adapter, "_create_agent") as mock_create:
                mock_agent = MagicMock()

                def _capture_run(user_message=None, conversation_history=None, task_id=None):
                    from tools.async_delegation import _current_origin_session_id

                    captured["origin_session_id"] = _current_origin_session_id()
                    return {"final_response": "done"}

                mock_agent.run_conversation.side_effect = _capture_run
                mock_agent.session_prompt_tokens = 0
                mock_agent.session_completion_tokens = 0
                mock_agent.session_total_tokens = 0
                mock_create.return_value = mock_agent

                resp = await cli.post(
                    "/v1/runs",
                    json={"input": "hello", "session_id": "runs-raw-sid"},
                )
                assert resp.status == 202
                data = await resp.json()
                run_id = data["run_id"]

                for _ in range(40):
                    status_resp = await cli.get(f"/v1/runs/{run_id}")
                    status = await status_resp.json()
                    if status["status"] == "completed":
                        break
                    await asyncio.sleep(0.05)

        assert captured.get("origin_session_id") == "runs-raw-sid", (
            "runs route must bind chat_id so delegation dispatch sees a wake target"
        )


    @pytest.mark.asyncio
    async def test_start_rejects_conflicting_route_and_request_provider(self):
        adapter = APIServerAdapter(
            PlatformConfig(
                enabled=True,
                extra={
                    "model_routes": {
                        "alias": {
                            "model": "route/model",
                            "provider": "openrouter",
                        }
                    }
                },
            )
        )
        app = _create_runs_app(adapter)
        async with TestClient(TestServer(app)) as cli:
            with patch.object(adapter, "_create_agent") as mock_create:
                resp = await cli.post(
                    "/v1/runs",
                    json={
                        "input": "hello",
                        "model": "alias",
                        "provider": "minimax",
                    },
                )
                data = await resp.json()

        assert resp.status == 400
        assert "provider" in data["error"]["message"].lower()
        assert adapter._run_streams == {}
        assert adapter._run_statuses == {}
        mock_create.assert_not_called()

    @pytest.mark.asyncio
    async def test_start_passes_request_model_provider_options_to_create_agent(self, adapter):
        app = _create_runs_app(adapter)
        model_options = {"reasoning_effort": "medium", "service_tier": "priority"}
        async with TestClient(TestServer(app)) as cli:
            with patch.object(adapter, "_create_agent") as mock_create:
                mock_agent = MagicMock()
                mock_agent.run_conversation.return_value = {"final_response": "done"}
                mock_agent.session_prompt_tokens = 0
                mock_agent.session_completion_tokens = 0
                mock_agent.session_total_tokens = 0
                mock_create.return_value = mock_agent

                resp = await cli.post(
                    "/v1/runs",
                    json={
                        "input": "hello",
                        "model": "MiniMax-M3",
                        "provider": "minimax",
                        "model_options": model_options,
                    },
                )
                assert resp.status == 202
                for _ in range(20):
                    if mock_create.call_args is not None:
                        break
                    await asyncio.sleep(0.05)

        kwargs = mock_create.call_args.kwargs
        assert kwargs["requested_model"] == "MiniMax-M3"
        assert kwargs["requested_provider"] == "minimax"
        assert kwargs["model_options"] == model_options


# ---------------------------------------------------------------------------
# GET /v1/runs/{run_id} — poll run status
# ---------------------------------------------------------------------------


class TestRunStatus:

    @pytest.mark.asyncio
    async def test_status_reflects_explicit_session_id(self, adapter):
        app = _create_runs_app(adapter)
        async with TestClient(TestServer(app)) as cli:
            with patch.object(adapter, "_create_agent") as mock_create:
                mock_agent = MagicMock()
                mock_agent.run_conversation.return_value = {"final_response": "done"}
                mock_agent.session_prompt_tokens = 0
                mock_agent.session_completion_tokens = 0
                mock_agent.session_total_tokens = 0
                mock_create.return_value = mock_agent

                resp = await cli.post(
                    "/v1/runs",
                    json={"input": "hello", "session_id": "space-session"},
                )
                data = await resp.json()
                run_id = data["run_id"]

                for _ in range(20):
                    status_resp = await cli.get(f"/v1/runs/{run_id}")
                    status = await status_resp.json()
                    if status["status"] == "completed":
                        break
                    await asyncio.sleep(0.05)

                mock_agent.run_conversation.assert_called_once()
                assert mock_agent.run_conversation.call_args.kwargs["task_id"] == "space-session"
                assert status["session_id"] == "space-session"


# ---------------------------------------------------------------------------
# GET /v1/runs/{run_id}/events — SSE event stream
# ---------------------------------------------------------------------------


class TestRunEvents:
    @pytest.mark.asyncio
    async def test_events_stream_returns_completed(self, adapter):
        """Events stream should receive run.completed when agent finishes."""
        app = _create_runs_app(adapter)
        async with TestClient(TestServer(app)) as cli:
            with patch.object(adapter, "_create_agent") as mock_create:
                mock_agent = MagicMock()
                mock_agent.run_conversation.return_value = {"final_response": "Hello!"}
                mock_agent.session_prompt_tokens = 10
                mock_agent.session_completion_tokens = 5
                mock_agent.session_total_tokens = 15
                mock_create.return_value = mock_agent

                # Start run
                resp = await cli.post("/v1/runs", json={"input": "hello"})
                assert resp.status == 202
                data = await resp.json()
                run_id = data["run_id"]

                # Subscribe to events
                events_resp = await cli.get(f"/v1/runs/{run_id}/events")
                assert events_resp.status == 200
                body = await events_resp.text()

                # Should contain run.completed
                assert "run.completed" in body
                assert "Hello!" in body

    @pytest.mark.asyncio
    async def test_tool_completed_events_record_final_tool_evidence(self, adapter):
        run_id = "run_tool_evidence"
        adapter._run_streams[run_id] = asyncio.Queue()
        adapter._run_statuses[run_id] = {
            "object": "hermes.run",
            "run_id": run_id,
            "status": "running",
            "tool_calls": 0,
            "tool_errors": 0,
            "last_tool_error": None,
        }
        callback = adapter._make_run_event_callback(
            run_id, asyncio.get_running_loop()
        )

        callback("tool.completed", tool_name="terminal", duration=0.1, is_error=True)
        callback("tool.completed", tool_name="terminal", duration=0.1, is_error=False)
        await asyncio.sleep(0)

        status = adapter._run_statuses[run_id]
        assert status["tool_calls"] == 2
        assert status["tool_errors"] == 1
        assert status["last_tool_error"] is False

    @pytest.mark.asyncio
    async def test_foreground_terminal_records_actual_command_exit(self, adapter):
        run_id = "run_command_foreground"
        adapter._run_streams[run_id] = asyncio.Queue()
        adapter._run_statuses[run_id] = {
            "object": "hermes.run",
            "run_id": run_id,
            "status": "running",
            "tool_calls": 0,
            "tool_errors": 0,
            "last_tool_error": None,
            "command_calls": 0,
            "command_errors": 0,
            "last_command_error": None,
            "pending_processes": 0,
            "command_evidence_invalid": False,
        }
        adapter._run_pending_processes[run_id] = set()
        callback = adapter._make_run_event_callback(
            run_id, asyncio.get_running_loop()
        )

        callback(
            "tool.completed",
            "terminal",
            None,
            {"command": "false", "background": False},
            duration=0.1,
            is_error=False,
            result=json.dumps({"output": "", "exit_code": 1, "error": None}),
        )
        await asyncio.sleep(0)

        status = adapter._run_statuses[run_id]
        assert status["command_calls"] == 1
        assert status["command_errors"] == 1
        assert status["last_command_error"] is True
        assert status["pending_processes"] == 0
        assert status["command_evidence_invalid"] is False

    @pytest.mark.asyncio
    async def test_background_terminal_requires_process_exit_evidence(self, adapter):
        run_id = "run_command_background"
        adapter._run_streams[run_id] = asyncio.Queue()
        adapter._run_statuses[run_id] = {
            "object": "hermes.run",
            "run_id": run_id,
            "status": "running",
            "tool_calls": 0,
            "tool_errors": 0,
            "last_tool_error": None,
            "command_calls": 0,
            "command_errors": 0,
            "last_command_error": None,
            "pending_processes": 0,
            "command_evidence_invalid": False,
        }
        adapter._run_pending_processes[run_id] = set()
        callback = adapter._make_run_event_callback(
            run_id, asyncio.get_running_loop()
        )

        callback(
            "tool.completed",
            "terminal",
            None,
            {"command": "false", "background": True},
            duration=0.01,
            is_error=False,
            result=json.dumps(
                {
                    "output": "Background process started",
                    "session_id": "proc-1",
                    "exit_code": 0,
                    "error": None,
                }
            ),
        )
        status = adapter._run_statuses[run_id]
        assert status["command_calls"] == 0
        assert status["pending_processes"] == 1

        callback(
            "tool.completed",
            "process",
            None,
            {"action": "wait", "session_id": "proc-1"},
            duration=0.01,
            is_error=False,
            result=json.dumps({"status": "exited", "exit_code": 1}),
        )
        await asyncio.sleep(0)

        status = adapter._run_statuses[run_id]
        assert status["command_calls"] == 1
        assert status["command_errors"] == 1
        assert status["last_command_error"] is True
        assert status["pending_processes"] == 0
        assert status["command_evidence_invalid"] is False

    @pytest.mark.asyncio
    async def test_approval_resolve_all_is_scoped_to_target_run(self, auth_adapter):
        """Same client session_id must not let one run approve another run's queue."""
        app = _create_runs_app(auth_adapter)
        async with TestClient(TestServer(app)) as cli:
            with patch.object(auth_adapter, "_create_agent") as mock_create:
                victim_agent, victim_ready, victim_interrupted = _make_slow_agent()
                attacker_agent, attacker_ready, attacker_interrupted = _make_slow_agent()
                mock_create.side_effect = [victim_agent, attacker_agent]

                victim_resp = await cli.post(
                    "/v1/runs",
                    json={"input": "victim", "session_id": "shared-project"},
                    headers={"Authorization": "Bearer sk-secret"},
                )
                attacker_resp = await cli.post(
                    "/v1/runs",
                    json={"input": "attacker", "session_id": "shared-project"},
                    headers={"Authorization": "Bearer sk-secret"},
                )
                assert victim_resp.status == 202
                assert attacker_resp.status == 202
                victim_run = (await victim_resp.json())["run_id"]
                attacker_run = (await attacker_resp.json())["run_id"]

                victim_ready.wait(timeout=3.0)
                attacker_ready.wait(timeout=3.0)
                assert auth_adapter._run_approval_sessions[victim_run] == victim_run
                assert auth_adapter._run_approval_sessions[attacker_run] == attacker_run
                assert auth_adapter._run_approval_sessions[victim_run] != auth_adapter._run_approval_sessions[attacker_run]

                victim_entry = approval_mod._ApprovalEntry({
                    "command": "bash -c victim-danger",
                    "description": "victim approval",
                    "pattern_keys": ["shell-c"],
                })
                attacker_entry = approval_mod._ApprovalEntry({
                    "command": "bash -c attacker-danger",
                    "description": "attacker approval",
                    "pattern_keys": ["shell-c"],
                })
                with approval_mod._lock:
                    approval_mod._gateway_queues[victim_run] = [victim_entry]
                    approval_mod._gateway_queues[attacker_run] = [attacker_entry]

                approval_resp = await cli.post(
                    f"/v1/runs/{attacker_run}/approval",
                    json={"choice": "always", "resolve_all": True},
                    headers={"Authorization": "Bearer sk-secret"},
                )
                approval_data = await approval_resp.json()

                assert approval_resp.status == 200
                assert approval_data["resolved"] == 1
                assert attacker_entry.result == "always"
                assert attacker_entry.event.is_set()
                assert victim_entry.result is None
                assert not victim_entry.event.is_set()
                with approval_mod._lock:
                    assert approval_mod._gateway_queues[victim_run] == [victim_entry]
                    assert victim_run in approval_mod._gateway_queues
                    assert attacker_run not in approval_mod._gateway_queues

                # Clean up the synthetic pending victim approval and unblock the
                # slow test agents so their background run tasks can finish.
                with approval_mod._lock:
                    approval_mod._gateway_queues.pop(victim_run, None)
                victim_interrupted.set()
                attacker_interrupted.set()


@pytest.mark.asyncio
async def test_bounded_run_rejects_persistent_and_bulk_approval(auth_adapter):
    app = _create_runs_app(auth_adapter)
    async with TestClient(TestServer(app)) as cli:
        with patch.object(auth_adapter, "_create_agent") as mock_create:
            agent, ready, interrupted = _make_slow_agent()
            mock_create.return_value = agent
            resp = await cli.post(
                "/v1/runs",
                json={"input": "bounded", "approval_budget": 1},
                headers={"Authorization": "Bearer sk-secret"},
            )
            assert resp.status == 202
            run_id = (await resp.json())["run_id"]
            ready.wait(timeout=3.0)

            entry = approval_mod._ApprovalEntry({
                "command": "bash -c bounded-danger",
                "description": "bounded approval",
                "pattern_keys": ["shell-c"],
            })
            with approval_mod._lock:
                approval_mod._gateway_queues[run_id] = [entry]

            persistent = await cli.post(
                f"/v1/runs/{run_id}/approval",
                json={"choice": "session"},
                headers={"Authorization": "Bearer sk-secret"},
            )
            assert persistent.status == 400
            assert (await persistent.json())["error"]["code"] == (
                "bounded_approval_choice_required"
            )

            bulk = await cli.post(
                f"/v1/runs/{run_id}/approval",
                json={"choice": "once", "resolve_all": True},
                headers={"Authorization": "Bearer sk-secret"},
            )
            assert bulk.status == 400
            assert (await bulk.json())["error"]["code"] == (
                "bounded_approval_bulk_forbidden"
            )
            assert entry.result is None
            assert not entry.event.is_set()

            with approval_mod._lock:
                approval_mod._gateway_queues.pop(run_id, None)
            interrupted.set()


@pytest.mark.asyncio
async def test_approval_budget_auto_denies_request_over_limit(adapter):
    app = _create_runs_app(adapter)
    decisions = []

    def _approval_run(user_message=None, conversation_history=None, task_id=None):
        del user_message, conversation_history
        with approval_mod._lock:
            notify = approval_mod._gateway_notify_cbs[task_id]
        for index in (1, 2):
            decision = approval_mod._await_gateway_decision(
                task_id,
                notify,
                {
                    "command": f"bash -c bounded-{index}",
                    "description": f"bounded approval {index}",
                    "pattern_key": "shell-c",
                    "pattern_keys": ["shell-c"],
                    "allow_permanent": True,
                    "allow_session": True,
                },
            )
            decisions.append(decision)
        return {"final_response": "bounded done"}

    async with TestClient(TestServer(app)) as cli:
        with patch.object(adapter, "_create_agent") as mock_create:
            agent = MagicMock()
            agent.run_conversation.side_effect = _approval_run
            agent.session_prompt_tokens = 0
            agent.session_completion_tokens = 0
            agent.session_total_tokens = 0
            mock_create.return_value = agent

            resp = await cli.post(
                "/v1/runs",
                json={"input": "bounded", "approval_budget": 1},
            )
            assert resp.status == 202
            run_id = (await resp.json())["run_id"]

            for _ in range(100):
                status_resp = await cli.get(f"/v1/runs/{run_id}")
                status = await status_resp.json()
                if status["status"] == "waiting_for_approval":
                    break
                await asyncio.sleep(0.01)
            else:
                pytest.fail("first bounded approval did not become pending")

            assert status["approval_budget"] == 1
            assert status["approval_count"] == 1
            approval = await cli.post(
                f"/v1/runs/{run_id}/approval",
                json={"choice": "once"},
            )
            assert approval.status == 200

            for _ in range(100):
                status_resp = await cli.get(f"/v1/runs/{run_id}")
                status = await status_resp.json()
                if status["status"] == "completed":
                    break
                await asyncio.sleep(0.01)
            else:
                pytest.fail("bounded run did not complete")

    assert decisions[0]["choice"] == "once"
    assert decisions[0]["resolved"] is True
    assert decisions[1]["choice"] == "deny"
    assert decisions[1]["resolved"] is True
    assert decisions[1]["reason"] == "Run approval budget exhausted"
    assert status["approval_budget"] == 1
    assert status["approval_count"] == 2
    assert status["approval_budget_exhausted"] is True


# ---------------------------------------------------------------------------
# POST /v1/runs/{run_id}/steer — steer a running agent
# ---------------------------------------------------------------------------


class TestSteerRun:
    @pytest.mark.asyncio
    async def test_steer_running_agent(self, adapter):
        app = _create_runs_app(adapter)
        agent = MagicMock()
        agent.steer.return_value = True
        queue = asyncio.Queue()
        adapter._active_run_agents["run_123"] = agent
        adapter._run_streams["run_123"] = queue
        adapter._set_run_status("run_123", "running")

        async with TestClient(TestServer(app)) as cli:
            resp = await cli.post("/v1/runs/run_123/steer", json={"input": "tighten the ending"})
            payload = await resp.json()

        assert resp.status == 200
        assert payload == {
            "object": "hermes.run.steer",
            "run_id": "run_123",
            "accepted": True,
        }
        agent.steer.assert_called_once_with("tighten the ending")
        assert adapter._run_statuses["run_123"]["last_event"] == "run.steered"
        event = queue.get_nowait()
        assert event["event"] == "run.steered"
        assert event["run_id"] == "run_123"
        assert event["accepted"] is True

    @pytest.mark.asyncio
    async def test_steer_nonexistent_run_returns_404(self, adapter):
        app = _create_runs_app(adapter)
        async with TestClient(TestServer(app)) as cli:
            resp = await cli.post("/v1/runs/run_missing/steer", json={"input": "hello"})
            payload = await resp.json()

        assert resp.status == 404
        assert payload["error"]["code"] == "run_not_found"

    @pytest.mark.asyncio
    async def test_steer_inactive_run_returns_409(self, adapter):
        app = _create_runs_app(adapter)
        adapter._set_run_status("run_done", "completed")

        async with TestClient(TestServer(app)) as cli:
            resp = await cli.post("/v1/runs/run_done/steer", json={"input": "hello"})
            payload = await resp.json()

        assert resp.status == 409
        assert payload["error"]["code"] == "run_not_accepting_steer"

    @pytest.mark.asyncio
    async def test_steer_missing_input_returns_400(self, adapter):
        app = _create_runs_app(adapter)
        agent = MagicMock()
        agent.steer.return_value = True
        adapter._active_run_agents["run_123"] = agent
        adapter._set_run_status("run_123", "running")

        async with TestClient(TestServer(app)) as cli:
            resp = await cli.post("/v1/runs/run_123/steer", json={"input": ""})
            payload = await resp.json()

        assert resp.status == 400
        assert payload["error"]["code"] == "invalid_steer_input"
        agent.steer.assert_not_called()

    @pytest.mark.asyncio
    async def test_stop_then_steer_rejects_retained_agent_ref(self, adapter):
        """Steer must reject a stopping run even if the executor thread is still live."""
        app = _create_runs_app(adapter)
        run_can_finish = threading.Event()
        run_started = threading.Event()

        async with TestClient(TestServer(app)) as cli:
            with patch.object(adapter, "_create_agent") as mock_create:
                mock_agent = MagicMock()
                mock_agent.session_prompt_tokens = 0
                mock_agent.session_completion_tokens = 0
                mock_agent.session_total_tokens = 0
                mock_agent.steer = MagicMock(return_value=True)

                def _interrupt(_message=None):
                    return None

                def _run_conversation(*_args, **_kwargs):
                    run_started.set()
                    run_can_finish.wait(timeout=5)
                    return {"final_response": "late result"}

                mock_agent.interrupt = MagicMock(side_effect=_interrupt)
                mock_agent.run_conversation.side_effect = _run_conversation
                mock_create.return_value = mock_agent

                start_resp = await cli.post("/v1/runs", json={"input": "hello"})
                run_id = (await start_resp.json())["run_id"]
                assert run_started.wait(timeout=3.0)

                stop_resp = await cli.post(f"/v1/runs/{run_id}/stop")
                assert stop_resp.status == 200
                assert run_id in adapter._active_run_agents

                steer_resp = await cli.post(
                    f"/v1/runs/{run_id}/steer",
                    json={"input": "tighten the ending"},
                )
                steer_data = await steer_resp.json()

                assert steer_resp.status == 409
                assert steer_data["error"]["code"] == "run_not_accepting_steer"
                mock_agent.steer.assert_not_called()

                run_can_finish.set()
                for _ in range(40):
                    if run_id not in adapter._active_run_tasks:
                        break
                    await asyncio.sleep(0.05)

    @pytest.mark.asyncio
    async def test_pending_steer_preserved_on_run_completed(self, adapter):
        """A steer drained by the turn finalizer (accepted after the final
        response) must surface as pending_steer on the terminal run status
        instead of being silently dropped."""
        app = _create_runs_app(adapter)
        async with TestClient(TestServer(app)) as cli:
            with patch.object(adapter, "_create_agent") as mock_create:
                mock_agent = MagicMock()
                mock_agent.session_prompt_tokens = 0
                mock_agent.session_completion_tokens = 0
                mock_agent.session_total_tokens = 0
                mock_agent.run_conversation.return_value = {
                    "final_response": "done",
                    "pending_steer": "tighten the ending",
                }
                mock_create.return_value = mock_agent

                start_resp = await cli.post("/v1/runs", json={"input": "hello"})
                run_id = (await start_resp.json())["run_id"]

                for _ in range(40):
                    status = adapter._run_statuses.get(run_id, {})
                    if status.get("status") == "completed":
                        break
                    await asyncio.sleep(0.05)

        assert adapter._run_statuses[run_id]["status"] == "completed"
        assert adapter._run_statuses[run_id]["pending_steer"] == "tighten the ending"

    @pytest.mark.asyncio
    async def test_steer_requires_auth(self, auth_adapter):
        app = _create_runs_app(auth_adapter)
        async with TestClient(TestServer(app)) as cli:
            resp = await cli.post("/v1/runs/run_any/steer", json={"input": "hello"})

        assert resp.status == 401


# ---------------------------------------------------------------------------
# Run lifecycle TTL sweeping
# ---------------------------------------------------------------------------


class TestRunLifecycleSweep:

    @pytest.mark.asyncio
    async def test_expired_live_run_drops_transport_but_keeps_control_state(self, adapter):
        """Stream TTL bounds buffering without detaching a live run."""
        app = _create_runs_app(adapter)
        adapter._max_concurrent_runs = 1

        async with TestClient(TestServer(app)) as cli:
            with patch.object(adapter, "_create_agent") as mock_create:
                mock_agent, agent_ready, _ = _make_slow_agent()
                mock_create.return_value = mock_agent

                start_resp = await cli.post("/v1/runs", json={"input": "hello"})
                assert start_resp.status == 202
                run_id = (await start_resp.json())["run_id"]
                assert agent_ready.wait(timeout=3.0)

                task = adapter._active_run_tasks[run_id]
                assert isinstance(task, asyncio.Task)
                assert not task.done()

                pending = approval_mod._ApprovalEntry({
                    "command": "bash -c long-running",
                    "description": "approval after stream TTL",
                    "pattern_keys": ["shell-c"],
                })
                with approval_mod._lock:
                    approval_mod._gateway_queues[run_id] = [pending]

                adapter._run_streams_created[run_id] -= adapter._RUN_STREAM_TTL + 1
                # Exercise one real sweeper iteration without waiting 60 seconds.
                with patch(
                    "gateway.platforms.api_server.asyncio.sleep",
                    side_effect=[None, asyncio.CancelledError()],
                ):
                    with pytest.raises(asyncio.CancelledError):
                        await adapter._sweep_orphaned_runs()

                assert adapter._active_run_tasks[run_id] is task
                assert adapter._active_run_agents[run_id] is mock_agent
                assert run_id not in adapter._run_streams
                assert run_id not in adapter._run_streams_created
                assert adapter._run_approval_sessions[run_id] == run_id

                limited = adapter._concurrency_limited_response()
                assert limited is not None
                assert limited.status == 429

                approval_resp = await cli.post(
                    f"/v1/runs/{run_id}/approval",
                    json={"choice": "once"},
                )
                assert approval_resp.status == 200
                assert pending.event.is_set()
                assert pending.result == "once"

                stop_resp = await cli.post(f"/v1/runs/{run_id}/stop")
                assert stop_resp.status == 200
                mock_agent.interrupt.assert_called_once_with("Stop requested via API")


# ---------------------------------------------------------------------------
# POST /v1/runs/{run_id}/stop — interrupt a running agent
# ---------------------------------------------------------------------------


class TestFinalizeRun:
    @staticmethod
    def _request(run_id: str):
        request = MagicMock()
        request.match_info = {"run_id": run_id}
        return request

    async def _finalize(self, adapter, run_id: str, profile: str = "fleet-execution"):
        token = _api_request_profile.set(profile)
        try:
            with patch.object(adapter, "_check_auth", return_value=None):
                return await adapter._handle_finalize_run(self._request(run_id))
        finally:
            _api_request_profile.reset(token)

    @pytest.mark.asyncio
    async def test_terminal_multiplex_run_finalizes_profile_runtime(self, adapter):
        run_id = "run_final"
        adapter._run_statuses[run_id] = {
            "object": "hermes.run",
            "run_id": run_id,
            "status": "completed",
            "quiescent": False,
            "tool_calls": 2,
            "tool_errors": 1,
            "last_tool_error": False,
        }
        adapter._run_profiles[run_id] = "fleet-execution"

        with patch.object(
            adapter,
            "_release_profile_runtime",
            return_value={"session_db_released": True, "log_handlers_released": 2},
        ) as release:
            response = await self._finalize(adapter, run_id)

        assert response.status == 200
        payload = json.loads(response.text)
        assert payload == {
            "object": "hermes.run.finalization",
            "run_id": run_id,
            "status": "completed",
            "quiescent": True,
            "session_db_released": True,
            "log_handlers_released": 2,
            "tool_calls": 2,
            "tool_errors": 1,
            "last_tool_error": False,
            "command_calls": 0,
            "command_errors": 0,
            "last_command_error": None,
            "pending_processes": 0,
            "command_evidence_invalid": False,
        }
        assert adapter._run_statuses[run_id]["quiescent"] is True
        assert adapter._run_statuses[run_id]["last_event"] == "run.finalized"
        release.assert_called_once_with("fleet-execution")

    @pytest.mark.asyncio
    async def test_finalize_resolves_unawaited_background_process(self, adapter):
        from tools.process_registry import process_registry

        run_id = "run_final_background"
        adapter._run_statuses[run_id] = {
            "object": "hermes.run",
            "run_id": run_id,
            "status": "completed",
            "quiescent": False,
            "tool_calls": 1,
            "tool_errors": 0,
            "last_tool_error": False,
            "command_calls": 0,
            "command_errors": 0,
            "last_command_error": None,
            "pending_processes": 1,
            "command_evidence_invalid": False,
        }
        adapter._run_profiles[run_id] = "fleet-execution"
        adapter._run_pending_processes[run_id] = {"proc-auto"}

        with (
            patch.object(
                process_registry,
                "poll",
                return_value={"status": "exited", "exit_code": 1},
            ) as poll,
            patch.object(
                adapter,
                "_release_profile_runtime",
                return_value={
                    "session_db_released": True,
                    "log_handlers_released": 0,
                },
            ),
        ):
            response = await self._finalize(adapter, run_id)

        assert response.status == 200
        payload = json.loads(response.text)
        assert payload["command_calls"] == 1
        assert payload["command_errors"] == 1
        assert payload["last_command_error"] is True
        assert payload["pending_processes"] == 0
        assert payload["command_evidence_invalid"] is False
        poll.assert_called_once_with("proc-auto")

    @pytest.mark.asyncio
    async def test_finalize_is_idempotent(self, adapter):
        run_id = "run_final_idempotent"
        adapter._run_statuses[run_id] = {
            "object": "hermes.run",
            "run_id": run_id,
            "status": "completed",
            "quiescent": False,
        }
        adapter._run_profiles[run_id] = "fleet-execution"
        with patch.object(
            adapter,
            "_release_profile_runtime",
            return_value={"session_db_released": True, "log_handlers_released": 2},
        ) as release:
            first = await self._finalize(adapter, run_id)
            second = await self._finalize(adapter, run_id)

        assert first.status == second.status == 200
        assert json.loads(second.text)["quiescent"] is True
        release.assert_called_once()

    @pytest.mark.asyncio
    async def test_finalize_rejects_unknown_and_nonterminal_runs(self, adapter):
        unknown = await self._finalize(adapter, "run_missing")
        assert unknown.status == 404

        run_id = "run_active"
        adapter._run_statuses[run_id] = {
            "object": "hermes.run",
            "run_id": run_id,
            "status": "running",
            "quiescent": False,
        }
        adapter._run_profiles[run_id] = "fleet-execution"
        nonterminal = await self._finalize(adapter, run_id)
        assert nonterminal.status == 409
        assert json.loads(nonterminal.text)["error"]["code"] == "run_not_terminal"

    @pytest.mark.asyncio
    async def test_finalize_rejects_wrong_profile(self, adapter):
        run_id = "run_wrong_profile"
        adapter._run_statuses[run_id] = {
            "object": "hermes.run",
            "run_id": run_id,
            "status": "completed",
            "quiescent": False,
        }
        adapter._run_profiles[run_id] = "fleet-execution"
        response = await self._finalize(adapter, run_id, profile="other-profile")
        assert response.status == 409
        assert json.loads(response.text)["error"]["code"] == "run_profile_mismatch"

    @pytest.mark.asyncio
    async def test_finalize_rejects_while_same_profile_run_is_active(self, adapter):
        run_id = "run_done"
        other_id = "run_other"
        adapter._run_statuses[run_id] = {
            "object": "hermes.run",
            "run_id": run_id,
            "status": "completed",
            "quiescent": False,
        }
        adapter._run_profiles[run_id] = "fleet-execution"
        adapter._run_profiles[other_id] = "fleet-execution"
        other_task = asyncio.create_task(asyncio.sleep(10))
        adapter._active_run_tasks[other_id] = other_task
        try:
            response = await self._finalize(adapter, run_id)
        finally:
            other_task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await other_task

        assert response.status == 409
        assert json.loads(response.text)["error"]["code"] == "run_profile_busy"


class TestStopRun:

    @pytest.mark.asyncio
    async def test_stop_keeps_uncooperative_executor_tracked_until_exit(self, adapter):
        """Cancelling an asyncio wrapper must not hide its live executor thread."""
        app = _create_runs_app(adapter)
        run_can_finish = threading.Event()
        run_finished = threading.Event()

        async with TestClient(TestServer(app)) as cli:
            with patch.object(adapter, "_create_agent") as mock_create:
                mock_agent = MagicMock()
                mock_agent.session_prompt_tokens = 0
                mock_agent.session_completion_tokens = 0
                mock_agent.session_total_tokens = 0
                started = threading.Event()

                def _run_conversation(*_args, **_kwargs):
                    started.set()
                    run_can_finish.wait(timeout=5)
                    run_finished.set()
                    return {"final_response": "late result"}

                mock_agent.run_conversation.side_effect = _run_conversation
                mock_create.return_value = mock_agent

                resp = await cli.post("/v1/runs", json={"input": "hello"})
                run_id = (await resp.json())["run_id"]
                assert started.wait(timeout=3)

                stop_resp = await cli.post(f"/v1/runs/{run_id}/stop")
                assert stop_resp.status == 200
                await asyncio.sleep(0.1)

                assert not run_finished.is_set()
                assert run_id in adapter._active_run_agents
                assert run_id in adapter._active_run_tasks
                assert adapter._run_statuses[run_id]["status"] == "stopping"

                run_can_finish.set()
                for _ in range(40):
                    if run_id not in adapter._active_run_tasks:
                        break
                    await asyncio.sleep(0.05)

                assert run_id not in adapter._active_run_agents
                assert run_id not in adapter._active_run_tasks
                assert adapter._run_statuses[run_id]["status"] == "cancelled"

    @pytest.mark.asyncio
    async def test_stop_running_agent(self, adapter):
        """Stop should interrupt the agent and cancel the task."""
        app = _create_runs_app(adapter)
        async with TestClient(TestServer(app)) as cli:
            with patch.object(adapter, "_create_agent") as mock_create:
                mock_agent, agent_ready, _ = _make_slow_agent()
                mock_create.return_value = mock_agent

                # Start run
                resp = await cli.post("/v1/runs", json={"input": "hello"})
                assert resp.status == 202
                data = await resp.json()
                run_id = data["run_id"]

                # Wait for agent to start running in the thread
                agent_ready.wait(timeout=3.0)
                await asyncio.sleep(0.1)

                # Verify agent ref is stored
                assert run_id in adapter._active_run_agents

                # Stop the run
                stop_resp = await cli.post(f"/v1/runs/{run_id}/stop")
                assert stop_resp.status == 200
                stop_data = await stop_resp.json()
                assert stop_data["run_id"] == run_id
                assert stop_data["status"] == "stopping"

                # Agent interrupt should have been called
                mock_agent.interrupt.assert_called_once_with("Stop requested via API")

                status_resp = await cli.get(f"/v1/runs/{run_id}")
                assert status_resp.status == 200
                status_data = await status_resp.json()
                assert status_data["status"] in {"stopping", "cancelled"}

                # Refs should be cleaned up
                await asyncio.sleep(0.2)
                assert run_id not in adapter._active_run_agents
                assert run_id not in adapter._active_run_tasks


    @pytest.mark.asyncio
    async def test_stop_sends_sentinel_to_events_stream(self, adapter):
        """After stop, the events stream should close."""
        app = _create_runs_app(adapter)
        async with TestClient(TestServer(app)) as cli:
            with patch.object(adapter, "_create_agent") as mock_create:
                mock_agent, agent_ready, _ = _make_slow_agent()
                mock_create.return_value = mock_agent

                # Start run
                resp = await cli.post("/v1/runs", json={"input": "hello"})
                assert resp.status == 202
                data = await resp.json()
                run_id = data["run_id"]

                agent_ready.wait(timeout=3.0)
                await asyncio.sleep(0.1)

                # Subscribe to events in background
                events_task = asyncio.ensure_future(
                    cli.get(f"/v1/runs/{run_id}/events")
                )

                await asyncio.sleep(0.1)

                # Stop the run
                stop_resp = await cli.post(f"/v1/runs/{run_id}/stop")
                assert stop_resp.status == 200

                # Events stream should close
                events_resp = await asyncio.wait_for(events_task, timeout=5.0)
                assert events_resp.status == 200
                body = await events_resp.text()
                # Stream should have received run.failed and closed
                assert "run.failed" in body or "stream closed" in body


class TestRunsProviderAuthFailure:
    @pytest.mark.asyncio
    async def test_status_reports_provider_auth_failure_distinctly(self, adapter):
        """/v1/runs builds its own agent via _create_agent() and does not
        route through _run_agent(), so the controlled "Provider
        authentication failed" message added there does not cover this
        endpoint. _handle_runs()'s own _ProviderAuthResolutionError branch
        must give the same distinguished message instead of the generic
        except-Exception "run failed" text."""
        from gateway.platforms.api_server import _ProviderAuthResolutionError

        app = _create_runs_app(adapter)
        async with TestClient(TestServer(app)) as cli:
            with patch.object(adapter, "_create_agent") as mock_create:
                mock_create.side_effect = _ProviderAuthResolutionError(
                    "No credentials found for provider 'nous'"
                )

                resp = await cli.post("/v1/runs", json={"input": "hello"})
                assert resp.status == 202
                data = await resp.json()
                run_id = data["run_id"]

                for _ in range(40):
                    status_resp = await cli.get(f"/v1/runs/{run_id}")
                    status = await status_resp.json()
                    if status["status"] == "failed":
                        break
                    await asyncio.sleep(0.05)

                assert status["status"] == "failed"
                assert status["error"] == "⚠️ Provider authentication failed: No credentials found for provider 'nous'"
                assert status["last_event"] == "run.failed"
