from __future__ import annotations

import queue
import stat
import time
from pathlib import Path

import pytest

from hermes_cli.local_supervisor import LocalSupervisorServer, _socket_request


class FakeAgent:
    def __init__(self):
        self.steers = []

    def steer(self, text):
        self.steers.append(text)
        return True


class FakeCLI:
    def __init__(self):
        self._should_exit = False
        self._agent_running = False
        self._interactive_turn = False
        self._tool_start_time = 0.0
        self._pending_tool_info = {}
        self._pending_input = queue.Queue()
        self.session_id = "session-123"
        self.model = "qwen3.5-9b"
        self.provider = "custom"
        self.api_mode = "chat_completions"
        self.agent = FakeAgent()
        self.conversation_history = [
            {"role": "user", "content": "hello"},
            {"role": "assistant", "content": "hi"},
            {"role": "tool", "content": "hidden tool output"},
        ]


def _wait_for_socket(path: Path) -> None:
    deadline = time.time() + 2
    while time.time() < deadline:
        if path.exists():
            return
        time.sleep(0.01)
    raise AssertionError(f"socket did not appear: {path}")


def test_local_supervisor_socket_round_trip(tmp_path):
    cli = FakeCLI()
    server = LocalSupervisorServer(cli, runtime_dir=tmp_path).start()
    try:
        _wait_for_socket(server.socket_path)
        mode = stat.S_IMODE(server.socket_path.stat().st_mode)
        assert mode == 0o600

        status = _socket_request(server.socket_path, {"action": "status"})
        assert status["success"] is True
        assert status["session_id"] == "session-123"
        assert status["model"] == "qwen3.5-9b"
        assert status["provider"] == "custom"
        assert status["turn_active"] is False
        assert status["tool_active"] is False
        assert status["active_tools"] == []

        queued = _socket_request(
            server.socket_path,
            {"action": "message", "text": "inspect the repo"},
        )
        assert queued["queued"] is True
        assert cli._pending_input.get_nowait() == "[External Katana supervisor]\ninspect the repo"

        history = _socket_request(server.socket_path, {"action": "history", "limit": 10})
        assert history["messages"] == [
            {"role": "user", "content": "hello"},
            {"role": "assistant", "content": "hi"},
        ]
    finally:
        cli._should_exit = True
        server.stop()

    assert not server.socket_path.exists()


def test_status_reports_turn_and_tool_activity(tmp_path):
    cli = FakeCLI()
    cli._interactive_turn = True
    cli._tool_start_time = 123.0
    cli._pending_tool_info = {"execute_code": [("preview", {"code": "..."})]}
    server = LocalSupervisorServer(cli, runtime_dir=tmp_path)

    status = server.dispatch({"action": "status"})

    assert status["turn_active"] is True
    assert status["tool_active"] is True
    assert status["active_tools"] == ["execute_code"]


def test_steer_active_turn_uses_agent_slot(tmp_path):
    cli = FakeCLI()
    cli._agent_running = True
    server = LocalSupervisorServer(cli, runtime_dir=tmp_path)

    result = server.dispatch({"action": "steer", "text": "check the projection writer"})

    assert result == {
        "success": True,
        "mode": "steer",
        "session_id": "session-123",
    }
    assert cli.agent.steers == [
        "[External Katana supervisor]\ncheck the projection writer"
    ]
    assert cli._pending_input.empty()


def test_steer_idle_falls_back_to_normal_next_turn(tmp_path):
    cli = FakeCLI()
    server = LocalSupervisorServer(cli, runtime_dir=tmp_path)

    result = server.dispatch({"action": "steer", "text": "use the local model"})

    assert result["success"] is True
    assert result["mode"] == "queued-next-turn"
    assert cli._pending_input.get_nowait().endswith("use the local model")


def test_interrupt_uses_hard_interrupt_when_running(tmp_path, monkeypatch):
    cli = FakeCLI()
    cli._agent_running = True
    server = LocalSupervisorServer(cli, runtime_dir=tmp_path)
    called = []

    monkeypatch.setattr(
        "agent.interrupt_compat.request_hard_interrupt",
        lambda agent, reason=None: called.append((agent, reason)),
    )

    result = server.dispatch({"action": "interrupt"})

    assert result["success"] is True
    assert result["interrupted"] is True
    assert called == [(cli.agent, "external Katana supervisor")]


def test_interrupt_idle_is_noop(tmp_path):
    cli = FakeCLI()
    server = LocalSupervisorServer(cli, runtime_dir=tmp_path)

    result = server.dispatch({"action": "interrupt"})

    assert result == {"success": True, "interrupted": False, "reason": "idle"}


def test_message_size_is_bounded(tmp_path):
    cli = FakeCLI()
    server = LocalSupervisorServer(cli, runtime_dir=tmp_path, max_message_chars=256)

    with pytest.raises(ValueError, match="exceeds 256 characters"):
        server.dispatch({"action": "message", "text": "x" * 257})
