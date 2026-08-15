from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from hermes_cli import main as main_mod
from hermes_cli.oneshot import _load_resume_state


class FakeSessionDB:
    def __init__(self):
        self.reopened = None
        self.safety_checked = None
        self.sessions = {
            "root": {"id": "root", "model": "qwen3.5-9b"},
            "tip": {"id": "tip", "model": "qwen3.5-9b"},
        }

    def get_session(self, session_id):
        return self.sessions.get(session_id)

    def resolve_session_by_title(self, title):
        return "root" if title == "Katana Session" else None

    def resolve_resume_session_id(self, session_id):
        return "tip" if session_id == "root" else session_id

    def assert_resume_safe(self, session_id):
        self.safety_checked = session_id

    def get_resume_conversations(self, session_id):
        assert session_id == "tip"
        model_history = [
            {"role": "session_meta", "content": "ignored"},
            {"role": "user", "content": "remember KATANA_NONCE"},
            {"role": "assistant", "content": "ok"},
        ]
        return model_history, list(model_history)

    def reopen_session(self, session_id):
        self.reopened = session_id


def test_load_resume_state_follows_tip_and_filters_session_meta():
    db = FakeSessionDB()

    session_id, history, meta = _load_resume_state(db, "root")

    assert session_id == "tip"
    assert meta == {"id": "tip", "model": "qwen3.5-9b"}
    assert history == [
        {"role": "user", "content": "remember KATANA_NONCE"},
        {"role": "assistant", "content": "ok"},
    ]
    assert db.safety_checked == "tip"
    assert db.reopened == "tip"


def test_load_resume_state_accepts_title():
    db = FakeSessionDB()

    session_id, history, _meta = _load_resume_state(db, "Katana Session")

    assert session_id == "tip"
    assert history[-1]["content"] == "ok"


def test_load_resume_state_rejects_missing_session():
    db = FakeSessionDB()

    with pytest.raises(RuntimeError, match="session not found"):
        _load_resume_state(db, "missing")


def test_resolve_oneshot_resume_latest_uses_cli_mru(monkeypatch):
    args = SimpleNamespace(resume="latest", continue_last=None)
    monkeypatch.setattr(main_mod, "_resolve_last_session", lambda source="cli": "sid-latest")
    monkeypatch.setattr(main_mod, "_resolve_session_by_name_or_id", lambda value: value)

    assert main_mod._resolve_oneshot_resume(args) == "sid-latest"


def test_resolve_oneshot_continue_title(monkeypatch):
    args = SimpleNamespace(resume=None, continue_last="named session")
    monkeypatch.setattr(
        main_mod,
        "_resolve_session_by_name_or_id",
        lambda value: "sid-named" if value == "named session" else None,
    )

    assert main_mod._resolve_oneshot_resume(args) == "sid-named"


def test_run_and_exit_oneshot_forwards_resume(monkeypatch):
    captured = {}

    def fake_run_oneshot(prompt, **kwargs):
        captured["prompt"] = prompt
        captured.update(kwargs)
        return 0

    monkeypatch.setattr("hermes_cli.oneshot.run_oneshot", fake_run_oneshot)
    monkeypatch.setattr(main_mod, "_cleanup_oneshot_runtime", lambda: None)

    def fake_exit(rc):
        raise RuntimeError(f"exit:{rc}")

    monkeypatch.setattr(main_mod, "_exit_after_oneshot", fake_exit)

    with pytest.raises(RuntimeError, match="exit:0"):
        main_mod._run_and_exit_oneshot(
            "hello",
            model=None,
            provider=None,
            toolsets=None,
            usage_file=None,
            resume="sid-123",
        )

    assert captured["prompt"] == "hello"
    assert captured["resume"] == "sid-123"
