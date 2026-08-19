from __future__ import annotations

import sqlite3
from pathlib import Path
from unittest.mock import MagicMock

from agent.context_compressor import _redact_compaction_text
from agent.memory_manager import MemoryManager
from agent.monitoring.redaction import redact_for_export
from gateway.config import PlatformConfig
from gateway.platforms.api_server import APIServerAdapter
from hermes_state import SessionDB

FAKE_KEY = "sk-phase13-example-12345678901234567890"


def test_transcript_and_fts_never_receive_raw_value(tmp_path: Path) -> None:
    path = tmp_path / "state.db"
    db = SessionDB(path)
    db.create_session("phase13", "test")
    db.append_message(
        "phase13",
        "user",
        content=f"please use {FAKE_KEY}",
        tool_calls=[
            {"function": {"name": "demo", "arguments": f'{{"key":"{FAKE_KEY}"}}'}}
        ],
        api_content=f"wire {FAKE_KEY}",
        display_metadata={"note": FAKE_KEY},
    )
    rows = db.get_messages("phase13")
    assert len(rows) == 1
    assert FAKE_KEY not in str(rows[0])

    connection = sqlite3.connect(path)
    try:
        stored = "\n".join(
            str(value)
            for row in connection.execute(
                "SELECT content, tool_calls, api_content, display_metadata FROM messages"
            )
            for value in row
        )
        assert FAKE_KEY not in stored
        # FTS is trigger-fed from messages, so raw intercepted material must not
        # be queryable in any enabled FTS table either.
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'messages_fts%'"
            )
        }
        for table in tables:
            if table.endswith(("_data", "_idx", "_docsize", "_config")):
                continue
            try:
                match = connection.execute(
                    f'SELECT count(*) FROM "{table}" WHERE "{table}" MATCH ?',
                    (FAKE_KEY,),
                ).fetchone()[0]
            except sqlite3.DatabaseError:
                continue
            assert match == 0

        db.replace_messages(
            "phase13",
            [{"role": "user", "content": f"replacement {FAKE_KEY}"}],
        )
        replaced = db.get_messages("phase13")
        assert FAKE_KEY not in str(replaced)
    finally:
        connection.close()
        db.close()


def test_summary_source_blocks_sensitive_body_but_preserves_redacted_context() -> None:
    result = _redact_compaction_text(f"important context {FAKE_KEY}")
    assert FAKE_KEY not in result
    assert "important context" in result
    assert "***" in result or "redacted" in result.lower()


def test_external_memory_sync_blocks_before_provider_indexing() -> None:
    manager = MemoryManager()
    provider = MagicMock()
    provider.name = "fixture"
    manager._providers.append(provider)
    manager._submit_background = lambda fn, kind="write": fn()

    manager.sync_all(
        f"user text {FAKE_KEY}",
        "assistant text",
        session_id="phase13",
    )
    provider.sync_turn.assert_not_called()

    manager.sync_all("safe user text", "safe assistant text", session_id="phase13")
    provider.sync_turn.assert_called_once()


def test_pollable_run_evidence_is_redacted() -> None:
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={}))
    status = adapter._set_run_status(
        "run-phase13",
        "completed",
        output=f"tool returned {FAKE_KEY}",
        evidence={"detail": FAKE_KEY},
    )
    assert FAKE_KEY not in str(status)
    assert status["status"] == "completed"


def test_monitoring_export_uses_same_interception_boundary() -> None:
    text = redact_for_export(f"failure Authorization: Bearer {FAKE_KEY}")
    assert text is not None
    assert FAKE_KEY not in text
    assert "failure" in text
