from __future__ import annotations

import sys
import types

sys.modules.setdefault("fire", types.SimpleNamespace(Fire=lambda *a, **k: None))
sys.modules.setdefault("firecrawl", types.SimpleNamespace(Firecrawl=object))
sys.modules.setdefault("fal_client", types.SimpleNamespace())

import run_agent


def _bootstrap(monkeypatch):
    monkeypatch.setattr(
        run_agent,
        "get_tool_definitions",
        lambda **kwargs: [
            {
                "type": "function",
                "function": {
                    "name": "terminal",
                    "description": "Run shell commands.",
                    "parameters": {"type": "object", "properties": {}},
                },
            }
        ],
    )
    monkeypatch.setattr(run_agent, "check_toolset_requirements", lambda: {})


def _agent(monkeypatch):
    _bootstrap(monkeypatch)
    return run_agent.AIAgent(
        model="gpt-5.6-sol",
        provider="katana-gpt",
        api_mode="codex_responses",
        base_url="https://chatgpt.com/backend-api/codex",
        api_key="codex-test-token",
        quiet_mode=True,
        max_iterations=2,
        skip_context_files=True,
        skip_memory=True,
    )


def test_katana_primary_runtime_snapshot_preserves_visible_provider(monkeypatch):
    agent = _agent(monkeypatch)
    assert agent.provider == "katana-gpt"
    assert agent._primary_runtime["provider"] == "katana-gpt"
    assert agent._primary_runtime["model"] == "gpt-5.6-sol"
    assert agent._primary_runtime["api_mode"] == "codex_responses"


def test_katana_codex_request_injects_identity_into_real_instructions(monkeypatch):
    agent = _agent(monkeypatch)
    kwargs = agent._build_api_kwargs(
        [
            {"role": "system", "content": "Hermes base system policy."},
            {"role": "user", "content": "Ping"},
        ]
    )

    marker = "[HERMES_KATANA_GPT_IDENTITY_V1]"
    assert kwargs["model"] == "gpt-5.6-sol"
    assert marker in kwargs["instructions"]
    assert kwargs["instructions"].count(marker) == 1
    assert "Hermes base system policy." in kwargs["instructions"]
    assert kwargs["input"][0]["role"] == "user"
    assert kwargs["tools"][0]["name"] == "terminal"


def test_katana_codex_request_is_idempotent_across_repeated_builds(monkeypatch):
    agent = _agent(monkeypatch)
    messages = [
        {"role": "system", "content": "Hermes base system policy."},
        {"role": "user", "content": "Ping"},
    ]

    first = agent._build_api_kwargs(messages)
    second = agent._build_api_kwargs(messages)
    marker = "[HERMES_KATANA_GPT_IDENTITY_V1]"

    assert first["instructions"].count(marker) == 1
    assert second["instructions"].count(marker) == 1
    assert messages[0]["content"] == "Hermes base system policy."


def test_katana_codex_credential_refresh_uses_backing_provider(monkeypatch):
    agent = _agent(monkeypatch)
    monkeypatch.setattr(
        "hermes_cli.auth.resolve_codex_runtime_credentials",
        lambda **kwargs: {
            "api_key": "codex-test-token",
            "base_url": "https://chatgpt.com/backend-api/codex",
        }
        if not kwargs.get("force_refresh")
        else {
            "api_key": "refreshed-token",
            "base_url": "https://chatgpt.com/backend-api/codex",
        },
    )
    monkeypatch.setattr(agent, "_replace_primary_openai_client", lambda **kwargs: True)

    assert agent._try_refresh_codex_client_credentials(force=True) is True
    assert agent.provider == "katana-gpt"
    assert agent.api_key == "refreshed-token"
