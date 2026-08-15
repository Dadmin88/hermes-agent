from __future__ import annotations

from types import SimpleNamespace

import hermes_cli.runtime_provider as runtime_provider
from hermes_cli import auth_commands
from hermes_cli import model_switch as model_switch_mod


class _EmptyPool:
    def has_credentials(self):
        return False


def test_runtime_resolution_keeps_katana_visible_and_borrows_codex(monkeypatch):
    monkeypatch.setattr(runtime_provider, "load_pool", lambda provider: _EmptyPool())
    monkeypatch.setattr(runtime_provider, "_get_model_config", lambda: {})
    monkeypatch.setattr(
        runtime_provider,
        "resolve_codex_runtime_credentials",
        lambda *args, **kwargs: {
            "api_key": "codex-test-token",
            "base_url": "https://chatgpt.com/backend-api/codex",
            "source": "test-codex",
            "last_refresh": 123,
        },
    )

    resolved = runtime_provider.resolve_runtime_provider(
        requested="katana-gpt",
        target_model="gpt-5.6-sol",
    )

    assert resolved["provider"] == "katana-gpt"
    assert resolved["backing_provider"] == "openai-codex"
    assert resolved["credential_provider"] == "openai-codex"
    assert resolved["model_provider"] == "openai-codex"
    assert resolved["api_mode"] == "codex_responses"
    assert resolved["base_url"] == "https://chatgpt.com/backend-api/codex"
    assert resolved["api_key"] == "codex-test-token"
    assert resolved["requested_provider"] == "katana-gpt"
    assert resolved["source"].startswith("composed:katana-gpt->")


def test_profile_config_startup_resolves_katana_without_explicit_provider(monkeypatch):
    monkeypatch.setattr(runtime_provider, "load_pool", lambda provider: _EmptyPool())
    monkeypatch.setattr(
        runtime_provider,
        "_get_model_config",
        lambda: {"provider": "katana-gpt", "default": "gpt-5.6-sol"},
    )
    monkeypatch.setattr(
        runtime_provider,
        "resolve_codex_runtime_credentials",
        lambda *args, **kwargs: {
            "api_key": "codex-test-token",
            "base_url": "https://chatgpt.com/backend-api/codex",
            "source": "profile-test",
            "last_refresh": 456,
        },
    )

    resolved = runtime_provider.resolve_runtime_provider(
        requested=None,
        target_model="gpt-5.6-sol",
    )

    assert resolved["provider"] == "katana-gpt"
    assert resolved["backing_provider"] == "openai-codex"
    assert resolved["credential_provider"] == "openai-codex"
    assert resolved["api_mode"] == "codex_responses"


def test_auth_add_redirects_katana_to_codex_without_katana_pool(monkeypatch, capsys):
    calls = []

    class FakePool:
        def __init__(self):
            self._entries = []

        def entries(self):
            return list(self._entries)

        def add_entry(self, entry):
            self._entries.append(entry)

    pools = {}

    def fake_load_pool(provider):
        calls.append(provider)
        return pools.setdefault(provider, FakePool())

    monkeypatch.setattr(auth_commands, "load_pool", fake_load_pool)
    monkeypatch.setattr(
        auth_commands.auth_mod,
        "_codex_device_code_login",
        lambda: {
            "tokens": {"access_token": "token"},
            "last_refresh": 1,
        },
    )
    monkeypatch.setattr(
        auth_commands.auth_mod,
        "mark_provider_active_if_unset",
        lambda provider: None,
    )

    # No Katana pool should ever be requested; the backing Codex pool owns the
    # newly added credential.
    args = SimpleNamespace(
        provider="katana-gpt",
        auth_type="oauth",
        label="test",
        api_key=None,
        timeout=None,
        no_browser=True,
        manual_paste=False,
    )
    auth_commands.auth_add_command(args)

    assert calls and set(calls) == {"openai-codex"}
    output = capsys.readouterr().out
    assert "delegates authentication to openai-codex" in output


def test_explicit_model_switch_keeps_katana_provider(monkeypatch):
    import hermes_cli.models as models_mod
    import hermes_cli.runtime_provider as runtime_mod

    monkeypatch.setattr(
        runtime_mod,
        "resolve_runtime_provider",
        lambda **kwargs: {
            "provider": "katana-gpt",
            "backing_provider": "openai-codex",
            "credential_provider": "openai-codex",
            "model_provider": "openai-codex",
            "api_mode": "codex_responses",
            "base_url": "https://chatgpt.com/backend-api/codex",
            "api_key": "codex-test-token",
        },
    )
    monkeypatch.setattr(
        models_mod,
        "validate_requested_model",
        lambda *args, **kwargs: {
            "accepted": True,
            "persist": True,
            "recognized": True,
            "message": "",
        },
    )

    result = model_switch_mod.switch_model(
        "gpt-5.6-sol",
        current_provider="openrouter",
        current_model="openai/gpt-5.5",
        explicit_provider="katana-gpt",
    )

    assert result.success is True
    assert result.target_provider == "katana-gpt"
    assert result.new_model == "gpt-5.6-sol"
    assert result.api_mode == "codex_responses"
    assert result.base_url == "https://chatgpt.com/backend-api/codex"
