from __future__ import annotations

import pytest
import providers as provider_registry
from providers.base import ProviderProfile
from providers import (
    get_provider_profile,
    provider_backing_chain,
    provider_model_catalog_provider,
    provider_runtime_provider,
    provider_uses_runtime,
)
from hermes_cli.models import (
    CANONICAL_PROVIDERS,
    get_default_model_for_provider,
    normalize_provider,
    provider_model_ids,
)
from hermes_cli.providers import determine_api_mode, get_label, get_provider


def test_katana_profile_is_discoverable_by_name_and_alias():
    profile = get_provider_profile("katana")
    assert profile is not None
    assert profile.name == "katana-gpt"
    assert normalize_provider("katana_gpt") == "katana-gpt"
    assert profile.auth_type == "delegated"


def test_katana_composition_targets_openai_codex():
    assert provider_backing_chain("katana-gpt") == ("katana-gpt", "openai-codex")
    assert provider_runtime_provider("katana-gpt") == "openai-codex"
    assert provider_model_catalog_provider("katana-gpt") == "openai-codex"
    assert provider_uses_runtime("katana-gpt", "openai-codex") is True


def test_katana_declares_gpt_56_sol_default():
    assert get_default_model_for_provider("katana-gpt") == "gpt-5.6-sol"


def test_katana_appears_once_in_canonical_provider_picker_data():
    katana_rows = [p for p in CANONICAL_PROVIDERS if p.slug == "katana-gpt"]
    assert len(katana_rows) == 1
    assert katana_rows[0].label == "Katana-GPT ⚔️"


def test_katana_model_catalog_borrows_codex_and_promotes_sol(monkeypatch):
    import hermes_cli.auth as auth_mod
    import hermes_cli.codex_models as codex_models

    monkeypatch.setattr(
        auth_mod,
        "resolve_codex_runtime_credentials",
        lambda **kwargs: {"api_key": "test-token"},
    )
    monkeypatch.setattr(
        codex_models,
        "get_codex_model_ids",
        lambda access_token=None: ["gpt-5.6-terra", "gpt-5.5"],
    )

    assert provider_model_ids("katana-gpt") == [
        "gpt-5.6-sol",
        "gpt-5.6-terra",
        "gpt-5.5",
    ]


def test_katana_provider_def_inherits_codex_transport_but_keeps_identity():
    provider = get_provider("katana-gpt")
    assert provider is not None
    assert provider.id == "katana-gpt"
    assert provider.name == "Katana-GPT ⚔️"
    assert provider.transport == "codex_responses"
    assert provider.base_url == "https://chatgpt.com/backend-api/codex"
    assert provider.auth_type == "delegated"
    assert determine_api_mode("katana-gpt", provider.base_url) == "codex_responses"
    assert get_label("katana") == "Katana-GPT ⚔️"


def test_katana_identity_injection_is_pure_and_idempotent():
    profile = get_provider_profile("katana-gpt")
    original = [
        {"role": "system", "content": "Hermes runtime policy."},
        {"role": "user", "content": "hello"},
    ]

    prepared = profile.prepare_messages(original)
    marker = "[HERMES_KATANA_GPT_IDENTITY_V1]"
    assert marker in prepared[0]["content"]
    assert "Hermes runtime policy." in prepared[0]["content"]
    assert original[0]["content"] == "Hermes runtime policy."

    repeated = profile.prepare_messages(prepared)
    assert repeated[0]["content"].count(marker) == 1


def test_katana_identity_adds_system_message_when_missing():
    profile = get_provider_profile("katana-gpt")
    prepared = profile.prepare_messages([{"role": "user", "content": "hello"}])
    assert prepared[0]["role"] == "system"
    assert "[HERMES_KATANA_GPT_IDENTITY_V1]" in prepared[0]["content"]
    assert prepared[1]["role"] == "user"


def test_composed_provider_cycle_fails_closed(monkeypatch):
    monkeypatch.setitem(
        provider_registry._REGISTRY,
        "cycle-a",
        ProviderProfile(name="cycle-a", backing_provider="cycle-b"),
    )
    monkeypatch.setitem(
        provider_registry._REGISTRY,
        "cycle-b",
        ProviderProfile(name="cycle-b", backing_provider="cycle-a"),
    )
    with pytest.raises(ValueError, match=r"cycle-a -> cycle-b -> cycle-a"):
        provider_backing_chain("cycle-a")


def test_valid_multihop_composition_resolves_terminal_runtime(monkeypatch):
    monkeypatch.setitem(
        provider_registry._REGISTRY,
        "layer-a",
        ProviderProfile(name="layer-a", backing_provider="layer-b"),
    )
    monkeypatch.setitem(
        provider_registry._REGISTRY,
        "layer-b",
        ProviderProfile(name="layer-b", backing_provider="openai-codex"),
    )
    assert provider_backing_chain("layer-a") == (
        "layer-a",
        "layer-b",
        "openai-codex",
    )
    assert provider_runtime_provider("layer-a") == "openai-codex"


def test_model_catalog_cycle_fails_closed(monkeypatch):
    monkeypatch.setitem(
        provider_registry._REGISTRY,
        "catalog-a",
        ProviderProfile(name="catalog-a", model_catalog_provider="catalog-b"),
    )
    monkeypatch.setitem(
        provider_registry._REGISTRY,
        "catalog-b",
        ProviderProfile(name="catalog-b", model_catalog_provider="catalog-a"),
    )
    with pytest.raises(ValueError, match=r"catalog-a -> catalog-b -> catalog-a"):
        provider_model_catalog_provider("catalog-a")
