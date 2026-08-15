"""Katana-GPT composed provider.

Katana-GPT keeps a distinct Hermes-visible provider identity while delegating
runtime, OAuth credentials, and model discovery to ``openai-codex``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from providers import register_provider
from providers.base import ProviderProfile

_IDENTITY_MARKER = "[HERMES_KATANA_GPT_IDENTITY_V1]"
_IDENTITY_PATH = Path(__file__).with_name("identity.md")


def _identity_text() -> str:
    return f"{_IDENTITY_MARKER}\n{_IDENTITY_PATH.read_text(encoding='utf-8').strip()}"


class KatanaGPTProfile(ProviderProfile):
    """Virtual Katana identity backed by the user's OpenAI Codex OAuth route."""

    def prepare_messages(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Inject Katana's stable identity exactly once into the system prompt."""
        identity = _identity_text()
        # Do not mutate the conversation list owned by the caller.
        prepared = [dict(message) for message in messages]

        for index, message in enumerate(prepared):
            if message.get("role") != "system":
                continue
            content = message.get("content")
            if isinstance(content, str):
                if _IDENTITY_MARKER in content:
                    return prepared
                prepared[index]["content"] = f"{identity}\n\n{content}" if content else identity
                return prepared
            if isinstance(content, list):
                # Preserve multimodal/list content while prepending a standard
                # OpenAI text part. Search serialized text parts for the marker
                # first so repeated preprocessing remains idempotent.
                if any(
                    isinstance(part, dict)
                    and _IDENTITY_MARKER in str(part.get("text") or part.get("content") or "")
                    for part in content
                ):
                    return prepared
                prepared[index]["content"] = [{"type": "text", "text": identity}, *content]
                return prepared
            prepared[index]["content"] = identity
            return prepared

        # Hermes normally supplies a system message. Keep the provider robust
        # for lightweight/direct AIAgent callers that do not.
        prepared.insert(0, {"role": "system", "content": identity})
        return prepared


katana_gpt = KatanaGPTProfile(
    name="katana-gpt",
    aliases=("katana", "katana_gpt"),
    api_mode="codex_responses",
    display_name="Katana-GPT ⚔️",
    description="Katana identity backed by GPT-5.6 through ChatGPT / Codex OAuth",
    auth_type="delegated",
    supports_health_check=False,
    backing_provider="openai-codex",
    model_catalog_provider="openai-codex",
    default_model="gpt-5.6-sol",
)

register_provider(katana_gpt)
