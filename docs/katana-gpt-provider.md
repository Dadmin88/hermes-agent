# Katana-GPT Provider

> **Personal fork only.** This provider and the composed-provider changes that support it belong to `Dadmin88/hermes-agent`. Do not push, PR, or otherwise upstream this work to `NousResearch/hermes-agent` unless that distribution rule is explicitly changed later.

Katana-GPT is a first-class Hermes model-provider identity backed by the existing OpenAI Codex / ChatGPT OAuth runtime.

## What it does

Selecting Katana-GPT gives Hermes a distinct provider identity while reusing the OpenAI Codex transport, credential pool, refresh flow, and model catalog.

```text
provider:            katana-gpt
backing provider:    openai-codex
credential provider: openai-codex
model provider:      openai-codex
preferred model:     gpt-5.6-sol
API mode:            codex_responses
```

Katana-GPT also adds a small stable engineering/operator identity to the actual Responses API `instructions`. Hermes remains authoritative for tool access, approvals, profile/project context, memory, Fleet authorization, and the current conversation.

## Authentication

Katana-GPT does not own credentials. Authenticate OpenAI Codex once:

```bash
hermes auth add openai-codex
```

You can also run:

```bash
hermes auth add katana-gpt
```

Hermes will explain that Katana delegates authentication and will add the credential to the `openai-codex` pool. No `katana-gpt` token store is created.

## Selecting Katana-GPT

Use the normal provider/model UI and choose **Katana-GPT ⚔️**. A profile can also declare it directly:

```yaml
model:
  provider: katana-gpt
  default: gpt-5.6-sol
```

Aliases `katana` and `katana_gpt` resolve to the canonical `katana-gpt` provider.

## Profiles, sessions, and subagents

The visible provider remains `katana-gpt` in the agent runtime and primary session snapshot. Named profiles resolve their backing OpenAI Codex runtime at startup rather than serializing a duplicate credential. Subagents inherit Katana as the visible provider when they inherit the parent model/runtime.

Model switching can move to or from Katana through the normal Hermes switching pipeline. When a fallback genuinely changes to another provider, Hermes reports that provider honestly rather than continuing to label it Katana.

## Identity and context

The packaged Katana identity is intentionally small and contains no user-specific memory. Dynamic context continues to come from Hermes:

1. Hermes runtime/safety policy
2. Katana stable identity
3. active profile/project instructions
4. Hermes memory/user context
5. conversation history
6. current user turn

The identity transformation is idempotent. Repeated request building and session resume do not duplicate the Katana marker/instructions.

## Failures and limits

Diagnostics keep the selected provider visible and show the backing provider when useful, for example:

```text
Provider: katana-gpt  Model: gpt-5.6-sol
↳ Backing provider: openai-codex
Endpoint: https://chatgpt.com/backend-api/codex
```

OpenAI Codex usage limits, authentication failures, model availability, network errors, and stalled streams remain backing-provider failures. Katana does not bypass account entitlement or quota.

## What Katana-GPT is not

Katana-GPT is not a reverse call into a live ChatGPT conversation, a copy of ChatGPT's hidden product instructions, a second model server, a separate OAuth identity, or a permission bypass. It is a Hermes-composed provider identity over an existing inference backend.

## Developer architecture

The reusable composition fields live on `ProviderProfile`:

```python
backing_provider: str = ""
model_catalog_provider: str = ""
default_model: str = ""
```

Runtime and catalog chains are bounded and cycle-safe. Helpers in `providers` expose terminal backing/catalog providers so downstream code can ask for the semantic capability it needs instead of hardcoding Katana alongside OpenAI Codex.

See `website/docs/developer-guide/model-provider-plugin.md` and `providers/README.md` for the generic composed-provider contract.
