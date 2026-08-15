# Katana-GPT as a Hermes Model Provider

Status: IMPLEMENTED / TEST-GREEN — successful live text generation is externally blocked by the current ChatGPT/Codex account usage limit
Branch: `feat/katana-gpt-provider`
Worktree: `/home/kyle/Create/worktrees/hermes-agent--katana-gpt-provider`
Baseline: personal fork `Dadmin88/hermes-agent` `main` at `9cb456a9b`
Distribution: PERSONAL FORK ONLY. Never push, PR, or otherwise upstream this feature to `NousResearch/hermes-agent`.

## Implementation closeout — 2026-08-14

Katana-GPT V1 is implemented on the current personal-fork codebase. The completed implementation includes:

- generic composed-provider metadata (`backing_provider`, `model_catalog_provider`, `default_model`);
- bounded, cycle-safe runtime and model-catalog delegation helpers;
- first-class `katana-gpt` provider plugin with `katana` / `katana_gpt` aliases;
- stable packaged Katana identity contract with idempotent system-message injection;
- visible-provider preservation while runtime, OAuth credentials, refresh, and model discovery delegate to `openai-codex`;
- no Katana credential store: `hermes auth add katana-gpt` redirects to the Codex pool;
- Codex Responses provider-message preprocessing so Katana reaches the real `instructions` payload exactly once;
- Katana-aware model defaults/catalog ordering with `gpt-5.6-sol` preferred;
- picker/setup integration on the fork's current `model_setup_flows.py` architecture;
- model-switch, session-primary-runtime, profile-startup, subagent inheritance, diagnostics, TUI/ACP and provider-list coverage;
- composed-provider developer docs and Katana user docs;
- package-data inclusion for `identity.md` in sealed wheels.

Validation on the rebased fork:

- Katana focused routing/identity/auth tests: `20 passed`;
- provider/Codex/setup regression bundle: `255 passed`;
- delegation + TUI + ACP + Codex auth/provider persistence/config bundle: `668 passed`;
- Python compile: passed;
- Ruff on all touched Python surfaces: passed;
- `git diff --check`: passed.

Live OAuth-backed proof reached the real backend on 2026-08-14 at 21:39 EDT:

```text
provider=katana-gpt
model=gpt-5.6-sol
endpoint=https://chatgpt.com/backend-api/codex
result=HTTP 429 usage_limit_reached
```

The backend returned an account-level ChatGPT/Codex usage-limit response (`plan_type=prolite`), currently reporting a reset around 2026-08-19 23:40 EDT. Therefore the provider/runtime/auth route is proven live; only a successful final text response cannot be produced until the external account allowance resets or a different entitled Codex account is used. Do not bypass or falsify this gate.

The historical phased plan below is retained as design/evidence context. This closeout section is the current source of truth for V1 implementation state.

## 1. Mission

Make `katana-gpt` a first-class, selectable Hermes model provider that:

- presents a stable Katana identity to users, profiles, Agency, Fleet, CLI, TUI, Desktop, gateways, and delegated agents;
- uses the existing OpenAI Codex / ChatGPT OAuth transport and account entitlement instead of creating a second authentication flow;
- defaults to the GPT-5.6 family, with `gpt-5.6-sol` as the primary target when the backing account exposes it;
- preserves Hermes' own tools, memory, profile context, project context, approvals, and operator policies;
- can be used anywhere Hermes accepts a provider/model pair;
- remains a clean reusable example of a composed/virtual provider rather than a one-off hardcoded alias.

The target user experience is:

```yaml
model:
  provider: katana-gpt
  default: gpt-5.6-sol
```

and in pickers/status:

```text
Katana-GPT ⚔️
GPT-5.6 via ChatGPT / Codex OAuth
```

## 2. What Katana-GPT is and is not

### It is

A Hermes-visible provider identity backed by another Hermes provider for low-level runtime concerns.

Conceptually:

```text
Hermes session/profile
       |
       v
katana-gpt                       visible provider identity
       |
       +-- Katana base identity/instructions
       +-- Katana provider policy
       +-- Hermes project/profile/memory context
       |
       v
openai-codex                     backing provider
       |
       +-- OAuth credential pool
       +-- refresh/rotation
       +-- Codex Responses transport
       +-- live model catalog
       |
       v
chatgpt.com/backend-api/codex
       |
       v
GPT-5.6 Sol / other entitled Codex models
```

### It is not

- a reverse MCP call from Hermes into the current ChatGPT conversation;
- a copy of ChatGPT's hidden system prompt or product harness;
- a second storage location for OpenAI access/refresh credentials;
- a hardcoded copy of Kyle/user memory;
- a tool-permission bypass;
- a separate model server;
- a thin display alias that collapses back to `provider=openai-codex` and loses Katana identity.

## 3. Core invariants

1. **Visible provider identity stays `katana-gpt`.** Metrics, status, session config, model picker, Fleet/Agency routing, and user-facing labels must not silently collapse to `openai-codex`.
2. **Backing runtime stays explicit.** The runtime must know the backing provider is `openai-codex` so refresh, retry, model normalization, transport quirks, and catalog behavior remain correct.
3. **No credential duplication.** `katana-gpt` never stores its own OAuth token set. It delegates to the existing `openai-codex` credential source/pool.
4. **No privilege escalation.** Katana's identity prompt cannot grant tools or permissions. Hermes toolsets, approvals, operator mode, plugin policy, and profile config remain authoritative.
5. **No personal data in provider source.** User/project-specific memory continues to come from Hermes context/memory/profile systems.
6. **Prompt injection is deterministic and idempotent.** Katana identity is inserted exactly once per request and never recursively duplicated across turns/resumes.
7. **Explicit user/system context survives.** Katana instructions augment Hermes' system prompt; they do not erase caller-provided system instructions.
8. **Delegation cycles fail closed.** Provider A -> B -> A must be detected and rejected before runtime construction.
9. **Backing-provider failures stay legible.** Missing auth, quota exhaustion, unsupported model, or transport incompatibility must report Katana as the selected provider and OpenAI Codex as the failing backing provider.
10. **Normal `openai-codex` behavior must not regress.** Existing users who never select Katana-GPT should observe no behavioral change.

## 4. Baseline findings

- Hermes provider profiles are registered from `plugins/model-providers/<name>/` through `providers.ProviderProfile`.
- `ProviderProfile` currently has provider identity, API mode, auth type, endpoint, model fallback, headers, and request hooks, but no backing/delegated-provider abstraction.
- The provider registry auto-wires API-key profiles broadly, while OAuth providers such as `openai-codex` still have bespoke auth/runtime paths.
- `openai-codex` uses `api_mode="codex_responses"`, `auth_type="oauth_external"`, and `https://chatgpt.com/backend-api/codex`.
- `hermes_cli.runtime_provider.resolve_runtime_provider()` ultimately returns the provider label that `cli.py` assigns to `self.provider`; therefore returning `openai-codex` for Katana would destroy the visible Katana provider identity.
- The Codex Responses transport already extracts the first `system` message into Responses API `instructions`.
- The normal chat-completions profile path calls `ProviderProfile.prepare_messages()`, but the Codex Responses path does not currently invoke the provider profile message hook. This is the clean insertion point to generalize.
- `hermes_cli.models.provider_model_ids("openai-codex")` already uses the existing Codex OAuth credential resolver and live Codex model catalog.
- Local Hermes profiles already reference `gpt-5.6-sol` on `openai-codex`.
- Current live failures observed for `gpt-5.6-sol` include account usage-limit HTTP 429 responses. Older logs also contain no-first-byte/no-event stalls, so transport compatibility and quota failures must be distinguished during validation.
- The canonical Hermes checkout currently has unrelated modifications. This feature therefore lives in a dedicated clean worktree/branch.

## 5. Proposed generic provider-composition contract

Add the minimum generic concepts needed for Katana without creating a large inheritance framework.

Proposed `ProviderProfile` additions:

```python
@dataclass
class ProviderProfile:
    ...
    backing_provider: str = ""
    model_catalog_provider: str = ""
    default_model: str = ""
```

Semantics:

- `backing_provider`: provider whose runtime/auth/transport should be resolved first.
- `model_catalog_provider`: provider whose model list should be reused. Empty means `backing_provider` when set, otherwise self.
- `default_model`: provider-preferred default. Empty preserves current fallback behavior.

`katana-gpt` profile:

```python
KatanaGPTProfile(
    name="katana-gpt",
    display_name="Katana-GPT",
    description="Katana identity backed by GPT-5.6 through ChatGPT / Codex OAuth",
    auth_type="delegated",
    backing_provider="openai-codex",
    model_catalog_provider="openai-codex",
    default_model="gpt-5.6-sol",
    api_mode="codex_responses",
)
```

Runtime result shape:

```python
{
    "provider": "katana-gpt",           # visible/provider-profile identity
    "backing_provider": "openai-codex",# runtime family
    "credential_provider": "openai-codex",
    "model_provider": "openai-codex",
    "api_mode": "codex_responses",
    "base_url": "https://chatgpt.com/backend-api/codex",
    "api_key": "<resolved at runtime>",
    "credential_pool": "<existing Codex pool if applicable>",
    "source": "delegated:katana-gpt->openai-codex",
}
```

The exact field count may be reduced during implementation if `backing_provider` can safely serve all three roles, but the code must preserve the conceptual distinction between **visible provider** and **runtime/backing provider**.

---

# PHASE 0 — Isolate, baseline, and lock success criteria

Status: IN PROGRESS

## Task 0.1 — Dedicated worktree

- [x] Verify canonical repo and current branch.
- [x] Confirm unrelated dirty changes exist in canonical checkout.
- [x] Create `/home/kyle/Create/worktrees/hermes-agent--katana-gpt-provider`.
- [x] Create branch `feat/katana-gpt-provider` from current HEAD.
- [x] Confirm new worktree is clean.

## Task 0.2 — Record architecture surfaces

- [x] Inspect `providers/base.py` and provider registry.
- [x] Inspect `plugins/model-providers/openai-codex/`.
- [x] Inspect `hermes_cli/auth.py` OAuth special cases.
- [x] Inspect `hermes_cli/runtime_provider.py` runtime resolution.
- [x] Inspect `hermes_cli/models.py` provider/model discovery.
- [x] Inspect Codex Responses transport/instruction extraction.
- [x] Map all direct `provider == "openai-codex"` checks and classify each as:
  - visible identity behavior;
  - backing transport behavior;
  - auth/refresh behavior;
  - model-catalog behavior;
  - diagnostics only.
- [ ] Map all persisted session/config fields that assume provider identity equals transport provider.

### Direct OpenAI-Codex check classification

Initial source audit found these load-bearing classes of checks:

| Surface | Current check | Classification | Katana action |
|---|---|---|---|
| `run_agent.py::_codex_silent_hang_hint()` | `self.provider == "openai-codex"` OR Codex URL | transport diagnostics | URL detection already covers Katana on the Codex backend; keep provider-specific wording honest. |
| `run_agent.py::_try_refresh_codex_client_credentials()` | provider in `{openai-codex, xai-oauth}` plus explicit branches | credential/auth recovery | MUST become backing/credential-provider aware so Katana refreshes Codex credentials without changing visible provider. |
| `hermes_cli/runtime_provider.py::_resolve_runtime_from_pool_entry()` | `provider == "openai-codex"` | backing transport construction | Leave behavior on the backing provider resolver; Katana should call this resolver first, then wrap/re-label the result. |
| `hermes_cli/runtime_provider.py::_resolve_explicit_runtime()` and final OAuth branch | `provider == "openai-codex"` | backing auth/runtime construction | Same: resolve backing Codex runtime unchanged, then compose Katana around it. |
| `_maybe_apply_codex_app_server_runtime()` | provider in `{openai, openai-codex}` | transport/runtime-family feature | V1 Katana should not automatically opt into Codex app-server unless composition explicitly declares support; decide separately. |
| `cli.py::_normalize_model_for_provider()` | `resolved_provider == "openai-codex"` | model-provider semantics | MUST use the runtime/model backing provider for validation while preserving visible `katana-gpt`. |
| `hermes_cli/models.py` Codex branches | normalized provider `openai-codex` | model catalog | Katana delegates catalog/default semantics rather than duplicating the list. |
| `hermes_cli/main.py` setup/model picker branches | selected provider `openai-codex` | bespoke OAuth picker UX | Katana needs delegated-provider UX that verifies backing auth instead of launching a new login. |
| `hermes_cli/auth.py` Codex state/pool functions | literal `openai-codex` | credential storage/ownership | DO NOT generalize storage keys to Katana. Katana intentionally keeps these owned by `openai-codex`. |
| image-generation `openai-codex` plugin | provider literal | separate image provider | Out of scope. Katana model-provider selection must not silently rename or clone the image-gen provider. |

The important implementation consequence is that most Codex-specific code should **not** be rewritten to understand Katana. The backing resolver should continue to run as OpenAI Codex. Only the boundary where runtime identity is wrapped, model semantics are chosen, and refresh behavior is dispatched needs composition awareness.

## Task 0.3 — Establish acceptance tests before implementation

Define the non-negotiable V1 proof:

1. `get_provider_profile("katana-gpt")` returns a real profile.
2. Hermes model/provider picker shows Katana-GPT.
3. Selecting Katana-GPT does not create new credentials.
4. Runtime resolution produces visible `katana-gpt` + backing `openai-codex`.
5. `gpt-5.6-sol` is the default when present/allowed.
6. Katana identity reaches Responses API `instructions` exactly once.
7. Existing Hermes system/project/profile context remains present.
8. Tool calls still execute through normal Hermes tool policy.
9. An expired Codex access token refreshes through the existing Codex path while the session remains `provider=katana-gpt`.
10. Quota/429 errors identify both Katana-GPT and its OpenAI Codex backing provider.
11. Session resume preserves `katana-gpt`.
12. Switching away and back works without process restart.
13. Existing `openai-codex` tests remain green.

### Phase 0 gate

No implementation begins until the direct-provider checks are classified and the runtime identity/backing-provider contract is settled.

---

# PHASE 1 — Add provider composition primitives

Goal: introduce the smallest reusable core abstraction that lets a provider keep its own identity while delegating runtime concerns.

## Task 1.1 — Extend `ProviderProfile`

Files:

- `providers/base.py`
- `providers/README.md`
- provider profile tests

Work:

- [ ] Add `backing_provider`.
- [ ] Add `model_catalog_provider` or derive it safely from `backing_provider`.
- [ ] Add `default_model` if needed for first-class defaults.
- [ ] Document `auth_type="delegated"` semantics.
- [ ] Keep defaults empty so every existing provider behaves identically.
- [ ] Add validation/helper methods such as:
  - `get_backing_provider()`;
  - `get_model_catalog_provider()`;
  - optional `is_composed` property.

Tests:

- [ ] legacy profiles instantiate unchanged;
- [ ] composed profile returns expected backing/catalog providers;
- [ ] blank fields resolve to existing behavior;
- [ ] malformed self-delegation is rejected or caught by runtime cycle detection.

## Task 1.2 — Add delegation-cycle protection

Files:

- `hermes_cli/runtime_provider.py`

Work:

- [ ] Resolve backing providers with an explicit visited stack/set.
- [ ] Reject self-delegation and A -> B -> A loops.
- [ ] Bound delegation depth even if cycles are somehow missed.
- [ ] Error should show the delegation chain.

Tests:

- [ ] direct self-cycle;
- [ ] two-provider cycle;
- [ ] valid one-hop delegate;
- [ ] valid multi-hop delegate if we choose to support it.

### Phase 1 gate

A synthetic test provider can resolve through a backing provider while retaining its own visible provider slug.

---

# PHASE 2 — Create the Katana-GPT provider plugin

Goal: make Katana exist as a real provider profile before giving it identity behavior.

## Task 2.1 — Plugin skeleton

Create:

- `plugins/model-providers/katana-gpt/__init__.py`
- `plugins/model-providers/katana-gpt/plugin.yaml`
- `plugins/model-providers/katana-gpt/identity.md` or equivalent packaged constant/module

Profile metadata:

- slug: `katana-gpt`
- aliases: initially `katana`, optionally `katana_gpt`
- display name: `Katana-GPT`
- backing provider: `openai-codex`
- model catalog provider: `openai-codex`
- preferred model: `gpt-5.6-sol`
- API mode: delegated/Codex Responses
- auth type: `delegated`
- health check: delegated to backing provider, not probed independently

## Task 2.2 — Discovery tests

- [ ] plugin loads lazily;
- [ ] canonical slug resolves;
- [ ] aliases resolve;
- [ ] no collision with existing provider aliases;
- [ ] user plugin override semantics continue to work;
- [ ] Katana appears once, not once per alias.

## Task 2.3 — Packaging test

- [ ] Ensure `plugin.yaml` and identity asset are included in editable/install/wheel paths used by Hermes.
- [ ] Avoid loading identity from a source-only path that disappears after install/update.

### Phase 2 gate

`get_provider_profile("katana-gpt")` and `get_provider_profile("katana")` return the Katana profile from a clean install-style import.

---

# PHASE 3 — Delegated runtime and OAuth credential reuse

Goal: make `katana-gpt` actually run through the current OpenAI Codex OAuth stack while staying visibly Katana.

## Task 3.1 — Runtime delegation

Files likely involved:

- `hermes_cli/runtime_provider.py`
- `hermes_cli/auth.py` only where provider validation/availability requires it
- tests under `tests/hermes_cli/`

Algorithm:

1. Resolve requested provider `katana-gpt`.
2. Load Katana provider profile.
3. Detect `backing_provider="openai-codex"`.
4. Resolve OpenAI Codex runtime normally.
5. Preserve returned key/base URL/API mode/pool/refresh metadata.
6. Re-label the visible runtime provider as `katana-gpt`.
7. Attach explicit `backing_provider` / `credential_provider` metadata.

## Task 3.2 — Provider validation

Current `resolve_provider()` primarily knows the legacy provider registry plus aliases. Update it so a registered delegated provider is valid even though it owns no API key/OAuth flow.

Requirements:

- [ ] `katana-gpt` is accepted as an explicit provider.
- [ ] it is not auto-selected merely because OpenAI Codex credentials exist unless we deliberately decide that later;
- [ ] `openai-codex` remains independently selectable;
- [ ] `hermes auth add katana-gpt` should not launch a second login flow. Prefer a clear message: Katana-GPT uses OpenAI Codex credentials; authenticate `openai-codex`.

## Task 3.3 — Refresh/recovery routing

Audit and adapt:

- `run_agent.py::_try_refresh_codex_client_credentials()`;
- credential-pool recovery paths;
- reactive 401 handling;
- model-switch credential refresh;
- gateway/TUI agent rebuild logic.

Required behavior:

```text
selected provider = katana-gpt
credential provider = openai-codex
401/expiry occurs
        -> refresh openai-codex
        -> rebuild client
        -> remain selected as katana-gpt
```

Tests:

- [ ] initial token resolution;
- [ ] expiring token refresh;
- [ ] forced refresh after auth failure;
- [ ] multi-credential pool rotation;
- [ ] backing auth missing;
- [ ] backing account rate-limited;
- [ ] no credential values appear in logs/errors.

### Phase 3 gate

A unit/integration test can execute a mocked Codex Responses request through `provider=katana-gpt` using mocked `openai-codex` credentials, then refresh those credentials without the visible provider changing.

---

# PHASE 4 — Model catalog, defaults, and picker behavior

Goal: make Katana feel native everywhere users choose a model.

## Task 4.1 — Delegated model catalog

Files:

- `hermes_cli/models.py`

Behavior:

- `provider_model_ids("katana-gpt")` delegates to the OpenAI Codex catalog.
- Live account availability remains authoritative when reachable.
- Static fallback is inherited from Codex rather than duplicated.
- Katana-specific ordering may promote GPT-5.6 models to the front without inventing unsupported slugs.

## Task 4.2 — Default model policy

Preferred order for V1:

1. `gpt-5.6-sol` if listed/allowed;
2. `gpt-5.6` alias if that is what the backing catalog exposes;
3. another entitled GPT-5.6 tier if deliberately allowed by configuration;
4. current Codex default/fallback.

Do not hard-fail startup simply because the preferred model is temporarily absent from live discovery.

## Task 4.3 — Provider picker

Katana should appear as a top-level provider, not hidden inside the OpenAI provider group, because its identity/behavior is intentionally distinct.

Picker text:

```text
Katana-GPT
Katana identity backed by GPT-5.6 through ChatGPT / Codex OAuth
```

Surfaces to test:

- `hermes model`;
- classic CLI `/model`;
- TUI model picker;
- gateway model command;
- Desktop model picker/structured model selector if it consumes provider catalog;
- setup wizard where applicable.

## Task 4.4 — Model normalization

`cli.py::_normalize_model_for_provider()` currently receives the visible resolved provider. Katana needs Codex model validation without being renamed to Codex.

Introduce backing/model-provider-aware normalization:

```text
visible provider: katana-gpt
model semantics: openai-codex
```

Tests:

- [ ] `gpt-5.6-sol` preserved;
- [ ] unsupported non-Codex model normalized/fails with an actionable message;
- [ ] model switch away/back works;
- [ ] session resume preserves model/provider pair.

### Phase 4 gate

A user can select `Katana-GPT -> gpt-5.6-sol` through normal Hermes model selection and the persisted config remains `provider: katana-gpt`.

---

# PHASE 5 — Generalize provider message hooks to Codex Responses

Goal: provide a clean, reusable way for provider profiles to augment messages/instructions on the Responses path.

## Task 5.1 — Invoke profile preprocessing on Codex path

Likely file:

- `agent/chat_completion_helpers.py`

Current Codex branch builds `_msgs_for_codex` and passes it directly to the Codex transport. Add the same conceptual profile preprocessing used by chat-completions, with careful copy/idempotency semantics.

Requirements:

- [ ] resolve profile from visible `agent.provider` (`katana-gpt`);
- [ ] process a request-local copy, never mutate durable conversation history;
- [ ] preserve image-stripping/media behavior;
- [ ] preserve developer/system roles;
- [ ] preserve encrypted reasoning replay items;
- [ ] do not alter existing OpenAI Codex requests when profile preprocessing is a pass-through.

## Task 5.2 — Codex instruction extraction test

Because `agent/transports/codex.py` converts the first system message into Responses API `instructions`, verify:

```text
Hermes system prompt + Katana identity
        -> first system message
        -> CodexTransport.build_kwargs()
        -> kwargs["instructions"]
```

Tests should inspect the final outbound kwargs, not merely the intermediate message list.

## Task 5.3 — Idempotency

Add a stable marker or structured helper so multiple preprocessing passes cannot produce:

```text
Katana identity
Katana identity
Katana identity
...
```

Test repeated build calls against the same source history.

### Phase 5 gate

A mocked Katana request contains exactly one Katana identity block in final Responses API `instructions`, while a normal `openai-codex` request is byte/semantically unchanged except for unavoidable request-local copies.

---

# PHASE 6 — Define the Katana identity contract

Goal: make the provider behave like Katana without smuggling product/private state into source code.

## Task 6.1 — Base identity content

The base identity should be compact and stable. It should define:

- name/identity: Katana-GPT;
- role: engineering/operator partner inside Hermes;
- directness and communication style;
- bias toward inspecting real state rather than guessing;
- build/fix semantics: authorized local in-scope changes can proceed when the user asks to build/fix;
- plan/review semantics: do not mutate when the user only asks for analysis/planning;
- respect for Hermes approvals/operator/tool boundaries;
- preference for reusable architecture over one-off patches;
- explicit separation of visible provider identity from backing model/provider;
- instruction to use Hermes context/memory/project files when available rather than inventing remembered facts.

## Task 6.2 — Keep identity lean

Do **not** copy:

- ChatGPT hidden/system prompts;
- giant project histories;
- user biography;
- all Hermes skills;
- all tool descriptions;
- ephemeral current-project state.

Those already enter through their own context channels and would waste cache/context.

## Task 6.3 — Context layering contract

Target order:

```text
1. Hermes core safety/runtime system prompt
2. Katana stable identity block
3. active Hermes profile/project instructions
4. memory/user context supplied by Hermes
5. current conversation/history
6. current user turn
```

If current Hermes system-prompt construction makes this exact ordering impractical, preserve the semantic precedence: Hermes runtime/security policy remains authoritative; Katana adds identity; profile/project context remains dynamic.

## Task 6.4 — Identity tests/evals

Golden behavioral cases:

- plan-only request -> inspect/report, no edits;
- explicit fix request -> make in-scope local edits + tests;
- destructive/external action -> preserve confirmation boundary;
- missing context -> inspect available state rather than hallucinate;
- tool failure -> report accurately rather than claim success;
- project-specific memory -> use injected Hermes context, not baked-in provider text.

### Phase 6 gate

The Katana identity is small, deterministic, test-covered, and clearly separated from user/project memory.

---

# PHASE 7 — Session, profile, Agency, Fleet, and delegation correctness

Goal: ensure Katana-GPT behaves correctly when used as an actual Hermes routing primitive, not just an interactive CLI novelty.

## Task 7.1 — Session persistence/resume

Test:

- new session on Katana;
- multi-turn conversation;
- save/quit/resume;
- provider remains Katana;
- backing provider is re-resolved at runtime rather than serialized with stale credentials;
- Katana identity still appears once after resume.

## Task 7.2 — Named Hermes profiles

A profile should be able to declare:

```yaml
model:
  provider: katana-gpt
  default: gpt-5.6-sol
```

Test profile activation and sleeping/waking behavior without pre-warming unrelated profiles.

## Task 7.3 — Delegation/subagents

Test Katana as:

- parent orchestrator provider;
- child subagent provider;
- fallback target;
- source provider when spawning an inherited child;
- explicit override for a single delegated task.

Verify child concurrency/iteration budgets remain Hermes-owned.

## Task 7.4 — Agency

Agency roles should be able to select Katana-GPT in model sets without treating it as a new credential family.

Potential follow-up:

- add a Katana-first Agency model-set preset;
- allow only senior/orchestration roles to use Katana while routine workers remain on cheaper models.

This preset is optional for V1 and should land only after core provider correctness.

## Task 7.5 — Fleet

Fleet should see Katana-GPT as a provider/model capability, but Fleet authorization remains independent from model identity.

Invariant:

```text
Katana model selected != Fleet permission granted
```

### Phase 7 gate

Katana works across interactive, profile, subagent, Agency/Fleet-routing contexts without leaking or duplicating credentials.

---

# PHASE 8 — Reliability, limits, retries, and diagnostics

Goal: make failures understandable and safe.

## Task 8.1 — Quota/429 handling

Current local Codex OAuth credentials are presently capable of returning account usage-limit 429s. Katana should surface:

```text
Katana-GPT request could not run because its backing OpenAI Codex account hit a usage limit.
```

Keep retry policy bounded. Do not spin indefinitely on a known account quota reset.

## Task 8.2 — No-first-byte / stale stream handling

Older local logs show GPT-5.6 requests that produced no first byte or no stream events. Classify live failures into:

- account quota/429;
- model unavailable/unsupported;
- client-version/backend compatibility response;
- transport stall;
- auth expiry;
- network failure.

Diagnostics should include visible provider, backing provider, model, endpoint family, and elapsed state without exposing credentials.

## Task 8.3 — Backing-provider-aware refresh helpers

Replace direct provider-name checks only where semantics truly mean "uses Codex backing runtime." Avoid globally changing every `provider == openai-codex` comparison.

Add a helper such as:

```python
agent.uses_backing_provider("openai-codex")
```

or equivalent runtime metadata helper.

## Task 8.4 — Fallback semantics

Decide and test:

- if Katana backing auth fails, should configured Hermes fallback chain run? Yes.
- if `gpt-5.6-sol` is unavailable but another Codex model is configured as fallback, should Katana identity remain? Prefer yes when fallback stays within Katana provider.
- if fallback switches to a different provider such as MiMo/OpenRouter, visible provider should change honestly; do not keep calling the result Katana unless the Katana identity is deliberately reapplied as a provider composition over that backend in a future feature.

### Phase 8 gate

Every common failure mode has a bounded action and truthful diagnostic.

---

# PHASE 9 — GPT-5.6 compatibility enhancements

Goal: make the provider exploit GPT-5.6 features Hermes can support cleanly, without blocking V1 on every new feature.

OpenAI's current GPT-5.6 guidance says the family supports `none`, `low`, `medium`, `high`, `xhigh`, and `max` reasoning effort, and Pro is an execution mode (`reasoning.mode="pro"`) rather than a separate Pro model slug.

## Task 9.1 — `max` reasoning effort

Hermes command/config currently exposes through `xhigh` in several surfaces. Audit and, if safe, add `max` generically.

Surfaces:

- `/reasoning` command choices;
- config validation/help;
- TUI/Desktop selector if present;
- Codex request builder;
- tests for older providers that do not support `max`.

This can be a separate commit if it is broader than Katana V1.

## Task 9.2 — Pro execution mode

Do not invent `gpt-5.6-sol-pro` as a model slug.

Potential future config:

```yaml
model:
  provider: katana-gpt
  default: gpt-5.6-sol
agent:
  reasoning_effort: high
  reasoning_mode: pro
```

Implement only after confirming the ChatGPT/Codex backend route accepts the same parameter semantics Hermes uses. API support alone does not prove the private Codex backend accepts it identically.

## Task 9.3 — Persisted reasoning

GPT-5.6 has newer persisted-reasoning behavior. Hermes currently manages manual history plus encrypted reasoning replay for Responses-compatible paths. Audit before changing anything; do not casually introduce `previous_response_id` or stored server state because Hermes currently uses `store: false` and owns session history.

### Phase 9 gate

V1 does not require Pro mode or persisted-reasoning changes. `max` can land independently if regression-safe.

---

# PHASE 10 — UI and operator experience

Goal: Katana should be obvious and understandable wherever Hermes exposes provider state.

## Task 10.1 — Labels/status

Desired examples:

```text
Provider: Katana-GPT ⚔️
Model: gpt-5.6-sol
Backing: OpenAI Codex (ChatGPT OAuth)
```

Normal compact status may omit Backing; diagnostics/details should show it.

## Task 10.2 — Desktop

Verify the Electron Desktop model selector consumes the provider catalog correctly. If no code change is needed, add an integration test or manual proof rather than duplicating model-picker logic.

## Task 10.3 — TUI and gateway

Verify:

- `/model` completion;
- provider/model switch event;
- footer/status;
- JSON-RPC session info reports `katana-gpt`;
- gateway model command and restart/resume behavior.

## Task 10.4 — Icon/branding

V1 should use text/emoji only if supported naturally. Do not make provider correctness depend on a visual asset pipeline.

Candidate identity marker: `⚔️`.

### Phase 10 gate

User-facing surfaces consistently say Katana-GPT while diagnostics can reveal OpenAI Codex as backing runtime.

---

# PHASE 11 — Test matrix

Goal: prove the abstraction, Katana behavior, and non-regression.

## Unit tests

### Provider profile

- [ ] discovery;
- [ ] aliases;
- [ ] backing/catalog/default metadata;
- [ ] identity preprocessing;
- [ ] idempotency.

### Runtime provider

- [ ] delegated provider resolution;
- [ ] cycle rejection;
- [ ] visible/backing identity separation;
- [ ] missing backing auth;
- [ ] refresh metadata propagation.

### Models

- [ ] delegated catalog;
- [ ] default selection;
- [ ] live model list passthrough;
- [ ] fallback catalog;
- [ ] model normalization uses backing provider semantics.

### Responses transport

- [ ] Katana instructions reach `kwargs["instructions"]`;
- [ ] non-Katana Codex path remains unchanged;
- [ ] tools preserved;
- [ ] reasoning config preserved;
- [ ] session cache key preserved;
- [ ] encrypted reasoning replay preserved.

## Integration tests

- [ ] CLI runtime resolution;
- [ ] `/model` switch;
- [ ] TUI gateway startup;
- [ ] session resume;
- [ ] profile-based startup;
- [ ] delegated subagent;
- [ ] mocked 401 -> refresh -> retry;
- [ ] mocked 429 -> bounded error;
- [ ] fallback provider transition.

## Regression suites

At minimum run focused suites for:

- provider profiles;
- runtime provider resolution;
- Codex auth;
- Codex model picker/catalog;
- Codex Responses transport;
- CLI model switching;
- TUI gateway provider/session tests.

Then run the repository-prescribed broader confidence bundle if focused suites are green and resource cost is reasonable.

### Phase 11 gate

No known regression in existing `openai-codex`, model selection, or provider resolution tests.

---

# PHASE 12 — Live end-to-end proof

Goal: prove the actual account/backing route, not only mocks.

Prerequisites:

- backing `openai-codex` OAuth usable;
- account not currently over GPT-5.6/Codex usage allowance;
- GPT-5.6 available to the account;
- Hermes service/test process running the feature worktree build.

## Proof A — Minimal CLI response

Run Katana with tools disabled/minimal context and ask for a deterministic identity probe.

Verify:

- selected provider = Katana-GPT;
- backing provider = OpenAI Codex;
- model = GPT-5.6 Sol;
- response arrives;
- logs contain no secrets.

## Proof B — Tool call

Ask Katana to read a harmless test fixture and report one value.

Verify normal Hermes tool execution and result continuation.

## Proof C — Multi-turn identity

Three turns with no process restart.

Verify:

- identity remains stable;
- prompt does not duplicate;
- reasoning/tool history works;
- session state remains Katana.

## Proof D — Resume

Exit and resume the same session.

Verify provider/model/identity survive while credentials are freshly resolved.

## Proof E — Model switch

Switch:

```text
Katana -> another provider -> Katana
```

Verify client rebuild and identity boundaries.

## Proof F — Profile/Agency route

Launch one named profile on Katana-GPT and complete one bounded delegated task.

## Proof G — Failure proof

When practical, simulate or use a mocked quota/auth failure and confirm diagnostic quality.

### Phase 12 gate

A real Hermes conversation completes end-to-end through `katana-gpt` and GPT-5.6 Sol using existing ChatGPT/Codex OAuth credentials.

---

# PHASE 13 — Documentation, release, and optional upstreaming

## Task 13.1 — User docs

Document:

- what Katana-GPT is;
- that it reuses OpenAI Codex OAuth;
- how to authenticate backing provider;
- how to select Katana-GPT;
- model/usage-limit behavior;
- what it does not inherit from ChatGPT product state.

## Task 13.2 — Developer docs

Document the generic composed-provider contract so future providers can reuse it.

Potential examples:

- branded/provider-persona layers;
- corporate policy providers backed by a common model vendor;
- local provider aliases with distinct instruction contracts;
- Agency-specific orchestration providers.

## Task 13.3 — Changelog/release notes

Call out:

- new composed-provider primitive;
- Katana-GPT provider;
- delegated OAuth/model catalog behavior;
- any general Codex Responses preprocessing improvement.

## Task 13.4 — Distribution boundary

This feature is a personal side project and is **fork-only**.

Hard rule:

- never push this branch or any Katana/composed-provider commits to `NousResearch/hermes-agent`;
- never open an upstream PR for this work;
- never change the upstream remote to a writable push URL;
- commits and pushes are allowed only to the user's fork, `Dadmin88/hermes-agent`, unless the user explicitly changes this rule later.

The local `upstream` push URL is intentionally `DISABLED`; preserve that guardrail.

---

# Implementation order / commit strategy

Prefer small reviewable commits:

1. `test(provider): characterize composed-provider runtime requirements`
2. `feat(provider): add backing-provider composition metadata`
3. `feat(provider): resolve delegated runtime while preserving provider identity`
4. `feat(models): support delegated provider catalogs and defaults`
5. `feat(codex): run provider message preprocessing on Responses path`
6. `feat(katana): add Katana-GPT provider and identity contract`
7. `test(katana): add runtime, refresh, session, and picker coverage`
8. `docs(katana): document provider and composed-provider architecture`

If a change is useful generically and can be tested independently, commit it before Katana-specific behavior.

# Rollback strategy

Because V1 is additive:

- disabling/removing the `katana-gpt` plugin should restore prior behavior;
- all new `ProviderProfile` fields default empty;
- normal providers should not enter delegated-runtime logic;
- normal Codex profile preprocessing remains pass-through;
- no migration should rewrite existing provider configs automatically;
- no OAuth credentials should move or change ownership.

If the feature proves unstable, users can switch back to:

```yaml
model:
  provider: openai-codex
  default: gpt-5.6-sol
```

without credential migration.

# Definition of done

Katana-GPT V1 is DONE only when all of the following are true:

- [ ] Katana is a first-class provider slug in Hermes.
- [ ] It is selectable from normal model/provider UI.
- [ ] It reuses OpenAI Codex OAuth without credential duplication.
- [ ] Runtime retains both visible provider and backing provider identities.
- [ ] GPT-5.6 Sol is selected when available and configured as the preferred model.
- [ ] Katana base identity reaches final Codex Responses `instructions` exactly once.
- [ ] Hermes memory/profile/project/tool context continues to work normally.
- [ ] Token refresh/recovery works through OpenAI Codex while provider remains Katana.
- [ ] Session resume and model switching work.
- [ ] Subagent/profile routing works.
- [ ] Quota/auth/transport errors are truthful and actionable.
- [ ] Existing OpenAI Codex behavior is regression-green.
- [ ] A live end-to-end manual proof succeeds on the real account.
- [ ] Documentation explains both the user experience and the generic provider-composition architecture.
