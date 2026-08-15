# Katana Local Qwen + ChatGPT Supervisor Architecture

Status: **IMPLEMENTATION IN PROGRESS — LOCAL KATANA GREEN; CLASSIC-CLI SUPERVISOR TIER 2 GREEN**  
Owner: Kyle / Katana personal fork  
Repositories: `Dadmin88/hermes-agent` + local `hermes-gpt` connector sidecar  
Upstream rule: **personal fork only; never push this work to NousResearch**

## 1. Objective

Make the `katana` Hermes profile fully usable with no OpenAI API/Codex inference dependency by giving it a local Qwen model, while preserving ChatGPT/Katana-GPT as a separate external supervisory/control plane.

The final system must support both paths simultaneously:

```text
LOCAL / NORMAL HERMES PATH
Kyle -> Hermes CLI/Desktop -> katana profile -> local Qwen -> Hermes tools -> machine

EXTERNAL SUPERVISOR PATH
Kyle -> ChatGPT / GPT-5.6 Sol -> Katana-GPT MCP connector -> Hermes runtime/tools -> machine
                                                        -> active Qwen-powered Katana session
```

Qwen is **not a second persona or subordinate agent**. Qwen is the resident inference model powering the existing `katana` profile. Katana remains the identity, profile, memory, skills, tools, sessions, Fleet authority, and operating context.

ChatGPT/Katana is **not** the normal Hermes provider. It is an external high-capability supervisor that can inspect, steer, message, interrupt, review, and directly operate the same Hermes environment while local Qwen keeps Hermes independently functional.

## 2. Core invariants

1. **Hermes must work without ChatGPT.** If the connector disappears, `hermes --profile katana` still chats and uses tools normally through local Qwen.
2. **ChatGPT must not be required for local inference.** No Codex/API call may be on the primary Katana turn path.
3. **Qwen powers Katana; it is not a separate agent identity.** The profile remains `katana`.
4. **Katana-GPT remains an external control plane.** ChatGPT can directly operate Hermes and, once the supervisor API is implemented, control the active Qwen-powered Katana runtime.
5. **No silent Codex fallback.** Local inference failure must fail visibly or use an explicitly local fallback; it must never silently consume Codex/API quota.
6. **No upstream push.** Changes may be committed/pushed only to `Dadmin88/hermes-agent` or the user's own Hermes-GPT repository/location.
7. **Existing Desktop/Fleet/gateway work is preserved.** No broad restarts, resets, or destructive cleanups.
8. **Rollback is always available.** Every live config mutation gets a backup or is reversible with one explicit config change.
9. **Resource use is bounded.** The local model must fit Katana's RTX 4060 Laptop / system RAM without making the machine unusable.
10. **Control surfaces are explicit and auditable.** Remote ChatGPT steering must be distinguishable from ordinary local user turns.

## 3. Baseline discovered before implementation

- Feature worktree: `/home/kyle/Create/worktrees/hermes-agent--katana-gpt-provider`
- Feature worktree currently clean.
- Current `katana` model config:
  - provider: `katana-gpt`
  - model: `gpt-5.6-sol`
  - base URL: ChatGPT/Codex backend
- Current result: account-level Codex `usage_limit_reached` prevents normal Hermes turns.
- `katana` gateway is running and healthy.
- The pre-existing local model was found at `/home/kyle/ods/data/models/Qwen3.5-9B-Q4_K_M.gguf`; **ODS is not a runtime dependency**. The weights were copied into a neutral Hermes-owned path at `~/.local/share/hermes/models/Qwen3.5-9B-Q4_K_M.gguf`.
- Standalone official Ollama v0.32.5 is installed user-locally under `~/.local/opt/ollama-v0.32.5`, served by `ollama-katana.service` on `127.0.0.1:11434` only. Ollama cloud is disabled for this service.
- Ollama model `qwen3.5-9b` imports the existing Qwen3.5-9B Q4_K_M GGUF with a verified 65,536 runtime context; the GGUF advertises 262,144 native context plus tool/thinking/completion capabilities.
- Hermes already contains native local-server/Ollama awareness, including server detection, context probing, vision probing, and local OpenAI-compatible endpoint behavior.
- Hermes-GPT durable OAuth persistence has already been implemented and proven across service restarts; connector restarts no longer require repeated reauthorization.

## 3.1 Implementation evidence — 2026-08-15

Completed and live-verified:

- `katana` primary inference is local: `custom -> qwen3.5-9b -> http://127.0.0.1:11434/v1`.
- `delegation` uses the same local Qwen route and is capped at one concurrent child while the 64K runner is measured on this laptop.
- `fallback_providers` is empty; the ordinary Katana path has no silent Codex fallback.
- Full Hermes chat through local Qwen: `HERMES_KATANA_LOCAL_OK`.
- Full Hermes tool loop through local Qwen: `HERMES_LOCAL_TOOL_LOOP_OK`.
- External HTTP/S deliberately poisoned while localhost remained available: `LOCAL_OFFLINE_PROOF_OK`.
- Local child-agent delegation under the same network isolation: `HERMES_LOCAL_DELEGATION_OK`.
- 64K runtime measurement: about 6.55 GiB Qwen VRAM on the RTX 4060 Laptop, with the machine remaining usable.
- Fork fix added so `-z/--oneshot` now honors `--resume` / `-c` instead of silently creating a new root session.
- Persistent supervisor proof: session `20260815_020933_eb73a4` retained `KATANA_REMOTE_BRIDGE_42`; connector-driven resumed one-shot recalled it and appended exactly one user/assistant pair with no duplicate history or new root.
- Bare `-c -z` also continued the same context: `KATANA_REMOTE_BRIDGE_42:CONTINUE_OK`.
- Targeted one-shot/resume regression bundle: 37 passing tests.
- Classic CLI local supervisor added as an opt-in per-profile AF_UNIX control socket under `<profile>/runtime/local-supervisor/`, directory mode `0700`, socket mode `0600`, with Linux `SO_PEERCRED` same-UID enforcement.
- Supervisor supports bounded `status`, `history`, `message`, `steer`, and `interrupt`; it exposes no arbitrary shell or Python execution surface.
- Live external message injection into a real interactive Qwen-powered Katana session: `SUPERVISOR_LIVE_OK`.
- Live mid-tool steering waited for `tool_active=true` / `active_tools=["execute_code"]`, then changed the running turn's final answer to `STEER_LIVE_OK`.
- Live hard interrupt persisted the active tool result as `status=interrupted` with `[execution interrupted — user sent a new message]`; the assistant recorded `Operation interrupted.` and the sleeper never produced its forbidden output.
- Supervisor status now distinguishes `turn_active`, `tool_active`, and bounded `active_tools` so remote control does not depend on timing guesses.
- Automatic compression and background review are explicitly pinned to `custom -> qwen3.5-9b -> http://127.0.0.1:11434/v1`; title generation is disabled. Healthy normal-agent side tasks no longer need cloud inference, and these pinned jobs fail locally instead of auto-discovering a cloud fallback if Ollama is unavailable.
- Broader confidence bundle covering supervisor, resumable one-shot, runtime provider resolution, Ollama context probing, resume model restore, and delegation: 185 passing tests; Ruff, Python compilation, and `git diff --check` all pass.

Current implementation boundary:

- **Supervisor tier 1 is green:** ChatGPT can directly operate Hermes/computer/Fleet and can start/resume persistent Qwen-powered Katana turns through existing connector owner tools. No new MCP catalog entry is required.
- **Supervisor tier 2 for the classic CLI is green:** ChatGPT can attach to a live interactive Katana CLI session and inspect, message, steer, or hard-interrupt the same Qwen-powered runtime through an owner-only Unix socket.
- **Remaining supervisor boundary:** extend equivalent live attach/control to TUI/Desktop gateway sessions. Local Qwen inference itself already works across Hermes through the profile config; the remaining work is only the external control surface for those frontend runtimes.

## 4. Target architecture

```text
                         KATANA PROFILE
                 identity / memory / skills
                 tools / sessions / Fleet
                           |
              +------------+-------------+
              |                          |
              v                          v
       LOCAL INFERENCE             REMOTE SUPERVISOR
        Qwen3.5 9B                 ChatGPT GPT-5.6 Sol
        via Ollama                       |
              |                    Katana-GPT MCP
              |                          |
              +------------+-------------+
                           |
                     Hermes runtime
                           |
        +------------------+------------------+
        |                  |                  |
        v                  v                  v
     filesystem           shell              Fleet
     computer UI          Git                services
```

The local Qwen path is the default model path for ordinary Hermes use. The ChatGPT path never has to impersonate an inference provider.

## 5. Phase 0 — Safety, branch isolation, and rollback

### Task 0.1 — Preserve the completed Katana-GPT provider checkpoint
- Record current feature commit SHA and fork remote tracking.
- Create a new fork-only branch for the local-supervisor architecture so the prior provider experiment remains independently recoverable.
- Do not rewrite or delete the existing provider commit.

### Task 0.2 — Capture live configuration baseline
- Back up the `katana` profile config before changing model routing.
- Record current primary model/provider/base URL.
- Record every other inference-bearing config section, especially:
  - delegation/subagents
  - auxiliary tasks
  - fallback providers
  - compression
  - MoA/reference models
  - background review/curator/monitor
- Identify every remaining `openai-codex`, `katana-gpt`, or GPT model reference that could consume quota.

### Task 0.3 — Capture runtime baseline
- Record active Hermes/gateway processes.
- Verify current gateway remains healthy.
- Record GPU state (`nvidia-smi`) and free disk/RAM before local model installation.

**Acceptance:** clean new branch, reversible config baseline, no live service disrupted.

## 6. Phase 1 — Local inference substrate

### Task 1.1 — Install Ollama safely
- Use the current official Ollama Linux distribution.
- Prefer a user-owned installation if system-level sudo is unavailable/non-interactive.
- Do not pipe an uninspected arbitrary third-party script into a privileged shell.
- Install only from Ollama's official distribution endpoint.

### Task 1.2 — Create a managed local Ollama service
- Bind to loopback only (`127.0.0.1:11434`) unless a later Fleet use case explicitly requires LAN/Tailscale exposure.
- Use a systemd user service if practical.
- Configure automatic restart with a bounded delay.
- Configure model storage deliberately; if the external SSD is mounted and suitable, consider moving model blobs there later as a separate optimization rather than blocking first success.

### Task 1.3 — GPU validation
- Verify NVIDIA GPU visibility before pulling a model.
- After first model load, verify Ollama uses the RTX 4060 rather than CPU-only execution.
- Capture VRAM/RAM footprint.

### Task 1.4 — Select the Katana resident model
Selected and live: `qwen3.5-9b`, imported from the existing `Qwen3.5-9B-Q4_K_M.gguf` into standalone Ollama.

Reasons:
- 9B dense model at Q4_K_M is a strong quality/footprint fit for the RTX 4060 Laptop.
- The GGUF advertises 262,144 native context.
- Ollama reports `tools`, `thinking`, and `completion` capabilities.
- Direct OpenAI-compatible testing produced valid structured tool calls before Hermes integration.
- It keeps sufficient VRAM headroom for the desktop while remaining substantially stronger than very small local fallback models.
- Larger dense 27B candidates remain benchmark candidates for an optional quality mode, not the always-on resident model until latency/RAM spill is measured.

### Task 1.5 — Context configuration
- Hermes enforces a minimum 64K context for an agent model; the first conservative 16K import was therefore rejected before inference.
- The GGUF's advertised native context is 262,144, so the Ollama model was rebuilt at 65,536 runtime context.
- Flash Attention is enabled in the standalone Ollama service.
- Verified loaded footprint at 64K: approximately 6.55 GiB VRAM on the 8.19 GiB RTX 4060, with approximately 10 GiB system RAM still available during the measured run.
- Hermes config explicitly records `model.context_length: 65536` to avoid stale server-probe metadata.

### Task 1.6 — Direct model smoke tests
- Plain chat request through Ollama API.
- OpenAI-compatible `/v1` chat path used by Hermes.
- Structured tool-call capability check.
- Thinking/non-thinking behavior check if Hermes exposes that mode.

**Acceptance:** local Qwen responds reliably through the same OpenAI-compatible shape Hermes expects, on GPU, with sufficient context.

## 7. Phase 2 — Make local Qwen the Katana profile brain

### Task 2.1 — Use Hermes' native local/custom-provider path
- Do not create another bespoke provider unless the existing local-provider mechanism is demonstrably insufficient.
- Determine the exact canonical config representation from current Hermes code/tests.
- Expected endpoint family: `http://127.0.0.1:11434/v1`.

### Task 2.2 — Switch only the Katana primary model first
- `profile = katana`
- resident model = `qwen3.5-9b`
- provider = `custom`
- base URL = `http://127.0.0.1:11434/v1`
- API mode = `chat_completions`
- context length = `65536`
- remove Codex URL from the primary path
- preserve Katana identity/SOUL/memory/skills unchanged

### Task 2.3 — Eliminate accidental cloud inference
Audit and migrate any secondary inference paths that still point to Codex, including at minimum:
- fallback providers
- delegation/subagent model/provider
- title generation
- compression
- triage/specifier
- kanban decomposer
- curator/monitor/background review
- MoA presets/reference/aggregator models

Policy:
- automatic tasks that can safely use the primary local model inherit or are explicitly pinned to Qwen.
- cosmetic/unneeded auxiliary inference may be disabled; title generation is disabled on Katana.
- compression and background review are explicitly pinned to the localhost Qwen route so an Ollama outage cannot make those normal side tasks auto-discover a cloud provider.
- opt-in cloud features such as existing MoA presets and image generation remain available only when deliberately invoked; they are not part of ordinary Katana chat/delegation execution.
- no hidden fallback to OpenAI/Codex on the ordinary Katana path.

### Task 2.4 — Validate model metadata
- Hermes detects Ollama.
- Correct context length is discovered/injected.
- tool capability is recognized.
- no provider normalization bug misroutes bare `ollama` to an unrelated cloud provider.

**Acceptance:** `katana` resolves to local Qwen for every ordinary Hermes inference path and has no silent Codex dependency.

## 8. Phase 3 — Restore normal Hermes behavior

### Task 3.1 — One-shot conversation
Run a minimal local turn through normal Hermes CLI code, not a direct Ollama curl.

Expected:
- provider/local endpoint shown correctly
- no 429
- coherent response

### Task 3.2 — Interactive CLI
Launch ordinary `hermes --profile katana` and verify:
- prompt accepts messages
- streaming works
- visible profile remains Katana
- model identity shows local Qwen
- session persistence works

### Task 3.3 — Read-only tool loop
Ask Katana to inspect a harmless local file/system fact.
Expected loop:
`Qwen inference -> Hermes tool call -> tool result -> Qwen final response`.

### Task 3.4 — Safe mutating tool loop
Use a scratch path to prove Qwen can:
- create a file
- inspect it
- modify it
- verify result
No project code mutation for this test.

### Task 3.5 — Coding-agent loop
Use a small disposable workspace with a deliberate test failure.
Require Katana/Qwen to:
- inspect
- patch
- run test
- report evidence

### Task 3.6 — Failure behavior
Stop Ollama briefly and prove Hermes:
- reports local model unavailable
- does **not** fall through to Codex/API
- recovers after Ollama returns

**Acceptance:** Hermes is once again independently usable as a normal agent powered locally by Qwen.

## 9. Phase 4 — ChatGPT supervisory control of the Qwen-powered Katana runtime

This phase is what turns the local-model fix into the system Kyle actually wants.

### Task 4.1 — Discover the existing runtime control surface
Prefer existing Hermes gateway/TUI/session APIs over terminal scraping.
Inspect:
- active profile/session registry
- gateway request methods
- TUI gateway RPC methods
- session message injection
- `/steer`, interrupt, resume, status, transcript facilities
- any existing local HTTP/WebSocket control path used by Hermes Desktop/Web UI

### Task 4.2 — Define a stable supervisor API
Expose through Hermes-GPT connector, initially read-only where possible:

- `hermes_agent_sessions`
  - list active Katana sessions and minimal metadata
- `hermes_agent_status`
  - model, state, active turn, tool activity
- `hermes_agent_transcript`
  - bounded recent exchanges/tool evidence
- `hermes_agent_message`
  - submit a normal new user-level turn to a chosen Katana session
- `hermes_agent_steer`
  - inject a steering correction into an in-progress turn
- `hermes_agent_interrupt`
  - stop the current run without killing the profile/runtime
- `hermes_agent_resume`
  - resume or continue where supported

### Task 4.3 — Preserve session semantics
- Remote messages must enter the same Hermes message pipeline as local user input where appropriate.
- Steering must remain steering, not masquerade as user input.
- Tool call/result ordering must remain valid.
- Session persistence must continue to work.

### Task 4.4 — Concurrency policy
Define deterministic behavior if Kyle types locally while ChatGPT is supervising:
- never silently drop either message
- visible queue/interruption behavior
- local user input has clear priority rules
- remote steering is labeled/auditable

### Task 4.5 — Connector security
- no secrets in supervisor responses
- bounded transcript size
- profile allowlist remains enforced
- destructive operations retain existing confirmation/policy gates
- supervisor APIs are limited to locally authorized Hermes profiles

**Acceptance:** from ChatGPT, Katana can inspect and control a live Qwen-powered Katana session without screen-scraping the terminal.

## 10. Phase 5 — Direct Katana takeover and mixed-mode operation

The supervisor must not be forced to use Qwen for every action.

### Task 5.1 — Keep direct connector tools available
ChatGPT can continue using:
- filesystem
- shell
- Git
- Fleet
- service/config operations
- computer-use surfaces
without involving the local Qwen turn loop.

### Task 5.2 — Handoff patterns
Support these workflows cleanly:

1. **Kyle -> local Katana/Qwen only**
2. **Kyle -> ChatGPT/Katana -> direct Hermes tools**
3. **ChatGPT/Katana -> Qwen-powered Katana session**
4. **ChatGPT inspects Qwen work -> steers it -> Qwen continues**
5. **ChatGPT interrupts Qwen -> performs direct repair -> resumes Qwen**

### Task 5.3 — Evidence handoff
Make it easy for ChatGPT to obtain:
- Qwen's recent decisions
- tool calls/results
- changed files
- test output
without re-reading the whole machine state manually.

**Acceptance:** GPT-5.6 Sol can function as a true external senior operator over the same Katana environment, while local Qwen remains a fully functional resident brain.

## 11. Phase 6 — UX and identity hardening

### Task 6.1 — Remove misleading provider naming
The ordinary Katana header should not imply GPT-5.6 Sol is the local inference model.
Target UI concept:

```text
Profile: Katana
Local model: Qwen3 8B
Supervisor: Katana-GPT connector (connected/disconnected)
```

### Task 6.2 — Optional supervisor status command
Potential command:
- `/katana` or `/supervisor`

Shows external connector/control availability without changing the local model.

### Task 6.3 — Visible remote-control events
When ChatGPT injects steering/message/interrupt events, make them visible in the local session, e.g.:

```text
⚔ External Katana steering received
```

Avoid pretending the local model generated those instructions itself.

**Acceptance:** user can always tell what is local inference versus external supervision without creating a second agent identity.

## 12. Phase 7 — Reliability and resource hardening

### Task 7.1 — Ollama lifecycle
- automatic startup
- health checking
- clear failure diagnostics
- restart recovery

### Task 7.2 — Memory pressure
- measure idle/load VRAM and RAM
- avoid running multiple heavy local models concurrently
- set sane keep-alive behavior
- prevent local inference from freezing Desktop/Fleet

### Task 7.3 — Context pressure
- verify tool schemas + Katana prompt fit reliably
- test compression locally
- ensure compression itself does not invoke Codex

### Task 7.4 — Gateway and connector independence
Prove all four states:
1. Qwen up + connector up
2. Qwen up + connector down
3. Qwen down + connector up
4. both unavailable

Expected:
- state 1: full dual-control system
- state 2: normal local Hermes still works
- state 3: ChatGPT can still directly operate connector tools; local chat clearly reports model unavailable
- state 4: clear diagnostics, no silent cloud fallback

## 13. Phase 8 — Test matrix

### Unit/regression
- local provider normalization
- Ollama model/context detection
- no-Codex fallback invariant
- supervisor message/steer routing
- concurrency semantics
- bounded transcript output

### Integration
- Ollama OpenAI-compatible endpoint -> Hermes agent
- Qwen tool call -> Hermes tool -> Qwen continuation
- connector -> active Katana session message
- connector -> steer active turn
- connector -> interrupt

### End-to-end acceptance
A. **Normal local use**
```text
hermes --profile katana
> hello
```
returns through Qwen with no cloud inference.

B. **Local tool use**
Katana/Qwen completes a real safe tool loop.

C. **External supervision**
From ChatGPT, inspect active Katana/Qwen session, inject a correction, observe Qwen continue accordingly.

D. **Direct takeover**
From ChatGPT, bypass Qwen and directly perform an allowed Hermes operation.

E. **Offline independence**
Disconnect Katana-GPT connector; local Hermes/Qwen still works.

F. **No premium fallback**
Stop Ollama; verify no request is sent to Codex/OpenAI.

## 14. Phase 9 — Deployment and Git discipline

### Task 9.1 — Hermes Agent fork
- commit only coherent, tested changes
- push only to `Dadmin88/hermes-agent`
- never push upstream to `NousResearch/hermes-agent`

### Task 9.2 — Hermes-GPT sidecar
- keep OAuth persistence work
- remove dead sampling/widget experiments that are no longer part of the final architecture
- add only the supervisor/session-control tools actually required
- run focused OAuth + supervisor regressions

### Task 9.3 — Live activation
- switch Katana config to local Qwen only after direct Ollama smoke tests pass
- restart only the minimum processes whose config/code must be reloaded
- preserve running Desktop/Fleet state where possible

## 15. Rollback

If local Qwen integration fails:
1. restore Katana config from pre-migration backup
2. stop/disable local Ollama service if necessary
3. leave Katana-GPT connector operational for direct computer control
4. do **not** restore the redundant Codex fallback chain
5. retain all diagnostic evidence for the next model/runtime choice

Rollback is a recovery mechanism, not a return to silently consuming exhausted Codex quota.

## 16. Completion definition

This project is complete when all of the following are simultaneously true:

- [ ] `katana` uses Qwen locally for ordinary Hermes inference.
- [ ] Kyle can chat normally inside Hermes again.
- [ ] Qwen can complete Hermes tool loops locally.
- [ ] No ordinary Katana path requires OpenAI API or Codex quota.
- [ ] ChatGPT/Katana-GPT remains connected as an external supervisor.
- [ ] ChatGPT can inspect and control an active Qwen-powered Katana session through a stable connector API.
- [ ] ChatGPT can bypass Qwen and directly operate Hermes tools when appropriate.
- [ ] Connector loss does not break local Hermes.
- [ ] Ollama loss does not silently invoke premium/cloud fallback.
- [ ] Tests and live E2E evidence are captured.
- [ ] Changes are committed/pushed only to Kyle's personal fork/repositories.
