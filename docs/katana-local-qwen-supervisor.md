# Katana Local Qwen + External Supervisor

This document describes the fork-only Katana architecture used to keep Hermes fully functional on local inference while allowing an authenticated external ChatGPT/Katana operator to control the same environment.

> Personal fork feature. Do not push or PR this work to `NousResearch/hermes-agent` unless the owner explicitly changes that rule.

## Architecture

```text
Normal Hermes use

Kyle -> Hermes -> katana profile -> Qwen3.5-9B -> Hermes tools

External supervision

Kyle -> ChatGPT / Katana -> Katana-GPT MCP -> Hermes tools
                                      \-> live Qwen-powered Katana CLI session
```

Qwen is the inference model powering the existing `katana` profile. It is not a second persona or subordinate agent. Katana identity, memory, skills, sessions, tools, and Fleet authority remain owned by the profile.

## Local inference route

The live Katana profile uses an OpenAI-compatible local endpoint:

```yaml
model:
  default: qwen3.5-9b
  provider: custom
  base_url: http://127.0.0.1:11434/v1
  api_mode: chat_completions
  context_length: 65536

fallback_providers: []
```

Delegation uses the same local route and is currently capped at one concurrent child on the RTX 4060 Laptop.

Automatic compression and background review are explicitly pinned to the same localhost Qwen endpoint. Title generation is disabled. Existing opt-in cloud features such as image generation or saved MoA presets are not part of normal Katana chat execution.

## Ollama runtime

The current runtime is standalone Ollama, installed user-locally rather than system-wide. It binds to `127.0.0.1:11434` only and is managed by a user systemd service.

The resident model is Qwen3.5-9B Q4_K_M. The GGUF advertises 262,144 native context and Ollama reports tool, thinking, and completion capabilities. The managed runtime uses 65,536 context because Hermes Agent requires at least 64K.

Measured at 64K context, the model occupied roughly 6.55 GiB of the 8.19 GiB RTX 4060 VRAM while leaving the machine usable.

## Resumable one-shot turns

This fork fixes a Hermes CLI mismatch where top-level `-z/--oneshot` was dispatched before `--resume` / `-c` handling and therefore silently started a new root session.

The following now preserve session history and append to the same session:

```bash
hermes -p katana --resume <session-id> -z "continue this work"
hermes -p katana -c -z "continue the most recent session"
```

Resumed one-shot loads the canonical persisted model-facing history, binds `AIAgent` to the existing session ID, reuses the existing DB row, and advances the DB flush cursor so historical rows are not duplicated.

## Classic CLI local supervisor

The `katana` profile may opt into an owner-local supervisor channel:

```yaml
supervisor:
  local_control:
    enabled: true
```

The classic interactive CLI then exposes one AF_UNIX socket per Hermes process under:

```text
<profile-home>/runtime/local-supervisor/cli-<pid>.sock
```

Security boundaries:

- runtime directory mode `0700`
- socket mode `0600`
- Linux `SO_PEERCRED` same-UID check
- no TCP listener
- no arbitrary shell/Python execution over the socket
- bounded request and transcript sizes
- disabled by default globally

Supported actions:

- `status`: model/provider/session, queue depth, `turn_active`, `tool_active`, bounded `active_tools`
- `history`: bounded user/assistant transcript projection
- `message`: inject a normal next-turn message through Hermes' existing `_pending_input` path
- `steer`: use the native `AIAgent.steer()` path while a turn is active; otherwise queue as the next normal turn
- `interrupt`: use Hermes' existing hard-interrupt path

The module also provides a small local client:

```bash
python -m hermes_cli.local_supervisor --profile katana list
python -m hermes_cli.local_supervisor --profile katana --session <id> status
python -m hermes_cli.local_supervisor --profile katana --session <id> history
python -m hermes_cli.local_supervisor --profile katana --session <id> message "inspect this repo"
python -m hermes_cli.local_supervisor --profile katana --session <id> steer "check the projection writer first"
python -m hermes_cli.local_supervisor --profile katana --session <id> interrupt
```

The ChatGPT/Katana connector can invoke this local client through its existing owner-gated command surface, so no new MCP tool catalog entry is required.

## Live acceptance evidence

Verified on the real Katana machine:

- normal local Hermes response: `HERMES_KATANA_LOCAL_OK`
- full local Hermes tool loop: `HERMES_LOCAL_TOOL_LOOP_OK`
- local operation with external HTTP/S deliberately unavailable: `LOCAL_OFFLINE_PROOF_OK`
- local child delegation under the same isolation: `HERMES_LOCAL_DELEGATION_OK`
- persistent resumed one-shot recalled `KATANA_REMOTE_BRIDGE_42` and appended to the same session without duplicate history
- external message into a real interactive CLI session: `SUPERVISOR_LIVE_OK`
- mid-tool external steering: waited for `tool_active=true`, then final response changed to `STEER_LIVE_OK`
- external hard interrupt persisted the active tool result as `status=interrupted`; assistant recorded `Operation interrupted.`

## Remaining frontend boundary

Local Qwen inference is profile-level and therefore is not limited to the classic CLI. The remaining control-plane work is to provide equivalent authenticated external attach/message/steer/interrupt for Hermes TUI/Desktop gateway sessions. The existing TUI gateway already owns `prompt.submit`, `session.steer`, and `session.interrupt`; the next implementation phase should adapt those existing semantics rather than invent a second agent loop.
