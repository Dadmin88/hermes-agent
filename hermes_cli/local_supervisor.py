"""Owner-local control channel for an interactive Hermes CLI session.

This module deliberately uses an AF_UNIX socket instead of a TCP listener.
The server is opt-in per profile and accepts only the local OS user on Linux
(SO_PEERCRED), with filesystem mode 0600 as a second boundary.

It does not execute shell commands. Supported actions are limited to the
existing Hermes CLI primitives: status, bounded transcript inspection, normal
message queueing, mid-turn steer, and hard interrupt.
"""

from __future__ import annotations

import argparse
import atexit
import json
import os
import socket
import struct
import threading
import weakref
from pathlib import Path
from typing import Any, Optional

MAX_REQUEST_BYTES = 64 * 1024
DEFAULT_MAX_MESSAGE_CHARS = 32 * 1024
DEFAULT_HISTORY_MESSAGES = 16
DEFAULT_HISTORY_CHARS = 4000
_SOCKET_PREFIX = "cli-"
_SOCKET_SUFFIX = ".sock"

_ACTIVE_SERVERS: "weakref.WeakSet[LocalSupervisorServer]" = weakref.WeakSet()


def _runtime_dir(home: Path) -> Path:
    return home / "runtime" / "local-supervisor"


def _active_home() -> Path:
    from hermes_constants import get_hermes_home

    return Path(get_hermes_home())


def _profile_home(profile: str) -> Path:
    from hermes_cli.profiles import get_profile_dir

    return Path(get_profile_dir(profile))


def _local_control_config(cli: Any) -> dict[str, Any]:
    config = getattr(cli, "config", None)
    if not isinstance(config, dict):
        return {}
    supervisor = config.get("supervisor") or {}
    if not isinstance(supervisor, dict):
        return {}
    local = supervisor.get("local_control") or {}
    return local if isinstance(local, dict) else {}


def _bounded_text(value: Any, *, max_chars: int) -> str:
    text = str(value or "")
    if len(text) > max_chars:
        raise ValueError(f"text exceeds {max_chars} characters")
    if not text.strip():
        raise ValueError("text must not be empty")
    return text


def _external_marker(text: str) -> str:
    return f"[External Katana supervisor]\n{text}"


def _safe_history(cli: Any, *, limit: int, max_chars: int) -> list[dict[str, Any]]:
    history = list(getattr(cli, "conversation_history", None) or [])
    result: list[dict[str, Any]] = []
    for message in history:
        if not isinstance(message, dict):
            continue
        role = str(message.get("role") or "")
        if role not in {"user", "assistant"}:
            continue
        content = message.get("content")
        if isinstance(content, str):
            text = content
        elif isinstance(content, list):
            text_parts = []
            for part in content:
                if isinstance(part, dict) and part.get("type") == "text":
                    text_parts.append(str(part.get("text") or ""))
            text = "\n".join(text_parts)
        else:
            text = str(content or "")
        if len(text) > max_chars:
            text = text[:max_chars] + "…"
        item: dict[str, Any] = {"role": role, "content": text}
        if role == "assistant":
            names: list[str] = []
            for call in message.get("tool_calls") or []:
                if not isinstance(call, dict):
                    continue
                fn = call.get("function") or {}
                if isinstance(fn, dict):
                    name = str(fn.get("name") or "").strip()
                    if name and name not in names:
                        names.append(name)
            if names:
                item["tool_calls"] = names[:12]
        result.append(item)
    return result[-max(1, limit) :]


def _peer_is_owner(conn: socket.socket) -> bool:
    """Return True when the AF_UNIX peer is the current OS user.

    Linux exposes peer credentials directly. Other POSIX platforms rely on the
    socket's owner-only filesystem mode; that remains fail-closed against other
    local users because they cannot open the socket path.
    """
    if hasattr(socket, "SO_PEERCRED"):
        raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        _pid, uid, _gid = struct.unpack("3i", raw)
        return uid == os.getuid()
    return True


def _read_request(conn: socket.socket) -> dict[str, Any]:
    conn.settimeout(2.0)
    data = bytearray()
    while len(data) <= MAX_REQUEST_BYTES:
        chunk = conn.recv(min(4096, MAX_REQUEST_BYTES + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
        if b"\n" in chunk:
            break
    if len(data) > MAX_REQUEST_BYTES:
        raise ValueError("request too large")
    line = bytes(data).split(b"\n", 1)[0].strip()
    if not line:
        raise ValueError("empty request")
    payload = json.loads(line.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("request must be a JSON object")
    return payload


def _write_response(conn: socket.socket, payload: dict[str, Any]) -> None:
    encoded = (json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    conn.sendall(encoded)


class LocalSupervisorServer:
    def __init__(
        self,
        cli: Any,
        *,
        runtime_dir: Optional[Path] = None,
        max_message_chars: int = DEFAULT_MAX_MESSAGE_CHARS,
        history_messages: int = DEFAULT_HISTORY_MESSAGES,
    ) -> None:
        self._cli_ref = weakref.ref(cli)
        self.runtime_dir = Path(runtime_dir or _runtime_dir(_active_home()))
        self.max_message_chars = max(256, int(max_message_chars))
        self.history_messages = max(1, min(int(history_messages), 100))
        self.socket_path = self.runtime_dir / f"{_SOCKET_PREFIX}{os.getpid()}{_SOCKET_SUFFIX}"
        self._stop = threading.Event()
        self._listener: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> "LocalSupervisorServer":
        if os.name != "posix" or not hasattr(socket, "AF_UNIX"):
            raise RuntimeError("local supervisor requires POSIX AF_UNIX sockets")
        self.runtime_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
        os.chmod(self.runtime_dir, 0o700)
        self._prune_stale_sockets()
        try:
            self.socket_path.unlink(missing_ok=True)
        except OSError:
            pass
        self._thread = threading.Thread(
            target=self._serve,
            daemon=True,
            name=f"hermes-local-supervisor-{os.getpid()}",
        )
        self._thread.start()
        _ACTIVE_SERVERS.add(self)
        return self

    def stop(self) -> None:
        self._stop.set()
        listener = self._listener
        if listener is not None:
            try:
                listener.close()
            except OSError:
                pass
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=1.0)
        try:
            self.socket_path.unlink(missing_ok=True)
        except OSError:
            pass

    def _prune_stale_sockets(self) -> None:
        for path in self.runtime_dir.glob(f"{_SOCKET_PREFIX}*{_SOCKET_SUFFIX}"):
            stem = path.name[len(_SOCKET_PREFIX) : -len(_SOCKET_SUFFIX)]
            try:
                pid = int(stem)
            except ValueError:
                continue
            if pid == os.getpid():
                continue
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                try:
                    path.unlink()
                except OSError:
                    pass
            except PermissionError:
                continue

    def _serve(self) -> None:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                self._listener = listener
                listener.bind(str(self.socket_path))
                os.chmod(self.socket_path, 0o600)
                listener.listen(8)
                listener.settimeout(0.25)
                while not self._stop.is_set():
                    cli = self._cli_ref()
                    if cli is None or bool(getattr(cli, "_should_exit", False)):
                        break
                    try:
                        conn, _addr = listener.accept()
                    except socket.timeout:
                        continue
                    except OSError:
                        if self._stop.is_set():
                            break
                        continue
                    with conn:
                        try:
                            if not _peer_is_owner(conn):
                                _write_response(conn, {"success": False, "error": "peer uid rejected"})
                                continue
                            request = _read_request(conn)
                            response = self.dispatch(request)
                        except Exception as exc:
                            response = {
                                "success": False,
                                "error": str(exc)[:500],
                                "error_type": type(exc).__name__,
                            }
                        try:
                            _write_response(conn, response)
                        except OSError:
                            pass
        finally:
            self._listener = None
            try:
                self.socket_path.unlink(missing_ok=True)
            except OSError:
                pass

    def dispatch(self, request: dict[str, Any]) -> dict[str, Any]:
        cli = self._cli_ref()
        if cli is None:
            return {"success": False, "error": "Hermes CLI is no longer available"}
        action = str(request.get("action") or "status").strip().lower()

        if action in {"ping", "status"}:
            pending = getattr(cli, "_pending_input", None)
            turn_active = bool(
                getattr(cli, "_interactive_turn", False)
                or getattr(cli, "_agent_running", False)
            )
            tool_started_at = float(getattr(cli, "_tool_start_time", 0.0) or 0.0)
            pending_tool_info = getattr(cli, "_pending_tool_info", None)
            active_tools: list[str] = []
            if isinstance(pending_tool_info, dict):
                active_tools = [
                    str(name)
                    for name, entries in pending_tool_info.items()
                    if entries
                ][:12]
            tool_active = bool(tool_started_at > 0.0 or active_tools)
            return {
                "success": True,
                "pid": os.getpid(),
                "session_id": str(getattr(cli, "session_id", "") or ""),
                "model": str(getattr(cli, "model", "") or ""),
                "provider": str(getattr(cli, "provider", "") or ""),
                "api_mode": str(getattr(cli, "api_mode", "") or ""),
                "agent_running": bool(getattr(cli, "_agent_running", False)),
                "turn_active": turn_active,
                "tool_active": tool_active,
                "active_tools": active_tools,
                "pending_messages": int(pending.qsize()) if pending is not None else 0,
                "cwd": os.getcwd(),
                "socket": str(self.socket_path),
            }

        if action == "history":
            requested = request.get("limit", self.history_messages)
            try:
                limit = max(1, min(int(requested), self.history_messages))
            except (TypeError, ValueError):
                limit = self.history_messages
            return {
                "success": True,
                "session_id": str(getattr(cli, "session_id", "") or ""),
                "messages": _safe_history(
                    cli,
                    limit=limit,
                    max_chars=DEFAULT_HISTORY_CHARS,
                ),
            }

        if action == "interrupt":
            agent = getattr(cli, "agent", None)
            if not bool(getattr(cli, "_agent_running", False)) or agent is None:
                return {"success": True, "interrupted": False, "reason": "idle"}
            from agent.interrupt_compat import request_hard_interrupt

            request_hard_interrupt(agent, "external Katana supervisor")
            return {
                "success": True,
                "interrupted": True,
                "session_id": str(getattr(cli, "session_id", "") or ""),
            }

        text = _bounded_text(request.get("text"), max_chars=self.max_message_chars)
        marked = _external_marker(text)

        if action == "message":
            pending = getattr(cli, "_pending_input", None)
            if pending is None:
                return {"success": False, "error": "Hermes input queue is unavailable"}
            pending.put(marked)
            return {
                "success": True,
                "queued": True,
                "session_id": str(getattr(cli, "session_id", "") or ""),
                "agent_running": bool(getattr(cli, "_agent_running", False)),
            }

        if action == "steer":
            agent = getattr(cli, "agent", None)
            if bool(getattr(cli, "_agent_running", False)) and agent is not None and hasattr(agent, "steer"):
                accepted = bool(agent.steer(marked))
                return {
                    "success": accepted,
                    "mode": "steer",
                    "session_id": str(getattr(cli, "session_id", "") or ""),
                }
            pending = getattr(cli, "_pending_input", None)
            if pending is None:
                return {"success": False, "error": "Hermes input queue is unavailable"}
            pending.put(marked)
            return {
                "success": True,
                "mode": "queued-next-turn",
                "session_id": str(getattr(cli, "session_id", "") or ""),
            }

        return {"success": False, "error": f"unsupported action: {action}"}


def maybe_start_local_supervisor(cli: Any) -> Optional[LocalSupervisorServer]:
    config = _local_control_config(cli)
    if not bool(config.get("enabled", False)):
        return None
    max_chars = config.get("max_message_chars", DEFAULT_MAX_MESSAGE_CHARS)
    history_messages = config.get("history_messages", DEFAULT_HISTORY_MESSAGES)
    return LocalSupervisorServer(
        cli,
        max_message_chars=int(max_chars),
        history_messages=int(history_messages),
    ).start()


def _socket_request(path: Path, payload: dict[str, Any], *, timeout: float = 3.0) -> dict[str, Any]:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(timeout)
        conn.connect(str(path))
        conn.sendall((json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8"))
        data = bytearray()
        while len(data) <= MAX_REQUEST_BYTES:
            chunk = conn.recv(min(4096, MAX_REQUEST_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if b"\n" in chunk:
                break
    line = bytes(data).split(b"\n", 1)[0].strip()
    if not line:
        raise RuntimeError("local supervisor returned an empty response")
    result = json.loads(line.decode("utf-8"))
    if not isinstance(result, dict):
        raise RuntimeError("invalid local supervisor response")
    return result


def list_local_supervisors(profile: str) -> list[dict[str, Any]]:
    root = _runtime_dir(_profile_home(profile))
    if not root.exists():
        return []
    results: list[dict[str, Any]] = []
    for path in sorted(root.glob(f"{_SOCKET_PREFIX}*{_SOCKET_SUFFIX}")):
        try:
            result = _socket_request(path, {"action": "status"}, timeout=0.75)
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError):
            continue
        if result.get("success"):
            results.append(result)
    return results


def request_local_supervisor(
    profile: str,
    payload: dict[str, Any],
    *,
    session_id: Optional[str] = None,
    pid: Optional[int] = None,
) -> dict[str, Any]:
    sessions = list_local_supervisors(profile)
    if session_id:
        sessions = [item for item in sessions if str(item.get("session_id") or "") == session_id]
    if pid is not None:
        sessions = [item for item in sessions if int(item.get("pid") or 0) == int(pid)]
    if not sessions:
        return {"success": False, "error": "no matching live Hermes supervisor session"}
    if len(sessions) > 1:
        return {
            "success": False,
            "error": "multiple live Hermes sessions match; select --session or --pid",
            "matches": sessions,
        }
    path = Path(str(sessions[0]["socket"]))
    return _socket_request(path, payload)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hermes-local-supervisor")
    parser.add_argument("--profile", default="default")
    parser.add_argument("--session")
    parser.add_argument("--pid", type=int)
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("list")
    sub.add_parser("status")
    history = sub.add_parser("history")
    history.add_argument("--limit", type=int, default=DEFAULT_HISTORY_MESSAGES)
    for name in ("message", "steer"):
        cmd = sub.add_parser(name)
        cmd.add_argument("text")
    sub.add_parser("interrupt")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.action == "list":
        result: Any = {"success": True, "sessions": list_local_supervisors(args.profile)}
    else:
        payload: dict[str, Any] = {"action": args.action}
        if args.action in {"message", "steer"}:
            payload["text"] = args.text
        if args.action == "history":
            payload["limit"] = args.limit
        result = request_local_supervisor(
            args.profile,
            payload,
            session_id=args.session,
            pid=args.pid,
        )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if bool(result.get("success")) else 1


def _shutdown_all() -> None:
    for server in list(_ACTIVE_SERVERS):
        try:
            server.stop()
        except Exception:
            pass


atexit.register(_shutdown_all)


if __name__ == "__main__":
    raise SystemExit(main())
