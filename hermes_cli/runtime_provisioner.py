"""Provision managed runtime tools into <install>/.hermes-runtime/.

THE one dep engine (design doc phase 1, item 4): both `hermes update`
(post-update MACHINE_STEPS) and the installers (`--install-phase` after
venv + uv sync) run this same code. The bash/ps1 tool-download
implementations it replaces are deleted in phase 3.

Per tool: resolve pin → check facts + on-disk binary → (salvage from a
legacy location | download) → verify by RUNNING the binary (version
banner must satisfy the pin) → record fact. A tool that cannot be
verified is not recorded — readers then see it as unprovisioned and fall
back to system PATH, and the next update retries.

Progress streams as installer stage-JSON lines when --json is on, so the
GUI install driver renders provisioning natively.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from hermes_constants import get_hermes_home, get_runtime_dir
from hermes_cli.runtime_registry import (
    RuntimeFact,
    load_facts,
    load_pins,
    satisfies,
    save_facts,
)

logger = logging.getLogger(__name__)

_UA = {"User-Agent": "hermes-agent-provisioner"}

# Download endpoints. Version-shaped URL templates, resolved against the
# pin at provision time by the per-tool `latest satisfying` resolvers.
_NODE_DIST_INDEX = "https://nodejs.org/dist/index.json"
_NODE_DIST_TMPL = "https://nodejs.org/dist/{ver}/{name}"
_GH_RELEASES = "https://api.github.com/repos/cli/cli/releases/latest"
_RG_RELEASES = "https://api.github.com/repos/BurntSushi/ripgrep/releases/latest"
_PORTABLE_GIT_TMPL = (
    "https://github.com/git-for-windows/git/releases/download/{tag}/{asset}"
)


def _is_windows() -> bool:
    return sys.platform == "win32"


def _machine_arch() -> str:
    m = platform.machine().lower()
    if m in ("x86_64", "amd64"):
        return "x64"
    if m in ("aarch64", "arm64"):
        return "arm64"
    return m


def _fetch_json(url: str) -> object:
    with urllib.request.urlopen(
        urllib.request.Request(url, headers=_UA), timeout=60
    ) as resp:
        return json.load(resp)


def _download(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(
        urllib.request.Request(url, headers=_UA), timeout=600
    ) as resp, open(dest, "wb") as out:
        shutil.copyfileobj(resp, out)


def _extract(archive: Path, dest: Path) -> None:
    """Extract tar.gz/tgz/zip. dest is wiped first (idempotent staging)."""
    shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True, exist_ok=True)
    name = archive.name.lower()
    if name.endswith((".tar.gz", ".tgz", ".tar.xz")):
        with tarfile.open(archive) as tf:
            tf.extractall(dest, filter="data")
    elif name.endswith(".zip"):
        with zipfile.ZipFile(archive) as zf:
            for info in zf.infolist():
                # extract() RETURNS the path it actually wrote, with the
                # entry name already sanitized (".." stripped, absolute
                # paths made relative). Chmod that, never info.filename:
                # an entry named "../../victim" chmods a file OUTSIDE the
                # destination, which is an arbitrary chmod +x for anyone
                # who can serve us an archive.
                written = Path(zf.extract(info, dest))
                mode = info.external_attr >> 16
                if mode & 0o111 and written.is_file():
                    written.chmod(mode & 0o777)
    else:
        raise ValueError(f"unsupported archive: {archive.name}")


def _flatten_single_dir(dest: Path) -> None:
    """Hoist a lone VERSIONED wrapper dir's contents up one level.

    Most projects nest everything under one dir named for the release
    (``gh_2.97.0_linux_amd64/``, ``node-v26.7.0-linux-x64/``), which would
    otherwise leak the version into every facts path and break on the
    next bump. Some archives unpack flat instead — same tool, different
    platform, in uv's case — so this keys off what is actually there.
    """
    # EVERY entry counts, dotfiles included. Skipping them made a
    # top-level ".config" invisible to this check, so an archive shaped
    # {".config", "wrapper/.config"} looked like a lone wrapper and the
    # move silently replaced the outer file.
    entries = list(dest.iterdir())
    if len(entries) != 1 or not entries[0].is_dir():
        return

    inner = entries[0]
    if inner.name.lower() in _LAYOUT_DIRS:
        return

    # Never overwrite. After the checks above the destination holds only
    # `inner`, so the sole way to collide is a child named like its own
    # parent ("gh/gh"); shutil.move's own error for that case names a
    # temp path and reads like a bug in us. Refuse the whole flatten
    # instead: the unflattened tree is merely ugly, a clobbered file is
    # data loss.
    collisions = [c.name for c in inner.iterdir() if (dest / c.name).exists()]
    if collisions:
        raise RuntimeError(
            f"cannot unwrap {inner.name}/: would overwrite {', '.join(sorted(collisions))}"
        )

    for child in inner.iterdir():
        shutil.move(str(child), dest / child.name)
    inner.rmdir()


def _probe_version(binary: Path, args: list[str] | None = None) -> Optional[str]:
    """Run `<binary> --version`, return the first token that parses as a
    version. None when the binary doesn't run — callers treat that as
    unprovisioned, never as fatal."""
    try:
        out = subprocess.run(
            [str(binary)] + (args or ["--version"]),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    import re as _re

    m = _re.search(r"\d+(?:\.\d+)+", out or "")
    return m.group(0) if m else None


# ─── per-tool provisioning ──────────────────────────────────────────────────


@dataclass
class ToolResult:
    tool: str
    action: str  # "kept" | "salvaged" | "downloaded" | "skipped" | "failed"
    version: Optional[str] = None
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.action != "failed"


def _binary_rel(tool: str) -> str:
    """The facts `path` for each tool in OUR layout (relative, stable)."""
    ext = ".exe" if _is_windows() else ""
    return {
        "node": f"node/bin/node{ext}" if not _is_windows() else "node/node.exe",
        "uv": f"uv/uv{ext}",
        "git": "git/cmd/git.exe",  # windows-only tool for now (phase 16+ adds dugite)
        "gh": f"gh/bin/gh{ext}",
        "ripgrep": f"ripgrep/rg{ext}",
    }[tool]


def _path_dirs(tool: str) -> Optional[list[str]]:
    if tool == "git":
        return ["git/cmd", "git/bin", "git/usr/bin"]
    return None


def _legacy_locations(tool: str) -> list[Path]:
    """Where pre-split installs put this tool (salvage sources)."""
    home = get_hermes_home()
    if tool == "node":
        return [home / "node"]
    if tool == "uv":
        return [home / "bin"]
    if tool == "git" and _is_windows():
        return [home / "git"]
    return []


def _salvage(tool: str, runtime_dir: Path, spec: str) -> Optional[str]:
    """Move a healthy legacy tree in when its version satisfies the pin.
    Returns the version on success. mv beats redownload; a failed or
    unsatisfying tree is left alone for uninstall/doctor."""
    rel = _binary_rel(tool)
    tool_root = runtime_dir / rel.split("/")[0]
    for legacy in _legacy_locations(tool):
        if not legacy.is_dir():
            continue
        # The legacy layout for uv is a bare bin/ dir with the binary in
        # it; for node/git the whole tree maps 1:1.
        candidate_bin = (
            legacy / Path(rel).name if tool == "uv" else legacy / Path(*rel.split("/")[1:])
        )
        version = _probe_version(candidate_bin)
        if version is None or not satisfies(version, spec):
            continue
        shutil.rmtree(tool_root, ignore_errors=True)
        tool_root.parent.mkdir(parents=True, exist_ok=True)
        if tool == "uv":
            tool_root.mkdir(parents=True, exist_ok=True)
            shutil.move(str(candidate_bin), tool_root / candidate_bin.name)
        else:
            shutil.move(str(legacy), tool_root)
        return version
    return None


def _resolve_node_download(spec: str) -> tuple[str, str]:
    """Pick the newest nodejs.org dist satisfying the pin. Returns
    (version_tag, archive_name)."""
    index = _fetch_json(_NODE_DIST_INDEX)
    assert isinstance(index, list)
    arch = _machine_arch()
    plat = {"win32": "win", "darwin": "darwin", "linux": "linux"}[sys.platform]
    ext = "zip" if _is_windows() else "tar.gz"
    for entry in index:  # index.json is newest-first
        ver = entry.get("version", "")
        if satisfies(ver, spec):
            name = f"node-{ver}-{plat}-{arch}.{ext}"
            return ver, name
    raise RuntimeError(f"no nodejs.org dist satisfies {spec!r}")


def _install_node(runtime_dir: Path, spec: str) -> str:
    ver, name = _resolve_node_download(spec)
    dest = runtime_dir / "node"
    with tempfile.TemporaryDirectory() as td:
        archive = Path(td) / name
        _download(_NODE_DIST_TMPL.format(ver=ver, name=name), archive)
        _extract(archive, dest)
    _flatten_single_dir(dest)
    return ver.lstrip("v")


def _install_uv(runtime_dir: Path, spec: str) -> str:
    """uv installs via its official standalone installer, pointed at our
    dir (same mechanism managed_uv.py uses today — UV_UNMANAGED_INSTALL)."""
    dest = runtime_dir / "uv"
    dest.mkdir(parents=True, exist_ok=True)
    if _is_windows():
        script = _download_text("https://astral.sh/uv/install.ps1")
        cmd = ["powershell", "-NoProfile", "-Command", script]
        env = {**os.environ, "UV_INSTALL_DIR": str(dest), "UV_NO_MODIFY_PATH": "1"}
    else:
        script = _download_text("https://astral.sh/uv/install.sh")
        cmd = ["sh", "-c", script]
        env = {**os.environ, "UV_UNMANAGED_INSTALL": str(dest)}
    subprocess.run(cmd, env=env, check=True, capture_output=True, timeout=600)
    binary = runtime_dir / _binary_rel("uv")
    version = _probe_version(binary)
    if version is None or not satisfies(version, spec):
        raise RuntimeError(f"installed uv reports {version!r}, want {spec!r}")
    return version


def _download_text(url: str) -> str:
    with urllib.request.urlopen(
        urllib.request.Request(url, headers=_UA), timeout=60
    ) as resp:
        return resp.read().decode("utf-8")


def _install_gh(runtime_dir: Path, spec: str) -> str:
    release = _fetch_json(_GH_RELEASES)
    assert isinstance(release, dict)
    tag = release.get("tag_name", "")
    if not satisfies(tag, spec):
        raise RuntimeError(f"latest gh {tag} does not satisfy {spec!r}")
    ver = tag.lstrip("v")
    arch = {"x64": "amd64", "arm64": "arm64"}[_machine_arch()]
    if _is_windows():
        name = f"gh_{ver}_windows_{arch}.zip"
    elif sys.platform == "darwin":
        name = f"gh_{ver}_macOS_{arch}.zip"
    else:
        name = f"gh_{ver}_linux_{arch}.tar.gz"
    url = next(
        a["browser_download_url"]
        for a in release["assets"]
        if a["name"] == name
    )
    dest = runtime_dir / "gh"
    with tempfile.TemporaryDirectory() as td:
        archive = Path(td) / name
        _download(url, archive)
        _extract(archive, dest)
    _flatten_single_dir(dest)
    return ver


def _install_ripgrep(runtime_dir: Path, spec: str) -> str:
    release = _fetch_json(_RG_RELEASES)
    assert isinstance(release, dict)
    tag = release.get("tag_name", "")
    if not satisfies(tag, spec):
        raise RuntimeError(f"latest ripgrep {tag} does not satisfy {spec!r}")
    arch = _machine_arch()
    if _is_windows():
        needle = f"{tag}-x86_64-pc-windows-msvc.zip" if arch == "x64" else f"{tag}-aarch64-pc-windows-msvc.zip"
    elif sys.platform == "darwin":
        needle = f"{tag}-x86_64-apple-darwin.tar.gz" if arch == "x64" else f"{tag}-aarch64-apple-darwin.tar.gz"
    else:
        needle = f"{tag}-x86_64-unknown-linux-musl.tar.gz" if arch == "x64" else f"{tag}-aarch64-unknown-linux-gnu.tar.gz"
    asset = next(a for a in release["assets"] if a["name"].endswith(needle))
    dest = runtime_dir / "ripgrep"
    with tempfile.TemporaryDirectory() as td:
        archive = Path(td) / asset["name"]
        _download(asset["browser_download_url"], archive)
        _extract(archive, dest)
    _flatten_single_dir(dest)
    return tag


def _install_git_windows(runtime_dir: Path, spec: str) -> str:
    """PortableGit for win32 (mirrors the install.ps1 pin this replaces).
    darwin/linux git arrives with dugite-native in phase 17."""
    # Pin lives in runtime-pins.json as 2.55.x; PortableGit assets need
    # the full tag. Resolve from the git-for-windows latest release and
    # check satisfaction — same shape as gh/rg.
    release = _fetch_json(
        "https://api.github.com/repos/git-for-windows/git/releases/latest"
    )
    assert isinstance(release, dict)
    tag = release.get("tag_name", "")  # v2.55.0.windows.3
    if not satisfies(tag.removeprefix("v"), spec):
        raise RuntimeError(f"latest PortableGit {tag} does not satisfy {spec!r}")
    arch = "arm64" if _machine_arch() == "arm64" else "64-bit"
    asset = next(
        a
        for a in release["assets"]
        if a["name"].startswith("PortableGit-") and a["name"].endswith(f"-{arch}.7z.exe")
    )
    dest = runtime_dir / "git"
    shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        sfx = Path(td) / asset["name"]
        _download(asset["browser_download_url"], sfx)
        proc = subprocess.run(
            [str(sfx), f"-o{dest}", "-y"], capture_output=True, timeout=600
        )
        if proc.returncode != 0:
            raise RuntimeError(f"PortableGit extraction exited {proc.returncode}")
    version = _probe_version(dest / "cmd" / "git.exe")
    if version is None:
        raise RuntimeError("extracted git.exe does not run")
    return version


_INSTALLERS: dict[str, Callable[[Path, str], str]] = {
    "node": _install_node,
    "uv": _install_uv,
    "gh": _install_gh,
    "ripgrep": _install_ripgrep,
}


def _tool_applies(tool: str) -> bool:
    # git is provisioned on Windows only until dugite lands (phase 17).
    if tool == "git":
        return _is_windows()
    return True


# ─── the provisioning loop ──────────────────────────────────────────────────


def _discard_scratch(scratch: Path) -> None:
    """Delete a provisioning scratch dir, and shrug when the OS says no.

    A scratch file we cannot delete is not a provisioning failure: by
    the time this runs the tool is already unpacked into the runtime
    dir, and the OS reclaims its own temp dir later. On Windows the
    deleter races whatever still holds the artifact open — the
    PortableGit self-extractor outlives its own exit, and Defender
    cannot be disabled on the windows-11-arm image, so it scans the
    downloaded .exe and holds it too. Both surface as WinError 5, which
    used to abort the whole tool AFTER it had been staged.
    """
    # ignore_errors, not onerror/onexc: the callback spelling changed in
    # 3.12 and the deprecated one is removed in 3.14, and nothing here
    # needs the per-file exception — only whether anything survived.
    shutil.rmtree(scratch, ignore_errors=True)
    if scratch.exists():
        logger.debug("scratch dir %s could not be removed — leaving it", scratch)


def _provision_one(
    tool: str,
    entry: dict,
    rt: Path,
    facts: dict[str, RuntimeFact],
    target: str,
    verify_runs: bool = True,
) -> ToolResult:
    """Bring ONE tool to the pinned state. Never raises."""
    rel = _binary_rel(tool, target)

    # Already exactly right? The pin is exact, so this is an equality
    # check, not a range check.
    fact = facts.get(tool)
    if fact is not None and fact.version == entry["version"] and (rt / rel).is_file():
        return ToolResult(tool, "kept", version=fact.version)

    try:
        pin = pinned_file(tool, target, pins={tool: entry})
    except KeyError as exc:
        return ToolResult(tool, "failed", detail=str(exc))

    try:
        td = Path(tempfile.mkdtemp(prefix="hermes-provision-"))
        try:
            _stage(tool, pin, rt / tool, Path(td), target)
        finally:
            _discard_scratch(td)

        binary = rt / rel
        if not binary.is_file():
            return ToolResult(tool, "failed", detail=f"{rel} missing after staging")
        binary.chmod(binary.stat().st_mode | 0o755)

        # Verify by RUNNING it, not by trusting the archive: a cross-arch
        # or half-extracted binary fails here rather than at first use.
        # Skipped when staging FOR another target, where the binary
        # cannot run on this host by definition.
        if verify_runs and _probe_version(binary) is None:
            return ToolResult(tool, "failed", detail="provisioned binary does not run")

        facts[tool] = RuntimeFact(
            version=pin.version, path=rel, path_dirs=_path_dirs(tool, target)
        )
        save_facts(facts, rt)
        return ToolResult(tool, "downloaded", version=pin.version)
    except Exception as exc:  # noqa: BLE001 — per-tool isolation is the contract
        logger.warning("provisioning %s failed: %s", tool, exc)
        return ToolResult(tool, "failed", detail=str(exc))


def provision_tool(
    tool: str,
    runtime_dir: Path | None = None,
    install_root: Path | None = None,
    target: str | None = None,
) -> ToolResult:
    """Provision a single pinned tool.

    Used by the self-heal paths that need exactly one runtime (the
    managed-Node bootstrap) without paying for a full sweep.
    """
    rt = runtime_dir if runtime_dir is not None else get_runtime_dir()
    rt.mkdir(parents=True, exist_ok=True)
    entry = load_pins(install_root).get(tool)
    if entry is None:
        return ToolResult(tool, "failed", detail=f"{tool} is not pinned")
    return _provision_one(tool, entry, rt, load_facts(rt), target or current_target())


def provision_runtimes(
    runtime_dir: Path | None = None,
    install_root: Path | None = None,
    emit: Callable[[dict], None] | None = None,
) -> list[ToolResult]:
    """Bring every pinned tool to a satisfying state. Never raises for a
    single tool — each failure is recorded and the rest proceed (a broken
    ripgrep download must not kill node provisioning)."""
    rt = runtime_dir if runtime_dir is not None else get_runtime_dir()
    rt.mkdir(parents=True, exist_ok=True)
    pins = load_pins(install_root)
    facts = load_facts(rt)
    results: list[ToolResult] = []

    def _emit(result: ToolResult) -> None:
        results.append(result)
        if emit:
            emit(
                {
                    "type": "runtime-tool",
                    "tool": result.tool,
                    "action": result.action,
                    "version": result.version,
                    "detail": result.detail,
                }
            )

    for tool, entry in pins.items():
        spec = entry["version"]
        if not _tool_applies(tool):
            _emit(ToolResult(tool, "skipped", detail="not managed on this platform"))
            continue

        # Already good? Fact recorded, binary present, version satisfies.
        fact = facts.get(tool)
        if fact is not None and (rt / fact.path).is_file() and satisfies(fact.version, spec):
            _emit(ToolResult(tool, "kept", version=fact.version))
            continue

        try:
            salvaged = _salvage(tool, rt, spec)
            if salvaged is not None:
                action, version = "salvaged", salvaged
            else:
                installer = _INSTALLERS.get(tool) if tool != "git" else _install_git_windows
                if installer is None:
                    _emit(ToolResult(tool, "failed", detail="no installer"))
                    continue
                version = installer(rt, spec)
                action = "downloaded"
            # Verify by running THE binary we recorded, not trusting the
            # installer's word.
            binary = rt / _binary_rel(tool)
            probed = _probe_version(binary)
            if probed is None:
                _emit(ToolResult(tool, "failed", detail="provisioned binary does not run"))
                continue
            facts[tool] = RuntimeFact(
                version=version, path=_binary_rel(tool), path_dirs=_path_dirs(tool)
            )
            save_facts(facts, rt)
            _emit(ToolResult(tool, action, version=version))
        except Exception as exc:  # noqa: BLE001 — per-tool isolation is the contract
            logger.warning("provisioning %s failed: %s", tool, exc)
            _emit(ToolResult(tool, "failed", detail=str(exc)))

    return results


def step_provision_runtimes() -> dict:
    """post_update MACHINE_STEPS entry."""
    results = provision_runtimes()
    failed = [r for r in results if not r.ok]
    return {
        "ok": not failed,
        "tools": {r.tool: r.action for r in results},
        **({"error": "; ".join(f"{r.tool}: {r.detail}" for r in failed)} if failed else {}),
    }
