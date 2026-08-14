"""The ONE place that turns runtime-registry facts into process environment.

Every Hermes-spawned subprocess that should see managed tools gets its
PATH (and tool-specific env) from here — locators, gateway spawns, the
desktop backend (mirrored in apps/desktop/electron/backend-env.ts; a
cross-language test keeps the two in lockstep). Managed tools go at the
FRONT of PATH so they override system ones uniformly.

Also owns per-tool environment: npm's package cache is pointed into the
install's runtime cache dir so `~/.npm` stops accumulating install-coupled
state.

Design doc: .hermes/plans/2026-08-12_hermes-home-lifetime-split.md (phase 1).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Mapping, Optional

from hermes_constants import get_runtime_dir
from hermes_cli.runtime_registry import RuntimeFact, load_facts

__all__ = [
    "managed_path_dirs",
    "managed_tool_env",
    "runtime_cache_dir",
    "with_managed_runtimes",
]

# PATH assembly order. Deliberate, stable, and data — not emergent from
# dict iteration. node before uv (npm shims may exec node), git's multi-dir
# spread preserved via pathDirs.
_PATH_ORDER: tuple[str, ...] = ("node", "uv", "git", "gh", "ripgrep")


def runtime_cache_dir(runtime_dir: Path | None = None) -> Path:
    """Install-keyed cache root: <runtime dir>/cache."""
    base = runtime_dir if runtime_dir is not None else get_runtime_dir()
    return base / "cache"


def _dirs_for(fact: RuntimeFact, base: Path) -> list[Path]:
    if fact.path_dirs is not None:
        return [base / d for d in fact.path_dirs]
    return [(base / fact.path).parent]


def managed_path_dirs(runtime_dir: Path | None = None) -> list[Path]:
    """Existing bin dirs of every provisioned tool, in assembly order.

    Tools absent from facts (or recorded but vanished) contribute nothing:
    an unprovisioned install degrades to system tools instead of shipping
    dead PATH entries.
    """
    base = runtime_dir if runtime_dir is not None else get_runtime_dir()
    facts = load_facts(base)
    dirs: list[Path] = []
    for tool in _PATH_ORDER:
        fact = facts.get(tool)
        if fact is None or not (base / fact.path).is_file():
            continue
        for d in _dirs_for(fact, base):
            if d.is_dir() and d not in dirs:
                dirs.append(d)
    return dirs


def managed_tool_env(runtime_dir: Path | None = None) -> dict[str, str]:
    """Tool-specific env for managed runtimes.

    - npm_config_cache: npm's package cache → install-keyed cache dir,
      only when node is managed (a system node keeps the user's ~/.npm).
    """
    base = runtime_dir if runtime_dir is not None else get_runtime_dir()
    facts = load_facts(base)
    env: dict[str, str] = {}
    node = facts.get("node")
    if node is not None and (base / node.path).is_file():
        env["npm_config_cache"] = str(runtime_cache_dir(base) / "npm")
    return env


def with_managed_runtimes(
    env: Optional[Mapping[str, str]] = None,
    runtime_dir: Path | None = None,
) -> dict[str, str]:
    """Return a copy of *env* (default: os.environ) with managed tool dirs
    prepended to PATH and tool env applied. The single entry point —
    callers never assemble PATH fragments themselves."""
    result = dict(os.environ if env is None else env)
    dirs = managed_path_dirs(runtime_dir)
    if dirs:
        path_key = next((k for k in result if k.upper() == "PATH"), "PATH")
        existing = result.get(path_key, "")
        prefix = os.pathsep.join(str(d) for d in dirs)
        result[path_key] = f"{prefix}{os.pathsep}{existing}" if existing else prefix
    # Tool env never clobbers explicit caller settings.
    for key, value in managed_tool_env(runtime_dir).items():
        result.setdefault(key, value)
    return result
