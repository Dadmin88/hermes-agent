"""Phase 26 hash-only provenance for Fleet context exposed by Hermes.

This module deliberately records identities and hashes, never memory/skill bodies.
The in-memory ledger is scoped by Fleet ``source_run`` and is snapshotted into
Hermes run finalization before being discarded.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from typing import Any, Mapping

_SCHEMA = "fleet.context-provenance.v1"
_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_RUN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,511}$")
_MAX_RUNS = 256
_MAX_ITEMS = 1024
_MAX_LABEL = 512

_LOCK = threading.RLock()
_RUNS: dict[str, dict[str, dict[str, dict[str, object]]]] = {}


class FleetProvenanceError(RuntimeError):
    """Hash-only Fleet context provenance cannot be recorded safely."""


def _hash(value: object, label: str) -> str:
    if type(value) is not str or _HASH_RE.fullmatch(value) is None:
        raise FleetProvenanceError(f"{label} is invalid")
    return value


def _run_id(value: object) -> str:
    if type(value) is not str or _RUN_RE.fullmatch(value) is None:
        raise FleetProvenanceError("Fleet provenance source run is invalid")
    return value


def _label(value: object, label: str, *, allow_empty: bool = False) -> str:
    if type(value) is not str or len(value.encode("utf-8")) > _MAX_LABEL:
        raise FleetProvenanceError(f"{label} is invalid")
    if not allow_empty and not value:
        raise FleetProvenanceError(f"{label} is invalid")
    return value


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise FleetProvenanceError("Fleet provenance is not canonical JSON") from error


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _record(source_run: str, category: str, item: Mapping[str, object]) -> None:
    source_run = _run_id(source_run)
    if category not in {"memory", "skill_index", "skill_body"}:
        raise FleetProvenanceError("Fleet provenance category is invalid")
    document = dict(item)
    key = _digest(document)
    with _LOCK:
        run = _RUNS.get(source_run)
        if run is None:
            if len(_RUNS) >= _MAX_RUNS:
                raise FleetProvenanceError("Fleet provenance run bound exceeded")
            run = {"memory": {}, "skill_index": {}, "skill_body": {}}
            _RUNS[source_run] = run
        bucket = run[category]
        if key in bucket:
            return
        if len(bucket) >= _MAX_ITEMS:
            raise FleetProvenanceError(
                f"Fleet provenance {category} exposure bound exceeded"
            )
        bucket[key] = document


def record_memory_exposure(
    *,
    source_run: str,
    target: str,
    scope_kind: str,
    scope_id: str,
    content_hash: str,
    origin_run: str,
    provenance: str,
    trust: str,
    promotion_state: str,
    sensitivity: str,
) -> None:
    if target not in {"memory", "user"}:
        raise FleetProvenanceError("Fleet provenance memory target is invalid")
    _record(
        source_run,
        "memory",
        {
            "target": target,
            "scope_kind": _label(scope_kind, "memory scope kind"),
            "scope_id": _label(scope_id, "memory scope id"),
            "content_hash": _hash(content_hash, "memory content hash"),
            "origin_run": _label(origin_run, "memory origin run"),
            "provenance": _label(provenance, "memory provenance"),
            "trust": _label(trust, "memory trust"),
            "promotion_state": _label(promotion_state, "memory promotion state"),
            "sensitivity": _label(sensitivity, "memory sensitivity"),
        },
    )


def record_skill_index_exposure(
    *, source_run: str, name: str, description: str | None
) -> None:
    description_hash = None
    if description is not None:
        _label(description, "skill index description", allow_empty=True)
        description_hash = "sha256:" + hashlib.sha256(description.encode()).hexdigest()
    _record(
        source_run,
        "skill_index",
        {
            "name": _label(name, "skill index name"),
            "description_hash": description_hash,
        },
    )


def record_current_skill_index_exposure(name: str, description: str | None) -> None:
    from agent.fleet_memory_scope import get_fleet_memory

    memory = get_fleet_memory()
    if memory is None:
        return
    record_skill_index_exposure(
        source_run=memory.source_run,
        name=name,
        description=description,
    )


def record_skill_body_exposure(
    *, source_run: str, kind: str, source: str, content_hash: str, trust: str
) -> None:
    if kind not in {"skill", "skill_file"}:
        raise FleetProvenanceError("Fleet provenance skill body kind is invalid")
    _record(
        source_run,
        "skill_body",
        {
            "kind": kind,
            "source": _label(source, "skill body source"),
            "content_hash": _hash(content_hash, "skill body content hash"),
            "trust": _label(trust, "skill body trust"),
        },
    )


def snapshot_fleet_context_provenance(source_run: str) -> dict[str, object]:
    source_run = _run_id(source_run)
    with _LOCK:
        run = _RUNS.get(source_run)
        categories = (
            {"memory": {}, "skill_index": {}, "skill_body": {}} if run is None else run
        )
        body: dict[str, object] = {
            "schema": _SCHEMA,
            "source_run": source_run,
            "memory": sorted(categories["memory"].values(), key=_canonical),
            "skill_index": sorted(categories["skill_index"].values(), key=_canonical),
            "skill_body": sorted(categories["skill_body"].values(), key=_canonical),
            "authority": "none",
        }
    return {**body, "provenance_digest": _digest(body)}


def clear_fleet_context_provenance(source_run: str) -> None:
    source_run = _run_id(source_run)
    with _LOCK:
        _RUNS.pop(source_run, None)


__all__ = [
    "FleetProvenanceError",
    "clear_fleet_context_provenance",
    "record_current_skill_index_exposure",
    "record_memory_exposure",
    "record_skill_body_exposure",
    "record_skill_index_exposure",
    "snapshot_fleet_context_provenance",
]
