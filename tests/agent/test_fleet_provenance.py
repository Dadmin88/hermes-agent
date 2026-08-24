from __future__ import annotations

import json

from agent.fleet_provenance import (
    clear_fleet_context_provenance,
    record_memory_exposure,
    record_skill_body_exposure,
    record_skill_index_exposure,
    record_terminal_command,
    snapshot_fleet_context_provenance,
)

RUN = "fleet-execution-26"
HASH1 = "sha256:" + "1" * 64
HASH2 = "sha256:" + "2" * 64


def teardown_function() -> None:
    clear_fleet_context_provenance(RUN)


def test_hash_only_provenance_is_deduplicated_and_body_free() -> None:
    record_memory_exposure(
        source_run=RUN,
        target="memory",
        scope_kind="principal",
        scope_id=HASH1,
        content_hash=HASH2,
        origin_run="fleet-origin-1",
        provenance="fleet-run-v1",
        trust="run-derived",
        promotion_state="private",
        sensitivity="private",
    )
    record_memory_exposure(
        source_run=RUN,
        target="memory",
        scope_kind="principal",
        scope_id=HASH1,
        content_hash=HASH2,
        origin_run="fleet-origin-1",
        provenance="fleet-run-v1",
        trust="run-derived",
        promotion_state="private",
        sensitivity="private",
    )
    record_skill_index_exposure(
        source_run=RUN,
        name="safe-helper",
        description="Useful helper text that must not be stored verbatim",
    )
    record_skill_body_exposure(
        source_run=RUN,
        kind="skill",
        source="safe-helper",
        content_hash=HASH1,
        trust="learned-promoted",
    )
    record_terminal_command(
        source_run=RUN,
        arguments={"command": "printf super-secret-command", "timeout": 30},
    )

    document = snapshot_fleet_context_provenance(RUN)
    assert document["schema"] == "fleet.context-provenance.v1"
    assert document["source_run"] == RUN
    assert document["authority"] == "none"
    assert document["provenance_digest"].startswith("sha256:")
    assert len(document["memory"]) == 1
    assert document["memory"][0]["content_hash"] == HASH2
    assert document["skill_index"][0]["name"] == "safe-helper"
    assert document["skill_index"][0]["description_hash"].startswith("sha256:")
    assert document["skill_body"][0]["content_hash"] == HASH1
    assert document["terminal_command"][0]["arguments_digest"].startswith("sha256:")
    assert document["terminal_command"][0]["argument_keys"] == ["command", "timeout"]
    serialized = json.dumps(document)
    assert "Useful helper text" not in serialized
    assert "super-secret-command" not in serialized


def test_clear_removes_transient_exposures_but_keeps_valid_empty_snapshot() -> None:
    record_skill_body_exposure(
        source_run=RUN,
        kind="skill_file",
        source="safe-helper/reference.md",
        content_hash=HASH2,
        trust="immutable-agency-base",
    )
    assert snapshot_fleet_context_provenance(RUN)["skill_body"]
    clear_fleet_context_provenance(RUN)
    empty = snapshot_fleet_context_provenance(RUN)
    assert empty["memory"] == []
    assert empty["skill_index"] == []
    assert empty["skill_body"] == []
    assert empty["terminal_command"] == []
