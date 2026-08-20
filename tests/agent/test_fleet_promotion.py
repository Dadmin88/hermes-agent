from __future__ import annotations

import hashlib
import json

import pytest

from agent.fleet_promotion import FleetPromotionAuthorization, FleetPromotionError

HASH = lambda char: "sha256:" + char * 64


def authorization(*, subject_kind: str = "memory", target_kind: str = "project") -> dict[str, object]:
    target_id = {"project": "fleet", "network": "mesh-a", "owner": "kyle"}[target_kind]
    unsigned: dict[str, object] = {
        "version": "fleet-promotion-v1",
        "policy_version": "phase18-v1",
        "subject_kind": subject_kind,
        "subject_key": HASH("8") if subject_kind == "skill" else "memory:" + HASH("3"),
        "source_owner_principal_id": HASH("1"),
        "agent_instance_id": HASH("2"),
        "source_scope": {"kind": "principal", "scope_id": HASH("1")},
        "target_scope": {"kind": target_kind, "scope_id": target_id},
        "source_content_hash": HASH("3"),
        "approved_content_hash": HASH("4"),
        "administrator": {
            "principal_id": HASH("1"),
            "kind": target_kind,
            "generation": 1,
            "binding_hash": HASH("6"),
        },
        "issued_at_ms": 10_000,
        "expires_at_ms": 20_000,
        "verification_digest": HASH("7") if subject_kind == "skill" else None,
        "expected_current_promotion_id": None,
        "rollback_to_promotion_id": None,
        "operation": "promote",
        "authority": "none",
    }
    digest = "sha256:" + hashlib.sha256(
        json.dumps(unsigned, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {**unsigned, "promotion_id": digest}


def test_exact_fleet_promotion_authorization_parses_and_remains_authority_free() -> None:
    parsed = FleetPromotionAuthorization.from_request(authorization(), now_ms=15_000)
    assert parsed.subject_kind == "memory"
    assert parsed.target_scope.kind == "project"
    assert parsed.unsigned_document()["authority"] == "none"


def test_changed_approved_hash_invalidates_exact_promotion_id() -> None:
    document = authorization()
    document["approved_content_hash"] = HASH("9")
    with pytest.raises(FleetPromotionError, match="promotion ID"):
        FleetPromotionAuthorization.from_request(document, now_ms=15_000)


def test_promotion_authorization_expires_fail_closed() -> None:
    with pytest.raises(FleetPromotionError, match="expired"):
        FleetPromotionAuthorization.from_request(authorization(), now_ms=20_000)


def test_promotion_cannot_smuggle_execution_authority() -> None:
    document = authorization()
    document["authority"] = "tool:terminal"
    with pytest.raises(FleetPromotionError, match="execution authority"):
        FleetPromotionAuthorization.from_request(document, now_ms=15_000)


def test_skill_promotion_requires_verification_digest() -> None:
    document = authorization(subject_kind="skill")
    document["verification_digest"] = None
    unsigned = dict(document)
    unsigned.pop("promotion_id")
    document["promotion_id"] = "sha256:" + hashlib.sha256(
        json.dumps(unsigned, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    with pytest.raises(FleetPromotionError, match="verification"):
        FleetPromotionAuthorization.from_request(document, now_ms=15_000)
