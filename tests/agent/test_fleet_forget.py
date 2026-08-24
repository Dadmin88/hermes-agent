from __future__ import annotations

import hashlib
import json

import pytest

from agent.fleet_forget import (
    FleetForgetAuthorization,
    FleetForgetError,
)

P1 = "sha256:" + "1" * 64
B1 = "sha256:" + "2" * 64
AGENT = "sha256:" + "3" * 64


def authorization(*, subject_kind: str = "memory", subject_key: str | None = None):
    if subject_key is None:
        subject_key = (
            "memory:sha256:" + "4" * 64
            if subject_kind == "memory"
            else "sha256:" + "4" * 64
        )
    unsigned = {
        "version": "fleet-forget-v1",
        "policy_version": "phase25-v1",
        "subject_kind": subject_kind,
        "subject_key": subject_key,
        "source_owner_principal_id": P1,
        "agent_instance_id": AGENT,
        "administrator": {
            "principal_id": P1,
            "kind": "owner",
            "generation": 2,
            "binding_hash": B1,
        },
        "issued_at_ms": 10_000,
        "expires_at_ms": 70_000,
        "authority": "none",
    }
    forget_id = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(
                unsigned,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
    )
    return FleetForgetAuthorization.from_request(
        {**unsigned, "forget_id": forget_id}, now_ms=10_001
    )


def test_forget_authorization_is_exact_content_addressed_and_authority_free() -> None:
    item = authorization()
    assert item.to_request()["authority"] == "none"
    assert item.forget_id.startswith("sha256:")

    changed = item.to_request()
    changed["agent_instance_id"] = "sha256:" + "9" * 64
    with pytest.raises(FleetForgetError, match="forget ID"):
        FleetForgetAuthorization.from_request(changed, now_ms=10_001)


def test_forget_rejects_paths_wrong_subject_shapes_and_execution_authority() -> None:
    with pytest.raises(FleetForgetError, match="memory subject"):
        authorization(subject_key="../../MEMORY.md")
    with pytest.raises(FleetForgetError, match="candidate"):
        authorization(subject_kind="skill", subject_key="skills/private")

    changed = authorization().to_request()
    changed["authority"] = "run-anything"
    with pytest.raises(FleetForgetError, match="execution authority"):
        FleetForgetAuthorization.from_request(changed, now_ms=10_001)


def test_forget_rejects_expired_and_extra_fields() -> None:
    item = authorization().to_request()
    with pytest.raises(FleetForgetError, match="expired"):
        FleetForgetAuthorization.from_request(item, now_ms=70_000)

    extra = {**item, "path": "/tmp/anything"}
    with pytest.raises(FleetForgetError, match="invalid shape"):
        FleetForgetAuthorization.from_request(extra, now_ms=10_001)
