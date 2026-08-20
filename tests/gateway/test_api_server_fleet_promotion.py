from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from agent.fleet_memory_scope import (
    FleetMemoryBinding,
    FleetMemoryScopeRef,
    fleet_memory_scope,
)
from gateway.config import PlatformConfig
from gateway.platforms.api_server import APIServerAdapter
from hermes_constants import reset_hermes_home_override, set_hermes_home_override
from tools.memory_tool import MemoryStore

P1 = "sha256:" + "1" * 64
B1 = "sha256:" + "2" * 64
AGENT = "sha256:" + "3" * 64
ADMIN = P1
ADMIN_BINDING = "sha256:" + "5" * 64


def memory() -> FleetMemoryBinding:
    private = FleetMemoryScopeRef("principal", P1)
    return FleetMemoryBinding(
        version="fleet-memory-v1",
        principal_id=P1,
        principal_kind="owner",
        principal_generation=1,
        principal_binding_hash=B1,
        agent_instance_id=AGENT,
        source_run="run-one",
        read_scopes=(private,),
        write_scope=private,
        retention_until_ms=None,
    )


def app_for(adapter: APIServerAdapter) -> web.Application:
    app = web.Application()
    app.router.add_get("/v1/capabilities", adapter._handle_capabilities)
    app.router.add_post(
        "/v1/fleet/promotions/prepare", adapter._handle_fleet_promotion_prepare
    )
    app.router.add_post(
        "/v1/fleet/promotions/commit", adapter._handle_fleet_promotion_commit
    )
    app.router.add_post(
        "/v1/fleet/promotions/rollback", adapter._handle_fleet_promotion_rollback
    )
    app.router.add_post(
        "/v1/fleet/promotions/history", adapter._handle_fleet_promotion_history
    )
    return app


def promotion_authorization(
    *,
    source_hash: str,
    approved_hash: str,
    expected_current: str | None = None,
    issued_at_ms: int | None = None,
) -> dict[str, object]:
    issued = int(time.time() * 1000) if issued_at_ms is None else issued_at_ms
    unsigned: dict[str, object] = {
        "version": "fleet-promotion-v1",
        "policy_version": "phase18-v1",
        "subject_kind": "memory",
        "subject_key": "memory:" + source_hash,
        "source_owner_principal_id": P1,
        "agent_instance_id": AGENT,
        "source_scope": {"kind": "principal", "scope_id": P1},
        "target_scope": {"kind": "project", "scope_id": "fleet"},
        "source_content_hash": source_hash,
        "approved_content_hash": approved_hash,
        "administrator": {
            "principal_id": ADMIN,
            "kind": "project",
            "generation": 1,
            "binding_hash": ADMIN_BINDING,
        },
        "issued_at_ms": issued,
        "expires_at_ms": issued + 60_000,
        "verification_digest": None,
        "expected_current_promotion_id": expected_current,
        "rollback_to_promotion_id": None,
        "operation": "promote",
        "authority": "none",
    }
    payload = json.dumps(
        unsigned,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return {
        **unsigned,
        "promotion_id": "sha256:" + hashlib.sha256(payload).hexdigest(),
    }


@pytest.fixture(autouse=True)
def isolated_home(tmp_path: Path):
    home = tmp_path / "hermes"
    home.mkdir()
    token = set_hermes_home_override(home)
    try:
        yield
    finally:
        reset_hermes_home_override(token)


def seed_private_memory(content: str) -> tuple[FleetMemoryBinding, str]:
    item = memory()
    with fleet_memory_scope(item):
        store = MemoryStore(memory_char_limit=10_000, user_char_limit=10_000)
        store.load_from_disk()
        result = store.add("memory", content)
        assert result["success"] is True
    return item, MemoryStore._entry_hash(content)


@pytest.mark.asyncio
async def test_capabilities_advertise_phase18_learning_promotion() -> None:
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={}))
    async with TestClient(TestServer(app_for(adapter))) as client:
        response = await client.get("/v1/capabilities")
        body = await response.json()
    assert response.status == 200
    assert body["features"]["fleet_learning_promotion"] is True


@pytest.mark.asyncio
async def test_memory_promotion_prepare_commit_and_history_api() -> None:
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={}))
    item, source_hash = seed_private_memory("Contact dev@example.com after release")

    async with TestClient(TestServer(app_for(adapter))) as client:
        response = await client.post(
            "/v1/fleet/promotions/prepare",
            json={
                "subject_kind": "memory",
                "target": "memory",
                "source_scope": item.write_scope.to_request(),
                "source_content_hash": source_hash,
                "source_owner_principal_id": P1,
                "agent_instance_id": AGENT,
            },
        )
        prepared_body = await response.json()
        assert response.status == 200
        prepared = prepared_body["prepared"]
        assert prepared["approved_content_hash"] != source_hash
        assert prepared["sanitized"] is True
        assert prepared["authority"] == "none"

        authorization = promotion_authorization(
            source_hash=source_hash,
            approved_hash=prepared["approved_content_hash"],
        )
        response = await client.post(
            "/v1/fleet/promotions/commit",
            json={"authorization": authorization, "target": "memory"},
        )
        commit_body = await response.json()
        assert response.status == 200
        result = commit_body["result"]
        assert result["promotion_id"] == authorization["promotion_id"]
        assert result["authority"] == "none"

        response = await client.post(
            "/v1/fleet/promotions/history",
            json={
                "subject_kind": "memory",
                "subject_key": "memory:" + source_hash,
                "source_owner_principal_id": P1,
                "agent_instance_id": AGENT,
                "source_scope": item.write_scope.to_request(),
                "target_scope": {"kind": "project", "scope_id": "fleet"},
            },
        )
        history_body = await response.json()
        assert response.status == 200
        history = history_body["result"]
        assert history["current_promotion_id"] == authorization["promotion_id"]
        assert history["history"] == [authorization["promotion_id"]]
        assert history["records"][0]["approved_content_hash"] == prepared[
            "approved_content_hash"
        ]
        assert history["authority"] == "none"


@pytest.mark.asyncio
async def test_promotion_api_rejects_tampered_and_expired_authorizations() -> None:
    adapter = APIServerAdapter(PlatformConfig(enabled=True, extra={}))
    item, source_hash = seed_private_memory("safe release fact")

    async with TestClient(TestServer(app_for(adapter))) as client:
        response = await client.post(
            "/v1/fleet/promotions/prepare",
            json={
                "subject_kind": "memory",
                "target": "memory",
                "source_scope": item.write_scope.to_request(),
                "source_content_hash": source_hash,
                "source_owner_principal_id": P1,
                "agent_instance_id": AGENT,
            },
        )
        prepared = (await response.json())["prepared"]

        tampered = promotion_authorization(
            source_hash=source_hash,
            approved_hash=prepared["approved_content_hash"],
        )
        tampered["authority"] = "execute"
        response = await client.post(
            "/v1/fleet/promotions/commit",
            json={"authorization": tampered, "target": "memory"},
        )
        body = await response.json()
        assert response.status == 409
        assert body["error"]["code"] == "fleet_promotion_commit_failed"

        expired = promotion_authorization(
            source_hash=source_hash,
            approved_hash=prepared["approved_content_hash"],
            issued_at_ms=1,
        )
        response = await client.post(
            "/v1/fleet/promotions/commit",
            json={"authorization": expired, "target": "memory"},
        )
        body = await response.json()
        assert response.status == 409
        assert body["error"]["code"] == "fleet_promotion_commit_failed"
