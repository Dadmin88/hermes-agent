from __future__ import annotations

from dataclasses import replace

import pytest

from agent.fleet_runtime_material import (
    FleetRuntimeMaterialError,
    FleetRuntimeMaterialHandle,
    FleetVaultBinding,
    fleet_vault_scope,
    get_fleet_vault,
    redeem_broker_material,
    redeem_environment_material,
    redeem_file_material,
    validate_fleet_vault_expiry,
)
from hermes_secure_store import (
    InjectionTarget,
    PrincipalContext,
    RunContext,
    ScopeRef,
    VaultStore,
)

P1 = "sha256:" + "1" * 64
B1 = "sha256:" + "2" * 64
AUTH = "sha256:" + "3" * 64


def handle(
    raw: str = "hvh1_" + "a" * 32,
    *,
    kind: str = "env",
    target: str = "PROVIDER_KEY",
    expires: int = 10_000,
) -> FleetRuntimeMaterialHandle:
    return FleetRuntimeMaterialHandle(
        handle=raw,
        injection_kind=kind,
        injection_target=target,
        version=1,
        expires_at_ms=expires,
    )


def binding(*handles: FleetRuntimeMaterialHandle) -> FleetVaultBinding:
    return FleetVaultBinding(
        run_id="fleet-run-one",
        run_authority_hash=AUTH,
        handles=tuple(handles),
    )


def test_binding_round_trip_repr_and_context_scope_do_not_expose_handles() -> None:
    item = handle()
    bound = binding(item)
    payload = bound.to_request()
    assert FleetVaultBinding.from_request(payload) == bound
    assert item.handle not in repr(item)
    assert item.handle not in repr(bound)
    assert get_fleet_vault() is None
    with fleet_vault_scope(bound):
        assert get_fleet_vault() is bound
    assert get_fleet_vault() is None


def test_binding_rejects_reserved_control_environment_and_duplicates() -> None:
    for target in (
        "API_SERVER_KEY",
        "HERMES_HOME",
        "FLEET_AUTHORITY",
        "DOCKER_HOST",
        "SSH_AUTH_SOCK",
        "PATH",
    ):
        with pytest.raises(FleetRuntimeMaterialError, match="control environment"):
            handle(target=target)

    item = handle()
    with pytest.raises(FleetRuntimeMaterialError, match="handles"):
        binding(item, item)
    with pytest.raises(FleetRuntimeMaterialError, match="handles"):
        binding(item, replace(item, handle="hvh1_" + "b" * 32))


def test_binding_expiry_fails_closed() -> None:
    bound = binding(handle(expires=100))
    validate_fleet_vault_expiry(bound, now_ms=99)
    with pytest.raises(FleetRuntimeMaterialError, match="expired"):
        validate_fleet_vault_expiry(bound, now_ms=100)


def test_real_store_redeems_env_file_and_broker_material_only_inside_scope(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    clock = [1_000]
    root = (tmp_path / "custody").absolute()
    custody = VaultStore(root, now_ms=lambda: clock[0])
    principal = PrincipalContext(
        principal_id=P1,
        principal_kind="owner",
        generation=1,
        binding_hash=B1,
        scopes=(ScopeRef("principal", P1),),
    )
    refs = (
        custody.put(
            "env-value",
            owner=principal,
            scope=ScopeRef("principal", P1),
            injection=InjectionTarget("env", "PROVIDER_KEY"),
        ),
        custody.put(
            b"file-bytes",
            owner=principal,
            scope=ScopeRef("principal", P1),
            injection=InjectionTarget("file", "provider.pem"),
        ),
        custody.put(
            "broker-value",
            owner=principal,
            scope=ScopeRef("principal", P1),
            injection=InjectionTarget("broker", "provider.auth"),
        ),
    )
    run = RunContext(
        principal=principal,
        run_id="fleet-run-one",
        run_authority_hash=AUTH,
        deadline_ms=9_999_999_999_999,
    )
    minted = custody.mint_run_handles(refs, run=run)
    bound = FleetVaultBinding(
        run_id=run.run_id,
        run_authority_hash=AUTH,
        handles=tuple(
            FleetRuntimeMaterialHandle(
                handle=item.handle,
                injection_kind=item.injection.kind,
                injection_target=item.injection.target,
                version=item.version,
                expires_at_ms=item.expires_at_ms,
            )
            for item in minted
        ),
    )
    monkeypatch.setenv("HERMES_VAULT_HOME", str(root))

    assert redeem_environment_material() == {}
    assert redeem_file_material() == {}
    with pytest.raises(FleetRuntimeMaterialError, match="no Fleet Vault"):
        redeem_broker_material("provider.auth")

    with fleet_vault_scope(bound):
        assert redeem_environment_material() == {"PROVIDER_KEY": "env-value"}
        assert redeem_file_material() == {"provider.pem": b"file-bytes"}
        assert redeem_broker_material("provider.auth") == "broker-value"
        with pytest.raises(FleetRuntimeMaterialError, match="not authorized"):
            redeem_broker_material("other.auth")

    audit_text = repr(custody.audit_records(limit=50))
    assert "env-value" not in audit_text
    assert "file-bytes" not in audit_text
    assert "broker-value" not in audit_text
    for item in minted:
        assert item.handle not in audit_text
