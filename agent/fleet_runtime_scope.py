"""Run-scoped Fleet execution binding carried only through ContextVar state."""

from __future__ import annotations

import re
from contextlib import contextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass
from typing import Iterator

_CONTAINER_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_IMAGE_RE = re.compile(
    r"^(?:sha256:[0-9a-f]{64}|[a-z0-9][a-z0-9./_-]{0,254}@sha256:[0-9a-f]{64})$"
)


class FleetRuntimeScopeError(ValueError):
    """A Fleet run-scoped runtime binding is malformed or overbroad."""


@dataclass(frozen=True, slots=True)
class FleetRuntimeBinding:
    version: str
    container_id: str
    plan_fingerprint: str
    image: str
    toolsets: tuple[str, ...]
    max_iterations: int

    def __post_init__(self) -> None:
        if self.version != "fleet-run-v1":
            raise FleetRuntimeScopeError("unsupported Fleet runtime version")
        if (
            type(self.container_id) is not str
            or _CONTAINER_ID_RE.fullmatch(self.container_id) is None
        ):
            raise FleetRuntimeScopeError("Fleet runtime container ID is invalid")
        if (
            type(self.plan_fingerprint) is not str
            or _HASH_RE.fullmatch(self.plan_fingerprint) is None
        ):
            raise FleetRuntimeScopeError("Fleet runtime plan fingerprint is invalid")
        if type(self.image) is not str or _IMAGE_RE.fullmatch(self.image) is None:
            raise FleetRuntimeScopeError("Fleet runtime image must be digest-pinned")
        if type(self.toolsets) not in {tuple, list}:
            raise FleetRuntimeScopeError("Fleet runtime toolsets are invalid")
        toolsets = tuple(self.toolsets)
        if toolsets != ("fleet-terminal",):
            raise FleetRuntimeScopeError(
                "Fleet runtime toolsets must be exactly ['fleet-terminal']"
            )
        object.__setattr__(self, "toolsets", toolsets)
        if (
            isinstance(self.max_iterations, bool)
            or type(self.max_iterations) is not int
            or not 1 <= self.max_iterations <= 32
        ):
            raise FleetRuntimeScopeError(
                "Fleet runtime max_iterations must be between 1 and 32"
            )

    @classmethod
    def from_request(cls, value: object) -> "FleetRuntimeBinding":
        if type(value) is not dict or set(value) != {
            "version",
            "container_id",
            "plan_fingerprint",
            "image",
            "toolsets",
            "max_iterations",
        }:
            raise FleetRuntimeScopeError("fleet_runtime has an invalid shape")
        return cls(
            version=value["version"],
            container_id=value["container_id"],
            plan_fingerprint=value["plan_fingerprint"],
            image=value["image"],
            toolsets=value["toolsets"],
            max_iterations=value["max_iterations"],
        )

    def to_request(self) -> dict[str, object]:
        return {
            "version": self.version,
            "container_id": self.container_id,
            "plan_fingerprint": self.plan_fingerprint,
            "image": self.image,
            "toolsets": list(self.toolsets),
            "max_iterations": self.max_iterations,
        }


_current_fleet_runtime: ContextVar[FleetRuntimeBinding | None] = ContextVar(
    "fleet_runtime_binding",
    default=None,
)


def get_fleet_runtime() -> FleetRuntimeBinding | None:
    return _current_fleet_runtime.get()


def set_fleet_runtime(
    binding: FleetRuntimeBinding | None,
) -> Token[FleetRuntimeBinding | None]:
    if binding is not None and type(binding) is not FleetRuntimeBinding:
        raise FleetRuntimeScopeError("Fleet runtime binding is invalid")
    return _current_fleet_runtime.set(binding)


def reset_fleet_runtime(token: Token[FleetRuntimeBinding | None]) -> None:
    _current_fleet_runtime.reset(token)


@contextmanager
def fleet_runtime_scope(
    binding: FleetRuntimeBinding | None,
) -> Iterator[None]:
    token = set_fleet_runtime(binding)
    try:
        yield
    finally:
        reset_fleet_runtime(token)
