from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from agent.fleet_skill_learning_scope import (
    FleetSkillFilesystemNeed,
    FleetSkillLearningBinding,
)
from agent.sensitive_interception import classify_sensitive_text
from tools import skills_guard
from tools.fleet_skill_candidates import (
    _METADATA_FILE,
    _bundle_manifest,
    _candidate_root,
    _load_existing_metadata,
    _private_file,
    _write_metadata,
)
from tools.fleet_skill_quarantine import (
    FleetSkillQuarantineError,
    quarantine_skill_candidate,
)

_VERIFIER_VERSION = "fleet-skill-verification-v1"
_RUNTIME_VERSION = "fleet-skill-bwrap-v1"
_FINAL_TEST_STATES = frozenset({"verified", "failed"})
_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,511}$")
_MAX_CHECKS = 128
_RUNTIME_TIMEOUT_SECONDS = 8
_RUNTIME_CPU_SECONDS = 3
_RUNTIME_ADDRESS_SPACE_BYTES = 256 * 1024 * 1024
_RUNTIME_FILE_BYTES = 4 * 1024 * 1024
_RUNTIME_OPEN_FILES = 64
_RUNTIME_PROCESSES = 16


class FleetSkillVerificationError(RuntimeError):
    """A quarantined learned-skill candidate cannot be verified safely."""


@dataclass(frozen=True, slots=True, order=True)
class VerificationCheck:
    category: str
    name: str
    passed: bool
    detail: str

    def to_document(self) -> dict[str, object]:
        return {
            "category": self.category,
            "name": self.name,
            "passed": self.passed,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class FleetSkillVerificationResult:
    candidate_id: str
    name: str
    state: str
    content_hash: str
    quarantine_digest: str
    verification_digest: str
    checks: tuple[VerificationCheck, ...]

    @property
    def verified(self) -> bool:
        return self.state == "verified"


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
        raise FleetSkillVerificationError(
            "verification evidence is not canonical JSON"
        ) from error


def _sha256(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _check(category: str, name: str, passed: bool, detail: str) -> VerificationCheck:
    return VerificationCheck(
        category=category,
        name=name,
        passed=bool(passed),
        detail=detail[:512],
    )


def _ordered_checks(checks: Iterable[VerificationCheck]) -> tuple[VerificationCheck, ...]:
    ordered = tuple(sorted(checks))
    if len(ordered) > _MAX_CHECKS:
        raise FleetSkillVerificationError(
            "verification exceeded the bounded result surface"
        )
    return ordered


def _binding_from_metadata(metadata: Mapping[str, Any]) -> FleetSkillLearningBinding:
    principal = metadata.get("principal")
    scope = metadata.get("scope")
    provenance = metadata.get("provenance")
    network = metadata.get("network_needs")
    filesystem = metadata.get("filesystem_needs")
    tools = metadata.get("tools")
    protected_material = metadata.get("secret_needs")
    if (
        type(principal) is not dict
        or type(scope) is not dict
        or type(provenance) is not dict
        or type(network) is not dict
        or type(filesystem) is not list
        or type(tools) is not list
        or type(protected_material) is not list
    ):
        raise FleetSkillVerificationError("candidate capability manifest is malformed")
    try:
        return FleetSkillLearningBinding(
            principal_id=principal["principal_id"],
            principal_kind=principal["kind"],
            principal_generation=principal["generation"],
            principal_binding_hash=principal["binding_hash"],
            agent_instance_id=metadata["agent_instance_id"],
            source_run=metadata["source_run"],
            scope_kind=scope["kind"],
            scope_id=scope["scope_id"],
            run_authority_hash=provenance["run_authority_hash"],
            recipe_hash=provenance["recipe_hash"],
            resolved_recipe_hash=provenance["resolved_recipe_hash"],
            plan_fingerprint=provenance["plan_fingerprint"],
            capabilities_hash=provenance["capabilities_hash"],
            target_digest=provenance["target_digest"],
            toolsets=tuple(tools),
            filesystem_needs=tuple(
                FleetSkillFilesystemNeed.from_request(item) for item in filesystem
            ),
            network_mode=network["mode"],
            network_policy_hash=network["policy_hash"],
            secret_need_fingerprints=tuple(protected_material),
        )
    except (KeyError, TypeError, ValueError, RuntimeError) as error:
        raise FleetSkillVerificationError(
            "candidate capability manifest is invalid"
        ) from error


def _text_files(
    candidate_dir: Path, observed_files: Iterable[Mapping[str, object]]
) -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    for item in observed_files:
        rel = item.get("path")
        if type(rel) is not str:
            continue
        path = candidate_dir / rel
        if path.name != "SKILL.md" and path.suffix.lower() not in skills_guard.SCANNABLE_EXTENSIONS:
            continue
        try:
            result.append((rel, path.read_text(encoding="utf-8")))
        except (OSError, UnicodeDecodeError) as error:
            raise FleetSkillVerificationError(
                "candidate text cannot be re-read for verification"
            ) from error
    return result


def _static_analysis_checks(
    candidate_dir: Path,
    observed_files: Iterable[Mapping[str, object]],
) -> list[VerificationCheck]:
    serious = 0
    syntax_failures = 0
    scanned = 0
    for item in observed_files:
        rel = item.get("path")
        if type(rel) is not str:
            continue
        path = candidate_dir / rel
        scanned += 1
        try:
            findings = skills_guard.scan_file(path, rel)
        except Exception as error:
            raise FleetSkillVerificationError("static analysis could not complete") from error
        serious += sum(
            1 for finding in findings if finding.severity in {"high", "critical"}
        )
        if path.suffix.lower() == ".py":
            try:
                source = path.read_text(encoding="utf-8")
                compile(source, rel, "exec")
            except (OSError, UnicodeDecodeError, SyntaxError):
                syntax_failures += 1
    return [
        _check(
            "static-analysis",
            "guard-scan",
            serious == 0,
            f"files={scanned};high_or_critical={serious}",
        ),
        _check(
            "positive-test",
            "python-syntax",
            syntax_failures == 0,
            f"syntax_failures={syntax_failures}",
        ),
    ]


def _sensitive_material_check(text_files: Iterable[tuple[str, str]]) -> VerificationCheck:
    finding_count = 0
    uncertain = False
    for _rel, text in text_files:
        findings, _redacted, item_uncertain = classify_sensitive_text(text)
        finding_count += len(findings)
        uncertain = uncertain or item_uncertain
    return _check(
        "secret-scan",
        "sensitive-material",
        finding_count == 0 and not uncertain,
        f"findings={finding_count};uncertain={str(uncertain).lower()}",
    )


def _capability_manifest_check(
    metadata: Mapping[str, Any],
    expected_binding: FleetSkillLearningBinding | None,
) -> tuple[VerificationCheck, FleetSkillLearningBinding, str]:
    binding = _binding_from_metadata(metadata)
    matches = expected_binding is None or binding == expected_binding
    manifest_hash = _sha256(_canonical(binding.to_request()))
    return (
        _check(
            "capability-manifest",
            "exact-source-envelope",
            matches,
            "exact binding" if matches else "binding mismatch",
        ),
        binding,
        manifest_hash,
    )


def _copy_bundle(
    candidate_dir: Path,
    observed_files: Iterable[Mapping[str, object]],
    destination: Path,
) -> None:
    destination.mkdir(mode=0o755, parents=False, exist_ok=False)
    for item in observed_files:
        rel = item.get("path")
        if type(rel) is not str:
            raise FleetSkillVerificationError("candidate manifest contains an invalid path")
        source = candidate_dir / rel
        target = destination / rel
        try:
            source_info = source.lstat()
        except OSError as error:
            raise FleetSkillVerificationError("candidate bundle changed while copying") from error
        if stat.S_ISLNK(source_info.st_mode) or not stat.S_ISREG(source_info.st_mode):
            raise FleetSkillVerificationError("candidate bundle contains an unsafe entry")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.parent.chmod(0o755)
        shutil.copyfile(source, target)
        target.chmod(0o644)


def _runtime_harness() -> str:
    # This is fixed verifier code. Candidate files are read/compiled but never
    # imported or executed. Dynamic checks exercise the disposable runtime
    # boundary itself rather than trusting candidate-controlled test code.
    return r'''
import json
import os
import pathlib
import resource
import socket

for kind, requested in (
    (resource.RLIMIT_CPU, 3),
    (resource.RLIMIT_AS, 268435456),
    (resource.RLIMIT_FSIZE, 4194304),
    (resource.RLIMIT_NOFILE, 64),
    (resource.RLIMIT_NPROC, 16),
    (resource.RLIMIT_CORE, 0),
):
    soft, hard = resource.getrlimit(kind)
    target = requested if hard == resource.RLIM_INFINITY else min(requested, hard)
    if soft == resource.RLIM_INFINITY or soft > target:
        resource.setrlimit(kind, (target, hard))

checks = []
def add(category, name, passed, detail):
    checks.append({"category": category, "name": name, "passed": bool(passed), "detail": detail})

skill = pathlib.Path("/skill")
try:
    files = sorted(path for path in skill.rglob("*") if path.is_file())
    payload_bytes = sum(len(path.read_bytes()) for path in files)
    add("positive-test", "bundle-readable", any(path.name == "SKILL.md" for path in files), f"files={len(files)};bytes={payload_bytes}")
except Exception:
    add("positive-test", "bundle-readable", False, "bundle read failed")

try:
    probe = pathlib.Path("/tmp/fleet-verification-probe")
    probe.write_text("ok", encoding="utf-8")
    add("positive-test", "scratch-write", probe.read_text(encoding="utf-8") == "ok", "isolated tmpfs")
except Exception:
    add("positive-test", "scratch-write", False, "isolated tmpfs unavailable")

for forbidden in ("/etc/passwd", "/home", "/root", "/run", "/var/run", "/mnt", "/media"):
    add("filesystem-denial", "host-path:" + forbidden, not pathlib.Path(forbidden).exists(), "host path absent")

sensitive_names = []
for key in os.environ:
    upper = key.upper()
    if any(token in upper for token in ("SECRET", "TOKEN", "PASSWORD", "COOKIE", "CREDENTIAL", "API_KEY")):
        sensitive_names.append(key)
add("secret-denial", "environment", not sensitive_names, f"sensitive_names={len(sensitive_names)}")

broker_paths = ("/run/docker.sock", "/var/run/docker.sock", "/run/hermes", "/var/run/hermes", "/run/fleet", "/var/run/fleet")
add("broker-denial", "broker-sockets", not any(pathlib.Path(path).exists() for path in broker_paths), "broker paths absent")
add("broker-denial", "docker-socket", not any(pathlib.Path(path).exists() for path in ("/run/docker.sock", "/var/run/docker.sock")), "Docker socket absent")

network_results = []
for address in (("1.1.1.1", 53), ("100.64.0.1", 443), ("192.168.1.1", 443)):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.15)
    try:
        rc = sock.connect_ex(address)
    finally:
        sock.close()
    network_results.append(rc)
add("network-denial", "internet", network_results[0] != 0, f"connect_rc={network_results[0]}")
add("network-denial", "management-network", all(code != 0 for code in network_results[1:]), "private/tailscale routes unreachable")

cap_eff = None
try:
    for line in pathlib.Path("/proc/self/status").read_text(encoding="utf-8").splitlines():
        if line.startswith("CapEff:"):
            cap_eff = int(line.split()[1], 16)
            break
except Exception:
    cap_eff = None
add("privilege-denial", "non-root-uid", os.geteuid() != 0, f"euid={os.geteuid()}")
add("privilege-denial", "effective-capabilities", cap_eff == 0, "CapEff=0" if cap_eff == 0 else "capability state unavailable/nonzero")

limits = {
    "cpu": (resource.RLIMIT_CPU, 3),
    "address-space": (resource.RLIMIT_AS, 268435456),
    "file-size": (resource.RLIMIT_FSIZE, 4194304),
    "open-files": (resource.RLIMIT_NOFILE, 64),
    "processes": (resource.RLIMIT_NPROC, 16),
}
for name, (kind, ceiling) in limits.items():
    soft, _hard = resource.getrlimit(kind)
    bounded = soft != resource.RLIM_INFINITY and soft <= ceiling
    add("resource-bound", name, bounded, f"soft={soft};ceiling={ceiling}")

print(json.dumps({"checks": checks}, sort_keys=True, separators=(",", ":")))
'''


def _runtime_checks(
    candidate_dir: Path,
    observed_files: Iterable[Mapping[str, object]],
) -> list[VerificationCheck]:
    if os.name != "posix" or not sys_platform_linux():
        raise FleetSkillVerificationError(
            "disposable verification runtime is currently available only on Linux"
        )
    bwrap = shutil.which("bwrap")
    if bwrap is None:
        raise FleetSkillVerificationError(
            "Bubblewrap is required for disposable skill verification"
        )
    python = "/usr/bin/python3"
    if not Path(python).is_file():
        raise FleetSkillVerificationError(
            "system Python is unavailable for disposable verification"
        )

    with tempfile.TemporaryDirectory(prefix="hermes-fleet-skill-verify-") as temp:
        root = Path(temp)
        bundle = root / "bundle"
        _copy_bundle(candidate_dir, observed_files, bundle)
        argv = [
            bwrap,
            "--unshare-all",
            "--die-with-parent",
            "--new-session",
            "--uid",
            "65534",
            "--gid",
            "65534",
            "--cap-drop",
            "ALL",
            "--hostname",
            "fleet-skill-verifier",
            "--ro-bind",
            "/usr",
            "/usr",
            "--ro-bind-try",
            "/lib",
            "/lib",
            "--ro-bind-try",
            "/lib64",
            "/lib64",
            "--ro-bind",
            str(bundle),
            "/skill",
            "--dev",
            "/dev",
            "--proc",
            "/proc",
            "--tmpfs",
            "/tmp",
            "--clearenv",
            "--setenv",
            "PATH",
            "/usr/bin:/bin",
            "--setenv",
            "HOME",
            "/tmp",
            "--setenv",
            "TMPDIR",
            "/tmp",
            "--setenv",
            "FLEET_SKILL_VERIFICATION",
            "1",
            "--chdir",
            "/skill",
            "--",
            python,
            "-I",
            "-S",
            "-c",
            _runtime_harness(),
        ]
        try:
            completed = subprocess.run(
                argv,
                check=False,
                capture_output=True,
                text=True,
                timeout=_RUNTIME_TIMEOUT_SECONDS,
                env={},
            )
        except subprocess.TimeoutExpired as error:
            raise FleetSkillVerificationError(
                "disposable verification runtime exceeded its wall-clock bound"
            ) from error
        except (OSError, subprocess.SubprocessError) as error:
            raise FleetSkillVerificationError(
                "disposable verification runtime could not start"
            ) from error
        if completed.returncode != 0:
            raise FleetSkillVerificationError(
                "disposable verification runtime failed closed"
            )
        try:
            document = json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            raise FleetSkillVerificationError(
                "disposable verification runtime returned invalid evidence"
            ) from error
        raw_checks = document.get("checks") if type(document) is dict else None
        if type(raw_checks) is not list or len(raw_checks) > _MAX_CHECKS:
            raise FleetSkillVerificationError(
                "disposable verification evidence has an invalid shape"
            )
        checks: list[VerificationCheck] = []
        for item in raw_checks:
            if (
                type(item) is not dict
                or type(item.get("category")) is not str
                or type(item.get("name")) is not str
                or type(item.get("passed")) is not bool
                or type(item.get("detail")) is not str
            ):
                raise FleetSkillVerificationError(
                    "disposable verification check is malformed"
                )
            checks.append(
                _check(
                    item["category"],
                    item["name"],
                    item["passed"],
                    item["detail"],
                )
            )
        return checks


def sys_platform_linux() -> bool:
    import sys

    return sys.platform.startswith("linux")


def _verification_document(
    *,
    metadata: Mapping[str, Any],
    state: str,
    observed_hash: str,
    quarantine_digest: str,
    capability_manifest_hash: str,
    checks: tuple[VerificationCheck, ...],
) -> tuple[dict[str, object], str]:
    result_documents = [check.to_document() for check in checks]
    result_digest = _sha256(_canonical(result_documents))
    runtime_policy = {
        "version": _RUNTIME_VERSION,
        "wall_clock_seconds": _RUNTIME_TIMEOUT_SECONDS,
        "cpu_seconds": _RUNTIME_CPU_SECONDS,
        "address_space_bytes": _RUNTIME_ADDRESS_SPACE_BYTES,
        "file_bytes": _RUNTIME_FILE_BYTES,
        "open_files": _RUNTIME_OPEN_FILES,
        "processes": _RUNTIME_PROCESSES,
        "network": "unshared",
        "host_filesystem": "not-mounted",
        "environment": "clearenv-allowlist",
        "docker_socket": "absent",
        "management_network": "unreachable",
        "privilege": "uid-65534-cap-drop-all",
        "candidate_execution": "disabled",
    }
    runtime_digest = _sha256(_canonical(runtime_policy))
    verification_digest = _sha256(
        _canonical(
            {
                "verifier": _VERIFIER_VERSION,
                "candidate_id": metadata.get("candidate_id"),
                "content_hash": observed_hash,
                "quarantine_digest": quarantine_digest,
                "capability_manifest_hash": capability_manifest_hash,
                "runtime_digest": runtime_digest,
                "state": state,
                "result_digest": result_digest,
            }
        )
    )
    document: dict[str, object] = {
        "state": state,
        "verifier": _VERIFIER_VERSION,
        "content_hash": observed_hash,
        "quarantine_digest": quarantine_digest,
        "capability_manifest_hash": capability_manifest_hash,
        "runtime": runtime_policy,
        "runtime_digest": runtime_digest,
        "result_digest": result_digest,
        "verification_digest": verification_digest,
        "results": result_documents,
        "next_phase": 18 if state == "verified" else 17,
    }
    return document, verification_digest


def _existing_verification(
    metadata: Mapping[str, Any],
    *,
    observed_hash: str,
    quarantine_digest: str,
    capability_manifest_hash: str,
) -> FleetSkillVerificationResult:
    tests = metadata.get("tests")
    if type(tests) is not dict or tests.get("state") not in _FINAL_TEST_STATES:
        raise FleetSkillVerificationError("candidate verification state is invalid")
    if tests.get("verifier") != _VERIFIER_VERSION:
        raise FleetSkillVerificationError("candidate verification record is unsupported")
    if (
        tests.get("content_hash") != observed_hash
        or tests.get("quarantine_digest") != quarantine_digest
        or tests.get("capability_manifest_hash") != capability_manifest_hash
    ):
        raise FleetSkillVerificationError(
            "candidate changed after its verification was recorded"
        )
    raw_results = tests.get("results")
    if type(raw_results) is not list or len(raw_results) > _MAX_CHECKS:
        raise FleetSkillVerificationError("candidate verification results are invalid")
    checks: list[VerificationCheck] = []
    for item in raw_results:
        if (
            type(item) is not dict
            or set(item) != {"category", "name", "passed", "detail"}
            or type(item["category"]) is not str
            or type(item["name"]) is not str
            or type(item["passed"]) is not bool
            or type(item["detail"]) is not str
        ):
            raise FleetSkillVerificationError(
                "candidate verification result shape changed"
            )
        checks.append(
            VerificationCheck(
                category=item["category"],
                name=item["name"],
                passed=item["passed"],
                detail=item["detail"],
            )
        )
    ordered = _ordered_checks(checks)
    if [check.to_document() for check in ordered] != raw_results:
        raise FleetSkillVerificationError(
            "candidate verification result order/content changed"
        )
    expected_document, expected_digest = _verification_document(
        metadata=metadata,
        state=tests["state"],
        observed_hash=observed_hash,
        quarantine_digest=quarantine_digest,
        capability_manifest_hash=capability_manifest_hash,
        checks=ordered,
    )
    for key in (
        "runtime",
        "runtime_digest",
        "result_digest",
        "verification_digest",
        "next_phase",
    ):
        if tests.get(key) != expected_document[key]:
            raise FleetSkillVerificationError(
                "candidate verification attestation changed"
            )
    if tests.get("verification_digest") != expected_digest:
        raise FleetSkillVerificationError(
            "candidate verification digest changed"
        )
    return FleetSkillVerificationResult(
        candidate_id=str(metadata.get("candidate_id", "")),
        name=str(metadata.get("name", "")),
        state=tests["state"],
        content_hash=observed_hash,
        quarantine_digest=quarantine_digest,
        verification_digest=expected_digest,
        checks=ordered,
    )


def verify_skill_candidate(
    candidate_dir: Path,
    *,
    expected_binding: FleetSkillLearningBinding | None = None,
) -> FleetSkillVerificationResult:
    """Verify one exact Phase 16 candidate without granting authority or activation."""
    if expected_binding is None:
        raise FleetSkillVerificationError(
            "Phase 17 verification requires the exact Fleet learning binding"
        )
    try:
        quarantine = quarantine_skill_candidate(
            candidate_dir,
            expected_binding=expected_binding,
        )
    except FleetSkillQuarantineError as error:
        raise FleetSkillVerificationError(
            "candidate does not have a valid Phase 16 quarantine seal"
        ) from error
    if quarantine.state != "verification-ready":
        raise FleetSkillVerificationError(
            "only verification-ready candidates may enter Phase 17"
        )

    metadata = _load_existing_metadata(candidate_dir)
    if metadata is None:
        raise FleetSkillVerificationError("candidate metadata is missing")
    if metadata.get("active") is not False or metadata.get("authority") != "none":
        raise FleetSkillVerificationError(
            "verification candidate is active or authority-bearing"
        )
    observed_files, observed_hash = _bundle_manifest(candidate_dir)
    if observed_hash != quarantine.content_hash:
        raise FleetSkillVerificationError(
            "candidate content changed after Phase 16 quarantine"
        )
    capability_check, _binding, capability_manifest_hash = _capability_manifest_check(
        metadata,
        expected_binding,
    )
    if not capability_check.passed:
        raise FleetSkillVerificationError(
            "candidate capability manifest does not match the verification binding"
        )

    tests = metadata.get("tests")
    if type(tests) is not dict:
        raise FleetSkillVerificationError("candidate verification metadata is malformed")
    if tests.get("state") in _FINAL_TEST_STATES:
        return _existing_verification(
            metadata,
            observed_hash=observed_hash,
            quarantine_digest=quarantine.quarantine_digest,
            capability_manifest_hash=capability_manifest_hash,
        )
    if tests != {"state": "unverified", "results": [], "next_phase": 17}:
        raise FleetSkillVerificationError(
            "candidate verification metadata changed before Phase 17"
        )

    checks: list[VerificationCheck] = [capability_check]
    text_files = _text_files(candidate_dir, observed_files)
    checks.extend(_static_analysis_checks(candidate_dir, observed_files))
    checks.append(_sensitive_material_check(text_files))
    checks.extend(_runtime_checks(candidate_dir, observed_files))
    ordered = _ordered_checks(checks)
    state = "verified" if all(check.passed for check in ordered) else "failed"
    verification_document, verification_digest = _verification_document(
        metadata=metadata,
        state=state,
        observed_hash=observed_hash,
        quarantine_digest=quarantine.quarantine_digest,
        capability_manifest_hash=capability_manifest_hash,
        checks=ordered,
    )

    updated = dict(metadata)
    updated["tests"] = verification_document
    # Phase 17 is explicitly non-authorizing. Candidate state, activation and
    # authority remain exactly as frozen by Phase 16.
    updated["active"] = False
    updated["authority"] = "none"
    _write_metadata(candidate_dir, updated)
    _private_file(candidate_dir / _METADATA_FILE)
    return FleetSkillVerificationResult(
        candidate_id=str(updated.get("candidate_id", "")),
        name=str(updated.get("name", "")),
        state=state,
        content_hash=observed_hash,
        quarantine_digest=quarantine.quarantine_digest,
        verification_digest=verification_digest,
        checks=ordered,
    )


def _matches_binding(
    metadata: Mapping[str, Any], binding: FleetSkillLearningBinding
) -> bool:
    principal = metadata.get("principal")
    provenance = metadata.get("provenance")
    return (
        type(principal) is dict
        and type(provenance) is dict
        and principal.get("principal_id") == binding.principal_id
        and principal.get("kind") == binding.principal_kind
        and principal.get("generation") == binding.principal_generation
        and principal.get("binding_hash") == binding.principal_binding_hash
        and metadata.get("agent_instance_id") == binding.agent_instance_id
        and metadata.get("source_run") == binding.source_run
        and provenance.get("run_authority_hash") == binding.run_authority_hash
        and provenance.get("plan_fingerprint") == binding.plan_fingerprint
    )


def verify_candidates_for_binding(
    binding: FleetSkillLearningBinding,
) -> tuple[FleetSkillVerificationResult, ...]:
    """Verify all exact Phase 16-ready candidates for one Fleet learning binding."""
    if type(binding) is not FleetSkillLearningBinding:
        raise FleetSkillVerificationError("Fleet skill-learning binding is invalid")
    root = _candidate_root()
    results: list[FleetSkillVerificationResult] = []
    for candidate_dir in sorted(
        path for path in root.iterdir() if path.is_dir() and not path.is_symlink()
    ):
        try:
            metadata = _load_existing_metadata(candidate_dir)
        except Exception:
            continue
        if metadata is None or not _matches_binding(metadata, binding):
            continue
        if metadata.get("state") != "verification-ready":
            continue
        results.append(
            verify_skill_candidate(candidate_dir, expected_binding=binding)
        )
    return tuple(results)
