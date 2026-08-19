"""Phase 13 interception boundary for sensitive persisted material."""

from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
from dataclasses import dataclass
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any, Callable, Mapping

_AUDIT = logging.getLogger("hermes.sensitive_interception")
_BLOCK_SINKS = frozenset({
    "memory",
    "skill",
    "embedding",
    "search_index",
    "summary",
    "promotion",
})
_REDACT_SINKS = frozenset({"log", "evidence", "transcript"})
_ALLOWED_SINKS = _BLOCK_SINKS | _REDACT_SINKS
_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$")
_ENV_LABEL_RE = re.compile(
    r"(?im)^\s*[A-Z][A-Z0-9_]{1,127}(?:KEY|PASS|PWD|AUTH|COOKIE|CREDENTIAL)[A-Z0-9_]*\s*="
)
_COOKIE_RE = re.compile(r"(?im)^\s*(?:set-)?cookie\s*:\s*\S+")
_AUTH_RE = re.compile(r"(?im)^\s*(?:proxy-)?authorization\s*:\s*\S+")
_PASSWORD_RE = re.compile(r"(?i)\bpassword\s*[:=]\s*[^\s,;]+")
_PRIVATE_KEY_MARKER_RE = re.compile(r"-----BEGIN[A-Z ]*PRIVATE KEY-----")
_SENSITIVE_FILE_BASENAMES = frozenset({
    ".netrc",
    ".pgpass",
    ".npmrc",
    ".pypirc",
    "credentials",
    "credentials.json",
    "service-account.json",
    "id_rsa",
    "id_ed25519",
})
_SENSITIVE_FILE_SUFFIXES = frozenset({".p12", ".pfx", ".jks", ".pkcs12"})
SecureReferenceHandler = Callable[[str, Mapping[str, str]], str]
_REFERENCE_HANDLER: SecureReferenceHandler | None = None
_REFERENCE_LOCK = threading.Lock()


class SensitiveInterceptionError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class SensitiveFinding:
    kind: str
    fingerprint: str


@dataclass(frozen=True, slots=True)
class SensitiveDecision:
    sink: str
    action: str
    found: bool
    uncertain: bool
    persisted_text: str | None
    reference: str | None
    findings: tuple[SensitiveFinding, ...]


def _fingerprint(text: str) -> str:
    return (
        "sha256:"
        + hashlib.sha256(text.encode("utf-8", errors="surrogatepass")).hexdigest()
    )


def _finding_kinds(text: str) -> tuple[str, ...]:
    kinds = []
    for kind, pattern in (
        ("private_key", _PRIVATE_KEY_MARKER_RE),
        ("authorization", _AUTH_RE),
        ("session_cookie", _COOKIE_RE),
        ("password", _PASSWORD_RE),
        ("environment_assignment", _ENV_LABEL_RE),
    ):
        if pattern.search(text):
            kinds.append(kind)
    return tuple(kinds or ["credential_material"])


def sensitive_path_kind(path: str | None) -> str | None:
    if not path:
        return None
    name = PurePosixPath(path.replace("\\", "/")).name.lower()
    win_name = PureWindowsPath(path).name.lower()
    candidate = win_name or name
    if candidate in _SENSITIVE_FILE_BASENAMES or any(
        candidate.endswith(s) for s in _SENSITIVE_FILE_SUFFIXES
    ):
        return "credential_file"
    return None


def classify_sensitive_text(
    text: str | None,
) -> tuple[tuple[SensitiveFinding, ...], str, bool]:
    raw = "" if text is None else str(text)
    if not raw:
        return (), raw, False
    try:
        from agent.redact import redact_sensitive_text

        try:
            redacted = redact_sensitive_text(
                raw,
                force=True,
                redact_url_credentials=True,
            )
            if redacted != raw:
                # Durable/export boundaries must not retain debugging fragments
                # of a credential body. Re-run in non-reusable file-read mode
                # where supported; fall back to the strict result for opaque
                # JSON/form fields that file-read mode intentionally skips.
                nonreusable = redact_sensitive_text(
                    raw,
                    force=True,
                    file_read=True,
                    redact_url_credentials=True,
                )
                if nonreusable != raw:
                    redacted = nonreusable
        except TypeError as error:
            # Some tests/plugins monkeypatch the historical two-argument
            # redactor. Preserve that compatibility while keeping the normal
            # runtime on strict URL-credential redaction.
            if "redact_url_credentials" not in str(error):
                raise
            redacted = redact_sensitive_text(raw, force=True)
    except Exception:
        finding = SensitiveFinding("classification_unavailable", _fingerprint(raw))
        return (finding,), "[classification-unavailable]", True
    explicit = _finding_kinds(raw)
    explicit_only = explicit != ("credential_material",)
    if redacted == raw and explicit_only:
        redacted = _COOKIE_RE.sub("[redacted-cookie-header]", redacted)
        redacted = _AUTH_RE.sub("[redacted-authorization]", redacted)
        redacted = _PASSWORD_RE.sub("password=[redacted]", redacted)
        redacted = _ENV_LABEL_RE.sub("SENSITIVE_VALUE=[redacted]", redacted)
        redacted = _PRIVATE_KEY_MARKER_RE.sub("[redacted-private-key]", redacted)
    if redacted == raw:
        return (), raw, False
    fp = _fingerprint(raw)
    kinds = explicit if explicit_only else ("credential_material",)
    return tuple(SensitiveFinding(k, fp) for k in kinds), redacted, False


def register_secure_reference_handler(handler: SecureReferenceHandler | None) -> None:
    if handler is not None and not callable(handler):
        raise TypeError("secure reference handler must be callable")
    global _REFERENCE_HANDLER
    with _REFERENCE_LOCK:
        _REFERENCE_HANDLER = handler


def _reference_for(raw: str, *, sink: str, metadata: Mapping[str, str]) -> str | None:
    with _REFERENCE_LOCK:
        handler = _REFERENCE_HANDLER
    if handler is None:
        return None
    reference = handler(raw, {"sink": sink, **dict(metadata)})
    if type(reference) is not str or _REF_RE.fullmatch(reference) is None:
        raise SensitiveInterceptionError(
            "secure reference handler returned an invalid reference"
        )
    return reference


def _audit(decision: SensitiveDecision, raw_fingerprint: str | None) -> None:
    _AUDIT.warning(
        "interception sink=%s action=%s uncertain=%s findings=%s fingerprint=%s reference=%s",
        decision.sink,
        decision.action,
        decision.uncertain,
        ",".join(f.kind for f in decision.findings) or "none",
        raw_fingerprint or "none",
        decision.reference or "none",
    )


def intercept_persistence(
    text: str | None,
    *,
    sink: str,
    path: str | None = None,
    allow_reference: bool = False,
    metadata: Mapping[str, str] | None = None,
) -> SensitiveDecision:
    if sink not in _ALLOWED_SINKS:
        raise ValueError("unsupported sensitive interception sink")
    raw = "" if text is None else str(text)
    findings, redacted, uncertain = classify_sensitive_text(raw)
    path_kind = sensitive_path_kind(path)
    if path_kind:
        findings = findings + (
            SensitiveFinding(path_kind, _fingerprint(raw or path or "")),
        )
    if not findings:
        return SensitiveDecision(sink, "allow", False, False, raw, None, ())
    fp = _fingerprint(raw or path or "")
    if uncertain:
        decision = SensitiveDecision(sink, "block", True, True, None, None, findings)
        _audit(decision, fp)
        return decision
    if sink in _REDACT_SINKS:
        decision = SensitiveDecision(
            sink, "redact", True, False, redacted, None, findings
        )
        _audit(decision, fp)
        return decision
    reference = (
        _reference_for(raw, sink=sink, metadata=metadata or {})
        if allow_reference
        else None
    )
    if reference is not None:
        decision = SensitiveDecision(
            sink,
            "reference",
            True,
            False,
            f"[secure-reference:{reference}]",
            reference,
            findings,
        )
    else:
        decision = SensitiveDecision(sink, "block", True, False, None, None, findings)
    _audit(decision, fp)
    return decision


def require_persistable_text(
    text: str | None, *, sink: str, path: str | None = None
) -> str:
    d = intercept_persistence(text, sink=sink, path=path)
    if d.action in {"allow", "reference"} and d.persisted_text is not None:
        return d.persisted_text
    kinds = ", ".join(f.kind for f in d.findings) or "unknown"
    raise SensitiveInterceptionError(
        f"{sink} persistence blocked by sensitive-content interception ({kinds})"
    )


def redact_persisted_value(value: Any, *, sink: str = "transcript") -> Any:
    if isinstance(value, str):
        d = intercept_persistence(value, sink=sink)
        if d.uncertain:
            return "[classification-unavailable]"
        return d.persisted_text if d.persisted_text is not None else "[blocked]"
    if isinstance(value, list):
        return [redact_persisted_value(v, sink=sink) for v in value]
    if isinstance(value, tuple):
        return tuple(redact_persisted_value(v, sink=sink) for v in value)
    if isinstance(value, dict):
        return {k: redact_persisted_value(v, sink=sink) for k, v in value.items()}
    return value


def block_if_sensitive(value: Any, *, sink: str) -> bool:
    if isinstance(value, str):
        return intercept_persistence(value, sink=sink).found
    if isinstance(value, Mapping):
        return any(block_if_sensitive(v, sink=sink) for v in value.values())
    if isinstance(value, (list, tuple)):
        return any(block_if_sensitive(v, sink=sink) for v in value)
    return False


def audit_document(decision: SensitiveDecision) -> str:
    return json.dumps(
        {
            "sink": decision.sink,
            "action": decision.action,
            "found": decision.found,
            "uncertain": decision.uncertain,
            "findings": [f.kind for f in decision.findings],
            "reference": decision.reference,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
