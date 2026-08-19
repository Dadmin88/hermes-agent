from __future__ import annotations

import json

import pytest

from agent.sensitive_interception import (
    SensitiveInterceptionError,
    audit_document,
    classify_sensitive_text,
    intercept_persistence,
    redact_persisted_value,
    register_secure_reference_handler,
    require_persistable_text,
    sensitive_path_kind,
)

FAKE_KEY = "sk-phase13-example-12345678901234567890"


def test_blocking_sinks_reject_raw_credential_body(caplog) -> None:
    text = f"provider_key={FAKE_KEY}"
    for sink in (
        "memory",
        "skill",
        "embedding",
        "search_index",
        "summary",
        "promotion",
    ):
        decision = intercept_persistence(text, sink=sink)
        assert decision.found is True
        assert decision.action == "block"
        assert decision.persisted_text is None
        assert FAKE_KEY not in audit_document(decision)
    assert FAKE_KEY not in caplog.text


def test_redacting_sinks_preserve_surrounding_text_without_raw_value() -> None:
    text = f"request failed with Authorization: Bearer {FAKE_KEY}"
    for sink in ("log", "evidence", "transcript"):
        decision = intercept_persistence(text, sink=sink)
        assert decision.action == "redact"
        assert decision.persisted_text is not None
        assert FAKE_KEY not in decision.persisted_text
        assert "request failed" in decision.persisted_text


def test_cookie_private_key_password_and_env_assignment_are_classified() -> None:
    samples = {
        "session_cookie": "Cookie: sessionid=abc1234567890",
        "private_key": "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
        "password": "password=correct-horse-battery-staple",
        "environment_assignment": f"SERVICE_API_KEY={FAKE_KEY}",
    }
    for expected, text in samples.items():
        findings, redacted, uncertain = classify_sensitive_text(text)
        assert uncertain is False
        assert expected in {finding.kind for finding in findings}
        assert redacted != text


def test_sensitive_file_names_block_even_without_detectable_body() -> None:
    assert sensitive_path_kind("references/id_rsa") == "credential_file"
    assert sensitive_path_kind("assets/client.p12") == "credential_file"
    assert sensitive_path_kind("references/public-cert.pem") is None
    with pytest.raises(SensitiveInterceptionError, match="skill persistence blocked"):
        require_persistable_text("opaque bytes", sink="skill", path="assets/client.p12")


def test_classification_failure_fails_closed(monkeypatch) -> None:
    import agent.redact as redact

    monkeypatch.setattr(
        redact,
        "redact_sensitive_text",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    decision = intercept_persistence("ordinary text", sink="memory")
    assert decision.uncertain is True
    assert decision.action == "block"
    assert decision.persisted_text is None


def test_optional_secure_reference_hook_never_persists_body() -> None:
    seen = []

    def handler(raw, metadata):
        seen.append((raw, dict(metadata)))
        return "ref:phase13:test-1"

    register_secure_reference_handler(handler)
    try:
        decision = intercept_persistence(
            FAKE_KEY,
            sink="memory",
            allow_reference=True,
            metadata={"principal": "principal-a"},
        )
        assert decision.action == "reference"
        assert decision.reference == "ref:phase13:test-1"
        assert decision.persisted_text == "[secure-reference:ref:phase13:test-1]"
        assert FAKE_KEY not in decision.persisted_text
        assert seen == [(FAKE_KEY, {"sink": "memory", "principal": "principal-a"})]
    finally:
        register_secure_reference_handler(None)


def test_structured_transcript_redaction_preserves_shape() -> None:
    value = {
        "role": "tool",
        "content": f"status key={FAKE_KEY}",
        "parts": ["safe", f"Bearer {FAKE_KEY}"],
    }
    redacted = redact_persisted_value(value, sink="transcript")
    assert redacted["role"] == "tool"
    assert redacted["parts"][0] == "safe"
    encoded = json.dumps(redacted)
    assert FAKE_KEY not in encoded
