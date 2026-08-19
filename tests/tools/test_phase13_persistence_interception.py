from __future__ import annotations

from pathlib import Path

import pytest

from tools.memory_tool import MemoryStore

FAKE_KEY = "sk-phase13-example-12345678901234567890"


def test_native_memory_add_replace_and_batch_block_sensitive_values(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "home"))
    store = MemoryStore()
    store.load_from_disk()

    result = store.add("memory", f"provider key {FAKE_KEY}")
    assert result["success"] is False
    assert "sensitive-content interception" in result["error"]
    assert not (tmp_path / "home" / "memories" / "MEMORY.md").exists()

    assert store.add("memory", "safe durable fact")["success"] is True
    result = store.replace("memory", "safe durable", f"replacement {FAKE_KEY}")
    assert result["success"] is False
    assert "safe durable fact" in (
        tmp_path / "home" / "memories" / "MEMORY.md"
    ).read_text(encoding="utf-8")

    result = store.apply_batch(
        "memory",
        [
            {"action": "add", "content": "another safe fact"},
            {"action": "add", "content": f"blocked {FAKE_KEY}"},
        ],
    )
    assert result["success"] is False
    persisted = (tmp_path / "home" / "memories" / "MEMORY.md").read_text(
        encoding="utf-8"
    )
    assert "another safe fact" not in persisted
    assert FAKE_KEY not in persisted


def _skill_doc(name: str, body: str) -> str:
    return f"---\nname: {name}\ndescription: phase 13 fixture\n---\n\n# Fixture\n\n{body}\n"


def test_skill_create_edit_patch_and_support_file_block_before_write(
    monkeypatch, tmp_path: Path
) -> None:
    import tools.skill_manager_tool as manager

    skills = tmp_path / "skills"
    monkeypatch.setattr(manager, "SKILLS_DIR", skills)

    blocked = manager._create_skill(
        "blocked-create", _skill_doc("blocked-create", FAKE_KEY)
    )
    assert blocked["success"] is False
    assert not (skills / "blocked-create").exists()

    created = manager._create_skill("safe-skill", _skill_doc("safe-skill", "safe body"))
    assert created["success"] is True
    skill_md = skills / "safe-skill" / "SKILL.md"
    original = skill_md.read_text(encoding="utf-8")

    edited = manager._edit_skill("safe-skill", _skill_doc("safe-skill", FAKE_KEY))
    assert edited["success"] is False
    assert skill_md.read_text(encoding="utf-8") == original

    patched = manager._patch_skill("safe-skill", "safe body", f"safe body {FAKE_KEY}")
    assert patched["success"] is False
    assert skill_md.read_text(encoding="utf-8") == original

    supporting = manager._write_file(
        "safe-skill", "references/id_rsa", "opaque fixture"
    )
    assert supporting["success"] is False
    assert not (skills / "safe-skill" / "references" / "id_rsa").exists()
