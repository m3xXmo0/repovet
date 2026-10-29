from pathlib import Path

import pytest

from helpers import write_rule
from repovet.engine.loader import (
    FILESETS_FILE,
    PATTERNS_FILE,
    RULES_DIR,
    RuleError,
    load_rule_dirs,
    load_rules,
)
from repovet.models import Severity


def test_builtin_rules_load() -> None:
    rules = load_rules()
    ids = [r.id for r in rules.rules]
    assert ids == sorted(ids)
    assert {"RC-AUTO-001", "RC-AUTO-020", "RC-AGENT-002"} <= set(ids)
    rule = rules.get("RC-AUTO-020")
    assert rule is not None
    assert rule.category == "danger"
    assert rule.severity is Severity.HIGH
    assert rule.applies_to(".vscode/tasks.json")
    assert not rule.applies_to("node_modules/x/.vscode/tasks.json")
    assert {"network_fetch", "shell_pipe_exec", "encoded_payload"} <= set(rules.patterns)
    assert rules.unsupported


def test_extra_rules_folder_is_added(tmp_path: Path) -> None:
    rules = load_rules([write_rule(tmp_path / "extra")])
    assert rules.get("RC-AUTO-901") is not None


def test_without_and_active() -> None:
    rules = load_rules().without(["RC-AUTO-001"])
    assert rules.get("RC-AUTO-001") is None
    assert all(r.area == "agents" for r in rules.active("agents"))


@pytest.mark.parametrize(
    ("kwargs", "error"),
    [
        ({"rule_id": "AUTO-1"}, "RC-<AREA>-<NNN>"),
        ({"rule_id": "RC-AGENT-901"}, "prefix must be RC-AUTO-"),
        ({"area": "nowhere"}, "unknown area"),
        ({"severity": "urgent"}, "unknown severity"),
        ({"message": "found {where}"}, "unknown placeholder"),
        ({"message": "found {path:>10}"}, "braces"),
        ({"files": "[{set: nothing}]"}, "unknown file set"),
        ({"files": "['/abs']"}, "relative posix"),
        ({"check": "{type: regex, pattern: '{{nothing}}'}"}, "unknown pattern"),
        ({"check": "{type: regex, pattern: '('}"}, "invalid regex"),
        ({"check": "{type: regex, pattern: 'x?'}"}, "empty string"),
        ({"check": "{type: metric}"}, "'conditions' must be a non-empty list"),
        (
            {"check": "{type: metric, conditions: [{fact: a.b, op: '~', value: 1}]}"},
            "'op' must be one of",
        ),
        ({"check": "{type: magic_words}"}, "unknown check type"),
        ({"check": "{type: filename, nmae_regex: x}"}, "unknown check parameter"),
        ({"check": "just text"}, "'check' must be a mapping"),
    ],
)
def test_invalid_rules(tmp_path: Path, kwargs: dict[str, str], error: str) -> None:
    folder = write_rule(tmp_path / "rules", **kwargs)
    with pytest.raises(RuleError) as info:
        load_rules([folder])
    assert "test_rules.yaml" in str(info.value)
    assert error in str(info.value)


def test_unknown_and_missing_fields(tmp_path: Path) -> None:
    folder = write_rule(tmp_path / "rules")
    path = folder / "test_rules.yaml"
    path.write_text(path.read_text(encoding="utf-8") + "  colour: red\n", encoding="utf-8")
    with pytest.raises(RuleError, match="unknown field"):
        load_rules([folder])
    path.write_text("- id: RC-AUTO-902\n  title: x\n", encoding="utf-8")
    with pytest.raises(RuleError, match="missing field"):
        load_rules([folder])


def test_duplicate_ids(tmp_path: Path) -> None:
    folder = write_rule(tmp_path / "rules", rule_id="RC-AUTO-001")
    with pytest.raises(RuleError, match="duplicate id"):
        load_rules([folder])


def test_reference_must_be_https(tmp_path: Path) -> None:
    folder = write_rule(tmp_path / "rules")
    path = folder / "test_rules.yaml"
    text = path.read_text(encoding="utf-8") + "  references: [http://example.invalid]\n"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(RuleError, match="https"):
        load_rules([folder])


def test_pattern_cycle_and_duplicates(tmp_path: Path) -> None:
    folder = tmp_path / "rules"
    folder.mkdir()
    (folder / PATTERNS_FILE).write_text("a: 'x{{b}}'\nb: 'y{{a}}'\n", encoding="utf-8")
    with pytest.raises(RuleError, match="cycle"):
        load_rules([folder])
    (folder / PATTERNS_FILE).write_text("network_fetch: 'x'\n", encoding="utf-8")
    with pytest.raises(RuleError, match="defined twice"):
        load_rules([folder])


def test_nested_patterns_resolve(tmp_path: Path) -> None:
    folder = tmp_path / "rules"
    folder.mkdir()
    (folder / PATTERNS_FILE).write_text("inner: 'ab'\nouter: 'x{{inner}}'\n", encoding="utf-8")
    assert load_rules([folder]).patterns["outer"] == "x(?:ab)"


def test_fileset_errors(tmp_path: Path) -> None:
    folder = tmp_path / "rules"
    folder.mkdir()
    (folder / FILESETS_FILE).write_text("bad: '**'\n", encoding="utf-8")
    with pytest.raises(RuleError, match="list of globs"):
        load_rules([folder])


def test_default_fileset_is_required(tmp_path: Path) -> None:
    folder = write_rule(tmp_path / "rules")
    with pytest.raises(RuleError, match="text_files"):
        load_rule_dirs([folder])


def test_missing_folder(tmp_path: Path) -> None:
    with pytest.raises(RuleError, match="not found"):
        load_rules([tmp_path / "missing"])


def test_unsupported_entries_are_validated(tmp_path: Path) -> None:
    folder = tmp_path / "rules"
    folder.mkdir()
    (folder / "_unsupported.yaml").write_text("- scope: x\n  files: ['a']\n", encoding="utf-8")
    with pytest.raises(RuleError, match="'reason'"):
        load_rules([folder])


def test_rules_dir_is_inside_the_package() -> None:
    assert RULES_DIR.name == "rules"
    assert (RULES_DIR / PATTERNS_FILE).is_file()
