"""Regression tests on reconstructions of documented attack techniques.

Every entry in tests/reconstructions/ is written to tmp_path and scanned offline with
the full pipeline (CLI, all built-in rules, JSON report). The rules in ``must_fire``
must report it, the rules in ``must_not_fire`` must stay silent, and every known gap
must still be open: when a gap closes, the test asks to move it to ``must_fire``.
"""

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

import reconstructions
from helpers import builtin_rules
from reconstructions import Entry, evaluate, file_content, load_entries, parse_entry

ENTRIES = load_entries()
# Hosts in fixture contents: placeholders only. The request-catcher service is needed
# for RC-DLX-005 and appears only with an all-zero placeholder id.
_URL = re.compile(r"https?://([^/\s\"'`<>)|]+)([^\s\"'`<>)|]*)")
_ALLOWED_URLS = {("webhook.site", "/00000000-0000-0000-0000-000000000000")}
# XML namespaces are identifiers, not addresses that anything contacts.
_NAMESPACES = {("schemas.microsoft.com", "/developer/msbuild/2003")}
_INVISIBLE = re.compile(
    "[\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufe00-\ufe0f\U000e0000-\U000e01ef]"
)


def test_there_are_reconstructions() -> None:
    assert len(ENTRIES) >= 10
    assert {e.kind for e in ENTRIES} == {"incident", "technique"}


def test_rules_exist_and_are_active() -> None:
    rules = builtin_rules()
    active = {rule.id for rule in rules.active()}
    for entry in ENTRIES:
        named = [e.rule for e in entry.must_fire + entry.known_gaps] + list(entry.must_not_fire)
        unknown = [rule for rule in named if rule not in active]
        assert not unknown, f"{entry.id}: unknown or deprecated rules {unknown}"


def test_fixture_hosts_are_placeholders() -> None:
    for entry in ENTRIES:
        for rel, content in entry.files.items():
            text = file_content(rel, content).decode("utf-8", errors="replace")
            for raw_host, rest in _URL.findall(text):
                host = raw_host.lower()
                placeholder = host == "example.invalid" or host.endswith(".example.invalid")
                assert placeholder or (host, rest) in _ALLOWED_URLS | _NAMESPACES, (
                    f"{entry.id}: {rel} contacts {host}{rest}"
                )


def test_reconstruction_files_have_no_raw_invisible_characters() -> None:
    for path in reconstructions.DIRECTORY.glob("*.yaml"):
        text = path.read_text(encoding="utf-8")
        assert not _INVISIBLE.search(text), f"{path.name}: write invisible characters as escapes"


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ({"id": "x"}, "missing"),
        (
            {
                "id": "Bad_Id",
                "title": "t",
                "kind": "incident",
                "year": 2024,
                "technique": "t",
                "sources": ["https://example.invalid/a"],
                "reconstruction": "r",
                "files": {"a.txt": "x"},
                "must_fire": ["RC-AUTO-001"],
            },
            "lowercase",
        ),
    ],
)
def test_format_errors(data: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        parse_entry(data, "case.yaml")


def _valid(**changes: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": "demo",
        "title": "Demo",
        "kind": "technique",
        "year": 2024,
        "technique": "t",
        "sources": ["https://example.invalid/report"],
        "reconstruction": "r",
        "files": {"package.json": '{"scripts": {"postinstall": "echo hi"}}'},
        "must_fire": ["RC-AUTO-001"],
    }
    data.update(changes)
    return data


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"kind": "rumour"}, "kind"),
        ({"sources": ["http://example.invalid/a"]}, "https"),
        ({"sources": []}, "sources"),
        ({"files": {}}, "files"),
        ({"must_fire": []}, "must_fire or known_gaps"),
        ({"must_fire": ["AUTO-1"]}, "not a rule id"),
        ({"must_not_fire": ["RC-AUTO-001"]}, "both expected"),
        ({"known_gaps": [{"rule": "RC-AUTO-003"}]}, "needs a reason"),
        ({"known_gaps": ["RC-AUTO-003"]}, "mapping"),
        ({"surprise": 1}, "unknown"),
    ],
)
def test_entry_validation(changes: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        parse_entry(_valid(**changes), "case.yaml")


def test_duplicate_ids_are_rejected(tmp_path: Path) -> None:
    for name in ("a.yaml", "b.yaml"):
        (tmp_path / name).write_text(yaml.safe_dump(_valid()), encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        load_entries(tmp_path)


def test_fixture_paths_stay_inside(tmp_path: Path) -> None:
    for bad in ("../x", "/abs", "a\\b", "c:/x", "a//b"):
        with pytest.raises(ValueError, match="inside"):
            reconstructions.materialize(tmp_path / "repo", {bad: "x"})
    with pytest.raises(TypeError):
        reconstructions.materialize(tmp_path / "repo", {"a": 1})
    root = reconstructions.materialize(
        tmp_path / "repo",
        {"bin/x": {"base64": "TVo="}, "long.js": {"prefix": "a", "repeat": "b", "count": 3}},
    )
    assert (root / "bin" / "x").read_bytes() == b"MZ"
    assert (root / "long.js").read_text(encoding="utf-8") == "abbb"


def _evaluation_of(entry: Entry, findings: list[dict[str, Any]], failed: list[str]) -> Any:
    coverage = [{"status": "failed", "sample": failed}] if failed else []
    return evaluate(entry, {"findings": findings, "coverage": coverage})


def test_evaluation_reports_each_problem() -> None:
    entry = parse_entry(
        _valid(
            must_fire=[{"rule": "RC-AUTO-001", "path": "package.json"}],
            must_not_fire=["RC-DLX-001"],
            known_gaps=[{"rule": "RC-AUTO-003", "reason": "not matched"}],
        ),
        "case.yaml",
    )
    elsewhere = {"rule_id": "RC-AUTO-001", "confidence": "high", "location": {"path": "x.json"}}
    noise = {"rule_id": "RC-DLX-001", "confidence": "medium", "location": {"path": "a.sh"}}
    closed = {"rule_id": "RC-AUTO-003", "confidence": "high", "location": None}
    result = _evaluation_of(entry, [elsewhere, noise, closed], ["package.json"])
    assert not result.ok
    assert reconstructions.describe(result) == [
        "fixture file could not be read or parsed: package.json",
        "expected but missing: RC-AUTO-001 at package.json",
        "must not fire, but fired: RC-DLX-001",
        "known gap closed, move it to must_fire: RC-AUTO-003",
    ]
    assert result.status == "partly detected"
    hit = {"rule_id": "RC-AUTO-001", "confidence": "high", "location": {"path": "package.json"}}
    assert _evaluation_of(entry, [hit], []).ok
    assert reconstructions.rule_counts([hit, hit, noise]) == {
        "RC-AUTO-001": {"high": 2, "medium": 0, "low": 0},
        "RC-DLX-001": {"high": 0, "medium": 1, "low": 0},
    }


def test_status_without_expected_hits() -> None:
    entry = parse_entry(
        _valid(must_fire=[], known_gaps=[{"rule": "RC-AUTO-003", "reason": "r"}]), "c.yaml"
    )
    assert _evaluation_of(entry, [], []).status == "not detected"
    assert _evaluation_of(parse_entry(_valid(), "c.yaml"), [], []).status == "detected"


@pytest.mark.parametrize("entry", ENTRIES, ids=[e.id for e in ENTRIES])
def test_reconstruction(entry: Entry, tmp_path: Path) -> None:
    result = evaluate(entry, reconstructions.scan(entry, tmp_path))
    assert result.ok, "\n".join(reconstructions.describe(result))
