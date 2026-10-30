"""Regression tests on reconstructions of documented attack techniques.

Every entry in tests/reconstructions/ is written to tmp_path and scanned offline with
the full pipeline (CLI, all built-in rules, JSON report). The rules in ``must_fire``
must report it, the rules in ``must_not_fire`` must stay silent, and every known gap
must still be open: when a gap closes, the test asks to move it to ``must_fire``.

Every variant (a rewrite with an evasion technique) must reach the severity of the
canonical fixture in the files it rewrites, or be listed as a known gap.
"""

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

import reconstructions
from helpers import builtin_rules
from reconstructions import (
    Entry,
    Variant,
    evaluate,
    evaluate_variant,
    file_content,
    load_entries,
    parse_entry,
)

ENTRIES = load_entries()
VARIANTS = [(entry, variant) for entry in ENTRIES for variant in entry.variants]
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
        for rel, content in reconstructions.all_files(entry):
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
        ({"variants": {"a": 1}}, "list"),
        ({"variants": [{"id": "a", "technique": "t"}]}, "exactly the keys"),
        ({"variants": [{"id": "A b", "technique": "t", "files": {"x": "y"}}]}, "lowercase"),
        ({"variants": [{"id": "a", "technique": " ", "files": {"x": "y"}}]}, "technique"),
        ({"variants": [{"id": "a", "technique": "t", "files": {}}]}, "needs files"),
        (
            {"variants": [{"id": "a", "technique": "t", "files": {"x": "y"}}] * 2},
            "duplicate variant",
        ),
        ({"known_gaps": [{"variant": "nope", "reason": "r"}]}, "unknown variants"),
        ({"known_gaps": [{"variant": "a", "rule": "RC-AUTO-001"}]}, "variant and reason"),
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


def _variant_entry(gap: bool = False) -> Entry:
    variant = {"id": "moved", "technique": "t", "files": {"package.json": "{}", "x.sh": "y"}}
    gaps = [{"variant": "moved", "reason": "r"}] if gap else []
    return parse_entry(_valid(variants=[variant], known_gaps=gaps), "c.yaml")


def _finding(rule: str, severity: str, path: str) -> dict[str, Any]:
    return {"rule_id": rule, "severity": severity, "location": {"path": path}}


def test_variant_files_replace_remove_and_add() -> None:
    entry = parse_entry(_valid(files={"a": "1", "b": "2"}), "c.yaml")
    variant = Variant("v", "t", {"a": "3", "b": None, "c": "4"})
    assert entry.variant_files(variant) == {"a": "3", "c": "4"}


def test_variant_evaluation() -> None:
    entry = _variant_entry()
    variant = entry.variants[0]
    canonical = {"findings": [_finding("RC-AUTO-001", "high", "package.json")]}
    below = {"findings": [_finding("RC-DLX-001", "medium", "x.sh")]}
    result = evaluate_variant(entry, variant, canonical, below)
    assert (result.target, result.reached, result.detected) == ("high", "medium", False)
    assert result.problems() == [
        "variant moved reaches medium, below high: fix the rules or list it under known_gaps"
    ]
    # A finding in a file the variant does not rewrite does not count.
    elsewhere = {"findings": [_finding("RC-AUTO-001", "critical", "other.json")]}
    assert evaluate_variant(entry, variant, canonical, elsewhere).reached is None
    reached = {"findings": [_finding("RC-AUTO-099", "critical", "x.sh")]}
    assert evaluate_variant(entry, variant, canonical, reached).ok
    gap_entry = _variant_entry(gap=True)
    assert evaluate_variant(gap_entry, gap_entry.variants[0], canonical, below).ok
    closed = evaluate_variant(gap_entry, gap_entry.variants[0], canonical, reached)
    assert closed.problems() == ["known gap closed, remove it from known_gaps: variant moved"]
    unrelated = {"findings": [_finding("RC-DLX-001", "high", "package.json")]}
    assert "rewrites no file" in evaluate_variant(entry, variant, unrelated, reached).problems()[0]


@pytest.fixture(scope="module")
def canonical_reports(tmp_path_factory: pytest.TempPathFactory) -> dict[str, dict[str, Any]]:
    workdir = tmp_path_factory.mktemp("canonical")
    entries = {entry.id: entry for entry, _ in VARIANTS}
    return {entry_id: reconstructions.scan(entry, workdir) for entry_id, entry in entries.items()}


def test_there_are_variants() -> None:
    assert len(VARIANTS) >= 40


@pytest.mark.parametrize(
    ("entry", "variant"), VARIANTS, ids=[f"{e.id}--{v.id}" for e, v in VARIANTS]
)
def test_variant(
    entry: Entry,
    variant: Variant,
    canonical_reports: dict[str, dict[str, Any]],
    tmp_path: Path,
) -> None:
    report = reconstructions.scan_variant(entry, variant, tmp_path)
    result = evaluate_variant(entry, variant, canonical_reports[entry.id], report)
    assert result.ok, "\n".join(result.problems())
