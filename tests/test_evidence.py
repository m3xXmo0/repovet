"""The README "Evidence" section is exactly what scripts/evidence.py generates.

The reconstructions are scanned again here and the false-positive numbers come from
docs/fp-benchmark.json, so no number in the section can be edited by hand. Only the
date is taken from README.md (it records when the section was generated).
"""

import json

import evidence
import fp_benchmark
import pytest
from evidence import current_section, render, replace_section, section_date

import reconstructions
from repovet import __version__

BENCHMARK = {
    "date": "2026-10-30",
    "repovet": "0.3.0",
    "requested": 2,
    "rules_loaded": 126,
    "max_clone_size": 1,
    "repositories": [
        {
            "repo": "octo/alpha",
            "stars": 3,
            "commit": "a" * 40,
            "files": 1,
            "findings": {"RC-AUTO-001": {"severity": "medium", "high": 1, "medium": 0, "low": 0}},
        }
    ],
    "skipped": [{"repo": "octo/huge", "stars": 1, "reason": "too large"}],
}


def _entry(entry_id: str, must_fire: list[object], gaps: list[object]) -> reconstructions.Entry:
    return reconstructions.parse_entry(
        {
            "id": entry_id,
            "title": entry_id.title(),
            "kind": "incident",
            "year": 2024,
            "technique": "t",
            "sources": ["https://example.invalid/report"],
            "reconstruction": "r",
            "files": {"a.txt": "x"},
            "must_fire": must_fire,
            "known_gaps": gaps,
        },
        f"{entry_id}.yaml",
    )


def test_render_counts_and_wording() -> None:
    gap = {"rule": "RC-OBF-003", "reason": "r"}
    evaluations = [
        reconstructions.evaluate(_entry("one", ["RC-AUTO-001"], []), {"findings": []}),
        reconstructions.evaluate(_entry("two", ["RC-AUTO-001"], [gap]), {"findings": []}),
        reconstructions.evaluate(_entry("three", [], [gap]), {"findings": []}),
    ]
    text = render(evaluations, BENCHMARK, version="9.9.9", date="2026-01-02")
    assert "(repovet 9.9.9, 2026-01-02)" in text
    assert "**1 detected**, **1 partly detected**" in text
    assert "**1 not detected**" in text
    rows = [line for line in text.splitlines() if line.startswith("| [")]
    assert [row.split("]")[0] for row in rows] == ["| [One", "| [Two", "| [Three"]
    assert "| detected | RC-AUTO-001 | - |" in rows[0]
    assert "| not detected | - | RC-OBF-003 |" in rows[2]
    assert "the 2 most-starred GitHub repositories** (repovet 0.3.0, 2026-10-30)" in text
    assert "1 scanned offline with all rules, 1 skipped" in text
    assert "RC-AUTO-001 (medium, 1 of 1)" in text
    assert "**No findings does not mean safe.**" in text
    assert section_date(text) == "2026-01-02"


def test_gap_of_a_firing_rule_names_its_file() -> None:
    entry = _entry(
        "worm",
        [{"rule": "RC-DLX-005", "path": "bundle.js"}],
        [
            {"rule": "RC-DLX-005", "path": "wf.yml", "reason": "r"},
            {"rule": "RC-OBF-003", "path": "x.js", "reason": "r"},
        ],
    )
    text = render(
        [reconstructions.evaluate(entry, {"findings": []})], BENCHMARK, version="1", date="d"
    )
    assert "| RC-DLX-005 | RC-DLX-005 in `wf.yml`, RC-OBF-003 |" in text


def test_section_replacement() -> None:
    text = f"intro\n{evidence.START}\nold\n{evidence.END}\noutro\n"
    assert current_section(text) == "old"
    assert replace_section(text, "new") == f"intro\n{evidence.START}\nnew\n{evidence.END}\noutro\n"
    with pytest.raises(ValueError, match="once each"):
        current_section("no markers")


def test_readme_section_is_generated() -> None:
    section = current_section(evidence.README.read_text(encoding="utf-8"))
    date = section_date(section)
    assert date, "the Evidence section has no date; run scripts/evidence.py --write"
    assert f"(repovet {__version__}, {date})" in section, (
        "the Evidence section is from another version; run scripts/evidence.py --write"
    )
    expected = evidence.build_section(date)
    assert section == expected, "README Evidence is out of date; run scripts/evidence.py --write"


def test_benchmark_data_is_present() -> None:
    data = json.loads(fp_benchmark.DATA.read_text(encoding="utf-8"))
    assert data["repositories"], "the benchmark has no scanned repositories"
