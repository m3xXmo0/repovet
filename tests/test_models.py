import pytest

from repovet.models import (
    AREAS,
    CATEGORIES,
    Confidence,
    CoverageCollector,
    CoverageStatus,
    Severity,
)


def test_severity_order_and_parse() -> None:
    assert Severity.INFO < Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL
    assert Severity.parse("High") is Severity.HIGH
    assert Severity.CRITICAL.label == "critical"
    assert Confidence.parse(" medium ") is Confidence.MEDIUM
    with pytest.raises(ValueError, match="unknown severity"):
        Severity.parse("urgent")


def test_areas_have_unique_prefixes_and_known_categories() -> None:
    prefixes = [info.prefix for info in AREAS.values()]
    assert len(prefixes) == len(set(prefixes))
    assert all(info.category in CATEGORIES for info in AREAS.values())


def test_coverage_collector_merges_and_counts_paths_once() -> None:
    collector = CoverageCollector()
    for path in ("b.bin", "a.bin", "a.bin", "c.bin", "d.bin", "e.bin", "f.bin"):
        collector.add("file", CoverageStatus.SKIPPED, "Binary files", path)
    collector.add("area:trust", CoverageStatus.NOT_IMPLEMENTED, "trust: not implemented yet")
    items = collector.items()
    assert [i.status for i in items] == [CoverageStatus.NOT_IMPLEMENTED, CoverageStatus.SKIPPED]
    binary = items[1]
    assert binary.count == 6
    assert binary.sample == ("a.bin", "b.bin", "c.bin", "d.bin", "e.bin")


def test_coverage_collector_counts_entries_without_paths() -> None:
    collector = CoverageCollector()
    collector.add("scan", CoverageStatus.PARTIAL, "limit reached")
    collector.add("scan", CoverageStatus.PARTIAL, "limit reached", count=2)
    (item,) = collector.items()
    assert item.count == 3
    assert item.sample == ()
