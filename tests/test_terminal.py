"""Golden test for the terminal report. Regenerate after an intended layout change with
``REPOCHECK_UPDATE_GOLDEN=1 uv run pytest tests/test_terminal.py`` and review the diff."""

import os
from datetime import UTC, datetime
from pathlib import Path

from repocheck.models import (
    Confidence,
    CoverageItem,
    CoverageStatus,
    Finding,
    Location,
    ScanResult,
    Severity,
)
from repocheck.report.terminal import no_findings, render, supports_unicode

GOLDEN = Path(__file__).parent / "golden" / "terminal_report.txt"


def finding(rule_id: str, severity: Severity, path: str | None, **kw: object) -> Finding:
    values: dict[str, object] = {
        "rule_id": rule_id,
        "title": "Title",
        "category": "danger",
        "area": "autorun",
        "severity": severity,
        "confidence": Confidence.HIGH,
        "location": Location(path, 3) if path else None,
        "message": "Something was found.",
        "evidence": None,
        "rationale": "Because tools run this automatically.",
        "recommendation": "Read it first.",
    }
    values.update(kw)
    return Finding(**values)  # type: ignore[arg-type]


def sample_result(findings: list[Finding]) -> ScanResult:
    return ScanResult(
        target="D:\\src\\demo",
        mode="local folder",
        online=False,
        tool_version="0.1.0",
        rules_loaded=3,
        files_scanned=1284,
        started=datetime(2026, 10, 29, tzinfo=UTC),
        duration_s=0.5,
        findings=findings,
        coverage=[
            CoverageItem(
                "area:trust",
                CoverageStatus.NOT_IMPLEMENTED,
                "trust (GitHub API): not implemented yet (milestone 4)",
                1,
            ),
            CoverageItem(
                "file",
                CoverageStatus.SKIPPED,
                "Files larger than 2 MB, content not checked",
                4,
                ("assets/a.mp4", "assets/b.mp4", "assets/c.mp4", "assets/d\u202e.mp4"),
            ),
        ],
        summaries={
            "provenance": [
                ("Files", "1,284 files, 12.3 MB; 1,100 text files with 98,765 lines, 184 binary"),
                ("Languages", "Python 80% (310 files), Shell 20% (4 files)"),
                ("Notable", "AI agent files (1): CLAUDE\u202e.md"),
                ("", "dev container (1): .devcontainer/devcontainer.json"),
            ]
        },
    )


def sample_findings() -> list[Finding]:
    return [
        finding(
            "RC-AUTO-001",
            Severity.MEDIUM,
            "package.json",
            message="package.json defines a 'postinstall' script: node x.js",
        ),
        finding(
            "RC-AGENT-002",
            Severity.CRITICAL,
            "CLAUDE.md",
            area="agents",
            message='2 invisible tag characters hide this text: "Hi"',
            evidence="Hello\U000e0048\U000e0069 \x1b[31m",
            rationale="Unicode tag characters are invisible in editors and on GitHub, but AI "
            "models read them as text and may follow hidden instructions in them.",
        ),
        finding("RC-TRUST-001", Severity.LOW, None, category="trust", area="trust"),
    ]


def test_terminal_report_matches_golden_output() -> None:
    text = render(sample_result(sample_findings()), color=False)
    if os.environ.get("REPOCHECK_UPDATE_GOLDEN"):
        GOLDEN.parent.mkdir(exist_ok=True)
        GOLDEN.write_bytes(text.encode("utf-8"))
    assert text == GOLDEN.read_bytes().decode("utf-8")


def test_report_contains_no_raw_control_or_invisible_characters() -> None:
    text = render(sample_result(sample_findings()), color=False)
    assert "\x1b" not in text
    assert "\u202e" not in text
    assert not any(0xE0000 <= ord(c) <= 0xE007F for c in text)


def test_no_findings_wording() -> None:
    text = render(sample_result([]), color=False)
    assert no_findings(3) in text
    assert "NOT CHECKED" in text
    assert "not a guarantee" in text


def test_min_severity_hides_and_counts() -> None:
    text = render(sample_result(sample_findings()), min_severity=Severity.HIGH)
    assert "RC-AUTO-001" not in text
    assert "2 finding(s) below 'high' not shown" in text


def test_color_codes_only_when_enabled() -> None:
    colored = render(sample_result(sample_findings()), color=True)
    assert "\x1b[1;91mCRITICAL" in colored


def test_ascii_mode_replaces_decorations() -> None:
    text = render(sample_result(sample_findings()), unicode=False)
    header = text.splitlines()[0]
    assert header == (
        "repocheck 0.1.0 | local folder D:\\src\\demo | offline | 1,284 files | 3 rules"
    )
    assert "1 critical | 1 medium" in text
    assert "\u00b7" not in text
    assert "\u2026" not in text
    assert "assets/c.mp4, ..." in text


class _Stream:
    def __init__(self, encoding: object) -> None:
        self.encoding = encoding


def test_supports_unicode() -> None:
    assert supports_unicode(_Stream("utf-8"))
    assert supports_unicode(_Stream("UTF8"))
    assert supports_unicode(_Stream("utf_16_le"))
    assert not supports_unicode(_Stream("cp1252"))
    assert not supports_unicode(_Stream("cp850"))
    assert not supports_unicode(_Stream("no-such-codec"))
    assert not supports_unicode(_Stream(None))
