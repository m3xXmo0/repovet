"""HTML report: self-contained, no scripts, everything from the repository escaped."""

import re
from dataclasses import replace
from html.parser import HTMLParser
from pathlib import Path

import pytest

from helpers import materialize
from repovet.cli import EXIT_FINDINGS, main
from repovet.models import Location, Severity
from repovet.report import html
from repovet.report.common import no_findings
from test_terminal import finding, sample_findings, sample_result

HOSTILE = '"><script>alert(1)</script><img src=x onerror=y>'


class _Tags(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[tuple[str, dict[str, str | None]]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, dict(attrs)))


def tags(text: str) -> list[tuple[str, dict[str, str | None]]]:
    parser = _Tags()
    parser.feed(text)
    return parser.tags


def test_self_contained_without_scripts_or_external_resources() -> None:
    text = html.render(sample_result(sample_findings()))
    found = tags(text)
    names = {tag for tag, _ in found}
    assert "script" not in names and "img" not in names and "link" not in names
    assert "iframe" not in names and "object" not in names
    assert not any(k.startswith("on") for _, attrs in found for k in attrs)
    assert not any(attrs.get("src") for _, attrs in found)
    csp = [a["content"] for t, a in found if t == "meta" and a.get("http-equiv")]
    assert csp == [html.CSP] and "default-src 'none'" in html.CSP
    # The only links are rule references (https) and anchors inside the page.
    hrefs = [a["href"] for t, a in found if t == "a"]
    assert hrefs and all(h and (h.startswith("#g") or h.startswith("https://")) for h in hrefs)
    assert "@import" not in text and "url(" not in text


def test_repository_strings_are_escaped_and_masked() -> None:
    hostile = replace(
        sample_findings()[0],
        message=HOSTILE,
        evidence=HOSTILE + "\u202e",
        location=Location(f"a{HOSTILE}\u202e.md", 2),
        context="test",
    )
    result = sample_result([hostile])
    result.target = HOSTILE
    text = html.render(result)
    assert "<script>" not in text and "<img" not in text and "onerror=y>" not in text
    assert "&lt;script&gt;" in text
    assert "\u202e" not in text and "&lt;U+202E&gt;" in text
    assert "\x1b" not in text


def test_groups_are_collapsible_and_severe_ones_open() -> None:
    text = html.render(sample_result(sample_findings()))
    details = [attrs for tag, attrs in tags(text) if tag == "details"]
    # critical, high chain, high (2 places), two medium chain parts, low, info (2 places)
    assert len(details) == 7
    opened = [d["class"] for d in details if "open" in d]
    assert opened == ["critical", "high", "high"]
    assert "2 places" in text
    assert '<span class="label">test</span>' in text
    assert '<span class="label">part of chain-1</span>' in text
    assert "<dt>Path</dt><dd>chain-1: <code>package.json:3</code> &rarr; <code>x.js</code>" in text
    assert '<p class="action">Do not let an AI coding agent work in it' in text


def test_profiles_not_checked_notice_and_dark_mode() -> None:
    text = html.render(sample_result(sample_findings()))
    assert "Provenance profile" in text
    assert "<h2>Not checked</h2>" in text
    assert "not proof that the repository is safe" in text
    assert "prefers-color-scheme: dark" in text
    assert "Look at these first" in text
    empty = html.render(sample_result([]))
    assert no_findings(3).replace("'", "&#x27;") in empty


def test_min_severity_and_only_info() -> None:
    text = html.render(sample_result(sample_findings()), min_severity=Severity.CRITICAL)
    assert "8 finding(s) below" in text
    info = html.render(sample_result([finding("RC-AGENT-001", Severity.INFO, "CLAUDE.md")]))
    assert "Only info findings" in info


def test_well_formed_nesting() -> None:
    text = html.render(sample_result(sample_findings()))
    for tag in ("details", "summary", "ul", "ol", "dl", "table", "section", "main"):
        opened = len(re.findall(f"<{tag}[ >]", text))
        assert opened == text.count(f"</{tag}>"), tag


def test_cli_html_to_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    tasks = (
        '{"tasks": [{"label": "x", "command": "node setup.js",'
        ' "runOptions": {"runOn": "folderOpen"}}]}'
    )
    repo = materialize(tmp_path / "repo", {".vscode/tasks.json": tasks})
    report = tmp_path / "report.html"
    assert main(["scan", str(repo), "--format", "html", "-o", str(report)]) == EXIT_FINDINGS
    text = report.read_text(encoding="utf-8")
    assert text.startswith("<!DOCTYPE html>")
    assert "RC-AUTO-020" in text
    assert "\x1b[" not in text
    capsys.readouterr()
