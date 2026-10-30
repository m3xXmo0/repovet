from pathlib import Path

import pytest

from helpers import builtin_rules, materialize, write_rule
from repovet import scanning
from repovet.cli import EXIT_ABORTED, EXIT_FINDINGS, EXIT_OK, EXIT_USAGE, main
from repovet.report import terminal

TASKS = '{"tasks": [{"label": "x", "runOptions": {"runOn": "folderOpen"}}]}'

type Capture = pytest.CaptureFixture[str]


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return materialize(tmp_path / "repo", {".vscode/tasks.json": TASKS, "README.md": "hi\n"})


def run(capsys: Capture, *args: str) -> tuple[int, str, str]:
    code = main(list(args))
    out, err = capsys.readouterr()
    return code, out, err


RULE_COUNT = len(builtin_rules().active())


def test_clean_folder_exits_0(tmp_path: Path, capsys: Capture) -> None:
    clean = materialize(tmp_path / "clean", {"README.md": "hello\n"})
    code, out, _ = run(capsys, "scan", str(clean), "--no-color")
    assert code == EXIT_OK
    assert f"No findings from {RULE_COUNT} rules" in out
    assert "NOT CHECKED" in out
    assert "trust (GitHub API): no GitHub repository is known for this folder" in out


def test_findings_at_fail_level_exit_1(repo: Path, capsys: Capture) -> None:
    code, out, _ = run(capsys, "scan", str(repo), "--no-color")
    assert code == EXIT_FINDINGS
    assert "RC-AUTO-020" in out
    assert ".vscode/tasks.json:1" in out
    assert "A missing finding is not proof that the repository is safe." in out


def test_fail_on_and_min_severity(repo: Path, capsys: Capture) -> None:
    assert run(capsys, "scan", str(repo), "--fail-on", "critical")[0] == EXIT_OK
    code, out, _ = run(capsys, "scan", str(repo), "--min-severity", "critical", "--no-color")
    assert code == EXIT_FINDINGS
    assert "RC-AUTO-020" not in out
    assert "not shown" in out


def test_ignore_rule(repo: Path, capsys: Capture) -> None:
    code, out, _ = run(capsys, "scan", str(repo), "--ignore-rule", "RC-AUTO-020", "--no-color")
    assert code == EXIT_OK
    assert f"No findings from {RULE_COUNT - 1} rules" in out
    code, _, err = run(capsys, "scan", str(repo), "--ignore-rule", "RC-AUTO-999")
    assert code == EXIT_USAGE
    assert "RC-AUTO-999" in err


@pytest.mark.parametrize(
    "target",
    [
        "http://example.invalid/x.git",
        "ssh://git@example.invalid/x.git",
        "git@github.com:example/repo.git",
        "https://example.invalid/o/r",
    ],
)
def test_unsupported_url_targets(target: str, capsys: Capture) -> None:
    code, _, err = run(capsys, "scan", target)
    assert code == EXIT_USAGE
    assert "supported" in err


def test_bad_targets(tmp_path: Path, capsys: Capture) -> None:
    assert run(capsys, "scan", str(tmp_path / "missing"))[0] == EXIT_USAGE
    file = tmp_path / "file.txt"
    file.write_text("x", encoding="utf-8")
    code, _, err = run(capsys, "scan", str(file))
    assert code == EXIT_USAGE
    assert "not a folder" in err


def test_argument_errors_exit_2(
    repo: Path, capsys: Capture, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CI", "1")  # no menu even if the tests run in a terminal
    assert run(capsys)[0] == EXIT_USAGE
    assert run(capsys, "scan", str(repo), "--fail-on", "urgent")[0] == EXIT_USAGE
    assert run(capsys, "scan", str(repo), "--max-file-size", "lots")[0] == EXIT_USAGE
    assert run(capsys, "frobnicate")[0] == EXIT_USAGE


def test_help_and_version_exit_0(capsys: Capture) -> None:
    code, out, _ = run(capsys, "--version")
    assert code == EXIT_OK
    assert "repovet 0.3.0" in out
    assert run(capsys, "scan", "--help")[0] == EXIT_OK


def test_extra_and_invalid_rules(repo: Path, tmp_path: Path, capsys: Capture) -> None:
    (repo / "marker.txt").write_text("x", encoding="utf-8")
    extra = write_rule(tmp_path / "extra", severity="critical")
    code, out, _ = run(capsys, "scan", str(repo), "--rules", str(extra), "--fail-on", "critical")
    assert code == EXIT_FINDINGS
    assert "RC-AUTO-901" in out
    broken = write_rule(tmp_path / "broken", severity="urgent")
    code, _, err = run(capsys, "scan", str(repo), "--rules", str(broken))
    assert code == EXIT_USAGE
    assert "RC-AUTO-901" in err and "unknown severity" in err
    assert run(capsys, "scan", str(repo), "--rules", str(tmp_path / "none"))[0] == EXIT_USAGE


def test_max_file_size(repo: Path, capsys: Capture) -> None:
    code, out, _ = run(capsys, "scan", str(repo), "--max-file-size", "10", "--no-color")
    assert code == EXIT_OK
    assert "Files larger than 10 bytes, content not checked" in out


def test_env_dirs_skipped_unless_included(tmp_path: Path, capsys: Capture) -> None:
    repo = materialize(
        tmp_path / "repo", {"node_modules/dep/.vscode/tasks.json": TASKS, "a.txt": "x"}
    )
    code, out, _ = run(capsys, "scan", str(repo), "--no-color")
    assert code == EXIT_OK
    assert "Environment and tool cache folders" in out
    assert "node_modules" in out
    code, out, _ = run(capsys, "scan", str(repo), "--no-color", "--include-env-dirs")
    assert "Environment and tool cache folders" not in out
    # The rule itself still excludes vendored folders.
    assert code == EXIT_OK


def test_output_uses_ascii_without_utf_encoding(
    repo: Path, capsys: Capture, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(terminal, "supports_unicode", lambda stream=None: False)
    _, out, _ = run(capsys, "scan", str(repo), "--no-color")
    assert "·" not in out
    assert " | offline | " in out


def test_repository_strings_are_sanitized(tmp_path: Path, capsys: Capture) -> None:
    repo = materialize(
        tmp_path / "repo", {"package.json": '{"scripts": {"install": "x \\u001b[2J\\u202e y"}}'}
    )
    code, out, _ = run(capsys, "scan", str(repo), "--no-color")
    assert code == EXIT_OK
    assert "\x1b" not in out and "\u202e" not in out
    assert "<U+001B>[2J<U+202E>" in out


def test_no_color_env(repo: Path, capsys: Capture, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    _, out, _ = run(capsys, "scan", str(repo))
    assert "\x1b[" not in out


def test_piped_output_has_no_color_by_default(repo: Path, capsys: Capture) -> None:
    _, out, _ = run(capsys, "scan", str(repo))
    assert "\x1b[" not in out


def test_force_color_env_colors_piped_output(
    repo: Path, capsys: Capture, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FORCE_COLOR", "1")
    _, out, _ = run(capsys, "scan", str(repo))
    assert "\x1b[91mHIGH" in out
    assert "\x1b[0m" in out


@pytest.mark.parametrize(
    ("env", "args"),
    [
        ({"FORCE_COLOR": ""}, ()),
        ({"FORCE_COLOR": "1", "NO_COLOR": "1"}, ()),
        ({"FORCE_COLOR": "1"}, ("--no-color",)),
    ],
    ids=["empty-force-color", "no-color-wins", "flag-wins"],
)
def test_force_color_is_overridden(
    repo: Path,
    capsys: Capture,
    monkeypatch: pytest.MonkeyPatch,
    env: dict[str, str],
    args: tuple[str, ...],
) -> None:
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    _, out, _ = run(capsys, "scan", str(repo), *args)
    assert "\x1b[" not in out


def test_force_color_does_not_color_report_files(
    repo: Path, tmp_path: Path, capsys: Capture, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("FORCE_COLOR", "1")
    report = tmp_path / "report.txt"
    run(capsys, "scan", str(repo), "-o", str(report))
    text = report.read_text(encoding="utf-8")
    assert "HIGH" in text
    assert "\x1b[" not in text


def test_internal_error_exits_3(
    repo: Path, capsys: Capture, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(ctx: object) -> list[object]:
        raise RuntimeError("bug \x1b[31m")

    monkeypatch.setattr(scanning, "run_all", boom)
    code, _, err = run(capsys, "scan", str(repo), "-v")
    assert code == EXIT_ABORTED
    assert "internal error" in err
    assert "\x1b" not in err
    assert "Traceback" in err


def test_rules_list(capsys: Capture) -> None:
    code, out, _ = run(capsys, "rules", "list")
    assert code == EXIT_OK
    rules = builtin_rules().rules
    assert [line.split()[0] for line in out.splitlines()] == [r.id for r in rules]
    assert "RC-AUTO-020" in out
    _, out, _ = run(capsys, "rules", "list", "--area", "agents")
    listed = [line.split()[0] for line in out.splitlines()]
    assert listed == [r.id for r in rules if r.area == "agents"]
    assert all(rule_id.startswith("RC-AGENT-") for rule_id in listed)
