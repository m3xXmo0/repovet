"""Interactive mode: menus driven by typed answers (StringIO), no real terminal."""

import io
import json
import sys
from pathlib import Path

import pytest

from helpers import materialize
from repovet import cli, interactive
from repovet.cli import EXIT_ABORTED, EXIT_FINDINGS, EXIT_OK, EXIT_USAGE, main
from repovet.interactive import Session
from repovet.scanning import Scanned, ScanOptions, scan

TASKS = '{"tasks": [{"label": "x", "runOptions": {"runOn": "folderOpen"}}]}'
TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"


class Tty(io.StringIO):
    def isatty(self) -> bool:
        return True


def session(answers: str, environ: dict[str, str] | None = None) -> tuple[Session, io.StringIO]:
    out = io.StringIO()
    return Session(io.StringIO(answers), out, environ or {}), out


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return materialize(tmp_path / "repo", {".vscode/tasks.json": TASKS, "README.md": "hi\n"})


def test_wanted_only_on_terminals_and_never_in_ci() -> None:
    assert interactive.wanted(Tty(), Tty(), {})
    assert not interactive.wanted(Tty(), Tty(), {"CI": "true"})
    assert not interactive.wanted(io.StringIO(), Tty(), {})
    assert not interactive.wanted(Tty(), io.StringIO(), {})
    assert interactive.wanted(Tty(), Tty(), {"CI": ""})


def test_exit_without_scan_returns_0() -> None:
    s, out = session("4\n")
    assert s.run() == EXIT_OK
    assert "Check a GitHub repository" in out.getvalue()


def test_invalid_input_shows_the_menu_again() -> None:
    s, out = session("x\n9\n\n4\n")
    assert s.run() == EXIT_OK
    text = out.getvalue()
    assert text.count("Please type a number from 1 to 4.") == 3
    assert text.count("Check a folder on this computer") == 4


def test_end_of_input_leaves_cleanly() -> None:
    s, _ = session("")
    assert s.run() == EXIT_OK


def test_folder_scan_details_and_exit_code(repo: Path) -> None:
    s, out = session(f"2\n{repo}\n1\n1\n4\n")
    assert s.run() == EXIT_FINDINGS
    text = out.getvalue()
    assert "SUMMARY" in text and "RC-AUTO-020" in text
    assert "Why  " in text and "Do   " in text  # the detail view
    assert "What next?" in text


def test_folder_given_with_quotes_and_missing_folder(repo: Path, tmp_path: Path) -> None:
    s, out = session(f'2\n"{repo}"\n4\n')
    assert s.run() == EXIT_FINDINGS
    s, out = session(f"2\n{tmp_path / 'missing'}\n4\n")
    assert s.run() == EXIT_OK
    assert "target not found" in out.getvalue()


def test_save_report_in_every_format(repo: Path, tmp_path: Path) -> None:
    for number, fmt in enumerate(("html", "json", "sarif", "text"), 1):
        target = tmp_path / f"report.{fmt}"
        s, out = session(f"2\n{repo}\n2\n{number}\n{target}\n4\n")
        s.run()
        assert target.is_file(), out.getvalue()
    assert json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))["findings"]
    assert (tmp_path / "report.html").read_text(encoding="utf-8").startswith("<!DOCTYPE html>")
    assert "\x1b[" not in (tmp_path / "report.text").read_text(encoding="utf-8")


def test_save_never_inside_the_checked_folder_and_asks_before_overwriting(
    repo: Path, tmp_path: Path
) -> None:
    s, out = session(f"2\n{repo}\n2\n2\n{repo / 'r.json'}\n4\n")
    s.run()
    assert "outside the checked folder" in out.getvalue()
    assert not (repo / "r.json").exists()
    existing = tmp_path / "keep.json"
    existing.write_text("old", encoding="utf-8")
    s, out = session(f"2\n{repo}\n2\n2\n{existing}\n\n4\n")
    s.run()
    assert "Not saved." in out.getvalue()
    assert existing.read_text(encoding="utf-8") == "old"


def test_settings_show_token_presence_never_the_value() -> None:
    s, out = session("3\n2\n4\n", {"GITHUB_TOKEN": TOKEN})
    s.run()
    text = out.getvalue()
    assert "set (from GITHUB_TOKEN)" in text
    assert TOKEN not in text
    s, out = session("3\n2\n4\n")
    s.run()
    assert "not set" in out.getvalue()


def test_offline_toggle_is_used_for_scans(repo: Path) -> None:
    seen: list[ScanOptions] = []

    def recording(options: ScanOptions, note: object) -> Scanned:
        seen.append(options)
        return scan(options, lambda _m: None)

    out = io.StringIO()
    s = Session(io.StringIO(f"3\n1\n2\n2\n{repo}\n3\n4\n"), out, {}, scanner=recording)
    s.run()
    assert "Offline mode:  on" in out.getvalue()
    assert seen and seen[0].offline


def test_url_input_is_checked(monkeypatch: pytest.MonkeyPatch) -> None:
    s, out = session("1\nnot a url\n1\nhttps://example.invalid/a/b\n1\n\n4\n")
    assert s.run() == EXIT_OK
    text = out.getvalue()
    assert "That is not a URL" in text
    assert "only GitHub repositories are supported" in text


def test_scan_another_repository(repo: Path, tmp_path: Path) -> None:
    clean = materialize(tmp_path / "clean", {"README.md": "hi\n"})
    s, out = session(f"2\n{repo}\n3\n2\n{clean}\n4\n")
    assert s.run() == EXIT_OK  # exit code of the last scan
    assert out.getvalue().count("SUMMARY") == 2


def test_main_starts_the_menu_only_without_arguments_on_a_terminal(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.setattr(sys, "stdin", Tty("4\n"))
    monkeypatch.setattr(interactive, "wanted", lambda stdin, stdout, environ: True)
    assert main([]) == EXIT_OK
    assert "What do you want to do?" in capsys.readouterr().out
    monkeypatch.setattr(interactive, "wanted", lambda stdin, stdout, environ: False)
    assert main([]) == EXIT_USAGE


def test_ctrl_c_exits_with_the_existing_code(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def interrupted(stdin: object, stdout: object, environ: object) -> int:
        raise KeyboardInterrupt

    monkeypatch.setattr(interactive, "wanted", lambda stdin, stdout, environ: True)
    monkeypatch.setattr(interactive, "run", interrupted)
    assert main([]) == EXIT_ABORTED
    assert "interrupted" in capsys.readouterr().err
    assert cli.EXIT_ABORTED == 3
