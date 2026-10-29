"""Trust area end to end through the CLI, with recorded API answers (no network)."""

import json
from pathlib import Path

import pytest

from github_fake import Answer, FakeTransport, install
from helpers import materialize
from repocheck.cli import EXIT_OK, main
from repocheck.github import target as github_target
from repocheck.github.client import Request, Response, TransportError

SECRET = "ghp_" + "S3cr3tT0kenValue" * 2 + "abcd"
REPO = "/repos/example-org/example-repo"

type Capture = pytest.CaptureFixture[str]


def folder(tmp_path: Path, remote: str = "git@github.com:example-org/example-repo.git") -> Path:
    root = materialize(tmp_path / "repo", {"README.md": "# demo\n"})
    (root / ".git").mkdir()
    (root / ".git" / "config").write_text(
        f'[remote "origin"]\n\turl = {remote}\n', encoding="utf-8"
    )
    return root


def scan_json(capsys: Capture, *args: str) -> tuple[int, dict[str, object], str]:
    code = main(["scan", *args, "--format", "json"])
    out, err = capsys.readouterr()
    return code, json.loads(out), err


def trust_coverage(report: dict[str, object]) -> list[str]:
    items = report["coverage"]
    assert isinstance(items, list)
    return [c["reason"] for c in items if c["scope"] == "area:trust"]


def test_local_folder_names_its_repository_through_the_remote(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Capture
) -> None:
    transport = install(
        monkeypatch, FakeTransport({REPO: Answer({"full_name": "example-org/example-repo"})})
    )
    code, report, _ = scan_json(capsys, str(folder(tmp_path)))
    assert code == EXIT_OK
    assert transport.paths[:2] == ["/rate_limit", REPO]
    facts = report["facts"]
    assert isinstance(facts, dict)
    assert facts["trust"]["repository"]["full_name"] == "example-org/example-repo"
    assert facts["trust"]["api"]["token"] is False
    assert report["scan"]["online"] is True  # type: ignore[index]


def test_offline_sends_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Capture
) -> None:
    transport = install(monkeypatch, FakeTransport())
    code, report, _ = scan_json(capsys, str(folder(tmp_path)), "--offline")
    assert code == EXIT_OK
    assert transport.requests == []
    assert report["scan"]["online"] is False  # type: ignore[index]
    assert trust_coverage(report) == [
        "trust (GitHub API): --offline: the GitHub API was not queried"
    ]
    assert "trust" not in report["facts"]  # type: ignore[operator]


@pytest.mark.parametrize(
    ("remote", "reason"),
    [
        ("https://gitlab.com/example-org/example-repo", "is not a GitHub repository"),
        ("", "no GitHub repository is known for this folder"),
    ],
)
def test_folder_without_a_github_remote(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Capture, remote: str, reason: str
) -> None:
    transport = install(monkeypatch, FakeTransport())
    root = folder(tmp_path, remote) if remote else materialize(tmp_path / "plain", {"a.txt": "a"})
    code, report, _ = scan_json(capsys, str(root))
    assert code == EXIT_OK and transport.requests == []
    assert any(reason in r for r in trust_coverage(report))


def test_rate_limit_is_not_an_abort(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Capture
) -> None:
    transport = install(monkeypatch, FakeTransport(remaining=0))
    code, report, _ = scan_json(capsys, str(folder(tmp_path)))
    assert code == EXIT_OK
    assert transport.paths == ["/rate_limit"]
    (reason,) = trust_coverage(report)
    assert "rate limit reached (0 of 60 requests left, resets at" in reason


def test_missing_repository_and_unreachable_api(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Capture
) -> None:
    install(monkeypatch, FakeTransport())
    code, report, _ = scan_json(capsys, str(folder(tmp_path)))
    assert code == EXIT_OK
    assert any("was not found (private, deleted or renamed)" in r for r in trust_coverage(report))

    def unreachable(request: Request, max_bytes: int) -> Response:
        raise TransportError("timed out")

    monkeypatch.setattr(github_target, "DEFAULT_TRANSPORT", lambda: unreachable)
    code, report, _ = scan_json(capsys, str(folder(tmp_path / "again")))
    assert code == EXIT_OK
    assert any("GitHub API not reachable" in r for r in trust_coverage(report))


def test_invalid_token_is_not_used_and_not_shown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Capture
) -> None:
    bad = "not a token " + SECRET
    monkeypatch.setenv("GITHUB_TOKEN", bad)
    transport = install(monkeypatch, FakeTransport({REPO: Answer({"full_name": "x/y"})}))
    code, report, err = scan_json(capsys, str(folder(tmp_path)))
    assert code == EXIT_OK
    assert all("Authorization" not in r.headers for r in transport.requests)
    assert any("does not look like a GitHub token" in r for r in trust_coverage(report))
    assert SECRET not in json.dumps(report) and SECRET not in err


@pytest.mark.parametrize("fmt", ["text", "json", "sarif"])
@pytest.mark.parametrize("variable", ["GITHUB_TOKEN", "GH_TOKEN"])
def test_token_never_appears_in_any_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Capture, fmt: str, variable: str
) -> None:
    monkeypatch.setenv(variable, SECRET)
    echo = Answer({"message": f"Bearer {SECRET} rejected", "full_name": SECRET}, 403)
    answers = {REPO: Answer({"full_name": "example-org/example-repo"}), "/users/x": echo}
    transport = install(monkeypatch, FakeTransport(answers))
    for args in (
        [str(folder(tmp_path / "ok"))],
        [str(folder(tmp_path / "echo", "https://github.com/x/y")), "-v"],
    ):
        main(["scan", *args, "--format", fmt])
        out, err = capsys.readouterr()
        assert SECRET not in out and SECRET not in err
        assert out  # a report was written
    sent = [r for r in transport.requests if "Authorization" in r.headers]
    assert sent and all(r.headers["Authorization"] == f"Bearer {SECRET}" for r in sent)


def test_token_does_not_leak_through_an_echoing_api(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Capture
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", SECRET)
    echo = Answer({"message": f"token {SECRET} not allowed"}, 403)
    install(monkeypatch, FakeTransport({REPO: echo}))
    for fmt in ("text", "json", "sarif"):
        main(["scan", str(folder(tmp_path / fmt)), "--format", fmt, "-v"])
        out, err = capsys.readouterr()
        assert SECRET not in out and SECRET not in err
        assert "***" in out
