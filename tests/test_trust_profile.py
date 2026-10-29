"""The trust profile (facts) from recorded, anonymized API answers."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from github_fake import Answer, FakeTransport, case_answers, install, load_fixture
from gitrepo import CommitSpec, build_repo, local_transport
from helpers import materialize
from repovet.analyzers import trust
from repovet.cli import EXIT_OK, main
from repovet.github.client import GitHubClient
from repovet.sources import remote
from test_report_formats import validate_json, validate_sarif
from test_trust import REPO, Capture, folder, scan_json, trust_coverage


def established(**changes: dict[str, object]) -> dict[str, Answer]:
    """The recorded answers of an established project; ``repo=`` updates the repository
    answer."""
    answers = load_fixture("established")
    for key, update in changes.items():
        assert key == "repo"
        body = answers[REPO].body
        assert isinstance(body, dict)
        body.update(update)
    return answers


def test_trust_profile_from_recorded_answers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Capture
) -> None:
    transport = install(monkeypatch, FakeTransport(established(), remaining=58))
    code, report, _ = scan_json(capsys, str(folder(tmp_path)))
    assert code == EXIT_OK
    validate_json(report)
    trust: Any = report["facts"]["trust"]  # type: ignore[index]
    repo = trust["repository"]
    assert repo["full_name"] == "example-org/example-repo" and repo["requested"] is None
    counts = (repo["stars"], repo["forks"], repo["watchers"], repo["open_issues"])
    assert counts == (74935, 17200, 2130, 4)
    assert (repo["created"], repo["pushed"]) == ("2010-04-06", "2026-10-07")
    assert repo["age_days"] > 5800 and repo["days_since_push"] >= 0
    assert repo["archived"] is False and repo["fork"] is False and repo["parent"] is None
    assert repo["default_branch"] == "main" and repo["default_branch_protected"] is True
    assert repo["license"] == "BSD-3-Clause"
    owner = trust["owner"]
    assert (owner["login"], owner["type"], owner["created"]) == (
        "example-org",
        "Organization",
        "2016-01-17",
    )
    assert (owner["public_repos"], owner["followers"]) == (16, 2654)
    activity = trust["activity"]
    assert (activity["commits"], activity["contributors"], activity["releases"]) == (5562, 864, 38)
    assert activity["last_commit"] == "2026-10-07"
    release = activity["latest_release"]
    assert release["tag"] == "3.1.3" and release["published"] == "2026-02-19"
    assert release["asset_names"] == [
        "example-repo-3.1.3-py3-none-any.whl",
        "example-repo-3.1.3.tar.gz",
    ]
    assert trust["security_policy"] is False
    assert trust["local"] == {
        "claimed_by": "remote 'origin' in .git/config",
        "head": None,
        "head_found": None,
    }
    assert (
        trust["api"]["requests"] == 7 and trust["api"]["rate_limit"]["remaining"] == 52
    )  # the search has its own limit
    assert trust_coverage(report) == []
    assert len(transport.requests) == 8  # 7 plus the free rate-limit check

    main(["scan", str(folder(tmp_path / "text")), "--no-color"])
    text = capsys.readouterr().out
    assert "TRUST PROFILE                            facts, not findings" in text
    flat = " ".join(text.split())
    for expected in (
        "Repository example-org/example-repo, created 2010-04-06",
        "Owner example-org (organization), account created 2016-01-17",
        "16 public repositories, 2,654 followers",
        "Popularity 74,935 stars, 17,200 forks, 2,130 watchers",
        "5,562 commits on main, last 2026-10-07",
        "864 contributors; 38 releases, latest 3.1.3 on 2026-02-19 (2 assets)",
        "not archived; not a fork; main is protected; license BSD-3-Clause (GitHub)",
        "no security policy in the files",
        "no token",
        "can be bought or faked; these are indicators, not proof.",
    ):
        assert expected in flat, expected
    assert text.index("TRUST PROFILE") < text.index("PROVENANCE PROFILE")

    main(["scan", str(folder(tmp_path / "sarif")), "--format", "sarif"])
    sarif = json.loads(capsys.readouterr().out)
    validate_sarif(sarif)
    properties = sarif["runs"][0]["properties"]
    assert properties["facts"]["trust"]["repository"]["stars"] == 74935
    assert properties["online"] is True


def test_security_policy_comes_from_the_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Capture
) -> None:
    install(monkeypatch, FakeTransport(established()))
    root = folder(tmp_path)
    (root / "SECURITY.md").write_text("Report issues privately.\n", encoding="utf-8")
    _, report, _ = scan_json(capsys, str(root))
    assert report["facts"]["trust"]["security_policy"] is True  # type: ignore[index]


@pytest.mark.parametrize("known", [True, False])
def test_local_head_is_looked_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Capture, known: bool
) -> None:
    root = materialize(tmp_path / "repo", {"a.txt": "a\n"})
    (head,) = build_repo(root / ".git", [CommitSpec({"a.txt": "a\n"})])
    with (root / ".git" / "config").open("a", encoding="utf-8") as handle:
        handle.write('[remote "origin"]\n\turl = https://github.com/example-org/example-repo\n')
    answers = established()
    if known:
        answers[f"{REPO}/commits/{head}"] = Answer(raw=head.encode("ascii"))
    transport = install(monkeypatch, FakeTransport(answers))
    _, report, _ = scan_json(capsys, str(root))
    local = report["facts"]["trust"]["local"]  # type: ignore[index]
    assert local == {
        "claimed_by": "remote 'origin' in .git/config",
        "head": head,
        "head_found": known,
    }
    lookup = next(r for r in transport.requests if r.url.endswith(f"/commits/{head}"))
    assert lookup.headers["Accept"] == "application/vnd.github.sha"
    assert trust_coverage(report) == []  # "not found" is the answer here, not a gap

    main(["scan", str(root), "--no-color"])
    word = "found" if known else "NOT found"
    flat = " ".join(capsys.readouterr().out.split())
    assert f"Local HEAD {head[:12]} {word} in example-org/example-repo" in flat


def test_gaps_are_listed_and_the_rest_is_kept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Capture
) -> None:
    answers = established()
    too_large = "The history or contributor list is too large to list contributors"
    answers[f"{REPO}/contributors?anon=true&per_page=1"] = Answer({"message": too_large}, 403)
    answers[f"{REPO}/releases?per_page=1"] = Answer({"message": "Server Error"}, 502)
    del answers["/users/example-org"]
    install(monkeypatch, FakeTransport(answers))
    code, report, _ = scan_json(capsys, str(folder(tmp_path)))
    assert code == EXIT_OK
    validate_json(report)
    trust: Any = report["facts"]["trust"]  # type: ignore[index]
    assert trust["owner"] is None
    assert trust["activity"]["contributors"] is None and trust["activity"]["releases"] is None
    assert trust["activity"]["commits"] == 5562
    assert sorted(trust_coverage(report)) == [
        f"trust (GitHub API): contributors not available (HTTP 403: {too_large})",
        "trust (GitHub API): owner account not available (not found)",
        "trust (GitHub API): releases not available (HTTP 502)",
    ]


def test_rate_limit_during_the_profile_keeps_what_was_learned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Capture
) -> None:
    transport = install(monkeypatch, FakeTransport(established(), remaining=3))
    code, report, _ = scan_json(capsys, str(folder(tmp_path)))
    assert code == EXIT_OK
    validate_json(report)
    trust: Any = report["facts"]["trust"]  # type: ignore[index]
    assert trust["repository"]["stars"] == 74935 and trust["owner"]["login"] == "example-org"
    assert trust["activity"]["commits"] == 5562
    assert trust["activity"]["contributors"] is None
    assert trust["api"]["requests"] == 3 and "rate limit reached" in trust["api"]["stopped"]
    assert len(transport.requests) == 4
    (reason,) = trust_coverage(report)
    assert reason.startswith("trust (GitHub API): stopped (GitHub API rate limit reached (0 of 60")
    assert reason.endswith("not checked: contributors, releases, default branch, name search")


def test_renamed_archived_fork_from_a_template(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Capture
) -> None:
    moved = "/repos/new-owner/new-name"
    answers = established(
        repo={
            "full_name": "new-owner/new-name",
            "owner": {"login": "new-owner", "type": "User"},
            "archived": True,
            "fork": True,
            "parent": {"full_name": "upstream-org/new-name", "stargazers_count": 12345},
            "source": {"full_name": "upstream-org/new-name"},
            "template_repository": {"full_name": "templates/starter"},
            "license": {"spdx_id": "NOASSERTION"},
        }
    )
    answers[moved] = answers[REPO]
    answers[REPO] = Answer(None, 301, {"location": f"https://api.github.com{moved}"})
    transport = install(monkeypatch, FakeTransport(answers))
    code, report, _ = scan_json(capsys, str(folder(tmp_path)))
    assert code == EXIT_OK
    validate_json(report)
    repo: Any = report["facts"]["trust"]["repository"]  # type: ignore[index]
    assert repo["requested"] == "example-org/example-repo"
    assert (repo["parent"], repo["parent_stars"], repo["source"]) == (
        "upstream-org/new-name",
        12345,
        "upstream-org/new-name",
    )
    assert repo["license"] is None and repo["license_other"] is True
    # Follow-up requests use the current name.
    assert "/users/new-owner" in transport.paths
    assert f"{moved}/commits?per_page=1&sha=main" in transport.paths

    main(["scan", str(folder(tmp_path / "text")), "--no-color"])
    flat = " ".join(capsys.readouterr().out.split())
    assert "new-owner/new-name (requested as example-org/example-repo: renamed or" in flat
    assert "archived; fork of upstream-org/new-name (12,345 stars)" in flat
    assert "generated from template templates/starter" in flat
    assert "license not recognized by GitHub" in flat


def test_url_target_queries_the_api_about_the_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Capture
) -> None:
    origin = tmp_path / "origin.git"
    build_repo(origin, [CommitSpec({"README.md": "# demo\n"})])
    served = local_transport({"example-org/example-repo": origin})
    monkeypatch.setattr(remote, "github_transport", served)
    transport = install(monkeypatch, FakeTransport(established()))
    code, report, _ = scan_json(capsys, "https://github.com/example-org/example-repo")
    assert code == EXIT_OK
    validate_json(report)
    trust: Any = report["facts"]["trust"]  # type: ignore[index]
    assert trust["local"] is None and trust["repository"]["stars"] == 74935
    assert transport.paths[1] == REPO
    assert not any("/commits/" in p for p in transport.paths)


def test_text_from_the_api_is_sanitized(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Capture
) -> None:
    answers = established(repo={"description": "nice\u202e tool\x1b[31m"})
    release = answers[f"{REPO}/releases?per_page=1"].body
    assert isinstance(release, list)
    release[0]["tag_name"] = "v1\u200b"
    install(monkeypatch, FakeTransport(answers))
    main(["scan", str(folder(tmp_path)), "--no-color"])
    text = capsys.readouterr().out
    assert "\u200b" not in text and "v1<U+200B>" in text
    _, report, _ = scan_json(capsys, str(folder(tmp_path / "json")))
    description = report["facts"]["trust"]["repository"]["description"]  # type: ignore[index]
    assert description == "nice<U+202E> tool<U+001B>[31m"


@pytest.mark.parametrize(
    ("value", "bare", "expected"),
    [
        ("git+https://github.com/Org/Widget.git", False, "Org/Widget"),
        ("https://www.github.com/org/widget/tree/main/packages/a", False, "org/widget"),
        ("git@github.com:org/widget.git", False, "org/widget"),
        ("ssh://git@github.com/org/widget", False, "org/widget"),
        ("https://github.com/org/widget#readme", False, "org/widget"),
        ("org/widget", True, "org/widget"),
        ("github:org/widget", True, "org/widget"),
        ("org/widget", False, None),
        ("https://github.com/sponsors/someone", False, None),
        ("https://github.com/org", False, None),
        ("https://github.com.example.invalid/org/widget", False, None),
        ("https://example.invalid/github.com/org/widget", False, None),
        ("https://gitlab.com/org/widget", False, None),
    ],
)
def test_repository_links_in_manifests(value: str, bare: bool, expected: str | None) -> None:
    repo = trust._repo_in(value, trust.load_data(), bare=bare)
    assert (f"{repo.owner}/{repo.name}" if repo else None) == expected


def test_largest_burst_within_a_day() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    times = [start + timedelta(hours=h) for h in (0, 1, 30, 31, 32, 33, 100)]
    assert trust._max_in_window(times, timedelta(hours=24)) == 4
    assert trust._max_in_window(times[:1], timedelta(hours=24)) == 1


def test_less_popular_copies_are_not_lookalikes() -> None:
    copy = {
        "full_name": "copy-org/example-repo",
        "description": "A small web framework (anonymized example).",
        "stargazers_count": 1,
        "created_at": "2009-01-01T00:00:00Z",
    }
    answers = case_answers({"search": [copy]})
    data = answers[REPO].body
    assert isinstance(data, dict)
    repository = {"full_name": "example-org/example-repo", "stars": 74935, "fork": False}
    client = GitHubClient(FakeTransport(answers))
    assert trust._lookalike(trust._Asker(), client, data, repository) is None
    popular = {**copy, "stargazers_count": 90000}
    client = GitHubClient(FakeTransport(case_answers({"search": [popular]})))
    found = trust._lookalike(trust._Asker(), client, data, repository)
    assert found is not None and found["full_name"] == "copy-org/example-repo"
