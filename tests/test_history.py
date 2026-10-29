"""Git history: safe discovery of a local .git, history facts, and the metric check."""

import json
import sys
from pathlib import Path
from typing import Any

import pytest

from gitrepo import CommitSpec, build_repo, local_transport
from helpers import builtin_rules, materialize, run_check
from repovet.analyzers import provenance
from repovet.cli import main
from repovet.engine.checks import BUILDERS
from repovet.engine.checks.base import BuildEnv, CheckError, Params
from repovet.engine.checks.metric import MetricCheck
from repovet.engine.context import ScanContext
from repovet.limits import DEFAULT_LIMITS, Limits
from repovet.models import CoverageCollector
from repovet.sources import gitmeta, remote
from repovet.sources.local import LocalTree

Capture = pytest.CaptureFixture[str]


def _repo(tmp_path: Path, commits: list[CommitSpec], **kwargs: Any) -> tuple[Path, list[str]]:
    root = tmp_path / "repo"
    root.mkdir(parents=True, exist_ok=True)
    return root, build_repo(root / ".git", commits, **kwargs)


def history_facts(root: Path, limits: Limits = DEFAULT_LIMITS) -> tuple[Any, CoverageCollector]:
    coverage = CoverageCollector()
    git = gitmeta.open_local(root)
    source = git if isinstance(git, gitmeta.GitSource) else None
    ctx = ScanContext(
        LocalTree(root, limits, coverage),
        builtin_rules(),
        limits,
        coverage,
        git=source,
        git_note=git if isinstance(git, str) else None,
    )
    try:
        facts = provenance.profile(ctx)[0]["provenance"]
    finally:
        if source is not None:
            source.objects.close()
    assert isinstance(facts, dict)
    return facts.get("history"), coverage


# --- open_local ---------------------------------------------------------------------


def test_no_git_folder(tmp_path: Path) -> None:
    assert gitmeta.open_local(tmp_path) == gitmeta.REASON_NO_GIT
    facts, coverage = history_facts(tmp_path)
    assert facts is None
    assert [c.reason for c in coverage.items() if c.scope == "history"] == [gitmeta.REASON_NO_GIT]


def test_git_file_is_not_followed(tmp_path: Path) -> None:
    (tmp_path / ".git").write_text("gitdir: ../elsewhere\n", encoding="utf-8")
    result = gitmeta.open_local(tmp_path)
    assert isinstance(result, str) and "points elsewhere" in result


@pytest.mark.parametrize("name", ["commondir", "objects/info/alternates"])
def test_redirecting_files_are_refused(tmp_path: Path, name: str) -> None:
    root, _ = _repo(tmp_path, [CommitSpec({"a.txt": "a"})])
    target = root / ".git" / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("C:/somewhere/else\n", encoding="utf-8")
    result = gitmeta.open_local(root)
    assert isinstance(result, str) and name in result


def test_links_inside_git_are_refused(tmp_path: Path) -> None:
    root, _ = _repo(tmp_path, [CommitSpec({"a.txt": "a"})])
    outside = tmp_path / "outside"
    outside.mkdir()
    link = root / ".git" / "refs" / "heads" / "evil"
    if sys.platform == "win32":
        # A junction needs no special rights (symlinks may).
        import _winapi

        _winapi.CreateJunction(str(outside), str(link))
    else:
        link.symlink_to(outside, target_is_directory=True)
    result = gitmeta.open_local(root)
    assert isinstance(result, str) and "links" in result


def test_head_ref_cannot_leave_git(tmp_path: Path) -> None:
    root, _ = _repo(tmp_path, [CommitSpec({"a.txt": "a"})])
    (root / ".git" / "HEAD").write_text("ref: refs/../../../outside\n", encoding="utf-8")
    result = gitmeta.open_local(root)
    assert isinstance(result, str) and "does not point to a commit" in result


def test_detached_head_and_packed_refs(tmp_path: Path) -> None:
    root, ids = _repo(tmp_path, [CommitSpec({"a.txt": "a"}), CommitSpec({"a.txt": "b"})])
    git = root / ".git"
    (git / "HEAD").write_text(ids[0] + "\n", encoding="utf-8")
    source = gitmeta.open_local(root)
    assert isinstance(source, gitmeta.GitSource) and source.head.decode() == ids[0]
    source.objects.close()
    (git / "refs" / "heads" / "main").unlink()
    (git / "packed-refs").write_text(f"# pack-refs\n{ids[1]} refs/heads/main\n", encoding="utf-8")
    (git / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    source = gitmeta.open_local(root)
    assert isinstance(source, gitmeta.GitSource) and source.head.decode() == ids[1]
    source.objects.close()


def test_sha256_head_is_unsupported(tmp_path: Path) -> None:
    root, _ = _repo(tmp_path, [CommitSpec({"a.txt": "a"})])
    (root / ".git" / "HEAD").write_text("a" * 64 + "\n", encoding="utf-8")
    result = gitmeta.open_local(root)
    assert isinstance(result, str) and "SHA-256" in result


# --- history facts --------------------------------------------------------------------


def test_history_facts(tmp_path: Path) -> None:
    alice = "Alice <alice@example.invalid>"
    bob = "Bob <bob@users.noreply.example.invalid>"
    root, ids = _repo(
        tmp_path,
        [
            CommitSpec({"a.txt": "a"}, author=alice, author_time=1_700_000_000),
            CommitSpec({"a.txt": "a", "b.txt": "b"}, author=bob, author_time=1_700_086_400),
            CommitSpec(
                {"a.txt": "a", "b.txt": "b", "c.txt": "c"},
                author=alice,
                author_time=1_700_172_800,
                gpgsig=True,
                message="Add c\n\nCo-Authored-By: Claude <noreply@anthropic.com>\n",
            ),
        ],
    )
    facts, coverage = history_facts(root)
    assert facts["origin"] == ".git folder"
    assert facts["head"] == ids[-1]
    assert facts["commits"] == 3
    assert facts["complete"] is True
    assert facts["first_commit"] == "2023-11-14"
    assert facts["last_commit"] == "2023-11-16"
    assert facts["author_span_days"] == 2.0
    assert facts["authors"] == 2
    assert facts["top_authors"] == [{"name": "Alice", "commits": 2}, {"name": "Bob", "commits": 1}]
    assert facts["email_domains"][0] == {"domain": "example.invalid", "commits": 2}
    assert facts["signed_commits"] == 1
    assert (facts["root_files"], facts["head_files"], facts["root_file_percent"]) == (1, 3, 33)
    assert facts["ai_commits"] == 1
    assert facts["ai_tools"] == "Claude Code"
    assert sum(facts["by_weekday"].values()) == 3
    assert sum(facts["by_hour"]) == 3
    assert not [c for c in coverage.items() if c.scope == "history"]


def test_merges_and_shallow_history(tmp_path: Path) -> None:
    root, ids = _repo(
        tmp_path,
        [
            CommitSpec({"a.txt": "1"}),
            CommitSpec({"a.txt": "2"}),
            CommitSpec({"a.txt": "3"}, extra_parents=[0]),
        ],
    )
    facts, _ = history_facts(root)
    assert facts["merges"] == 1
    assert facts["commits"] == 3
    # Remove the root commit: the history is incomplete (like a shallow clone).
    obj = root / ".git" / "objects" / ids[0][:2] / ids[0][2:]
    obj.chmod(0o644)
    obj.unlink()
    facts, coverage = history_facts(root)
    assert facts["commits"] == 2
    assert facts["complete"] is False
    assert any("incomplete" in c.reason for c in coverage.items() if c.scope == "history")


def test_commit_limit(tmp_path: Path) -> None:
    root, _ = _repo(tmp_path, [CommitSpec({"a.txt": str(i)}) for i in range(5)])
    facts, coverage = history_facts(root, Limits(max_commits=3))
    assert facts["commits"] == 3
    assert facts["complete"] is False
    assert any("only part" in c.reason for c in coverage.items())


def test_terminal_history_lines(tmp_path: Path, capsys: Capture) -> None:
    root, _ = _repo(tmp_path, [CommitSpec({"a.txt": "a"}, author="Eve\u202e <e@example.invalid>")])
    materialize(root, {"a.txt": "a"})
    main(["scan", str(root), "--no-color"])
    out = capsys.readouterr().out
    profile = out[out.index("PROVENANCE PROFILE") : out.index("NOT CHECKED")]
    assert "History    1 commit from 2023-11-14 to 2023-11-14" in profile
    assert "Eve<U+202E> (1)" in profile
    assert "can be faked" in profile


def test_url_scan_reads_the_clone_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Capture
) -> None:
    origin = tmp_path / "origin.git"
    build_repo(
        origin,
        [
            CommitSpec({"a.txt": "a"}),
            CommitSpec({"a.txt": "b"}, message="Fix\n\nCo-authored-by: Copilot <c@x.invalid>\n"),
        ],
    )
    monkeypatch.setattr(remote, "github_transport", local_transport({"o/r": origin}))
    main(["scan", "https://github.com/o/r", "--format", "json"])
    report = json.loads(capsys.readouterr().out)
    history = report["facts"]["provenance"]["history"]
    assert (history["origin"], history["commits"], history["ai_tools"]) == (
        "clone",
        2,
        "GitHub Copilot",
    )
    assert [f["rule_id"] for f in report["findings"]] == ["RC-PROV-010"]
    finding = report["findings"][0]
    assert finding["location"] is None
    assert "indicator" in finding["message"] and "may" in finding["message"]


# --- metric check ------------------------------------------------------------------


def _metric(spec: dict[str, Any]) -> MetricCheck:
    check = BUILDERS["metric"](Params({"type": "metric", **spec}), BuildEnv({}))
    assert isinstance(check, MetricCheck)
    return check


FACTS: dict[str, object] = {"p": {"n": 5, "share": 0.95, "flag": True, "name": "x", "none": None}}


@pytest.mark.parametrize(
    ("conditions", "fires"),
    [
        ([{"fact": "p.n", "op": ">=", "value": 5}], True),
        ([{"fact": "p.n", "op": ">", "value": 5}], False),
        (
            [{"fact": "p.share", "op": ">=", "value": 0.9}, {"fact": "p.n", "op": "<", "value": 9}],
            True,
        ),
        (
            [{"fact": "p.share", "op": ">=", "value": 0.9}, {"fact": "p.n", "op": "<", "value": 2}],
            False,
        ),
        ([{"fact": "p.flag", "op": "==", "value": True}], True),
        ([{"fact": "p.flag", "op": ">=", "value": 1}], False),
        ([{"fact": "p.n", "op": "==", "value": True}], False),
        ([{"fact": "p.name", "op": "==", "value": "x"}], True),
        ([{"fact": "p.name", "op": ">", "value": 1}], False),
        ([{"fact": "p.none", "op": "<", "value": 1}], False),
        ([{"fact": "p.missing", "op": "!=", "value": 1}], False),
        ([{"fact": "q.n", "op": ">=", "value": 0}], False),
    ],
)
def test_metric_conditions(conditions: list[dict[str, object]], fires: bool) -> None:
    assert bool(list(_metric({"conditions": conditions}).fact_matches(FACTS))) is fires


def test_metric_values_for_the_message() -> None:
    check = _metric(
        {
            "conditions": [{"fact": "p.n", "op": ">=", "value": 1}],
            "show": {"count": "p.share", "match": "p.name"},
        }
    )
    (match,) = check.fact_matches(FACTS)
    assert dict(match.values) == {"count": "0.95", "match": "x", "value": "5"}


@pytest.mark.parametrize(
    ("spec", "error"),
    [
        ({"conditions": []}, "non-empty list"),
        ({"conditions": [{"fact": "a", "op": ">"}]}, "exactly"),
        ({"conditions": [{"fact": "a..b", "op": ">", "value": 1}]}, "dotted name"),
        ({"conditions": [{"fact": "a", "op": ">", "value": [1]}]}, "number"),
        ({"conditions": [{"fact": "a", "op": ">", "value": 1}], "show": {"path": "a"}}, "maps"),
        ({"conditions": [{"fact": "a", "op": ">", "value": 1}], "extra": 1}, "unknown"),
    ],
)
def test_metric_validation(spec: dict[str, object], error: str) -> None:
    with pytest.raises(CheckError, match=error):
        _metric(spec)


def test_metric_never_matches_files() -> None:
    spec = {"type": "metric", "conditions": [{"fact": "p.n", "op": ">=", "value": 0}]}
    assert run_check(spec, "a.txt", "x") == []
