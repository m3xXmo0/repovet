import pytest

from helpers import run_check
from repovet.engine.checks.base import CheckError
from repovet.engine.checks.dependency import distance, popular


def test_popular_lists_are_ranked_and_normalized() -> None:
    pypi = popular("pypi")
    npm = popular("npm")
    assert len(pypi) >= 10_000
    assert len(npm) >= 10_000
    assert pypi["requests"] < 100
    assert "typing-extensions" in pypi
    assert "@types/node" in npm


def test_distance() -> None:
    assert distance("requests", "requests", 1) == 0
    assert distance("reqeusts", "requests", 1) == 1  # swapped neighbours count once
    assert distance("requestss", "requests", 1) == 1
    assert distance("rqst", "requests", 2) == 3  # early exit: more than the limit
    assert distance("abcdef", "abcxyz", 1) == 2


def test_typosquat_reports_rank_and_target() -> None:
    spec = {"type": "dependency", "mode": "typosquat", "top": 1000}
    (match,) = run_check(spec, "requirements.txt", "reqeusts==1\n")
    assert match.line == 1
    assert match.values["match"] == "requests"
    assert match.values["value"] == "reqeusts"
    assert int(match.values["count"].replace(",", "")) <= 1000


def test_typosquat_ecosystem_filter() -> None:
    spec = {"type": "dependency", "mode": "typosquat", "ecosystems": ["pypi"]}
    assert run_check(spec, "package.json", '{"dependencies": {"expresss": "1"}}') == []


def test_source_and_index_modes() -> None:
    source = {"type": "dependency", "mode": "source", "kinds": ["git"]}
    text = "git+https://example.invalid/t.git#egg=t\nhttps://example.invalid/x.whl\n"
    assert [m.values["key"] for m in run_check(source, "requirements.txt", text)] == ["git"]
    index = {"type": "dependency", "mode": "index", "allow_hosts": ["pypi.org"]}
    text = "-i https://pypi.org/simple\n--extra-index-url https://x.example.invalid/simple\n"
    assert [m.line for m in run_check(index, "requirements.txt", text)] == [2]


def test_broken_setup_cfg_is_coverage() -> None:
    spec = {"type": "dependency", "mode": "typosquat"}
    assert run_check(spec, "setup.cfg", "no header\n") == []


@pytest.mark.parametrize(
    ("spec", "message"),
    [
        ({"mode": "guess"}, "'mode' must be one of"),
        ({"mode": "typosquat", "ecosystems": ["cargo"]}, "unknown ecosystem"),
        ({"mode": "typosquat", "max_distance": 3}, "1 or 2"),
        ({"mode": "typosquat", "top": 10, "rank_from": 20}, "rank_from"),
        ({"mode": "source"}, "needs 'kinds'"),
        ({"mode": "source", "kinds": ["ftp"]}, "'kinds' must be from"),
    ],
)
def test_invalid_parameters(spec: dict[str, object], message: str) -> None:
    with pytest.raises(CheckError, match=message):
        run_check({"type": "dependency", **spec}, "requirements.txt", "")
