"""GitHub API client: headers, token handling, rate limit, budget, limits, redirects."""

import re
from pathlib import Path
from typing import Any

import pytest

from github_fake import RESET, Answer, FakeTransport
from repovet.github.client import (
    API_ROOT,
    BUDGET_ANONYMOUS,
    BUDGET_TOKEN,
    SHA_MEDIA,
    GitHubClient,
    NotFound,
    Refused,
    Request,
    Response,
    Result,
    Stopped,
    Token,
    TransportError,
    token_from_env,
)
from repovet.github.transport import UrllibTransport, _describe
from repovet.sources import gitmeta
from repovet.sources.remote import GitHubRepo, github_repo_from_remote

SECRET = "ghp_" + "S3cr3tT0kenValue" * 2 + "abcd"
REPO = "/repos/example-org/example-repo"


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0
        self.slept: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


def client(transport: FakeTransport, **kwargs: object) -> tuple[GitHubClient, Clock]:
    clock = Clock()
    made = GitHubClient(
        transport,
        clock=clock.monotonic,
        sleep=clock.sleep,
        wall=lambda: RESET - 3600,
        **kwargs,  # type: ignore[arg-type]
    )
    return made, clock


# --- token -----------------------------------------------------------------------


def test_token_from_environment() -> None:
    token, note = token_from_env({"GH_TOKEN": SECRET})
    assert token is not None and token.source == "GH_TOKEN" and note is None
    token, _ = token_from_env({"GITHUB_TOKEN": SECRET, "GH_TOKEN": "other" * 5})
    assert token is not None and token.source == "GITHUB_TOKEN"
    assert token_from_env({}) == (None, None)
    assert token_from_env({"GITHUB_TOKEN": "  "}) == (None, None)


def test_token_with_unexpected_characters_is_not_used() -> None:
    token, note = token_from_env({"GITHUB_TOKEN": "abc def\r\nX-Evil: 1" + "x" * 20})
    assert token is None
    assert note is not None and "GITHUB_TOKEN" in note and "abc" not in note


def test_token_value_never_shows_in_repr_or_str() -> None:
    token = Token(SECRET, "GITHUB_TOKEN")
    assert SECRET not in repr(token) and SECRET not in str(token) and SECRET not in f"{token}"
    made, _ = client(FakeTransport(), token=token)
    assert SECRET not in repr(made)


# --- requests ----------------------------------------------------------------------


def test_headers_without_and_with_token() -> None:
    transport = FakeTransport({REPO: Answer({"id": 1})})
    anonymous, _ = client(transport)
    anonymous.get(REPO)
    headers = transport.requests[-1].headers
    assert headers["Accept"] == "application/vnd.github+json"
    assert headers["X-GitHub-Api-Version"] == "2022-11-28"
    assert headers["User-Agent"].startswith("repovet")
    assert "Authorization" not in headers
    assert anonymous.budget == BUDGET_ANONYMOUS

    authed, _ = client(transport, token=Token(SECRET, "GITHUB_TOKEN"))
    authed.get(REPO)
    assert transport.requests[-1].headers["Authorization"] == f"Bearer {SECRET}"
    assert authed.budget == BUDGET_TOKEN


def test_only_api_github_com_over_https_is_requested() -> None:
    transport = FakeTransport({f"{REPO}?anon=true&per_page=1": Answer([])})
    made, _ = client(transport)
    made.get(REPO, {"per_page": 1, "anon": "true"})
    assert transport.requests[0].url == f"{API_ROOT}{REPO}?anon=true&per_page=1"
    assert all(r.url.startswith("https://api.github.com/") for r in transport.requests)
    for bad in ("/repos/../users", "repos/x", "/repos//x", "/a b", "https://example.invalid/x"):
        with pytest.raises(ValueError, match="invalid API path"):
            made.get(bad)


def test_answers_are_requested_once_per_scan() -> None:
    transport = FakeTransport({REPO: Answer({"id": 1})})
    made, _ = client(transport)
    assert made.get(REPO).data == {"id": 1}
    assert made.get(REPO).data == {"id": 1}
    with pytest.raises(NotFound):
        made.get("/repos/example-org/missing")
    with pytest.raises(NotFound):
        made.get("/repos/example-org/missing")
    assert transport.paths == [REPO, "/repos/example-org/missing"]
    assert made.requests == 2


@pytest.mark.parametrize("status", [404, 409, 410, 422, 451])
def test_missing_objects(status: int) -> None:
    made, _ = client(FakeTransport({REPO: Answer({"message": "x"}, status)}))
    with pytest.raises(NotFound):
        made.get(REPO)
    assert made.stopped is None


def test_empty_answer_and_sha_media_type() -> None:
    transport = FakeTransport(
        {
            REPO + "/contributors": Answer(None, 204),
            REPO + "/commits/abc": Answer(raw=b"0123abc\n", headers={"content-type": "text"}),
        }
    )
    made, _ = client(transport)
    assert made.get(REPO + "/contributors").data is None
    assert made.get(REPO + "/commits/abc", accept=SHA_MEDIA).data == "0123abc"
    assert transport.requests[-1].headers["Accept"] == SHA_MEDIA


def test_bad_content_is_refused_not_fatal() -> None:
    made, _ = client(
        FakeTransport(
            {
                REPO: Answer(raw=b"<html>", headers={"content-type": "text/html"}),
                REPO + "/a": Answer(raw=b"{not json"),
                REPO + "/b": Answer(raw=b"\xff\xfe"),
                REPO + "/c": Answer({"message": "Server Error"}, 502),
            }
        )
    )
    for path in (REPO, REPO + "/a", REPO + "/b", REPO + "/c"):
        with pytest.raises(Refused):
            made.get(path)
    assert made.stopped is None


def test_last_page_from_link_header() -> None:
    link = (
        f'<{API_ROOT}{REPO}/contributors?per_page=1&anon=true&page=2>; rel="next", '
        f'<{API_ROOT}{REPO}/contributors?per_page=1&anon=true&page=873>; rel="last"'
    )
    assert Result([], {"link": link}).last_page() == 873
    assert Result([], {}).last_page() is None
    assert Result([], {"link": '<x?page=2>; rel="next"'}).last_page() is None


# --- redirects ---------------------------------------------------------------------


def test_redirect_within_the_api_is_followed() -> None:
    transport = FakeTransport(
        {
            REPO: Answer(None, 301, {"location": f"{API_ROOT}/repositories/42"}),
            "/repositories/42": Answer({"id": 42}),
        }
    )
    made, _ = client(transport)
    assert made.get(REPO).data == {"id": 42}
    assert transport.paths == [REPO, "/repositories/42"]


@pytest.mark.parametrize(
    "location",
    [
        "https://example.invalid/repositories/42",
        "http://api.github.com/repositories/42",
        "https://user@api.github.com/repositories/42",
        "https://api.github.com:8443/repositories/42",
    ],
)
def test_redirect_away_from_the_api_is_refused(location: str) -> None:
    transport = FakeTransport({REPO: Answer(None, 302, {"location": location})})
    made, _ = client(transport)
    with pytest.raises(Refused, match="redirect"):
        made.get(REPO)
    assert len(transport.requests) == 1


def test_redirect_loop_is_cut() -> None:
    transport = FakeTransport({REPO: Answer(None, 307, {"location": REPO})})
    made, _ = client(transport)
    with pytest.raises(Refused, match="too many redirects"):
        made.get(REPO)
    assert len(transport.requests) == 4


# --- rate limit, budget, time ------------------------------------------------------


def test_rate_limit_check_does_not_count() -> None:
    transport = FakeTransport(remaining=42)
    made, _ = client(transport)
    core = made.check_rate_limit()
    assert core is not None and (core.limit, core.remaining, core.reset) == (60, 42, RESET)
    assert made.requests == 0 and made.sent == 1
    assert made.rates["search"].limit == 10


def test_exhausted_rate_limit_stops_without_sending() -> None:
    transport = FakeTransport({REPO: Answer({"id": 1})}, remaining=0)
    made, clock = client(transport)
    made.check_rate_limit()
    with pytest.raises(Stopped, match=r"rate limit reached \(0 of 60 requests left, resets at"):
        made.get(REPO)
    assert transport.paths == ["/rate_limit"] and clock.slept == []
    with pytest.raises(Stopped):
        made.get("/users/example-org")
    assert transport.paths == ["/rate_limit"]


def test_rate_limit_hit_during_the_scan_stops_cleanly() -> None:
    limited = Answer({"message": "API rate limit exceeded"}, 403, {"x-ratelimit-remaining": "0"})
    transport = FakeTransport({REPO: limited})
    made, clock = client(transport)
    with pytest.raises(Stopped, match="rate limit reached"):
        made.get(REPO)
    assert clock.slept == []  # the reset is an hour away: no waiting
    assert made.stopped is not None and "resets at" in made.stopped


def test_short_waits_are_waited_once() -> None:
    calls = {"n": 0}

    def flaky(request: Request) -> Answer:
        calls["n"] += 1
        if calls["n"] == 1:
            return Answer({"message": "secondary rate limit"}, 429, {"retry-after": "3"})
        return Answer({"id": 1})

    made, clock = client(FakeTransport({REPO: flaky}))
    assert made.get(REPO).data == {"id": 1}
    assert clock.slept == [3.0]


def test_long_waits_stop_the_api_step() -> None:
    slow = Answer({"message": "secondary rate limit"}, 403, {"retry-after": "120"})
    made, clock = client(FakeTransport({REPO: slow}))
    with pytest.raises(Stopped, match="wait 120 s"):
        made.get(REPO)
    assert clock.slept == []


def test_other_403_is_refused_for_this_request_only() -> None:
    too_large = Answer({"message": "The history or contributor list is too large"}, 403)
    transport = FakeTransport({REPO + "/contributors": too_large, REPO: Answer({"id": 1})})
    made, _ = client(transport)
    with pytest.raises(Refused, match="too large"):
        made.get(REPO + "/contributors")
    assert made.get(REPO).data == {"id": 1}


def test_request_budget() -> None:
    transport = FakeTransport({REPO: Answer({"id": 1})})
    made, _ = client(transport, budget=2)
    made.check_rate_limit()
    made.get(REPO)
    with pytest.raises(NotFound):
        made.get("/users/x")
    with pytest.raises(Stopped, match="budget of 2"):
        made.get("/users/y")
    assert made.requests == 2 and made.sent == 3


def test_time_limit() -> None:
    transport = FakeTransport({REPO: Answer({"id": 1})})
    made, clock = client(transport, total_timeout=60.0)
    made.get(REPO)
    clock.now += 61
    with pytest.raises(Stopped, match="time limit of 60 s"):
        made.get("/users/x")
    assert len(transport.requests) == 1


def test_per_request_timeout_shrinks_with_the_total() -> None:
    transport = FakeTransport({REPO: Answer({"id": 1}), "/users/x": Answer({})})
    made, clock = client(transport, total_timeout=30.0)
    made.get(REPO)
    clock.now += 25
    made.get("/users/x")
    assert transport.requests[0].timeout == 20.0
    assert transport.requests[1].timeout == pytest.approx(5.0)


def test_rejected_token_stops() -> None:
    made, _ = client(FakeTransport({REPO: Answer({"message": "Bad credentials"}, 401)}))
    with pytest.raises(Stopped, match="rejected the token"):
        made.get(REPO)


# --- the token never leaks ----------------------------------------------------------


def test_token_is_redacted_from_every_error() -> None:
    def leaky(request: Request, max_bytes: int) -> Response:
        raise TransportError(f"proxy said: bad header Authorization: Bearer {SECRET}")

    made, _ = client(FakeTransport(), token=Token(SECRET, "GITHUB_TOKEN"))
    made.transport = leaky
    with pytest.raises(Stopped) as info:
        made.get(REPO)
    assert SECRET not in str(info.value) and "***" in str(info.value)
    assert made.stopped is not None and SECRET not in made.stopped

    echo = Answer({"message": f"token {SECRET} is not allowed here"}, 403)
    made, _ = client(FakeTransport({REPO: echo}), token=Token(SECRET, "GITHUB_TOKEN"))
    with pytest.raises(Refused) as refused:
        made.get(REPO)
    assert SECRET not in str(refused.value)


# --- transport ---------------------------------------------------------------------


def test_transport_only_contacts_the_api() -> None:
    transport = UrllibTransport()
    for url in ("http://api.github.com/x", "https://example.invalid/x", "file:///etc/passwd"):
        with pytest.raises(TransportError, match=re.escape("only https://api.github.com")):
            transport(Request(url, {}, 1.0), 1024)


def test_transport_opener_can_only_speak_https() -> None:
    # The proxy handler only registers itself when the environment names a proxy.
    opener: Any = UrllibTransport()._opener  # "handlers" is not in the type stubs
    handlers = {type(h).__name__ for h in opener.handlers}
    assert "HTTPSHandler" in handlers
    assert handlers <= {"ProxyHandler", "HTTPSHandler"}


def test_transport_error_texts() -> None:
    import urllib.error

    assert _describe(urllib.error.URLError(TimeoutError())) == "timed out"
    assert _describe(urllib.error.URLError(OSError("name not resolved"))).startswith("OSError")
    assert len(_describe(ValueError("x" * 500))) == 200


# --- which repository ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://github.com/octo/demo", GitHubRepo("octo", "demo")),
        ("https://github.com/octo/demo.git", GitHubRepo("octo", "demo")),
        ("https://user:pw@github.com/octo/demo.git/", GitHubRepo("octo", "demo")),
        ("git@github.com:octo/demo.git", GitHubRepo("octo", "demo")),
        ("ssh://git@github.com/octo/demo", GitHubRepo("octo", "demo")),
        ("ssh://git@GitHub.com:22/octo/demo.git", GitHubRepo("octo", "demo")),
        ("git://github.com/octo/demo.git", GitHubRepo("octo", "demo")),
        ("https://gitlab.com/octo/demo", None),
        ("https://github.com.example.invalid/octo/demo", None),
        ("https://github.com/octo", None),
        ("https://github.com/octo/demo/tree/main", None),
        ("https://github.com/-bad/demo", None),
        ("/home/me/demo.git", None),
        ("ext::sh -c touch% /tmp/x", None),
    ],
)
def test_github_repo_from_remote(url: str, expected: GitHubRepo | None) -> None:
    assert github_repo_from_remote(url) == expected


def test_remote_urls_from_git_config(tmp_path: Path) -> None:
    git = tmp_path / "repo" / ".git"
    git.mkdir(parents=True)
    assert gitmeta.remote_urls(tmp_path / "repo") == {}
    (git / "config").write_text(
        '[core]\n\tbare = false\n[remote "origin"]\n\turl = git@github.com:octo/demo.git\n'
        '[remote "upstream"]\n\turl = https://github.com/up/demo\n',
        encoding="utf-8",
    )
    assert gitmeta.remote_urls(tmp_path / "repo") == {
        "origin": "git@github.com:octo/demo.git",
        "upstream": "https://github.com/up/demo",
    }
    assert gitmeta.remote_urls(tmp_path / "missing") == {}
