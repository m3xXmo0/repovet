"""A GitHub API transport with recorded answers, for tests (no network).

Fixtures in ``tests/github_fixtures/<name>.json`` map an API path with query
(``/repos/example-org/example-repo``) to ``{status, headers, body}``. They are recorded
from the real API and anonymized (names, ids and URLs replaced).
"""

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from repovet.github import target as github_target
from repovet.github.client import API_ROOT, GitHubClient, Request, Response
from repovet.github.target import TrustTarget
from repovet.sources.gitmeta import GitSource
from repovet.sources.remote import GitHubRepo

FIXTURES = Path(__file__).parent / "github_fixtures"
RESET = 1_900_000_000  # far in the future: limits never reset during a test


@dataclass
class Answer:
    body: object = None
    status: int = 200
    headers: dict[str, str] = field(default_factory=dict)
    raw: bytes | None = None


type Handler = Answer | Callable[[Request], Answer]


class FakeTransport:
    """Answers by path (with query); unknown paths get 404 like the real API.

    ``remaining`` counts down with each request that is not ``/rate_limit``, and every
    answer carries the rate-limit headers, as GitHub's do."""

    def __init__(
        self, answers: Mapping[str, Handler] | None = None, *, limit: int = 60, remaining: int = 60
    ) -> None:
        self.answers: dict[str, Handler] = dict(answers or {})
        self.requests: list[Request] = []
        self.limit = limit
        self.remaining = remaining

    @property
    def paths(self) -> list[str]:
        return [r.url.removeprefix(API_ROOT) for r in self.requests]

    def __call__(self, request: Request, max_bytes: int) -> Response:
        self.requests.append(request)
        path = request.url.removeprefix(API_ROOT)
        if path == "/rate_limit":
            body: object = {
                "resources": {
                    "core": {"limit": self.limit, "remaining": self.remaining, "reset": RESET},
                    "search": {"limit": 10, "remaining": 10, "reset": RESET},
                }
            }
            return self._response(Answer(body), path)
        self.remaining = max(0, self.remaining - 1)
        handler = self.answers.get(path)
        if handler is None:
            answer = Answer({"message": "Not Found"}, 404)
        elif isinstance(handler, Answer):
            answer = handler
        else:
            answer = handler(request)
        return self._response(answer, path)

    def _response(self, answer: Answer, path: str) -> Response:
        headers = {
            "content-type": "application/json; charset=utf-8",
            "x-ratelimit-limit": str(self.limit),
            "x-ratelimit-remaining": str(self.remaining),
            "x-ratelimit-reset": str(RESET),
            "x-ratelimit-resource": "search" if path.startswith("/search/") else "core",
        }
        headers.update({k.lower(): v for k, v in answer.headers.items()})
        if answer.raw is not None:
            body = answer.raw
        elif answer.body is None:
            body = b""
        else:
            body = json.dumps(answer.body).encode("utf-8")
        return Response(answer.status, headers, body)


def load_fixture(name: str) -> dict[str, Answer]:
    data: dict[str, Any] = json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))
    answers = {}
    for path, entry in data["answers"].items():
        answers[path] = Answer(
            entry.get("body"), int(entry.get("status", 200)), dict(entry.get("headers", {}))
        )
    return answers


REPO = "/repos/example-org/example-repo"
# Rule cases compute ages against this fixed time (the fixture was recorded the same day).
FIXED_NOW = datetime(2026, 10, 29, 12, 0, tzinfo=UTC)


def _update(answers: dict[str, Answer], path: str, changes: Mapping[str, Any]) -> None:
    body = answers[path].body
    assert isinstance(body, dict), path
    body.update(changes)


def case_answers(spec: Mapping[str, Any]) -> dict[str, Answer]:
    """The recorded answers of an established project, changed as a rule case says:

    ``repo``/``owner``: fields of the repository/owner answer; ``release``: fields of the
    latest release (``assets`` as a list of names); ``last_commit``: date of the newest
    commit; ``stars``: ``{count, start, minutes}`` star times, one every ``minutes``;
    ``search``: the repositories a name search finds; ``answers``: more answers by path
    (``{status, body}``).
    """
    answers = load_fixture("established")
    _update(answers, REPO, spec.get("repo", {}))
    _update(answers, "/users/example-org", spec.get("owner", {}))
    releases = answers[f"{REPO}/releases?per_page=1"].body
    assert isinstance(releases, list)
    release = dict(spec.get("release", {}))
    if "assets" in release:
        release["assets"] = [{"name": name} for name in release["assets"]]
    releases[0].update(release)
    if "last_commit" in spec:
        commits = answers[f"{REPO}/commits?per_page=1&sha=main"].body
        assert isinstance(commits, list)
        for role in ("author", "committer"):
            commits[0]["commit"][role]["date"] = spec["last_commit"]
    if "stars" in spec:
        stars = spec["stars"]
        start = datetime.fromisoformat(str(stars["start"]))
        times = [
            (start + timedelta(minutes=float(stars["minutes"]) * i)).strftime("%Y-%m-%dT%H:%M:%SZ")
            for i in range(int(stars["count"]))
        ]
        _update(answers, REPO, {"stargazers_count": len(times), **spec.get("repo", {})})
        for page in range(0, len(times), 100):
            items = [
                {"starred_at": t, "user": {"login": "user-1"}} for t in times[page : page + 100]
            ]
            answers[f"{REPO}/stargazers?page={page // 100 + 1}&per_page=100"] = Answer(items)
    if "search" in spec:
        search = next(p for p in answers if p.startswith("/search/repositories"))
        items = [{"name": item["full_name"].partition("/")[2], **item} for item in spec["search"]]
        _update(answers, search, {"items": items})
    for path, entry in spec.get("answers", {}).items():
        answers[path] = Answer(entry.get("body"), int(entry.get("status", 200)))
    return answers


def case_target(spec: Mapping[str, Any], source: GitSource | None) -> TrustTarget:
    """A trust target for example-org/example-repo with the answers of ``spec``.
    ``local: true`` makes it a local folder whose HEAD is looked up."""
    local = bool(spec.get("local"))
    head = source.head.decode("ascii") if local and source is not None else None
    answers = case_answers(spec)
    if head is not None and spec.get("head_known"):
        answers[f"{REPO}/commits/{head}"] = Answer(raw=head.encode("ascii"))
    return TrustTarget(
        GitHubRepo("example-org", "example-repo"),
        GitHubClient(FakeTransport(answers)),
        claimed_by="remote 'origin' in .git/config" if local else None,
        local_head=head,
        now=lambda: FIXED_NOW,
    )


def install(monkeypatch: pytest.MonkeyPatch, transport: FakeTransport) -> FakeTransport:
    """Make the CLI use ``transport`` for the GitHub API."""
    monkeypatch.setattr(github_target, "DEFAULT_TRANSPORT", lambda: transport)
    return transport
