"""The GitHub REST endpoints the trust area uses, as plain data.

Every function sends at most one request (the client remembers answers within a scan)
and raises ``ApiError`` subclasses on failure. Counts come from the ``Link`` header of
a one-item page, so a count costs one request however large it is.
"""

from dataclasses import dataclass
from urllib.parse import quote

from repocheck.github.client import SHA_MEDIA, STAR_MEDIA, GitHubClient
from repocheck.sources.remote import GitHubRepo


@dataclass(frozen=True)
class Page:
    """The first item of a list and the total number of items."""

    first: dict[str, object] | None
    total: int


def _object(data: object) -> dict[str, object]:
    return data if isinstance(data, dict) else {}


def _base(repo: GitHubRepo) -> str:
    return f"/repos/{repo.owner}/{repo.name}"


def repository(client: GitHubClient, repo: GitHubRepo) -> dict[str, object]:
    return _object(client.get(_base(repo)).data)


def account(client: GitHubClient, login: str) -> dict[str, object]:
    return _object(client.get(f"/users/{quote(login, safe='')}").data)


def _page(client: GitHubClient, path: str, params: dict[str, str | int]) -> Page:
    result = client.get(path, {**params, "per_page": 1})
    items = result.data if isinstance(result.data, list) else []
    first = items[0] if items and isinstance(items[0], dict) else None
    last = result.last_page()
    return Page(first, last if last is not None else len(items))


def contributors(client: GitHubClient, repo: GitHubRepo) -> Page:
    """Contributors including those without a GitHub account (``anon``)."""
    return _page(client, f"{_base(repo)}/contributors", {"anon": "true"})


def commits(client: GitHubClient, repo: GitHubRepo, branch: str) -> Page:
    """Commits reachable from ``branch``, newest first."""
    return _page(client, f"{_base(repo)}/commits", {"sha": branch})


def releases(client: GitHubClient, repo: GitHubRepo) -> Page:
    """Releases, newest first; the first one comes with its assets."""
    return _page(client, f"{_base(repo)}/releases", {})


def branch(client: GitHubClient, repo: GitHubRepo, name: str) -> dict[str, object]:
    return _object(client.get(f"{_base(repo)}/branches/{quote(name, safe='')}").data)


STARS_PER_PAGE = 100


def stargazers(client: GitHubClient, repo: GitHubRepo, page: int) -> list[dict[str, object]]:
    """One page of stars with their time (``starred_at``), oldest first."""
    data = client.get(
        f"{_base(repo)}/stargazers", {"per_page": STARS_PER_PAGE, "page": page}, STAR_MEDIA
    ).data
    return [item for item in data if isinstance(item, dict)] if isinstance(data, list) else []


def search_by_name(client: GitHubClient, name: str, count: int = 5) -> list[dict[str, object]]:
    """The most starred repositories whose name contains ``name``."""
    params: dict[str, str | int] = {
        "q": f"{name} in:name",
        "sort": "stars",
        "order": "desc",
        "per_page": count,
    }
    items = _object(client.get("/search/repositories", params).data).get("items")
    return [item for item in items if isinstance(item, dict)] if isinstance(items, list) else []


def commit_exists(client: GitHubClient, repo: GitHubRepo, sha: str) -> bool:
    """Whether GitHub knows ``sha`` in this repository (``NotFound`` otherwise). GitHub
    also finds commits that exist only in forks of the repository."""
    data = client.get(f"{_base(repo)}/commits/{sha}", accept=SHA_MEDIA).data
    return isinstance(data, str) and data.strip() == sha
