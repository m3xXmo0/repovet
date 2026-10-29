"""Area ``trust``: what the GitHub API says about the repository and its owner.

Online and optional: ``--offline`` switches it off, and every error, the rate limit
and the request budget end up under "Not checked", never as an abort. The profile is
facts (``facts["trust"]``); findings come only from RC-TRUST rules. Stars, forks and
accounts can be bought or faked, so everything here is an indicator.

Requests, most important first (each at most once): rate limit (free), repository,
owner, the local HEAD commit (local folders), commits and contributors (counted from
the ``Link`` header), releases, default branch.
"""

import re
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timedelta
from functools import cache, partial
from pathlib import Path

import yaml

from repovet.engine.checks.base import FileView
from repovet.engine.context import ScanContext
from repovet.engine.runner import run_rules
from repovet.github import api
from repovet.github.client import ApiError, GitHubClient, NotFound, Refused, Stopped
from repovet.github.target import OFFLINE, TrustTarget
from repovet.models import AreaResult, CoverageCollector, CoverageStatus
from repovet.parsers.structured import ParseError, parse
from repovet.sources.remote import GitHubRepo, github_repo_from_remote

AREA = "trust"
SCOPE = "area:trust"
NO_TARGET = "no GitHub repository is known for this target"
NOTE = (
    "Stars, forks, followers and accounts can be bought or faked; these are indicators, not proof."
)
_MAX_ASSETS = 20
DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "trust.yaml"
# Star times are fetched only when all of them fit into two pages (two requests), and
# only from 50 stars on: below that no star indicator applies.
STAR_SAMPLE_MIN = 50
STAR_SAMPLE_MAX = 2 * api.STARS_PER_PAGE
# The name search runs only for descriptions long enough to be distinctive.
MIN_DESCRIPTION = 20
_SPACES = re.compile(r"\s+")
_BARE_REPO = re.compile(r"(?:github:)?([A-Za-z0-9-]+)/([A-Za-z0-9._-]+)")
_GITHUB_URL = re.compile(
    r"(?:git\+)?(?:(?:https?|git|ssh)://(?:[^@/\s]+@)?(?:www\.)?github\.com[:/]"
    r"|[A-Za-z0-9._-]+@github\.com:)([^/\s#?]+)/([^/\s#?]+)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class DeclaredField:
    file: str
    fmt: str
    paths: tuple[str, ...]
    keys: re.Pattern[str] | None


@dataclass(frozen=True)
class TrustData:
    binary_assets: tuple[str, ...]
    declared: tuple[DeclaredField, ...]
    reserved: frozenset[str]


@cache
def load_data() -> TrustData:
    raw = yaml.safe_load(DATA_FILE.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("data/trust.yaml must be a mapping")
    declared = tuple(
        DeclaredField(
            str(item["file"]),
            str(item["format"]),
            tuple(str(p) for p in item["paths"]),
            re.compile(str(item["keys"])) if item.get("keys") else None,
        )
        for item in raw["declared_repository"]
    )
    return TrustData(
        tuple(str(e).lower() for e in raw["binary_assets"]),
        declared,
        frozenset(str(r).lower() for r in raw["github_reserved"]),
    )


def _not_checked(ctx: ScanContext, status: CoverageStatus, reason: str) -> None:
    ctx.coverage.add(SCOPE, status, f"trust (GitHub API): {reason}")


# --- small helpers -------------------------------------------------------------------


def _int(data: Mapping[str, object], key: str) -> int | None:
    value = data.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _bool(data: Mapping[str, object], key: str) -> bool | None:
    value = data.get(key)
    return value if isinstance(value, bool) else None


def _str(data: Mapping[str, object], key: str) -> str | None:
    value = data.get(key)
    return value if isinstance(value, str) and value else None


def _obj(data: object, key: str) -> dict[str, object]:
    value = data.get(key) if isinstance(data, Mapping) else None
    return value if isinstance(value, dict) else {}


def _time(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _date(moment: datetime | None) -> str | None:
    return moment.date().isoformat() if moment is not None else None


def _days(moment: datetime | None, now: datetime) -> int | None:
    return max(0, (now - moment).days) if moment is not None else None


def _ago(days: object) -> str:
    if not isinstance(days, int):
        return ""
    if days < 1:
        return " (today)"
    if days < 60:
        return f" ({days} day{'' if days == 1 else 's'} ago)"
    if days < 730:
        return f" ({days // 30} months ago)"
    return f" ({days // 365} years ago)"


def _n(value: object, word: str, plural: str | None = None) -> str:
    many = plural or f"{word}s"
    if not isinstance(value, int):
        return f"? {many}"
    return f"{value:,} {word if value == 1 else many}"


# --- collecting ----------------------------------------------------------------------


class _Asker:
    """Runs API calls; remembers what could not be learned and why."""

    def __init__(self) -> None:
        self.stopped: str | None = None
        self.skipped: list[str] = []
        self.unavailable: list[tuple[str, str]] = []

    def __call__[T](self, what: str, call: Callable[[], T], missing: T | None = None) -> T | None:
        """``call()``, or ``None`` if it failed. ``missing`` is the answer for
        "not found" when that is a result rather than a gap (a commit lookup)."""
        if self.stopped is not None:
            self.skipped.append(what)
            return None
        try:
            return call()
        except Stopped as exc:
            self.stopped = str(exc)
            self.skipped.append(what)
        except NotFound:
            if missing is not None:
                return missing
            self.unavailable.append((what, "not found"))
        except Refused as exc:
            self.unavailable.append((what, str(exc)))
        return None


def _repository_facts(
    data: Mapping[str, object], requested: GitHubRepo, now: datetime
) -> dict[str, object]:
    created, pushed = _time(_str(data, "created_at")), _time(_str(data, "pushed_at"))
    full_name = _str(data, "full_name")
    asked = f"{requested.owner}/{requested.name}"
    parent, source = _obj(data, "parent"), _obj(data, "source")
    license_id = _str(_obj(data, "license"), "spdx_id")
    return {
        "full_name": full_name,
        # Set when GitHub redirected: the repository was renamed or transferred.
        "requested": asked if full_name and full_name.lower() != asked.lower() else None,
        "url": _str(data, "html_url"),
        "description": _str(data, "description"),
        "created": _date(created),
        "pushed": _date(pushed),
        "age_days": _days(created, now),
        "days_since_push": _days(pushed, now),
        "stars": _int(data, "stargazers_count"),
        "forks": _int(data, "forks_count"),
        "watchers": _int(data, "subscribers_count"),
        "open_issues": _int(data, "open_issues_count"),
        "has_issues": _bool(data, "has_issues"),
        "archived": _bool(data, "archived"),
        "disabled": _bool(data, "disabled"),
        "fork": _bool(data, "fork"),
        "parent": _str(parent, "full_name"),
        "parent_stars": _int(parent, "stargazers_count"),
        "parent_star_ratio": _ratio(
            _int(parent, "stargazers_count"), _int(data, "stargazers_count")
        ),
        "source": _str(source, "full_name"),
        "is_template": _bool(data, "is_template"),
        "template": _str(_obj(data, "template_repository"), "full_name"),
        "default_branch": _str(data, "default_branch"),
        "default_branch_protected": None,
        "license": None if license_id == "NOASSERTION" else license_id,
        "license_other": license_id == "NOASSERTION",
    }


def _ratio(more: int | None, fewer: int | None) -> float | None:
    """How many times ``more`` is larger than ``fewer`` (counted as at least 1)."""
    if more is None or fewer is None:
        return None
    return round(more / max(fewer, 1), 1)


def _owner_facts(data: Mapping[str, object], now: datetime) -> dict[str, object]:
    created = _time(_str(data, "created_at"))
    return {
        "login": _str(data, "login"),
        "type": _str(data, "type"),
        "created": _date(created),
        "age_days": _days(created, now),
        "public_repos": _int(data, "public_repos"),
        "followers": _int(data, "followers"),
    }


def _commit_time(item: Mapping[str, object] | None) -> datetime | None:
    commit = _obj(item, "commit")
    return _time(_str(_obj(commit, "committer"), "date") or _str(_obj(commit, "author"), "date"))


def _release_facts(
    item: Mapping[str, object] | None, now: datetime, table: TrustData
) -> dict[str, object] | None:
    if item is None:
        return None
    published = _time(_str(item, "published_at") or _str(item, "created_at"))
    assets = item.get("assets")
    names = [
        name
        for asset in (assets if isinstance(assets, list) else [])
        if isinstance(asset, dict) and (name := _str(asset, "name"))
    ]
    return {
        "tag": _str(item, "tag_name"),
        "published": _date(published),
        "age_days": _days(published, now),
        "prerelease": _bool(item, "prerelease"),
        "assets": len(names),
        "binary_assets": sum(1 for n in names if n.lower().endswith(table.binary_assets)),
        "asset_names": names[:_MAX_ASSETS],
    }


def _api_facts(client: GitHubClient) -> dict[str, object]:
    core = client.core
    return {
        "requests": client.requests,
        "token": client.token is not None,
        "token_source": client.token.source if client.token is not None else None,
        "rate_limit": None
        if core is None
        else {"limit": core.limit, "remaining": core.remaining, "reset": core.reset},
        "stopped": client.stopped,
    }


def _repository_gap(ctx: ScanContext, ask: _Asker, repo: GitHubRepo) -> None:
    if ask.stopped is not None:
        reason = f"stopped: {ask.stopped}"
    elif ask.unavailable and ask.unavailable[0][1] == "not found":
        reason = f"{repo.owner}/{repo.name} was not found (private, deleted or renamed)"
    else:
        detail = ask.unavailable[0][1] if ask.unavailable else "empty answer"
        reason = f"repository data not available ({detail})"
    _not_checked(ctx, CoverageStatus.FAILED, reason)


def _code_files(provenance: object) -> int | None:
    """Files in a programming language among the checked files (provenance profile)."""
    languages = provenance.get("languages") if isinstance(provenance, Mapping) else None
    if not isinstance(languages, list):
        return None
    return sum(
        int(str(item.get("files", 0)))
        for item in languages
        if isinstance(item, dict) and item.get("type") == "programming"
    )


def _max_in_window(times: Sequence[datetime], window: timedelta) -> int:
    """The largest number of ``times`` (sorted) within any ``window``."""
    best, start = 0, 0
    for end, moment in enumerate(times):
        while moment - times[start] > window:
            start += 1
        best = max(best, end - start + 1)
    return best


def _star_sample(
    ask: _Asker, client: GitHubClient, repo: GitHubRepo, stars: object
) -> dict[str, object] | None:
    """When the stars arrived; only if all of them fit into two pages."""
    if not isinstance(stars, int) or not STAR_SAMPLE_MIN <= stars <= STAR_SAMPLE_MAX:
        return None
    times: list[datetime] = []
    for page in range(1, -(-stars // api.STARS_PER_PAGE) + 1):
        items = ask("star times", partial(api.stargazers, client, repo, page))
        if items is None:
            return None
        times += [t for item in items if (t := _time(_str(item, "starred_at")))]
    if not times:
        return None
    times.sort()
    burst = _max_in_window(times, timedelta(hours=24))
    return {
        "sampled": len(times),
        "complete": len(times) >= stars,
        "first": _date(times[0]),
        "last": _date(times[-1]),
        "max_24h": burst,
        "max_24h_share": round(burst / len(times), 3),
    }


def _normalized(text: str | None) -> str:
    return _SPACES.sub(" ", text or "").strip().lower()


def _lookalike(
    ask: _Asker,
    client: GitHubClient,
    data: Mapping[str, object],
    repository: Mapping[str, object],
) -> dict[str, object] | None:
    """A repository of another owner with the same name and the same description."""
    description = _normalized(_str(data, "description"))
    full_name = str(repository.get("full_name") or "")
    owner, _, name = full_name.partition("/")
    if repository.get("fork") or len(description) < MIN_DESCRIPTION or not name:
        return None
    items = ask("name search", lambda: api.search_by_name(client, name))
    related = {
        str(n).lower() for n in (full_name, repository.get("parent"), repository.get("source")) if n
    }
    related.add(str(repository.get("template") or "").lower())
    ours = _time(_str(data, "created_at"))
    our_stars = _int(repository, "stars") or 0
    for item in items or []:
        other = _str(item, "full_name") or ""
        other_owner, _, other_name = other.partition("/")
        stars = _int(item, "stargazers_count")
        # Copies of this repository (fewer stars) say nothing about it; only a more
        # popular one can be the original this one copies.
        if (
            other.lower() in related
            or other_owner.lower() == owner.lower()
            or other_name.lower() != name.lower()
            or _normalized(_str(item, "description")) != description
            or stars is None
            or stars <= our_stars
        ):
            continue
        created = _time(_str(item, "created_at"))
        return {
            "full_name": other,
            "stars": stars,
            "star_ratio": _ratio(stars, _int(repository, "stars")),
            "created": _date(created),
            "older": created is not None and ours is not None and created < ours,
        }
    return None


def _values(node: object, keys: list[str]) -> list[tuple[str, str]]:
    """(key, value) for the string values at a dotted path; '*' takes every key."""
    if not keys or not isinstance(node, dict):
        return []
    head, rest = keys[0], keys[1:]
    pairs = list(node.items()) if head == "*" else [(head, node.get(head))]
    out: list[tuple[str, str]] = []
    for key, value in pairs:
        if rest:
            out += _values(value, rest)
        elif isinstance(value, str):
            out.append((str(key), value))
    return out


def _repo_in(value: str, table: TrustData, *, bare: bool) -> GitHubRepo | None:
    """The GitHub repository a manifest value points to: a github.com URL (its first
    two path segments) or, for npm's ``repository``, the short form ``owner/name``."""
    text = value.strip()
    match = _BARE_REPO.fullmatch(text) if bare else None
    match = match or _GITHUB_URL.match(text)
    if match is None:
        return None
    owner, name = match.groups()
    name = name.removesuffix(".git")
    repo = github_repo_from_remote(f"https://github.com/{owner}/{name}")
    if repo is None or repo.owner.lower() in table.reserved:
        return None
    return repo


def _declared(ctx: ScanContext, table: TrustData) -> list[dict[str, str]]:
    """GitHub repositories that root manifests name as the project's repository."""
    roots = {f.path.lower(): f for f in ctx.tree.files() if "/" not in f.path}
    found: list[dict[str, str]] = []
    for entry in table.declared:
        file = roots.get(entry.file.lower())
        if file is None:
            continue
        # Parse errors are already reported by the danger rules.
        text = FileView(file, ctx.limits, CoverageCollector()).text()
        if text is None:
            continue
        try:
            parsed = parse(text, entry.fmt, ctx.limits)
        except ParseError:
            continue
        for dotted in entry.paths:
            for key, value in _values(parsed, dotted.split(".")):
                if entry.keys is not None and not entry.keys.match(key):
                    continue
                repo = _repo_in(value, table, bare=dotted == "repository")
                if repo is not None:
                    found.append({"file": file.path, "repository": f"{repo.owner}/{repo.name}"})
    return found


def _manifest(
    ctx: ScanContext,
    ask: _Asker,
    client: GitHubClient,
    data: Mapping[str, object],
    repository: Mapping[str, object],
    requested: GitHubRepo,
    table: TrustData,
) -> dict[str, object]:
    """Whether a root manifest names another owner's repository as the project's own.
    Forks, templates, renamed and transferred repositories are not counted."""
    declared = _declared(ctx, table)
    full_name = str(repository.get("full_name") or "")
    owners = {full_name.partition("/")[0].lower(), requested.owner.lower()}
    related = {
        str(n).lower()
        for n in (repository.get("parent"), repository.get("source"), repository.get("template"))
        if n
    }
    other = next(
        (
            d
            for d in declared
            if d["repository"].partition("/")[0].lower() not in owners
            and d["repository"].lower() not in related
        ),
        None,
    )
    exists: bool | None = None
    if other is not None:
        o_owner, _, o_name = other["repository"].partition("/")
        missing: dict[str, object] = {}
        answer = ask(
            "repository named in a manifest",
            partial(api.repository, client, GitHubRepo(o_owner, o_name)),
            missing,
        )
        if answer:
            exists = True
            network = {
                str(n).lower()
                for n in (
                    _str(answer, "full_name"),
                    _str(_obj(answer, "source"), "full_name"),
                    _str(_obj(answer, "parent"), "full_name"),
                )
                if n
            }
            if _int(answer, "id") == _int(data, "id") or network & {full_name.lower(), *related}:
                other = None  # the same repository (transferred) or the same fork network
        elif answer == {}:
            exists = False
    return {
        "declared": declared,
        "other": other["repository"] if other else None,
        "other_file": other["file"] if other else None,
        "other_exists": exists if other else None,
    }


def collect(
    ctx: ScanContext, target: TrustTarget, client: GitHubClient, repo: GitHubRepo
) -> dict[str, object] | None:
    """The trust facts, or ``None`` if not even the repository could be read (the
    reason is in coverage)."""
    now = target.now()
    ask = _Asker()
    with suppress(ApiError):  # the limits also arrive with every answer
        client.check_rate_limit()
    data = ask("repository", lambda: api.repository(client, repo))
    if not data:
        _repository_gap(ctx, ask, repo)
        return None

    repository = _repository_facts(data, repo, now)
    owner, _, name = str(repository["full_name"] or f"{repo.owner}/{repo.name}").partition("/")
    current = GitHubRepo(owner, name or repo.name)
    login = _str(_obj(data, "owner"), "login") or owner
    owner_data = ask("owner account", lambda: api.account(client, login))
    local: dict[str, object] | None = None
    if target.claimed_by is not None:
        head = target.local_head
        found = (
            ask("local HEAD commit", lambda: api.commit_exists(client, current, head), False)
            if head is not None
            else None
        )
        local = {"claimed_by": target.claimed_by, "head": head, "head_found": found}
    branch = repository["default_branch"]
    commits = (
        ask("commits", lambda: api.commits(client, current, branch))
        if isinstance(branch, str)
        else None
    )
    people = ask("contributors", lambda: api.contributors(client, current))
    releases = ask("releases", lambda: api.releases(client, current))
    if isinstance(branch, str):
        branch_data = ask("default branch", lambda: api.branch(client, current, branch))
        if branch_data:
            repository["default_branch_protected"] = _bool(branch_data, "protected")
    last_commit = _commit_time(commits.first if commits else None)
    provenance = ctx.facts.get("provenance")
    present = _obj(provenance, "markers").get("present")
    table = load_data()
    stars = _star_sample(ask, client, current, repository["stars"])
    lookalike = _lookalike(ask, client, data, repository)
    manifest = _manifest(ctx, ask, client, data, repository, repo, table)

    facts: dict[str, object] = {
        "repository": repository,
        "owner": _owner_facts(owner_data, now) if owner_data else None,
        "activity": {
            "commits": commits.total if commits else None,
            "last_commit": _date(last_commit),
            "days_since_commit": _days(last_commit, now),
            "contributors": people.total if people else None,
            "releases": releases.total if releases else None,
            "latest_release": _release_facts(releases.first, now, table) if releases else None,
        },
        "security_policy": isinstance(present, list) and "security_policy" in present,
        "code_files": _code_files(provenance),
        "stars": stars,
        "lookalike": lookalike,
        "manifest": manifest,
        "local": local,
        "api": _api_facts(client),
    }
    if ask.stopped is not None:
        _not_checked(
            ctx,
            CoverageStatus.PARTIAL,
            f"stopped ({ask.stopped}); not checked: {', '.join(ask.skipped)}",
        )
    for what, reason in ask.unavailable:
        _not_checked(ctx, CoverageStatus.PARTIAL, f"{what} not available ({reason})")
    return facts


# --- summary -------------------------------------------------------------------------


def summary_lines(facts: Mapping[str, object], client: GitHubClient) -> list[tuple[str, str]]:
    repository = _obj(facts, "repository")
    text = str(repository.get("full_name"))
    if repository.get("requested"):
        text += f" (requested as {repository['requested']}: renamed or transferred)"
    if repository.get("created"):
        text += f", created {repository['created']}{_ago(repository.get('age_days'))}"
    if repository.get("pushed"):
        text += f"; last push {repository['pushed']}{_ago(repository.get('days_since_push'))}"
    lines = [("Repository", text)]

    owner = facts.get("owner")
    if isinstance(owner, dict):
        kind = str(owner.get("type") or "account").lower()
        repos = _n(owner.get("public_repos"), "public repository", "public repositories")
        lines.append(
            (
                "Owner",
                f"{owner.get('login')} ({kind}), account created {owner.get('created')}"
                f"{_ago(owner.get('age_days'))}; {repos}, "
                f"{_n(owner.get('followers'), 'follower')}",
            )
        )
    lines.append(
        (
            "Popularity",
            f"{_n(repository.get('stars'), 'star')}, {_n(repository.get('forks'), 'fork')}, "
            f"{_n(repository.get('watchers'), 'watcher')}",
        )
    )
    stars = facts.get("stars")
    if isinstance(stars, dict):
        share = round(float(str(stars.get("max_24h_share"))) * 100)
        lines.append(
            (
                "Star times",
                f"{_n(stars.get('sampled'), 'star')} from {stars.get('first')} to "
                f"{stars.get('last')}; at most {stars.get('max_24h')} ({share}%) "
                "within 24 hours",
            )
        )
    activity = _obj(facts, "activity")
    if parts := _activity(activity, repository):
        lines.append(("Activity", "; ".join(parts)))
    lines.append(("Status", _status(facts, repository)))
    lookalike = facts.get("lookalike")
    if isinstance(lookalike, dict):
        lines.append(
            (
                "Lookalike",
                f"{lookalike.get('full_name')} has the same name and description "
                f"({_n(lookalike.get('stars'), 'star')}, created {lookalike.get('created')})",
            )
        )
    manifest = _obj(facts, "manifest")
    if manifest.get("other"):
        missing = (
            " (that repository does not exist)" if manifest.get("other_exists") is False else ""
        )
        lines.append(
            (
                "Manifest",
                f"{manifest.get('other_file')} names {manifest.get('other')} as the "
                f"project's repository{missing}",
            )
        )
    local = facts.get("local")
    if isinstance(local, dict):
        lines.append(("Local", _local(local, repository)))
    lines.append(("API", _api_line(client)))
    lines.append(("", NOTE))
    return lines


def _activity(activity: Mapping[str, object], repository: Mapping[str, object]) -> list[str]:
    parts = []
    if activity.get("commits") is not None:
        parts.append(
            f"{_n(activity['commits'], 'commit')} on {repository.get('default_branch')}, last "
            f"{activity.get('last_commit')}{_ago(activity.get('days_since_commit'))}"
        )
    if activity.get("contributors") is not None:
        parts.append(_n(activity["contributors"], "contributor"))
    if activity.get("releases") is not None:
        text = _n(activity["releases"], "release")
        release = activity.get("latest_release")
        if isinstance(release, dict):
            text += (
                f", latest {release.get('tag')} on {release.get('published')} "
                f"({_n(release.get('assets'), 'asset')})"
            )
        parts.append(text)
    if isinstance(repository.get("open_issues"), int):
        parts.append(f"{repository['open_issues']:,} open issues and pull requests")
    return parts


def _status(facts: Mapping[str, object], repository: Mapping[str, object]) -> str:
    parts = ["archived" if repository.get("archived") else "not archived"]
    if repository.get("disabled"):
        parts.append("disabled")
    if repository.get("fork"):
        parent = repository.get("parent") or "an unknown repository"
        stars = repository.get("parent_stars")
        parts.append(f"fork of {parent}" + (f" ({_n(stars, 'star')})" if stars is not None else ""))
    else:
        parts.append("not a fork")
    if repository.get("template"):
        parts.append(f"generated from template {repository['template']}")
    if repository.get("is_template"):
        parts.append("is a template")
    protected = repository.get("default_branch_protected")
    if protected is not None:
        state = "is" if protected else "is not"
        parts.append(f"{repository.get('default_branch')} {state} protected")
    if repository.get("license"):
        parts.append(f"license {repository['license']} (GitHub)")
    elif repository.get("license_other"):
        parts.append("license not recognized by GitHub")
    else:
        parts.append("no license recognized by GitHub")
    found = facts.get("security_policy")
    parts.append("security policy in the files" if found else "no security policy in the files")
    return "; ".join(parts)


def _local(local: Mapping[str, object], repository: Mapping[str, object]) -> str:
    head, found = local.get("head"), local.get("head_found")
    if head is None:
        text = "no HEAD commit to look up"
    elif found is None:
        text = f"HEAD {str(head)[:12]} could not be looked up"
    else:
        where = repository.get("full_name")
        text = f"HEAD {str(head)[:12]} {'found' if found else 'NOT found'} in {where}"
    return f"{text} (repository named by {local.get('claimed_by')})"


def _api_line(client: GitHubClient) -> str:
    parts = [_n(client.requests, "request")]
    core = client.core
    if core is not None:
        parts.append(f"{core.remaining} of {core.limit} left (resets {core.reset_text()})")
    parts.append(f"token from {client.token.source}" if client.token else "no token")
    return ", ".join(parts)


# --- area ----------------------------------------------------------------------------


def profile(ctx: ScanContext) -> tuple[dict[str, object], list[tuple[str, str]]]:
    """``{"trust": facts}`` and summary lines; empty if the API is not queried."""
    target = ctx.trust
    if target is None or target.repo is None:
        note = target.note if target is not None and target.note else NO_TARGET
        _not_checked(ctx, CoverageStatus.SKIPPED, note)
        return {}, []
    if target.client is None:
        _not_checked(ctx, CoverageStatus.SKIPPED, target.note or OFFLINE)
        return {}, []
    if target.token_note:
        _not_checked(ctx, CoverageStatus.PARTIAL, target.token_note)
    facts = collect(ctx, target, target.client, target.repo)
    if facts is None:
        return {}, []
    return {AREA: facts}, summary_lines(facts, target.client)


def analyze(ctx: ScanContext) -> AreaResult:
    facts, summary = profile(ctx)
    findings = run_rules(ctx.rules.active(AREA), ctx, facts=facts or None)
    return AreaResult(AREA, findings, facts=facts, summary=summary)
