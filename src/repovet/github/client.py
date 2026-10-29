"""GitHub REST API client: token, rate limit, request budget, limits.

The client never opens a connection itself; a ``Transport`` does (``transport.py`` for
real use, recorded responses in tests). Only ``https://api.github.com`` is contacted,
redirects are followed only within it, responses are capped in size and must be JSON
(or a bare commit id). The token is held in ``Token`` and never appears in
``repr``, errors or reports.

Errors never abort a scan: the trust area turns them into "Not checked" entries. Once
the rate limit, the request budget or the time limit is reached, every further call
fails at once with the same reason, without sending anything.
"""

import json
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol
from urllib.parse import urlencode, urljoin, urlsplit

API_ROOT = "https://api.github.com"
API_VERSION = "2022-11-28"
JSON_MEDIA = "application/vnd.github+json"
SHA_MEDIA = "application/vnd.github.sha"
STAR_MEDIA = "application/vnd.github.star+json"
MAX_RESPONSE_BYTES = 1024 * 1024
REQUEST_TIMEOUT = 20.0
TOTAL_TIMEOUT = 60.0
MAX_WAIT = 20.0
BUDGET_ANONYMOUS = 25
BUDGET_TOKEN = 100
MAX_REDIRECTS = 3
TOKEN_VARIABLES = ("GITHUB_TOKEN", "GH_TOKEN")

# Classic (40 hex), fine-grained (github_pat_...) and app tokens (ghp_, ghs_, ...).
_TOKEN = re.compile(r"[A-Za-z0-9_]{20,255}")
_PATH = re.compile(r"/[A-Za-z0-9._@:+/%-]*")
_LINK_LAST = re.compile(r'<([^<>\s]+)>\s*;\s*rel="last"')
_REDIRECTS = frozenset({301, 302, 307, 308})
_NOT_FOUND = frozenset({404, 409, 410, 422, 451})


class ApiError(Exception):
    """A request failed. Messages never contain the token."""


class NotFound(ApiError):
    """404 and similar: the object does not exist or is not visible without access."""


class Refused(ApiError):
    """GitHub answered, but not with the data (for example 403 for a list that is too
    large, or a 5xx error). Other requests may still work."""


class Stopped(ApiError):
    """No further requests in this scan: rate limit, budget, time limit, rejected
    token or an unreachable API."""


class TransportError(Exception):
    """The connection failed (DNS, TLS, timeout)."""


class TooLarge(TransportError):
    """The answer is larger than the limit; only this request fails."""


@dataclass(frozen=True)
class Request:
    url: str
    headers: Mapping[str, str]
    timeout: float


@dataclass(frozen=True)
class Response:
    status: int
    headers: Mapping[str, str]  # names in lower case
    body: bytes


class Transport(Protocol):
    def __call__(self, request: Request, max_bytes: int) -> Response: ...


class Token:
    """An API token from the environment. ``repr``/``str`` never show the value."""

    __slots__ = ("_value", "source")

    def __init__(self, value: str, source: str) -> None:
        self._value = value
        self.source = source

    def __repr__(self) -> str:
        return f"Token(from {self.source})"

    __str__ = __repr__

    def header(self) -> str:
        return f"Bearer {self._value}"

    def redact(self, text: str) -> str:
        return text.replace(self._value, "***")


def token_from_env(environ: Mapping[str, str]) -> tuple[Token | None, str | None]:
    """The token from GITHUB_TOKEN or GH_TOKEN, plus a note if one was set but unusable."""
    for name in TOKEN_VARIABLES:
        value = environ.get(name, "").strip()
        if not value:
            continue
        if not _TOKEN.fullmatch(value):
            return None, f"{name} is set but does not look like a GitHub token; it was not used"
        return Token(value, name), None
    return None, None


@dataclass
class RateLimit:
    limit: int
    remaining: int
    reset: int  # Unix time
    resource: str = "core"

    def reset_text(self) -> str:
        return datetime.fromtimestamp(self.reset, UTC).strftime("%H:%M UTC")


@dataclass
class Result:
    data: object
    headers: Mapping[str, str]

    def last_page(self) -> int | None:
        """Number of the last page from the ``Link`` header (None: only one page)."""
        match = _LINK_LAST.search(self.headers.get("link", ""))
        if match is None:
            return None
        for key, value in _query(match.group(1)):
            if key == "page" and value.isdigit():
                return int(value)
        return None


def _query(url: str) -> list[tuple[str, str]]:
    query = urlsplit(url).query
    pairs = []
    for part in query.split("&"):
        key, _, value = part.partition("=")
        pairs.append((key, value))
    return pairs


def _int(value: str | None) -> int | None:
    return int(value) if value is not None and value.strip().isdigit() else None


@dataclass
class GitHubClient:
    transport: Transport
    token: Token | None = None
    budget: int = 0  # 0: the default for anonymous or token use
    max_wait: float = MAX_WAIT
    total_timeout: float = TOTAL_TIMEOUT
    clock: Callable[[], float] = time.monotonic
    wall: Callable[[], float] = time.time
    sleep: Callable[[float], None] = time.sleep
    user_agent: str = "repovet"
    # Requests that count against the budget, and all requests sent (incl. /rate_limit).
    requests: int = 0
    sent: int = 0
    stopped: str | None = None
    rates: dict[str, RateLimit] = field(default_factory=dict)
    _memo: dict[tuple[str, str], Result | ApiError] = field(default_factory=dict)
    _deadline: float | None = None

    def __post_init__(self) -> None:
        if self.budget <= 0:
            self.budget = BUDGET_TOKEN if self.token is not None else BUDGET_ANONYMOUS

    @property
    def core(self) -> RateLimit | None:
        return self.rates.get("core")

    # --- public calls ---------------------------------------------------------

    def check_rate_limit(self) -> RateLimit | None:
        """Ask for the current limits (this request does not count against them)."""
        result = self._get("/rate_limit", {}, JSON_MEDIA, counts=False)
        resources = result.data.get("resources") if isinstance(result.data, dict) else None
        if isinstance(resources, dict):
            for name, raw in resources.items():
                if name in ("core", "search") and isinstance(raw, dict):
                    limit, remaining, reset = (
                        raw.get("limit"),
                        raw.get("remaining"),
                        raw.get("reset"),
                    )
                    if all(isinstance(v, int) for v in (limit, remaining, reset)):
                        self.rates[name] = RateLimit(
                            int(str(limit)), int(str(remaining)), int(str(reset)), name
                        )
        return self.core

    def get(
        self, path: str, params: Mapping[str, str | int] | None = None, accept: str = JSON_MEDIA
    ) -> Result:
        return self._get(path, params or {}, accept, counts=True)

    # --- internals ------------------------------------------------------------

    def _redact(self, text: str) -> str:
        return self.token.redact(text) if self.token is not None else text

    def _stop(self, reason: str) -> Stopped:
        self.stopped = self._redact(reason)
        return Stopped(self.stopped)

    def _url(self, path: str, params: Mapping[str, str | int]) -> str:
        if not _PATH.fullmatch(path) or ".." in path or "//" in path:
            raise ValueError(f"invalid API path {path!r}")
        query = urlencode(sorted((k, str(v)) for k, v in params.items()))
        return f"{API_ROOT}{path}" + (f"?{query}" if query else "")

    def _headers(self, accept: str) -> dict[str, str]:
        headers = {
            "Accept": accept,
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": self.user_agent,
        }
        if self.token is not None:
            headers["Authorization"] = self.token.header()
        return headers

    def _get(
        self, path: str, params: Mapping[str, str | int], accept: str, *, counts: bool
    ) -> Result:
        url = self._url(path, params)
        key = (url, accept)
        if key in self._memo:
            cached = self._memo[key]
            if isinstance(cached, ApiError):
                raise cached
            return cached
        try:
            result = self._fetch(url, accept, counts=counts)
        except (NotFound, Refused) as exc:
            self._memo[key] = exc
            raise
        self._memo[key] = result
        return result

    def _before_send(self, url: str, counts: bool) -> float:
        if self.stopped is not None:
            raise Stopped(self.stopped)
        now = self.clock()
        if self._deadline is None:
            self._deadline = now + self.total_timeout
        left = self._deadline - now
        if left <= 0:
            raise self._stop(f"time limit of {self.total_timeout:.0f} s for GitHub API requests")
        if counts:
            if self.requests >= self.budget:
                raise self._stop(f"request budget of {self.budget} per scan used up")
            rate = self.rates.get(_resource(url))
            if rate is not None and rate.remaining <= 0 and rate.reset > self.wall():
                raise self._stop(_rate_message(rate))
            self.requests += 1
        return min(REQUEST_TIMEOUT, left)

    def _fetch(self, url: str, accept: str, *, counts: bool) -> Result:
        waited = False
        redirects = 0
        while True:
            timeout = self._before_send(url, counts)
            request = Request(url, self._headers(accept), timeout)
            self.sent += 1
            try:
                response = self.transport(request, MAX_RESPONSE_BYTES)
            except TooLarge as exc:
                raise Refused(self._redact(str(exc))) from None
            except TransportError as exc:
                raise self._stop(f"GitHub API not reachable: {exc}") from None
            self._track(url, response.headers)
            status = response.status
            if status in _REDIRECTS:
                redirects += 1
                url = self._redirect(url, response.headers.get("location", ""), redirects)
                continue
            if status in (403, 429):
                wait = self._wait_time(response.headers)
                if wait is not None and wait <= self.max_wait and not waited:
                    waited = True
                    self.sleep(wait)
                    continue
                rate = self.rates.get(_resource(url))
                if rate is not None and rate.remaining <= 0:
                    raise self._stop(_rate_message(rate))
                if wait is not None:
                    raise self._stop(f"GitHub asked to wait {wait:.0f} s (secondary rate limit)")
                raise Refused(self._redact(f"HTTP {status}: {_api_message(response.body)}"))
            if status == 401:
                raise self._stop("GitHub rejected the token (HTTP 401)")
            if status in _NOT_FOUND:
                raise NotFound(self._redact(f"HTTP {status}"))
            if status == 204:
                return Result(None, response.headers)
            if status != 200:
                raise Refused(self._redact(f"HTTP {status}"))
            return Result(self._parse(response, accept), response.headers)

    def _redirect(self, url: str, location: str, count: int) -> str:
        target = urljoin(url, location)
        parts = urlsplit(target)
        if count > MAX_REDIRECTS:
            raise Refused("too many redirects")
        if parts.scheme != "https" or parts.netloc != "api.github.com" or parts.username:
            raise Refused("redirect away from https://api.github.com refused")
        if not _PATH.fullmatch(parts.path) or ".." in parts.path:
            raise Refused("redirect to an unexpected path refused")
        return target

    def _wait_time(self, headers: Mapping[str, str]) -> float | None:
        retry_after = _int(headers.get("retry-after"))
        if retry_after is not None:
            return float(retry_after)
        if headers.get("x-ratelimit-remaining") == "0":
            reset = _int(headers.get("x-ratelimit-reset"))
            if reset is not None:
                return max(0.0, reset - self.wall())
        return None

    def _track(self, url: str, headers: Mapping[str, str]) -> None:
        limit = _int(headers.get("x-ratelimit-limit"))
        remaining = _int(headers.get("x-ratelimit-remaining"))
        reset = _int(headers.get("x-ratelimit-reset"))
        if limit is None or remaining is None or reset is None:
            return
        resource = headers.get("x-ratelimit-resource") or _resource(url)
        if resource in ("core", "search"):
            self.rates[resource] = RateLimit(limit, remaining, reset, resource)

    def _parse(self, response: Response, accept: str) -> object:
        try:
            text = response.body.decode("utf-8")
        except UnicodeDecodeError:
            raise Refused("response is not UTF-8") from None
        if accept == SHA_MEDIA:
            return text.strip()
        content_type = response.headers.get("content-type", "")
        if "json" not in content_type.lower():
            raise Refused("response is not JSON")
        try:
            return json.loads(text)
        except (ValueError, RecursionError):
            raise Refused("response is not valid JSON") from None


def _resource(url: str) -> str:
    return "search" if urlsplit(url).path.startswith("/search/") else "core"


def _rate_message(rate: RateLimit) -> str:
    return (
        f"GitHub API rate limit reached ({rate.remaining} of {rate.limit} requests left, "
        f"resets at {rate.reset_text()})"
    )


def _api_message(body: bytes) -> str:
    """GitHub's short error text (``message``), at most 200 characters."""
    try:
        data = json.loads(body.decode("utf-8"))
    except (ValueError, RecursionError):
        return "request refused"
    message = data.get("message") if isinstance(data, dict) else None
    return str(message)[:200] if isinstance(message, str) and message else "request refused"
