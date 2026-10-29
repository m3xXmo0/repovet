"""Which repository the trust step asks the GitHub API about, and with which client."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime

from repovet import __version__
from repovet.github.client import GitHubClient, Transport, token_from_env
from repovet.github.transport import UrllibTransport
from repovet.sources.remote import GitHubRepo

# Replaced in tests by a transport with recorded responses.
DEFAULT_TRANSPORT: Callable[[], Transport] = UrllibTransport

OFFLINE = "--offline: the GitHub API was not queried"


@dataclass
class TrustTarget:
    """``client`` is None when the API is not queried; ``note`` says why."""

    repo: GitHubRepo | None
    client: GitHubClient | None = None
    note: str | None = None
    token_note: str | None = None
    # Local folders: where the repository name comes from, and the HEAD to look up.
    claimed_by: str | None = None
    local_head: str | None = None
    # Ages are computed against this clock (fixed in tests).
    now: Callable[[], datetime] = lambda: datetime.now(UTC)


def setup(
    repo: GitHubRepo | None,
    *,
    offline: bool,
    environ: Mapping[str, str],
    note: str | None = None,
    claimed_by: str | None = None,
    local_head: str | None = None,
) -> TrustTarget:
    target = TrustTarget(repo, note=note, claimed_by=claimed_by, local_head=local_head)
    if repo is None:
        return target
    if offline:
        target.note = OFFLINE
        return target
    token, target.token_note = token_from_env(environ)
    target.client = GitHubClient(DEFAULT_TRANSPORT(), token, user_agent=f"repovet/{__version__}")
    return target
