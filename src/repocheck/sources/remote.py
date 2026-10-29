"""GitHub URL targets: validate the URL and fetch the repository's objects with dulwich.

This and ``github/`` are the only modules that use the network. The fetch
writes nothing but a pack file and its index into a fresh temporary folder: no working
tree, no refs, no config from the remote, no hooks, submodules, LFS or filters, and no
``git`` binary. The folder is deleted afterwards (pack files are read-only on Windows,
so deletion clears that flag first).
"""

import re
import shutil
import stat
import tempfile
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from dulwich.client import GitClient, HTTPUnauthorized, Urllib3HttpGitClient
from dulwich.errors import GitProtocolError, HangupException, NotGitRepository
from dulwich.object_store import DiskObjectStore, ObjectStoreGraphWalker
from dulwich.objects import ObjectID
from dulwich.refs import Ref

from repocheck.sources.gitobjects import GitObjectError, GitObjects, is_hex_id

# Strings that are meant as a URL rather than a folder (scheme://, scp-like ssh).
_URL_LIKE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]+://|git@|[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:")
_OWNER = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})")
_REPO = re.compile(r"[A-Za-z0-9._-]{1,100}")
_REF_NAME = re.compile(r"[A-Za-z0-9._/-]{1,200}")
SUPPORTED = "https://github.com/<owner>/<repo>"
DEFAULT_MAX_CLONE_SIZE = 500 * 1024 * 1024
DEFAULT_CLONE_TIMEOUT = 300.0
_SOCKET_TIMEOUT = 60.0


class UrlError(ValueError):
    """The target looks like a URL but is not a supported one (a usage error)."""


class CloneError(Exception):
    """Fetching failed or hit a limit (the analysis is aborted)."""


@dataclass(frozen=True)
class GitHubRepo:
    owner: str
    name: str

    @property
    def url(self) -> str:
        return f"https://github.com/{self.owner}/{self.name}"

    @property
    def path(self) -> str:
        return f"/{self.owner}/{self.name}.git"


def looks_like_url(target: str) -> bool:
    return _URL_LIKE.match(target) is not None


def parse_github_url(target: str) -> GitHubRepo:
    """Accept only ``https://github.com/<owner>/<repo>`` (optionally ``.git`` or a
    trailing slash). Other schemes (ssh, git, file, ``ext::``) and hosts are rejected."""
    try:
        parts = urlsplit(target)
        port = parts.port
    except ValueError:
        raise UrlError(f"invalid URL; only {SUPPORTED} is supported") from None
    if parts.scheme.lower() != "https":
        raise UrlError(f"only HTTPS URLs of the form {SUPPORTED} are supported")
    if (parts.hostname or "").lower() != "github.com" or port not in (None, 443):
        raise UrlError(f"only GitHub repositories are supported ({SUPPORTED})")
    if parts.username is not None or parts.password is not None:
        raise UrlError("URLs with credentials are not accepted")
    if parts.query or parts.fragment:
        raise UrlError(f"the URL must not have a query or fragment ({SUPPORTED})")
    segments = parts.path.strip("/").split("/")
    if len(segments) != 2:
        raise UrlError(f"the URL must name exactly one repository ({SUPPORTED})")
    owner, name = segments
    if name.lower().endswith(".git"):
        name = name[:-4]
    if not _OWNER.fullmatch(owner) or not _REPO.fullmatch(name) or name in (".", ".."):
        raise UrlError(f"not a valid GitHub owner/repository name ({SUPPORTED})")
    return GitHubRepo(owner, name)


_REMOTE = re.compile(
    r"(?:(?:https?|git|ssh|git\+ssh)://(?:[^@/\s]*@)?github\.com(?::\d{1,5})?/"
    r"|[A-Za-z0-9._-]+@github\.com:/?)"
    r"([^/\s]+)/([^/\s]+?)(?:\.git)?/?",
    re.IGNORECASE,
)


def github_repo_from_remote(url: str) -> GitHubRepo | None:
    """The GitHub repository named by a Git remote URL (HTTPS, SSH or git://), or None.
    Credentials in the URL are ignored and never kept."""
    match = _REMOTE.fullmatch(url.strip())
    if match is None:
        return None
    owner, name = match.groups()
    if not _OWNER.fullmatch(owner) or not _REPO.fullmatch(name) or name in (".", ".."):
        return None
    return GitHubRepo(owner, name)


def validate_ref(ref: str) -> str:
    """A branch, a tag or a full 40-character commit id."""
    if not _REF_NAME.fullmatch(ref) or ".." in ref or ref.startswith(("/", "-")):
        raise UrlError(f"invalid --ref {ref!r} (expected a branch, a tag or a full commit id)")
    return ref


type Transport = Callable[[GitHubRepo, float], tuple[GitClient, str]]


def github_transport(repo: GitHubRepo, timeout: float) -> tuple[GitClient, str]:
    """Smart HTTP client without Git configuration: no credential helpers, no extra
    headers or proxies from config files, no dumb-HTTP fallback, TLS verified."""
    client = Urllib3HttpGitClient(
        "https://github.com/", dumb=False, config=None, timeout=timeout, quiet=True
    )
    return client, repo.path


@dataclass
class Clone:
    repo: GitHubRepo
    workspace: Path
    objects: GitObjects
    commit: bytes
    ref: str
    pack_bytes: int

    @property
    def label(self) -> str:
        return f"{self.repo.url} @ {self.ref} ({self.commit.decode('ascii')[:12]})"


class _Budget:
    """Pack bytes go to the pack file until the size or time limit is reached."""

    def __init__(self, max_bytes: int, deadline: float) -> None:
        self.write: Callable[[bytes], object] = lambda _data: None
        self.max_bytes = max_bytes
        self.deadline = deadline
        self.total = 0

    def check_time(self) -> None:
        if time.monotonic() > self.deadline:
            raise CloneError("clone time limit reached; try a larger --clone-timeout")

    def pack_data(self, data: bytes) -> int:
        self.total += len(data)
        if self.total > self.max_bytes:
            raise CloneError(
                f"repository is larger than the clone limit of {self.max_bytes:,} bytes; "
                "try a larger --max-clone-size"
            )
        self.check_time()
        self.write(data)
        return len(data)

    def progress(self, _message: bytes) -> None:
        self.check_time()


class _Wants:
    """dulwich callback: pick the object to fetch from the advertised refs."""

    def __init__(self, ref: str | None) -> None:
        self.ref = ref
        self.chosen: dict[str, str] = {}

    def __call__(self, refs: Mapping[Ref, ObjectID], depth: int | None = None) -> list[ObjectID]:
        ref, chosen = self.ref, self.chosen
        if ref is not None and is_hex_id(ref.lower()):
            chosen["ref"] = chosen["sha"] = ref.lower()
            return [ObjectID(ref.lower().encode("ascii"))]
        names = [Ref(b"HEAD")] if ref is None else _candidates(ref)
        for name in names:
            sha = refs.get(name)
            if sha:
                chosen["ref"] = ref or _default_branch(refs, sha)
                chosen["sha"] = sha.decode("ascii")
                return [sha]
        if ref is None:
            raise CloneError("the remote has no default branch (empty repository?)")
        hint = (
            "; commit ids must be given in full (40 characters)"
            if re.fullmatch(r"[0-9a-fA-F]{7,39}", ref)
            else ""
        )
        raise CloneError(f"branch or tag {ref!r} not found in the remote repository{hint}")


def _candidates(ref: str) -> list[Ref]:
    if ref.startswith("refs/"):
        return [Ref(ref.encode("ascii"))]
    return [Ref(f"refs/heads/{ref}".encode("ascii")), Ref(f"refs/tags/{ref}".encode("ascii"))]


def _default_branch(refs: Mapping[Ref, ObjectID], sha: bytes) -> str:
    for name, value in sorted(refs.items()):
        if value == sha and name.startswith(b"refs/heads/"):
            return name[len(b"refs/heads/") :].decode("utf-8", "replace")
    return "HEAD"


def _new_workspace() -> Path:
    return Path(tempfile.mkdtemp(prefix="repocheck-clone-"))


def _remove_workspace(path: Path) -> str | None:
    """Delete the clone folder; ``None`` on success, otherwise the reason."""

    def make_writable(func: Callable[[str], object], name: str, _exc: BaseException) -> None:
        # Git pack files are read-only, which blocks deletion on Windows. On POSIX a
        # folder without write or search permission blocks deleting its entries. Only
        # the entry and its parent are changed, and only inside the clone folder.
        entry = Path(name)
        for target in (entry.parent, entry):
            if not target.is_relative_to(path) or target.is_symlink():
                continue
            target.chmod(stat.S_IRWXU if target.is_dir() else stat.S_IREAD | stat.S_IWRITE)
        func(name)

    try:
        shutil.rmtree(path, onexc=make_writable)
    except OSError as exc:
        return exc.strerror or str(exc)
    return None


def _fetch(
    client: GitClient,
    remote_path: str,
    store: DiskObjectStore,
    ref: str | None,
    budget: _Budget,
) -> tuple[str, str]:
    """Fetch into ``store``; returns (ref name, wanted object id)."""
    wants = _Wants(ref)
    chosen = wants.chosen
    ref_prefix = None if ref is None or is_hex_id(ref.lower()) else _candidates(ref)
    pack, commit, abort = store.add_pack()
    budget.write = pack.write
    try:
        client.fetch_pack(
            remote_path,
            wants,
            ObjectStoreGraphWalker([], lambda _sha: []),
            budget.pack_data,
            progress=budget.progress,
            ref_prefix=ref_prefix,
        )
    except BaseException:
        abort()
        raise
    commit()
    if "sha" not in chosen:  # pragma: no cover - determine_wants always sets it or raises
        raise CloneError("nothing was fetched")
    return chosen["ref"], chosen["sha"]


@contextmanager
def clone(
    repo: GitHubRepo,
    *,
    ref: str | None = None,
    max_bytes: int = DEFAULT_MAX_CLONE_SIZE,
    timeout: float = DEFAULT_CLONE_TIMEOUT,
    keep: bool = False,
    transport: Transport | None = None,
    on_cleanup: Callable[[Path, str | None], None] | None = None,
) -> Iterator[Clone]:
    """Fetch ``ref`` (default: the default branch) with its history into a temporary
    object store and yield it. ``on_cleanup(path, error)`` reports what happened to the
    folder (``error`` is ``None`` when it was deleted or kept on purpose)."""
    workspace = _new_workspace()
    objects: GitObjects | None = None
    try:
        objects_dir = str(workspace / "objects")
        store = DiskObjectStore.init(objects_dir)
        budget = _Budget(max_bytes, time.monotonic() + timeout)
        client, remote_path = (transport or github_transport)(repo, min(timeout, _SOCKET_TIMEOUT))
        try:
            ref_name, wanted = _fetch(client, remote_path, store, ref, budget)
        except CloneError:
            raise
        except HTTPUnauthorized:
            raise CloneError(
                f"{repo.url} was not found or is not public (only public repositories "
                "can be checked)"
            ) from None
        except NotGitRepository:
            raise CloneError(f"{repo.url} was not found") from None
        except (GitProtocolError, HangupException, OSError, KeyError, AssertionError) as exc:
            raise CloneError(f"fetching {repo.url} failed: {exc}") from None
        finally:
            store.close()
            client.close()
        objects = GitObjects(objects_dir)
        try:
            commit = objects.peel(wanted.encode("ascii"))
        except GitObjectError as exc:
            raise CloneError(f"the fetched data has no usable commit: {exc}") from None
        yield Clone(repo, workspace, objects, commit, ref_name, budget.total)
    finally:
        if objects is not None:
            objects.close()
        error = None if keep else _remove_workspace(workspace)
        if on_cleanup is not None:
            on_cleanup(workspace, error)
