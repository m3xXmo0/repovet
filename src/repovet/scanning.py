"""Scan orchestration shared by the command line and the interactive mode.

Options in, ``ScanResult`` out; rendering, questions and exit codes stay with the
callers. A URL scan is a context manager so that ``repovet clone`` can write the
working tree from the very objects that were checked.
"""

import os
import time
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from repovet import __version__
from repovet.analyzers import run_all
from repovet.engine.context import ScanContext
from repovet.engine.loader import RuleSet, load_rules
from repovet.github import target as github_target
from repovet.limits import DEFAULT_LIMITS, Limits
from repovet.models import AREAS, CoverageCollector, ScanResult, Severity
from repovet.sources import gitmeta, remote
from repovet.sources.gittree import GitTree
from repovet.sources.local import LocalTree
from repovet.sources.tree import FileTree

type Note = Callable[[str], None]


class UsageError(Exception):
    """Invalid input from the user (exit code 2)."""


@dataclass
class ScanOptions:
    target: str
    offline: bool = False
    ref: str | None = None
    keep_clone: bool = False
    max_clone_size: int = remote.DEFAULT_MAX_CLONE_SIZE
    clone_timeout: float = remote.DEFAULT_CLONE_TIMEOUT
    rules: Sequence[str] = ()
    ignore_rules: Sequence[str] = ()
    max_file_size: int = DEFAULT_LIMITS.max_file_size
    include_env_dirs: bool = False
    environ: dict[str, str] = field(default_factory=lambda: dict(os.environ))


@dataclass
class Scanned:
    result: ScanResult
    rules: RuleSet
    # The checked folder of a local scan (reports must not be written into it).
    root: Path | None = None


def is_url(target: str) -> bool:
    return remote.looks_like_url(target)


def load_rule_dirs(rule_dirs: Sequence[str]) -> RuleSet:
    dirs = [Path(d) for d in rule_dirs]
    for directory in dirs:
        if not directory.is_dir():
            raise UsageError(f"rules folder not found: {directory}")
    return load_rules(dirs)


def _prepare(options: ScanOptions) -> tuple[RuleSet, Limits]:
    rules = load_rule_dirs(options.rules)
    unknown = [rule_id for rule_id in options.ignore_rules if rules.get(rule_id) is None]
    if unknown:
        raise UsageError(f"unknown rule id(s) for --ignore-rule: {', '.join(unknown)}")
    limits = Limits(max_file_size=options.max_file_size, skip_env_dirs=not options.include_env_dirs)
    return rules.without(options.ignore_rules), limits


def local_root(target: str) -> Path:
    """The folder named by ``target``; usage errors for anything else."""
    root = Path(target)
    if not root.exists():
        raise UsageError(f"target not found: {target}")
    if not root.is_dir():
        raise UsageError(f"target is not a folder: {target}")
    return root


def github_repo(options: ScanOptions) -> tuple[remote.GitHubRepo, str | None]:
    try:
        repo = remote.parse_github_url(options.target)
        ref = remote.validate_ref(options.ref) if options.ref is not None else None
    except remote.UrlError as exc:
        raise UsageError(str(exc)) from None
    return repo, ref


def scan_local(options: ScanOptions) -> Scanned:
    if options.ref is not None or options.keep_clone:
        raise UsageError("--ref and --keep-clone only apply to URL targets")
    root = local_root(options.target).resolve()
    rules, limits = _prepare(options)
    started, t0 = datetime.now(UTC), time.monotonic()
    coverage = CoverageCollector()
    tree = LocalTree(root, limits, coverage)
    git = gitmeta.open_local(root)
    source = git if isinstance(git, gitmeta.GitSource) else None
    trust = _local_trust(options, root, source)
    try:
        scanned = _analyze(
            tree,
            "local folder",
            rules,
            limits,
            coverage,
            started,
            t0,
            git=source,
            git_note=git if isinstance(git, str) else None,
            trust=trust,
        )
    finally:
        if source is not None:
            source.objects.close()
    scanned.root = root
    return scanned


@contextmanager
def scan_remote(options: ScanOptions, note: Note) -> Iterator[tuple[Scanned, remote.Clone]]:
    """Fetch and scan a GitHub repository; the clone stays open inside the block."""
    repo, ref = github_repo(options)
    rules, limits = _prepare(options)
    started, t0 = datetime.now(UTC), time.monotonic()

    def cleanup(path: Path, error: str | None) -> None:
        if options.keep_clone:
            note(f"clone kept in {path}")
        elif error is not None:
            note(f"could not delete the temporary clone folder {path}: {error}")

    with remote.clone(
        repo,
        ref=ref,
        max_bytes=options.max_clone_size,
        timeout=options.clone_timeout,
        keep=options.keep_clone,
        on_cleanup=cleanup,
    ) as cloned:
        coverage = CoverageCollector()
        tree = GitTree(cloned.objects, cloned.commit, limits, coverage, cloned.label)
        commit = cloned.commit.decode("ascii")
        source: dict[str, object] = {
            "type": "github",
            "url": repo.url,
            "ref": cloned.ref,
            "commit": commit,
        }
        scanned = _analyze(
            tree,
            "GitHub repository",
            rules,
            limits,
            coverage,
            started,
            t0,
            facts={"source": source},
            root_uri=f"{repo.url}/blob/{commit}/",
            git=gitmeta.GitSource(cloned.objects, cloned.commit, "clone"),
            trust=github_target.setup(repo, offline=options.offline, environ=options.environ),
        )
        yield scanned, cloned


def scan(options: ScanOptions, note: Note) -> Scanned:
    """Scan a folder or a GitHub URL."""
    if is_url(options.target):
        with scan_remote(options, note) as (scanned, _clone):
            return scanned
    return scan_local(options)


def _local_trust(
    options: ScanOptions, root: Path, source: gitmeta.GitSource | None
) -> github_target.TrustTarget:
    """A local folder names its GitHub repository only through a remote in
    .git/config. That is a claim; the trust area checks whether HEAD exists there."""
    environ = options.environ
    urls = gitmeta.remote_urls(root)
    name = "origin" if "origin" in urls else (next(iter(urls)) if len(urls) == 1 else None)
    if name is None:
        missing = "no remote 'origin'" if urls else "no Git remote"
        note = f"no GitHub repository is known for this folder ({missing} in .git/config)"
        return github_target.setup(None, offline=options.offline, environ=environ, note=note)
    repo = remote.github_repo_from_remote(urls[name])
    if repo is None:
        note = f"the remote '{name}' in .git/config is not a GitHub repository"
        return github_target.setup(None, offline=options.offline, environ=environ, note=note)
    return github_target.setup(
        repo,
        offline=options.offline,
        environ=environ,
        claimed_by=f"remote '{name}' in .git/config",
        local_head=source.head.decode("ascii") if source is not None else None,
    )


def _analyze(
    tree: FileTree,
    mode: str,
    rules: RuleSet,
    limits: Limits,
    coverage: CoverageCollector,
    started: datetime,
    t0: float,
    *,
    facts: dict[str, object] | None = None,
    root_uri: str | None = None,
    git: gitmeta.GitSource | None = None,
    git_note: str | None = None,
    trust: github_target.TrustTarget | None = None,
) -> Scanned:
    ctx = ScanContext(tree, rules, limits, coverage, git=git, git_note=git_note, trust=trust)
    results = run_all(ctx)
    findings = [f for r in results for f in r.findings]
    all_facts: dict[str, object] = dict(facts or {})
    summaries: dict[str, list[tuple[str, str]]] = {}
    for area_result in results:
        all_facts.update(area_result.facts)
        if area_result.summary:
            category = AREAS[area_result.area].category
            summaries.setdefault(category, []).extend(area_result.summary)
    result = ScanResult(
        target=tree.label,
        mode=mode,
        online=trust is not None and trust.client is not None and trust.client.sent > 0,
        tool_version=__version__,
        rules_loaded=len(rules.active()),
        files_scanned=len(tree.files()),
        started=started,
        duration_s=time.monotonic() - t0,
        findings=findings,
        coverage=coverage.items(),
        facts=all_facts,
        root_uri=root_uri,
        summaries=summaries,
    )
    return Scanned(result, rules)


def fails(result: ScanResult, fail_on: Severity) -> bool:
    """True if a finding is at or above ``fail_on`` (exit code 1)."""
    return any(f.severity >= fail_on for f in result.findings)


def output_path(value: str, root: Path | None) -> Path:
    """Resolve a report file name. The checked folder is never written to, so the file
    must be outside it."""
    path = Path(value).expanduser().resolve()
    if root is not None and _inside(path, root.resolve()):
        raise UsageError(f"output file must be outside the checked folder: {value}")
    if path.is_dir():
        raise UsageError(f"output path is a folder: {value}")
    if not path.parent.is_dir():
        raise UsageError(f"output folder not found: {path.parent}")
    return path


def _inside(path: Path, root: Path) -> bool:
    """True if ``path`` lies in ``root``. Besides comparing the names, every existing
    parent is compared by file identity: on case-insensitive file systems (macOS) the
    same folder can be named in another case, and POSIX paths compare case-sensitively."""
    if path.is_relative_to(root):
        return True
    for parent in path.parents:
        try:
            if parent.samefile(root):
                return True
        except OSError:
            continue
    return False


def write_report(path: Path, report: str) -> None:
    """The only place where repovet writes a report file: the one the user asked for."""
    try:
        with path.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(report)
    except OSError as exc:
        raise UsageError(f"cannot write report to {path}: {exc.strerror or exc}") from None
