"""Command line: argument parsing, orchestration and exit codes.

Exit codes (a stable interface): 0 = no findings at or above --fail-on,
1 = findings at or above --fail-on, 2 = usage error, 3 = analysis aborted.
"""

import argparse
import io
import os
import sys
import time
import traceback
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from repocheck import __version__
from repocheck.analyzers import run_all
from repocheck.engine.context import ScanContext
from repocheck.engine.loader import RuleError, RuleSet, load_rules
from repocheck.github import target as github_target
from repocheck.limits import DEFAULT_LIMITS, Limits, format_size, parse_size
from repocheck.models import AREAS, CoverageCollector, ScanResult, Severity
from repocheck.report import json_out, sarif, terminal
from repocheck.report.sanitize import sanitize
from repocheck.sources import gitmeta, remote
from repocheck.sources.gitobjects import GitObjectError
from repocheck.sources.gittree import GitTree
from repocheck.sources.local import LocalTree
from repocheck.sources.tree import FileTree

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_ABORTED = 3

_LEVELS = [s.label for s in Severity]
FORMATS = ("text", "json", "sarif")


class UsageError(Exception):
    pass


def _size(value: str) -> int:
    try:
        return parse_size(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def _seconds(value: str) -> float:
    try:
        seconds = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid number of seconds: {value!r}") from None
    if not 0 < seconds <= 24 * 3600:
        raise argparse.ArgumentTypeError("seconds must be between 0 and 86400")
    return seconds


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="repocheck",
        description="Statically check an untrusted Git repository before running anything "
        "from it. repocheck never executes code from the repository.",
    )
    parser.add_argument("--version", action="version", version=f"repocheck {__version__}")
    commands = parser.add_subparsers(dest="command", metavar="COMMAND", required=True)

    scan = commands.add_parser("scan", help="check a local folder or a GitHub repository")
    scan.add_argument(
        "target",
        metavar="PATH|URL",
        help=f"folder to check, or a public GitHub repository as {remote.SUPPORTED}",
    )
    scan.add_argument(
        "--offline",
        action="store_true",
        help="no GitHub API queries for the trust area (the analysis itself is always "
        "offline; a URL target is still cloned). An optional token is read from "
        "GITHUB_TOKEN or GH_TOKEN",
    )
    scan.add_argument(
        "--ref",
        metavar="REF",
        help="URL targets: branch, tag or full commit id to check (default: default branch)",
    )
    scan.add_argument(
        "--keep-clone",
        action="store_true",
        help="URL targets: keep the temporary clone folder (its path is printed to stderr)",
    )
    scan.add_argument(
        "--max-clone-size",
        type=_size,
        default=remote.DEFAULT_MAX_CLONE_SIZE,
        metavar="SIZE",
        help=f"URL targets: abort if the download is larger (default: "
        f"{format_size(remote.DEFAULT_MAX_CLONE_SIZE).replace(' ', '')})",
    )
    scan.add_argument(
        "--clone-timeout",
        type=_seconds,
        default=remote.DEFAULT_CLONE_TIMEOUT,
        metavar="SECONDS",
        help=f"URL targets: abort the download after this time "
        f"(default: {remote.DEFAULT_CLONE_TIMEOUT:.0f})",
    )
    scan.add_argument(
        "--min-severity",
        choices=_LEVELS,
        default="info",
        help="hide findings below this level (default: info)",
    )
    scan.add_argument(
        "--fail-on",
        choices=_LEVELS,
        default="high",
        help="exit with 1 if a finding has at least this level (default: high)",
    )
    scan.add_argument(
        "--rules",
        action="append",
        default=[],
        metavar="DIR",
        help="additional rules folder (repeatable)",
    )
    scan.add_argument(
        "--ignore-rule",
        action="append",
        default=[],
        metavar="ID",
        help="do not run this rule (repeatable)",
    )
    scan.add_argument(
        "--max-file-size",
        type=_size,
        default=DEFAULT_LIMITS.max_file_size,
        metavar="SIZE",
        help=f"largest file whose content is checked (default: "
        f"{format_size(DEFAULT_LIMITS.max_file_size).replace(' ', '')})",
    )
    scan.add_argument(
        "--include-env-dirs",
        action="store_true",
        help="also check environment folders (.venv, venv, node_modules, ...), "
        "which are skipped by default",
    )
    scan.add_argument(
        "--format",
        choices=FORMATS,
        default="text",
        help="report format (default: text)",
    )
    scan.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="write the report to FILE instead of stdout (never inside the checked folder)",
    )
    scan.add_argument("--no-color", action="store_true", help="plain output without colors")
    scan.add_argument("-v", "--verbose", action="store_true", help="more detail")

    rules = commands.add_parser("rules", help="inspect the detection rules")
    rules_commands = rules.add_subparsers(dest="rules_command", metavar="ACTION", required=True)
    listing = rules_commands.add_parser("list", help="list the rules")
    listing.add_argument("--area", choices=list(AREAS), help="only rules of this area")
    listing.add_argument("--rules", action="append", default=[], metavar="DIR")
    listing.add_argument(
        "--markdown",
        action="store_true",
        help="Markdown tables grouped by area (used for the rule table in README.md)",
    )
    return parser


def _load(rule_dirs: Sequence[str]) -> RuleSet:
    dirs = [Path(d) for d in rule_dirs]
    for directory in dirs:
        if not directory.is_dir():
            raise UsageError(f"rules folder not found: {directory}")
    return load_rules(dirs)


def _prepare(args: argparse.Namespace) -> tuple[RuleSet, Limits]:
    rules = _load(args.rules)
    unknown = [rule_id for rule_id in args.ignore_rule if rules.get(rule_id) is None]
    if unknown:
        raise UsageError(f"unknown rule id(s) for --ignore-rule: {', '.join(unknown)}")
    limits = Limits(max_file_size=args.max_file_size, skip_env_dirs=not args.include_env_dirs)
    return rules.without(args.ignore_rule), limits


def _scan(args: argparse.Namespace) -> int:
    target: str = args.target
    if remote.looks_like_url(target):
        return _scan_url(args)
    if args.ref is not None or args.keep_clone:
        raise UsageError("--ref and --keep-clone only apply to URL targets")
    root = Path(target)
    if not root.exists():
        raise UsageError(f"target not found: {target}")
    if not root.is_dir():
        raise UsageError(f"target is not a folder: {target}")

    output = _output_path(args.output, root)
    rules, limits = _prepare(args)
    started = datetime.now(UTC)
    t0 = time.monotonic()
    coverage = CoverageCollector()
    tree = LocalTree(root.resolve(), limits, coverage)
    git = gitmeta.open_local(root.resolve())
    source = git if isinstance(git, gitmeta.GitSource) else None
    trust = _local_trust(args, root.resolve(), source)
    try:
        return _analyze(
            args,
            tree,
            "local folder",
            rules,
            limits,
            coverage,
            output,
            started,
            t0,
            git=source,
            git_note=git if isinstance(git, str) else None,
            trust=trust,
        )
    finally:
        if source is not None:
            source.objects.close()


def _scan_url(args: argparse.Namespace) -> int:
    try:
        repo = remote.parse_github_url(args.target)
        ref = remote.validate_ref(args.ref) if args.ref is not None else None
    except remote.UrlError as exc:
        raise UsageError(str(exc)) from None
    output = _output_path(args.output, None)
    rules, limits = _prepare(args)
    started = datetime.now(UTC)
    t0 = time.monotonic()

    def cleanup(path: Path, error: str | None) -> None:
        if args.keep_clone:
            _note(f"clone kept in {path}")
        elif error is not None:
            _note(f"could not delete the temporary clone folder {path}: {error}")

    with remote.clone(
        repo,
        ref=ref,
        max_bytes=args.max_clone_size,
        timeout=args.clone_timeout,
        keep=args.keep_clone,
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
        return _analyze(
            args,
            tree,
            "GitHub repository",
            rules,
            limits,
            coverage,
            output,
            started,
            t0,
            facts={"source": source},
            root_uri=f"{repo.url}/blob/{commit}/",
            git=gitmeta.GitSource(cloned.objects, cloned.commit, "clone"),
            trust=github_target.setup(repo, offline=args.offline, environ=os.environ),
        )


def _local_trust(
    args: argparse.Namespace, root: Path, source: gitmeta.GitSource | None
) -> github_target.TrustTarget:
    """A local folder names its GitHub repository only through a remote in
    .git/config. That is a claim; the trust area checks whether HEAD exists there."""
    urls = gitmeta.remote_urls(root)
    name = "origin" if "origin" in urls else (next(iter(urls)) if len(urls) == 1 else None)
    if name is None:
        missing = "no remote 'origin'" if urls else "no Git remote"
        note = f"no GitHub repository is known for this folder ({missing} in .git/config)"
        return github_target.setup(None, offline=args.offline, environ=os.environ, note=note)
    repo = remote.github_repo_from_remote(urls[name])
    if repo is None:
        note = f"the remote '{name}' in .git/config is not a GitHub repository"
        return github_target.setup(None, offline=args.offline, environ=os.environ, note=note)
    return github_target.setup(
        repo,
        offline=args.offline,
        environ=os.environ,
        claimed_by=f"remote '{name}' in .git/config",
        local_head=source.head.decode("ascii") if source is not None else None,
    )


def _analyze(
    args: argparse.Namespace,
    tree: FileTree,
    mode: str,
    rules: RuleSet,
    limits: Limits,
    coverage: CoverageCollector,
    output: Path | None,
    started: datetime,
    t0: float,
    *,
    facts: dict[str, object] | None = None,
    root_uri: str | None = None,
    git: gitmeta.GitSource | None = None,
    git_note: str | None = None,
    trust: github_target.TrustTarget | None = None,
) -> int:
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
    min_severity = Severity.parse(args.min_severity)
    if args.format == "json":
        report = json_out.render(result, min_severity=min_severity)
    elif args.format == "sarif":
        report = sarif.render(result, rules.active(), min_severity=min_severity)
    else:
        to_terminal = output is None
        use_color = (
            to_terminal
            and not args.no_color
            and not os.environ.get("NO_COLOR")
            and terminal.enable_color()
        )
        report = terminal.render(
            result,
            color=use_color,
            min_severity=min_severity,
            verbose=args.verbose,
            unicode=not to_terminal or terminal.supports_unicode(),
        )
    if output is None:
        sys.stdout.write(report)
    else:
        _write_report(output, report)
    fail_on = Severity.parse(args.fail_on)
    return EXIT_FINDINGS if any(f.severity >= fail_on for f in findings) else EXIT_OK


def _output_path(value: str | None, root: Path | None) -> Path | None:
    """Resolve ``-o``. The checked folder is never written to, so the report file must
    be outside it."""
    if value is None:
        return None
    path = Path(value).resolve()
    if root is not None and path.is_relative_to(root.resolve()):
        raise UsageError(f"output file must be outside the checked folder: {value}")
    if path.is_dir():
        raise UsageError(f"output path is a folder: {value}")
    if not path.parent.is_dir():
        raise UsageError(f"output folder not found: {path.parent}")
    return path


def _write_report(path: Path, report: str) -> None:
    """The only place where repocheck writes a file: the report the user asked for."""
    try:
        with path.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(report)
    except OSError as exc:
        raise UsageError(f"cannot write report to {path}: {exc.strerror or exc}") from None


def _rules_markdown(rules: RuleSet, area: str | None) -> str:
    blocks: list[str] = []
    for info in AREAS.values():
        selected = sorted(
            (r for r in rules.rules if r.area == info.name and area in (None, info.name)),
            key=lambda r: r.id,
        )
        if not selected:
            continue
        lines = [
            f"#### {info.label[:1].upper()}{info.label[1:]} (`{info.name}`, {len(selected)} rules)",
            "",
            "| ID | Severity | Description |",
            "|----|----------|-------------|",
        ]
        for rule in selected:
            title = sanitize(rule.title, None).replace("|", "\\|")
            flag = " (deprecated)" if rule.deprecated else ""
            lines.append(f"| {rule.id} | {rule.severity.label} | {title}{flag} |")
        blocks.append("\n".join(lines) + "\n")
    return "\n".join(blocks)


def _rules_list(args: argparse.Namespace) -> int:
    rules = _load(args.rules)
    if args.markdown:
        sys.stdout.write(_rules_markdown(rules, args.area))
        return EXIT_OK
    for rule in rules.rules:
        if args.area and rule.area != args.area:
            continue
        flag = " (deprecated)" if rule.deprecated else ""
        sys.stdout.write(
            f"{rule.id:<14} {rule.severity.label:<9} {rule.area:<14} "
            f"{sanitize(rule.title, None)}{flag}\n"
        )
    return EXIT_OK


def _configure_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper):
            stream.reconfigure(errors="backslashreplace")


def _error(message: str) -> None:
    sys.stderr.write(f"repocheck: error: {sanitize(message, None)}\n")


def _note(message: str) -> None:
    sys.stderr.write(f"repocheck: {sanitize(message, None)}\n")


def main(argv: Sequence[str] | None = None) -> int:
    _configure_stdio()
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:  # argparse: --help/--version (0) or invalid arguments (2)
        return exc.code if isinstance(exc.code, int) else EXIT_USAGE
    try:
        if args.command == "scan":
            return _scan(args)
        return _rules_list(args)
    except (UsageError, RuleError) as exc:
        _error(str(exc))
        return EXIT_USAGE
    except (remote.CloneError, GitObjectError) as exc:
        _error(f"analysis aborted: {exc}")
        return EXIT_ABORTED
    except KeyboardInterrupt:
        _error("interrupted")
        return EXIT_ABORTED
    except Exception as exc:
        _error(f"internal error, analysis aborted: {type(exc).__name__}: {exc}")
        if getattr(args, "verbose", False):
            for line in traceback.format_exc().splitlines():
                sys.stderr.write(sanitize(line, None) + "\n")
        return EXIT_ABORTED
