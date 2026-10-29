"""Command line: argument parsing, the commands and exit codes.

Exit codes (a stable interface): 0 = no findings at or above --fail-on,
1 = findings at or above --fail-on, 2 = usage error, 3 = analysis aborted.
``repovet clone`` returns the result of its scan (0 or 1) whether or not it cloned;
without a terminal, 1 always means that nothing was cloned.
"""

import argparse
import io
import os
import sys
import traceback
from collections.abc import Sequence
from pathlib import Path

from repovet import __version__, interactive
from repovet.engine.loader import RuleError, RuleSet
from repovet.limits import DEFAULT_LIMITS, format_size, parse_size
from repovet.models import AREAS, Severity
from repovet.report import formats, terminal
from repovet.report.formats import FORMATS
from repovet.report.sanitize import sanitize, sanitize_path
from repovet.scanning import (
    Scanned,
    ScanOptions,
    UsageError,
    fails,
    github_repo,
    is_url,
    load_rule_dirs,
    local_root,
    output_path,
    scan_local,
    scan_remote,
    write_report,
)
from repovet.sources import checkout, remote
from repovet.sources.gitobjects import GitObjectError

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_ABORTED = 3

_LEVELS = [s.label for s in Severity]

__all__ = ["EXIT_ABORTED", "EXIT_FINDINGS", "EXIT_OK", "EXIT_USAGE", "UsageError", "main"]


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


def _common_options() -> argparse.ArgumentParser:
    """Options that ``scan`` and ``clone`` share."""
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--offline",
        action="store_true",
        help="no GitHub API queries for the trust area (the analysis itself is always "
        "offline; a URL target is still cloned). An optional token is read from "
        "GITHUB_TOKEN or GH_TOKEN",
    )
    common.add_argument(
        "--ref",
        metavar="REF",
        help="URL targets: branch, tag or full commit id to check (default: default branch)",
    )
    common.add_argument(
        "--max-clone-size",
        type=_size,
        default=remote.DEFAULT_MAX_CLONE_SIZE,
        metavar="SIZE",
        help=f"URL targets: abort if the download is larger (default: "
        f"{format_size(remote.DEFAULT_MAX_CLONE_SIZE).replace(' ', '')})",
    )
    common.add_argument(
        "--clone-timeout",
        type=_seconds,
        default=remote.DEFAULT_CLONE_TIMEOUT,
        metavar="SECONDS",
        help=f"URL targets: abort the download after this time "
        f"(default: {remote.DEFAULT_CLONE_TIMEOUT:.0f})",
    )
    common.add_argument(
        "--min-severity",
        choices=_LEVELS,
        default="info",
        help="hide findings below this level (default: info)",
    )
    common.add_argument(
        "--fail-on",
        choices=_LEVELS,
        default="high",
        help="exit with 1 if a finding has at least this level (default: high)",
    )
    common.add_argument(
        "--rules",
        action="append",
        default=[],
        metavar="DIR",
        help="additional rules folder (repeatable)",
    )
    common.add_argument(
        "--ignore-rule",
        action="append",
        default=[],
        metavar="ID",
        help="do not run this rule (repeatable)",
    )
    common.add_argument(
        "--max-file-size",
        type=_size,
        default=DEFAULT_LIMITS.max_file_size,
        metavar="SIZE",
        help=f"largest file whose content is checked (default: "
        f"{format_size(DEFAULT_LIMITS.max_file_size).replace(' ', '')})",
    )
    common.add_argument(
        "--include-env-dirs",
        action="store_true",
        help="also check environment folders (.venv, venv, node_modules, ...), "
        "which are skipped by default",
    )
    common.add_argument(
        "--no-color",
        action="store_true",
        help="plain output without colors (NO_COLOR does the same; FORCE_COLOR keeps "
        "colors when the output is piped, for example into a pager)",
    )
    common.add_argument("-v", "--verbose", action="store_true", help="more detail")
    return common


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="repovet",
        description="Statically check an untrusted Git repository before running anything "
        "from it. repovet never executes code from the repository. Run it without "
        "arguments in a terminal for a menu.",
    )
    parser.add_argument("--version", action="version", version=f"repovet {__version__}")
    commands = parser.add_subparsers(dest="command", metavar="COMMAND", required=True)
    common = _common_options()

    scan = commands.add_parser(
        "scan", parents=[common], help="check a local folder or a GitHub repository"
    )
    scan.add_argument(
        "target",
        metavar="PATH|URL",
        help=f"folder to check, or a public GitHub repository as {remote.SUPPORTED}",
    )
    scan.add_argument(
        "--keep-clone",
        action="store_true",
        help="URL targets: keep the temporary clone folder (its path is printed to stderr)",
    )
    scan.add_argument(
        "--format",
        choices=FORMATS,
        default="text",
        help="report format (default: text); html is one self-contained file without "
        "scripts or external resources",
    )
    scan.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="write the report to FILE instead of stdout (never inside the checked folder)",
    )
    scan.add_argument(
        "--details",
        action="store_true",
        help="text report: explain every finding (Why/Do; by default only critical and "
        "high) and list every place of grouped findings",
    )

    clone = commands.add_parser(
        "clone",
        parents=[common],
        help="check a GitHub repository, then clone it if you agree",
        description="Check a GitHub repository first, show the summary and ask before "
        "cloning. The clone is written from the checked Git objects: no hooks, filters, "
        "LFS or submodules, and no symbolic links.",
    )
    clone.add_argument("url", metavar="URL", help=f"repository as {remote.SUPPORTED}")
    clone.add_argument(
        "directory",
        metavar="DIR",
        nargs="?",
        help="folder to clone into; must not exist or be empty (default: the repository name)",
    )
    clone.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="clone without asking, but only if no finding is at or above --fail-on",
    )

    rules = commands.add_parser("rules", help="inspect the detection rules")
    rules_commands = rules.add_subparsers(dest="rules_command", metavar="ACTION", required=True)
    listing = rules_commands.add_parser("list", help="list the rules")
    listing.add_argument("--area", choices=list(AREAS), help="only rules of this area")
    listing.add_argument("--rules", action="append", default=[], metavar="DIR")
    listing.add_argument(
        "--markdown",
        action="store_true",
        help="Markdown tables grouped by area (used for RULES.md)",
    )
    return parser


def _options(args: argparse.Namespace, target: str) -> ScanOptions:
    return ScanOptions(
        target,
        offline=args.offline,
        ref=args.ref,
        keep_clone=getattr(args, "keep_clone", False),
        max_clone_size=args.max_clone_size,
        clone_timeout=args.clone_timeout,
        rules=args.rules,
        ignore_rules=args.ignore_rule,
        max_file_size=args.max_file_size,
        include_env_dirs=args.include_env_dirs,
        environ=dict(os.environ),
    )


def _scan(args: argparse.Namespace) -> int:
    options = _options(args, args.target)
    if is_url(args.target):
        github_repo(options)  # usage errors before anything else
        output = None if args.output is None else output_path(args.output, None)
        with scan_remote(options, _note) as (scanned, _clone):
            return _emit(args, scanned, output)
    root = local_root(args.target)
    output = None if args.output is None else output_path(args.output, root)
    return _emit(args, scan_local(options), output)


def _emit(args: argparse.Namespace, scanned: Scanned, output: Path | None) -> int:
    to_terminal = output is None
    use_color = (
        args.format == "text"
        and to_terminal
        and not args.no_color
        and terminal.color_wanted(os.environ)
    )
    report = formats.render(
        args.format,
        scanned.result,
        scanned.rules.active(),
        min_severity=Severity.parse(args.min_severity),
        color=use_color,
        verbose=args.verbose,
        details=args.details,
        unicode=not to_terminal or terminal.supports_unicode(),
    )
    if output is None:
        sys.stdout.write(report)
    else:
        write_report(output, report)
    return EXIT_FINDINGS if fails(scanned.result, Severity.parse(args.fail_on)) else EXIT_OK


def _confirm(prompt: str) -> bool:
    sys.stdout.write(prompt)
    sys.stdout.flush()
    answer = sys.stdin.readline()
    if not answer:
        sys.stdout.write("\n")
    return answer.strip().lower() in ("y", "yes")


def _clone(args: argparse.Namespace) -> int:
    options = _options(args, args.url)
    repo, _ref = github_repo(options)
    dest = Path(args.directory if args.directory else repo.name)
    try:
        checkout.check_destination(dest)
    except checkout.CheckoutError as exc:
        raise UsageError(str(exc)) from None
    fail_on = Severity.parse(args.fail_on)
    asking = interactive.can_ask(sys.stdin, os.environ)
    with scan_remote(options, _note) as (scanned, cloned):
        result = scanned.result
        color = not args.no_color and terminal.color_wanted(os.environ)
        sys.stdout.write(
            terminal.render_summary(
                result,
                color=color,
                min_severity=Severity.parse(args.min_severity),
                unicode=terminal.supports_unicode(),
            )
        )
        commit = cloned.commit.decode("ascii")
        sys.stdout.write(f"Full report: repovet scan {repo.url} --ref {commit}\n\n")
        code = EXIT_FINDINGS if fails(result, fail_on) else EXIT_OK
        if code == EXIT_FINDINGS and not asking:
            _note(f"not cloned: findings at or above '{fail_on.label}' (--fail-on)")
            return code
        if args.yes and code == EXIT_OK:
            confirmed = True
        elif asking:
            confirmed = _confirm("Clone anyway? [y/N] ")
        else:
            _note("not cloned: no terminal to confirm; use --yes")
            return code
        if not confirmed:
            _note("clone declined; nothing was written")
            return code
        written = checkout.write(
            cloned.objects,
            cloned.commit,
            cloned.workspace / "objects" / "pack",
            dest,
            url=repo.url,
            ref=cloned.full_ref,
        )
    _report_clone(dest, written)
    return code


def _report_clone(dest: Path, written: checkout.Written) -> None:
    where = sanitize_path(str(dest))
    branch = f"branch {written.branch}" if written.branch else "detached HEAD"
    sys.stdout.write(
        f"Cloned into {where}: {written.files:,} files, {format_size(written.bytes)} ({branch}).\n"
    )
    for label, paths in (
        ("Symbolic links not created", written.links),
        ("Submodules not fetched", written.submodules),
    ):
        if paths:
            shown = ", ".join(sanitize_path(p) for p in paths[:10])
            more = f", ... (+{len(paths) - 10})" if len(paths) > 10 else ""
            sys.stdout.write(f"{label} ({len(paths)}): {shown}{more}\n")
    sys.stdout.write(
        "Nothing was run. Read the findings before you run, build or install anything "
        "from it, or open it in an editor that trusts the folder.\n"
    )


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
    rules = load_rule_dirs(args.rules)
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
    sys.stderr.write(f"repovet: error: {sanitize(message, None)}\n")


def _note(message: str) -> None:
    sys.stderr.write(f"repovet: {sanitize(message, None)}\n")


def main(argv: Sequence[str] | None = None) -> int:
    _configure_stdio()
    arguments = sys.argv[1:] if argv is None else list(argv)
    if not arguments and interactive.wanted(sys.stdin, sys.stdout, os.environ):
        try:
            return interactive.run(sys.stdin, sys.stdout, os.environ)
        except KeyboardInterrupt:
            sys.stdout.write("\n")
            _error("interrupted")
            return EXIT_ABORTED
    parser = build_parser()
    try:
        args = parser.parse_args(arguments)
    except SystemExit as exc:  # argparse: --help/--version (0) or invalid arguments (2)
        return exc.code if isinstance(exc.code, int) else EXIT_USAGE
    try:
        if args.command == "scan":
            return _scan(args)
        if args.command == "clone":
            return _clone(args)
        return _rules_list(args)
    except (UsageError, RuleError) as exc:
        _error(str(exc))
        return EXIT_USAGE
    except (remote.CloneError, GitObjectError) as exc:
        _error(f"analysis aborted: {exc}")
        return EXIT_ABORTED
    except checkout.CheckoutError as exc:
        _error(f"clone aborted, nothing kept: {exc}")
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
