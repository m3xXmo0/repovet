"""Human-readable terminal report.

Compact by default: a summary box with the counts per severity and the findings to look
at first, findings of the same rule and message grouped (one explanation, a list of
places), and Why/Do only for critical and high findings. ``details=True`` explains every
finding and lists every place.
"""

import codecs
import sys
import textwrap
from collections.abc import Mapping, Sequence

from repovet.models import CATEGORIES, CoverageItem, Finding, ScanResult, Severity
from repovet.report.common import (
    Group,
    disclaimer,
    group_findings,
    no_findings,
    severity_counts,
    top_groups,
    visible_findings,
)
from repovet.report.sanitize import ELLIPSIS, sanitize, sanitize_path

__all__ = [
    "color_wanted",
    "disclaimer",
    "enable_color",
    "no_findings",
    "render",
    "render_finding",
    "render_summary",
    "supports_unicode",
]

WIDTH = 79
INDENT = " " * 12
PROFILE_LABEL = 11
PROFILE_NOTE = "facts, not findings"
# Places listed per group before "+N more" (all of them with details).
PLACES = 5
_RESET = "\x1b[0m"
_STYLES = {
    Severity.CRITICAL: "\x1b[1;91m",
    Severity.HIGH: "\x1b[91m",
    Severity.MEDIUM: "\x1b[93m",
    Severity.LOW: "\x1b[96m",
    Severity.INFO: "\x1b[2m",
}
_BOLD = "\x1b[1m"
_DIM = "\x1b[2m"

UNTRUSTED_NOTE = "Lines starting with '>' are untrusted content quoted from the repository."
DETAILS_NOTE = "Why/Do for medium, low and info findings and all places: --details"
SEPARATOR = " · "
ASCII_SEPARATOR = " | "
ASCII_ELLIPSIS = "..."
# Box drawing: top-left, top-right, bottom-left, bottom-right, horizontal, vertical.
_BOX = "┌┐└┘─│"
_ASCII_BOX = "++++-|"


class _Style:
    def __init__(self, color: bool) -> None:
        self.color = color

    def __call__(self, code: str, text: str) -> str:
        return f"{code}{text}{_RESET}" if self.color else text


def _location(finding: Finding) -> str:
    loc = finding.location
    if loc is None:
        return "(repository)"
    path = sanitize_path(loc.path)
    place = f"{path}:{loc.line}" if loc.line else path
    return f"{place} [{finding.context}]" if finding.context else place


def _wrap(label: str, text: str) -> list[str]:
    return textwrap.wrap(
        sanitize(text, None),
        WIDTH,
        initial_indent=f"{INDENT}{label:<5}",
        subsequent_indent=f"{INDENT}     ",
        break_on_hyphens=False,
    )


def _head(finding: Finding, where: str, style: _Style) -> str:
    severity = finding.severity.label.upper()
    head = f"  {style(_STYLES[finding.severity], f'{severity:<9}')} {finding.rule_id:<13} "
    confidence = f"confidence {finding.confidence.label}"
    plain_len = 2 + 10 + 14 + len(where)
    gap = max(2, WIDTH - plain_len - len(confidence))
    return f"{head}{where}{' ' * gap}{style(_DIM, confidence)}"


def _group(group: Group, style: _Style, details: bool) -> list[str]:
    first = group.first
    single = len(group.findings) == 1
    where = _location(first) if single else f"{len(group.findings)} places"
    lines = [_head(first, where, style)]
    lines += textwrap.wrap(
        sanitize(first.message, None),
        WIDTH,
        initial_indent=INDENT,
        subsequent_indent=INDENT,
        break_on_hyphens=False,
    )
    if single:
        if first.evidence:
            lines.append(style(_DIM, f"{INDENT}> {sanitize(first.evidence)}"))
    else:
        shown = group.findings if details else group.findings[:PLACES]
        for finding in shown:
            lines.append(f"{INDENT}- {_location(finding)}")
            if finding.evidence:
                lines.append(style(_DIM, f"{INDENT}  > {sanitize(finding.evidence)}"))
        if len(group.findings) > len(shown):
            lines.append(f"{INDENT}+{len(group.findings) - len(shown)} more")
    if details or group.explained:
        lines += _wrap("Why", first.rationale)
        lines += _wrap("Do", first.recommendation)
    return lines


def render_finding(finding: Finding, *, color: bool = False) -> str:
    """One finding with everything: place, message, quoted evidence, Why, Do and
    references (the interactive mode's detail view)."""
    style = _Style(color)
    lines = _group(Group([finding]), style, details=True)
    lines += [f"{INDENT}See  {sanitize(ref, None)}" for ref in finding.references]
    return "\n".join(lines) + "\n"


def _profile(category: str, lines: list[tuple[str, str]], style: _Style) -> list[str]:
    out = [style(_BOLD, f"{category.upper() + ' PROFILE':<40} ") + style(_DIM, PROFILE_NOTE)]
    for label, text in lines:
        out += textwrap.wrap(
            sanitize(text, None),
            WIDTH,
            initial_indent=f"  {label:<{PROFILE_LABEL}}",
            subsequent_indent=" " * (PROFILE_LABEL + 2),
            break_on_hyphens=False,
            break_long_words=False,
        )
    out.append("")
    return out


def _coverage(item: CoverageItem, verbose: bool) -> list[str]:
    text = sanitize(item.reason, None)
    if not item.sample:
        text = f"{text} ({item.count})" if item.count > 1 else text
    else:
        shown = item.sample if verbose else item.sample[:3]
        sample = ", ".join(sanitize_path(p) for p in shown)
        more = f", {ELLIPSIS}" if item.count > len(shown) else ""
        text = f"{text} ({item.count}): {sample}{more}"
    return textwrap.wrap(
        text,
        WIDTH,
        initial_indent="  - ",
        subsequent_indent="    ",
        break_on_hyphens=False,
        break_long_words=False,
    )


def _clip(text: str, width: int) -> str:
    return text if len(text) <= width else text[: width - 1] + ELLIPSIS


def _box(rows: Sequence[tuple[str, str]], title: str, unicode: bool) -> list[str]:
    """A box around ``rows`` of (plain, styled) text; the plain text sets the padding."""
    chars = _BOX if unicode else _ASCII_BOX
    tl, tr, bl, br, h, v = (chars[i] for i in range(6))
    inner = WIDTH - 4
    top = f"{tl}{h} {title} "
    lines = [top + h * (WIDTH - len(top) - 1) + tr]
    for plain, styled in rows:
        lines.append(f"{v} {styled}{' ' * (inner - len(plain))} {v}")
    lines.append(bl + h * (WIDTH - 2) + br)
    return lines


def _summary_rows(
    visible: Sequence[Finding], groups: Sequence[Group], style: _Style, sep: str
) -> list[tuple[str, str]]:
    counts = severity_counts(visible)
    plain = sep.join(f"{n} {s.label}" for s, n in counts)
    styled = sep.join(
        style(_STYLES[s], f"{n} {s.label}") if n else f"{n} {s.label}" for s, n in counts
    )
    rows = [(plain, styled)]
    first = top_groups(groups)
    if not visible:
        return rows
    rows.append(("", ""))
    if not first:
        only_info = "Only info findings: facts worth knowing, no warnings."
        rows.append((only_info, only_info))
        return rows
    rows.append(("Look at these first", style(_BOLD, "Look at these first")))
    inner = WIDTH - 4
    for number, group in enumerate(first, 1):
        finding = group.first
        level = f"{finding.severity.label.upper():<9}"
        where = _location(finding) if len(group.findings) == 1 else f"{len(group.findings)} places"
        lead = f"{number}. {level} {finding.rule_id:<13} "
        where = _clip(where, inner - len(lead))
        styled = f"{number}. {style(_STYLES[finding.severity], level)} {finding.rule_id:<13} "
        rows.append((f"{lead}{where}", f"{styled}{where}"))
        title = _clip(f"   {sanitize(finding.title, None)}", inner)
        rows.append((title, title))
    return rows


def render_summary(
    result: ScanResult,
    *,
    color: bool = False,
    min_severity: Severity = Severity.INFO,
    unicode: bool = True,
) -> str:
    """Header line and summary box only (used by ``repovet clone`` before it asks)."""
    style = _Style(color)
    sep = SEPARATOR if unicode else ASCII_SEPARATOR
    visible = visible_findings(result, min_severity)
    lines = [_header(result, sep)]
    lines += _box(_summary_rows(visible, group_findings(visible), style, sep), "SUMMARY", unicode)
    text = "\n".join(lines) + "\n"
    return text if unicode else text.replace(ELLIPSIS, ASCII_ELLIPSIS)


def _header(result: ScanResult, sep: str) -> str:
    online = "online" if result.online else "offline"
    return sep.join(
        [
            f"repovet {result.tool_version}",
            f"{result.mode} {sanitize_path(result.target)}",
            online,
            f"{result.files_scanned:,} files",
            f"{result.rules_loaded} rules",
        ]
    )


def render(
    result: ScanResult,
    *,
    color: bool = False,
    min_severity: Severity = Severity.INFO,
    verbose: bool = False,
    details: bool = False,
    unicode: bool = True,
) -> str:
    """Render the report. ``unicode=False`` uses ASCII for repovet's own decorations
    (box, separator, ellipsis), for consoles that do not use a UTF encoding."""
    style = _Style(color)
    sep = SEPARATOR if unicode else ASCII_SEPARATOR
    visible = visible_findings(result, min_severity)
    hidden = len(result.findings) - len(visible)
    groups = group_findings(visible)
    lines = [_header(result, sep)]
    if any(f.evidence for f in visible):
        lines.append(style(_DIM, UNTRUSTED_NOTE))
    lines.append("")
    lines += _box(_summary_rows(visible, groups, style, sep), "SUMMARY", unicode)
    lines.append("")

    if visible:
        for category in CATEGORIES:
            in_category = [g for g in groups if g.first.category == category]
            if not in_category:
                continue
            found = [f for g in in_category for f in g.findings]
            counts = sep.join(f"{n} {s.label}" for s, n in severity_counts(found) if n)
            lines.append(style(_BOLD, f"{category.upper():<40} {counts}"))
            for group in in_category:
                lines += _group(group, style, details)
                lines.append("")
        if not details and any(not g.explained for g in groups):
            lines.append(style(_DIM, DETAILS_NOTE))
            lines.append("")
    else:
        lines.append(no_findings(result.rules_loaded))
        lines.append("")
    if hidden:
        lines.append(
            f"{hidden} finding(s) below '{min_severity.label}' not shown (--min-severity)."
        )
        lines.append("")

    for category in CATEGORIES:
        if result.summaries.get(category):
            lines += _profile(category, result.summaries[category], style)

    lines.append(style(_BOLD, "NOT CHECKED"))
    if result.coverage:
        for item in result.coverage:
            lines += _coverage(item, verbose)
    else:
        lines.append("  - nothing recorded")
    lines.append("")
    if visible:
        lines += disclaimer(result.rules_loaded)
    text = "\n".join(lines).rstrip("\n") + "\n"
    return text if unicode else text.replace(ELLIPSIS, ASCII_ELLIPSIS)


def supports_unicode(stream: object = None) -> bool:
    """True if ``stream`` (default: stdout) encodes text as UTF-8/16/32.

    Other encodings (for example cp1252 or cp850 when output is redirected on Windows)
    may turn decorations like '·' into replacement characters on the reading side.
    """
    out = sys.stdout if stream is None else stream
    encoding = getattr(out, "encoding", None)
    if not isinstance(encoding, str) or not encoding:
        return False
    try:
        return codecs.lookup(encoding).name.startswith("utf")
    except LookupError:
        return False


def color_wanted(environ: Mapping[str, str], stream: object = None) -> bool:
    """Color decision for a report on ``stream`` (default: stdout).

    A non-empty NO_COLOR turns colors off (no-color.org). Otherwise a non-empty
    FORCE_COLOR turns them on even when the output is not a terminal, for example when
    it is piped into a pager (force-color.org). Otherwise colors are used on terminals
    that support them.
    """
    if environ.get("NO_COLOR"):
        return False
    if environ.get("FORCE_COLOR"):
        enable_color(stream)  # switches on VT processing if stream is a Windows console
        return True
    return enable_color(stream)


def enable_color(stream: object = None) -> bool:
    """True if ANSI colors can be used on ``stream`` (default: stdout)."""
    out = sys.stdout if stream is None else stream
    isatty = getattr(out, "isatty", None)
    if not callable(isatty) or not isatty():
        return False
    if sys.platform == "win32":
        return _enable_windows_vt()
    else:  # explicit branch: mypy checks reachability per platform
        return True


def _enable_windows_vt() -> bool:
    # if/else instead of an early return: mypy checks reachability per platform.
    if sys.platform == "win32":
        import ctypes  # noqa: PLC0415 - Windows only
        from ctypes import wintypes  # noqa: PLC0415

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = wintypes.DWORD()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        enable_vt = 0x0004  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        if mode.value & enable_vt:
            return True
        return bool(kernel32.SetConsoleMode(handle, mode.value | enable_vt))
    else:  # pragma: no cover - ctypes.windll exists only on Windows
        return False
