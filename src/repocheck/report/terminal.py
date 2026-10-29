"""Human-readable terminal report."""

import codecs
import sys
import textwrap

from repocheck.models import CATEGORIES, CoverageItem, Finding, ScanResult, Severity
from repocheck.report.common import disclaimer, no_findings, visible_findings
from repocheck.report.sanitize import ELLIPSIS, sanitize, sanitize_path

__all__ = ["disclaimer", "enable_color", "no_findings", "render", "supports_unicode"]

WIDTH = 79
INDENT = " " * 12
PROFILE_LABEL = 11
PROFILE_NOTE = "facts, not findings"
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
SEPARATOR = " · "
ASCII_SEPARATOR = " | "
ASCII_ELLIPSIS = "..."


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
    return f"{path}:{loc.line}" if loc.line else path


def _wrap(label: str, text: str) -> list[str]:
    return textwrap.wrap(
        sanitize(text, None),
        WIDTH,
        initial_indent=f"{INDENT}{label:<5}",
        subsequent_indent=f"{INDENT}     ",
        break_on_hyphens=False,
    )


def _finding(finding: Finding, style: _Style) -> list[str]:
    severity = finding.severity.label.upper()
    head = f"  {style(_STYLES[finding.severity], f'{severity:<9}')} {finding.rule_id:<13} "
    location = _location(finding)
    confidence = f"confidence {finding.confidence.label}"
    plain_len = 2 + 10 + 14 + len(location)
    gap = max(2, WIDTH - plain_len - len(confidence))
    lines = [f"{head}{location}{' ' * gap}{style(_DIM, confidence)}"]
    lines += textwrap.wrap(
        sanitize(finding.message, None),
        WIDTH,
        initial_indent=INDENT,
        subsequent_indent=INDENT,
        break_on_hyphens=False,
    )
    if finding.evidence:
        lines.append(style(_DIM, f"{INDENT}> {sanitize(finding.evidence)}"))
    lines += _wrap("Why", finding.rationale)
    lines += _wrap("Do", finding.recommendation)
    return lines


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


def render(
    result: ScanResult,
    *,
    color: bool = False,
    min_severity: Severity = Severity.INFO,
    verbose: bool = False,
    unicode: bool = True,
) -> str:
    """Render the report. ``unicode=False`` uses ASCII for repocheck's own decorations
    (separator, ellipsis), for consoles that do not use a UTF encoding."""
    style = _Style(color)
    sep = SEPARATOR if unicode else ASCII_SEPARATOR
    visible = visible_findings(result, min_severity)
    hidden = len(result.findings) - len(visible)
    online = "online" if result.online else "offline"
    header = [
        f"repocheck {result.tool_version}",
        f"{result.mode} {sanitize_path(result.target)}",
        online,
        f"{result.files_scanned:,} files",
        f"{result.rules_loaded} rules",
    ]
    lines = [sep.join(header)]
    if any(f.evidence for f in visible):
        lines.append(style(_DIM, UNTRUSTED_NOTE))
    lines.append("")

    if visible:
        for category in CATEGORIES:
            group = [f for f in visible if f.category == category]
            if not group:
                continue
            counts = sep.join(
                f"{sum(1 for f in group if f.severity == s)} {s.label}"
                for s in sorted(Severity, reverse=True)
                if any(f.severity == s for f in group)
            )
            lines.append(style(_BOLD, f"{category.upper():<40} {counts}"))
            for finding in group:
                lines += _finding(finding, style)
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
