"""Check type ``import_ref``: ``@path`` imports (CLAUDE.md, AGENTS.md) that reach outside
the repository, into the home directory, or to secrets.

Imports inside Markdown code spans and code blocks are ignored, as the agents ignore
them. A path escapes the repository when its ``..`` segments climb above the root,
counted from the folder of the file that contains the import.
"""

import re
from collections.abc import Iterator

from repovet.engine.checks.base import BuildEnv, Check, FileView, Match, Params

_IMPORT = re.compile(r"(?<![\w@./\\`-])@([^\s`<>()\[\]{}\"',;|*]+)")
_TRAILING = ".:!?"
_FENCE = re.compile(r" {0,3}(`{3,}|~{3,})")
# Single-backtick spans only: linear, and covers how imports are quoted in practice.
_CODE_SPAN = re.compile(r"`[^`\n]*`")
_HOME = re.compile(
    r"(?:~|\$HOME\b|\$\{HOME\}|%USERPROFILE%|%HOMEPATH%|\$env:USERPROFILE\b)",
    re.IGNORECASE,
)
_ABSOLUTE = re.compile(r"(?:[\\/]|[A-Za-z]:[\\/])")


def markdown_lines(lines: list[str]) -> Iterator[tuple[int, str]]:
    """Lines outside fenced or indented code blocks, with code spans blanked out."""
    fence: str | None = None
    for number, line in enumerate(lines, start=1):
        opener = _FENCE.match(line)
        if fence is not None:
            if opener and opener.group(1)[0] == fence[0] and len(opener.group(1)) >= len(fence):
                fence = None
            continue
        if opener:
            fence = opener.group(1)
            continue
        if line.startswith(("    ", "\t")):
            continue
        yield number, _CODE_SPAN.sub(lambda m: " " * len(m.group(0)), line)


def classify(target: str, file_path: str, secret: re.Pattern[str] | None) -> str | None:
    """Why an import target is a problem, or ``None``."""
    if _HOME.match(target):
        return "home directory"
    if _ABSOLUTE.match(target):
        return "absolute path outside the repository"
    depth = file_path.count("/")
    for segment in re.split(r"[\\/]", target):
        if segment == "..":
            depth -= 1
            if depth < 0:
                return "path outside the repository"
        elif segment not in ("", "."):
            depth += 1
    if secret is not None and secret.search(target):
        return "secret or credential file"
    return None


class ImportRefCheck(Check):
    def __init__(self, secret: re.Pattern[str] | None, skip_code: bool) -> None:
        self.secret = secret
        self.skip_code = skip_code

    def matches(self, view: FileView) -> Iterator[Match]:
        lines = view.lines()
        limit = view.limits.max_line_length
        numbered = markdown_lines(lines) if self.skip_code else enumerate(lines, start=1)
        for number, line in numbered:
            if len(line) > limit:
                view.note_long_lines()
                continue
            for found in _IMPORT.finditer(line):
                target = found.group(1).rstrip(_TRAILING)
                if not target:
                    continue
                reason = classify(target, view.path, self.secret)
                if reason is not None:
                    yield Match(
                        number,
                        found.start() + 1,
                        lines[number - 1],
                        {"match": f"@{target}", "value": reason},
                    )

    def regexes(self) -> list[re.Pattern[str]]:
        return [self.secret] if self.secret is not None else []


def build(params: Params, env: BuildEnv) -> Check:
    secret = params.get_str("secret_regex")
    skip_code = params.get_bool("skip_markdown_code", default=True)
    params.done()
    return ImportRefCheck(env.compile(secret) if secret else None, skip_code)
