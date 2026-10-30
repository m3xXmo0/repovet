"""Chains from auto-run entry points to dangerous code in other files of the repository.

An entry point (a VS Code task that runs on folder open, a dev container command, an
npm install script) often only starts a file of the repository, and the dangerous line
is in that file. This module follows such references for at most two files after the
entry point. Every file reached is checked with the rules of the endpoint areas, also
those whose file patterns would skip it (a script without an extension, a script in a
test folder). For each entry point whose path reaches a finding of medium or above, one
chain finding is reported; the findings of the entry point and of the files on the path
are kept but marked as part of the chain, so that they are not counted twice.

What is followed: the first word of a command (``./setup.sh``), the file given to an
interpreter (``bash x.sh``, ``node x.js``, ``python x.py``, ``pwsh -File x.ps1``), the
target of ``make`` (its recipe and prerequisites in the Makefile) and ``npm run NAME``
(the script in package.json). Commands in reached files are their lines (shell, batch,
PowerShell) or their string literals (JavaScript, TypeScript, Python). Paths are
resolved relative to the folder the command runs in (and to the folder of the file that
names them), must stay inside the repository, are never in vendored folders and are
never links (links are not part of the file tree). A file already on the path is not
followed again. Nothing is run.
"""

import posixpath
import re
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, replace

from repovet.engine.checks.base import FileView, Match
from repovet.engine.checks.blob import BlobCheck
from repovet.engine.checks.chain import ChainCheck, EntryKind
from repovet.engine.checks.regex import RegexCheck, logical_lines
from repovet.engine.checks.split_payload import SplitPayloadCheck
from repovet.engine.checks.unicode import UnicodeCheck
from repovet.engine.context import ScanContext
from repovet.engine.loader import Rule
from repovet.engine.runner import make_finding, rule_findings
from repovet.models import AREAS, AreaResult, Chain, Finding, Location, Severity
from repovet.parsers.codelex import family_of, literal_spans
from repovet.sources.tree import GlobSet, RepoFile, basename

_TASKS = GlobSet(["**/.vscode/tasks.json"])
_DEVCONTAINER = GlobSet(
    [
        "**/.devcontainer/devcontainer.json",
        "**/.devcontainer.json",
        "**/.devcontainer/*/devcontainer.json",
    ]
)
_PACKAGE = GlobSet(["**/package.json"])
_INSTALL_SCRIPTS = ("preinstall", "install", "postinstall", "prepare")
_CONTAINER_COMMANDS = (
    "onCreateCommand",
    "updateContentCommand",
    "postCreateCommand",
    "postStartCommand",
    "postAttachCommand",
)
_MAKEFILES = ("GNUmakefile", "makefile", "Makefile")
_SCRIPT_EXTENSIONS = {"js", "mjs", "cjs", "ts", "mts", "cts", "py", "pyw"}
# Commands are split at these separators; a pipe ends a command too.
_SEPARATORS = re.compile(r"&&|\|\||[;&|\n]")
_TOKEN = re.compile(r"\"[^\"\n]*\"|'[^'\n]*'|[^\s\"']+")
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=\S*")
_PREFIXES = {"sudo", "exec", "env", "nohup", "time", "command", "call", "start", "/b", "nice"}
_INTERPRETERS = {
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "fish",
    "node",
    "nodejs",
    "bun",
    "deno",
    "tsx",
    "ts-node",
    "python",
    "python2",
    "python3",
    "py",
    "perl",
    "ruby",
    "php",
    "pwsh",
    "powershell",
    "cmd",
    "source",
    ".",
    "cscript",
    "wscript",
}
# Options after which the next token is code, not a file.
_INLINE = {"-c", "-e", "/c", "/k", "-command", "-encodedcommand"}
_WORKSPACE = re.compile(
    r"\$\{(?:workspaceFolder|workspaceRoot|localWorkspaceFolder|containerWorkspaceFolder)\}"
    r"|\$\{?PWD\}?|%CD%"
)
_SCRIPT_DIR = re.compile(r"\$\(dirname[ \t]+\"?\$0\"?\)|\$\{0%/\*\}|%~dp0")
_UNRESOLVED = re.compile(r"[$%{}*?<>|`]")
_MAKE_RULE = re.compile(r"([^\s:#=][^:#=]*?)[ \t]*::?(?!=)[ \t]*([^;#]*)(?:;(.*))?")
_MAX_TRAILS = 64
_CONTENT_CHECKS = (RegexCheck, BlobCheck, UnicodeCheck, SplitPayloadCheck)
_MAX_DEPTH = 3


@dataclass(frozen=True)
class _Entry:
    kind: EntryKind
    path: str
    commands: tuple[str, ...]
    # The folder the commands run in, relative to the repository root ("" = root).
    base: str


@dataclass(frozen=True)
class _Ref:
    """A file a command runs; ``commands`` are what it runs (``None``: read the file)."""

    path: str
    commands: tuple[str, ...] | None
    base: str


@dataclass(frozen=True)
class _Trail:
    paths: tuple[str, ...]
    commands: tuple[str, ...]
    base: str


# --- entry points -------------------------------------------------------------------


def _command_text(value: object) -> list[str]:
    """Command strings of a JSON value: a string, an argument list, or (dev containers)
    an object of named commands."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return [" ".join(_quote(v) for v in value)]
    if isinstance(value, dict):
        return [text for v in value.values() for text in _command_text(v)]
    return []


def _quote(word: str) -> str:
    return f'"{word}"' if " " in word and '"' not in word else word


def _task_commands(task: Mapping[str, object]) -> list[str]:
    commands: list[str] = []
    for scope in (task, task.get("windows"), task.get("linux"), task.get("osx")):
        if not isinstance(scope, dict):
            continue
        command = scope.get("command")
        if isinstance(command, dict):
            command = command.get("value")
        if not isinstance(command, str):
            continue
        words = [command]
        args = scope.get("args")
        if isinstance(args, list):
            for arg in args:
                value = arg.get("value") if isinstance(arg, dict) else arg
                if isinstance(value, str):
                    words.append(_quote(value))
        commands.append(" ".join(words))
    return commands


def _vscode_entries(data: object, path: str, kind: EntryKind) -> Iterator[_Entry]:
    tasks = data.get("tasks") if isinstance(data, dict) else None
    if not isinstance(tasks, list):
        return
    by_label = {t.get("label"): t for t in tasks if isinstance(t, dict)}
    workspace = posixpath.dirname(posixpath.dirname(path))
    for task in tasks:
        if not isinstance(task, dict):
            continue
        options = task.get("runOptions")
        if not isinstance(options, dict) or options.get("runOn") != "folderOpen":
            continue
        commands = _task_commands(task)
        # Tasks named in dependsOn run first.
        depends = task.get("dependsOn")
        for label in [depends] if isinstance(depends, str) else depends or []:
            other = by_label.get(label) if isinstance(label, str) else None
            if isinstance(other, dict):
                commands += _task_commands(other)
        yield _Entry(kind, path, tuple(commands), workspace)


def _devcontainer_entries(
    data: object, path: str, kinds: Mapping[str, EntryKind]
) -> Iterator[_Entry]:
    if not isinstance(data, dict):
        return
    folder = posixpath.dirname(path)
    workspace = posixpath.dirname(folder) if basename(folder) == ".devcontainer" else folder
    if basename(path) == "devcontainer.json" and basename(posixpath.dirname(folder)) == (
        ".devcontainer"
    ):
        workspace = posixpath.dirname(posixpath.dirname(folder))
    host = kinds.get("devcontainer_host")
    if host is not None and "initializeCommand" in data:
        yield _Entry(host, path, tuple(_command_text(data["initializeCommand"])), workspace)
    container = kinds.get("devcontainer_container")
    if container is not None:
        commands = [c for key in _CONTAINER_COMMANDS for c in _command_text(data.get(key))]
        if commands:
            yield _Entry(container, path, tuple(commands), workspace)


def _npm_scripts(data: object) -> dict[str, str]:
    scripts = data.get("scripts") if isinstance(data, dict) else None
    if not isinstance(scripts, dict):
        return {}
    return {k: v for k, v in scripts.items() if isinstance(k, str) and isinstance(v, str)}


def _expand_scripts(scripts: Mapping[str, str], names: Sequence[str]) -> list[str]:
    """The commands of ``names`` with their pre/post scripts and the scripts they start
    with ``npm run`` (same file, not counted as a step)."""
    commands: list[str] = []
    seen: set[str] = set()

    def add(name: str, depth: int) -> None:
        if depth > _MAX_DEPTH or name in seen:
            return
        seen.add(name)
        for each in (f"pre{name}", name, f"post{name}"):
            command = scripts.get(each)
            if command is None or (each != name and each in seen):
                continue
            seen.add(each)
            commands.append(command)
            for other in _npm_names(command):
                add(other, depth + 1)

    for name in names:
        add(name, 0)
    return commands


def _npm_names(command: str) -> list[str]:
    names: list[str] = []
    for segment in _SEPARATORS.split(command):
        tokens = _tokens(segment)
        if len(tokens) >= 2 and basename(tokens[0]).lower() in ("npm", "pnpm", "yarn"):
            rest = tokens[1:]
            if rest[0] in ("run", "run-script") and len(rest) > 1:
                names.append(rest[1])
            elif rest[0] in ("start", "test"):
                names.append(rest[0])
    return names


def entry_points(ctx: ScanContext, check: ChainCheck, vendored: GlobSet) -> list[_Entry]:
    kinds = {k.kind: k for k in check.entries}
    entries: list[_Entry] = []
    for file in ctx.tree.files():
        path = file.path
        if vendored.matches(path):
            continue
        if "vscode_folder_open" in kinds and _TASKS.matches(path):
            data = FileView(file, ctx.limits, ctx.coverage).structured("jsonc")
            entries += _vscode_entries(data, path, kinds["vscode_folder_open"])
        elif _DEVCONTAINER.matches(path):
            data = FileView(file, ctx.limits, ctx.coverage).structured("jsonc")
            entries += _devcontainer_entries(data, path, kinds)
        elif "npm_install" in kinds and _PACKAGE.matches(path):
            scripts = _npm_scripts(FileView(file, ctx.limits, ctx.coverage).structured("json"))
            names = [name for name in _INSTALL_SCRIPTS if name in scripts]
            if names:
                commands = tuple(_expand_scripts(scripts, names))
                entries.append(
                    _Entry(kinds["npm_install"], path, commands, posixpath.dirname(path))
                )
    return sorted(entries, key=lambda e: (e.path, e.kind.kind))


# --- commands and references ---------------------------------------------------------


def _tokens(segment: str) -> list[str]:
    tokens = [t.strip("\"'") for t in _TOKEN.findall(segment)]
    while tokens and (tokens[0].lower() in _PREFIXES or _ASSIGNMENT.fullmatch(tokens[0])):
        tokens.pop(0)
        # Options of the prefix (sudo -E, env -i).
        while tokens and tokens[0].startswith("-"):
            tokens.pop(0)
    return tokens


def references(command: str, depth: int = 0) -> Iterator[tuple[str, str, tuple[str, ...]]]:
    """What a command runs: ``("file", path, ())``, ``("make", folder, targets)`` or
    ``("npm", "", (script,))``. Paths are as written (not yet resolved)."""
    for segment in _SEPARATORS.split(command):
        tokens = _tokens(segment)
        if not tokens:
            continue
        name = basename(tokens[0].replace("\\", "/")).lower().removesuffix(".exe")
        rest = tokens[1:]
        if name in ("make", "gmake"):
            yield _make_reference(rest)
        elif name in ("npm", "pnpm", "yarn"):
            for script in _npm_names(segment):
                yield "npm", "", (script,)
        elif name in _INTERPRETERS:
            yield from _interpreter_reference(name, rest, depth)
        else:
            yield "file", tokens[0], ()


def _make_reference(args: Sequence[str]) -> tuple[str, str, tuple[str, ...]]:
    folder, targets = "", []
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "-C" and index + 1 < len(args):
            folder = args[index + 1]
            index += 2
            continue
        if not arg.startswith("-") and "=" not in arg:
            targets.append(arg)
        index += 1
    return "make", folder, tuple(targets)


def _interpreter_reference(
    name: str, args: Sequence[str], depth: int
) -> Iterator[tuple[str, str, tuple[str, ...]]]:
    index = 0
    while index < len(args):
        arg = args[index]
        lower = arg.lower()
        if lower in _INLINE:
            if depth < _MAX_DEPTH and index + 1 < len(args):
                yield from references(args[index + 1], depth + 1)
            return
        if lower == "-file" or (name in ("deno", "bun") and lower == "run"):
            index += 1
            continue
        if arg.startswith("-") or (name == "cmd" and arg.startswith("/")):
            index += 1
            continue
        yield "file", arg, ()
        return


def _file_commands(path: str, text: str) -> tuple[str, ...]:
    """What a reached file runs: string literals of JavaScript, TypeScript and Python,
    lines of everything else (shell, batch, PowerShell)."""
    extension = basename(path).rpartition(".")[2].lower()
    if extension in _SCRIPT_EXTENSIONS:
        spans = literal_spans(text, path)
        if spans is None:
            return ()
        return tuple(
            text[start:end].strip("\"'`")
            for start, end, kind in zip(spans.starts, spans.ends, spans.kinds, strict=True)
            if kind == "s"
        )
    family = family_of(path)
    commands = []
    for _, line in logical_lines(text.splitlines()):
        stripped = line.strip()
        if (
            not stripped
            or stripped.startswith("#")
            or (family == "batch" and re.match(r"(?i)(?:rem\b|::)", stripped))
        ):
            continue
        commands.append(stripped)
    return tuple(commands)


def _make_recipes(text: str, targets: Sequence[str]) -> tuple[str, ...]:
    """Recipe lines of ``targets`` (default: the first target) and their prerequisites."""
    rules: dict[str, tuple[list[str], list[str]]] = {}
    order: list[str] = []
    current: list[str] = []
    for _, line in logical_lines(text.splitlines()):
        if line.startswith("\t"):
            for target in current:
                rules[target][1].append(line.strip().lstrip("@-+").strip())
            continue
        current = []
        found = _MAKE_RULE.fullmatch(line.rstrip())
        if found is None:
            continue
        current = found.group(1).split()
        for target in current:
            rules.setdefault(target, ([], []))
            rules[target][0].extend(found.group(2).split())
            if found.group(3):
                rules[target][1].append(found.group(3).strip())
            if target not in order:
                order.append(target)
    wanted = list(targets) or [t for t in order if not t.startswith(".")][:1]
    commands: list[str] = []
    seen: set[str] = set()

    def add(target: str, depth: int) -> None:
        if depth > _MAX_DEPTH or target in seen or target not in rules:
            return
        seen.add(target)
        prerequisites, recipe = rules[target]
        for prerequisite in prerequisites:
            add(prerequisite, depth + 1)
        commands.extend(recipe)

    for target in wanted:
        add(target, 0)
    return tuple(commands)


# --- resolving -------------------------------------------------------------------------


class _Resolver:
    def __init__(self, ctx: ScanContext, vendored: GlobSet) -> None:
        self.ctx = ctx
        self.vendored = vendored
        self.files: dict[str, RepoFile] = {f.path: f for f in ctx.tree.files()}
        self._texts: dict[str, str | None] = {}

    def text(self, path: str) -> str | None:
        if path not in self._texts:
            self._texts[path] = FileView(
                self.files[path], self.ctx.limits, self.ctx.coverage
            ).text()
        return self._texts[path]

    def path(self, raw: str, anchors: Sequence[str]) -> str | None:
        """The repository path of ``raw``, tried relative to each anchor folder."""
        raw = raw.strip()
        workspace = _WORKSPACE.match(raw)
        script_dir = _SCRIPT_DIR.match(raw)
        if workspace is not None:
            raw, anchors = raw[workspace.end() :], anchors[:1]
        elif script_dir is not None:
            raw, anchors = raw[script_dir.end() :], anchors[1:]
        raw = (
            raw.replace("\\", "/").lstrip("/")
            if workspace or script_dir
            else raw.replace("\\", "/")
        )
        if (
            not raw
            or raw.startswith(("/", "~"))
            or re.match(r"[A-Za-z]:", raw)
            or _UNRESOLVED.search(raw)
        ):
            return None
        for anchor in anchors:
            joined = posixpath.normpath(posixpath.join(anchor, raw))
            if joined in {".", ".."} or joined.startswith("../"):
                continue
            if joined in self.files and not self.vendored.matches(joined):
                return joined
        return None

    def refs(self, command: str, base: str, here: str) -> Iterator[_Ref]:
        for kind, raw, extra in references(command):
            if kind == "file":
                path = self.path(raw, (base, here))
                if path is not None:
                    yield _Ref(path, None, base)
            elif kind == "make":
                folder = posixpath.normpath(posixpath.join(base, raw)) if raw else base
                for name in _MAKEFILES:
                    path = self.path(name, (folder,))
                    text = None if path is None else self.text(path)
                    if path is not None and text is not None:
                        yield _Ref(
                            path, _make_recipes(text, extra), "" if folder == "." else folder
                        )
                        break
            elif kind == "npm":
                path = self.path("package.json", (base,))
                text = None if path is None else self.text(path)
                if path is not None and text is not None:
                    view = FileView(self.files[path], self.ctx.limits, self.ctx.coverage)
                    scripts = _npm_scripts(view.structured("json"))
                    commands = tuple(_expand_scripts(scripts, extra))
                    if commands:
                        yield _Ref(path, commands, base)

    def trails(self, entry: _Entry, max_hops: int) -> list[tuple[str, ...]]:
        """Every path of files from the entry point, at most ``max_hops`` files long
        after it; a file already on a path is not followed again."""
        found: list[tuple[str, ...]] = []
        frontier = [_Trail((entry.path,), entry.commands, entry.base)]
        for _ in range(max_hops):
            following: list[_Trail] = []
            for trail in frontier:
                here = posixpath.dirname(trail.paths[-1])
                for command in trail.commands:
                    for ref in self.refs(command, trail.base, here):
                        if ref.path in trail.paths or len(found) >= _MAX_TRAILS:
                            continue
                        paths = (*trail.paths, ref.path)
                        if paths in found:
                            continue
                        found.append(paths)
                        commands = ref.commands
                        if commands is None:
                            text = self.text(ref.path)
                            commands = () if text is None else _file_commands(ref.path, text)
                        following.append(_Trail(paths, commands, ref.base))
            frontier = following
        return found


# --- chains --------------------------------------------------------------------------


def apply(ctx: ScanContext, results: list[AreaResult]) -> None:
    """Resolve the chains of every active chain rule and update ``results`` in place."""
    for rule in ctx.rules.active():
        if isinstance(rule.check, ChainCheck):
            _Chains(ctx, results, rule, rule.check).run()


class _Chains:
    def __init__(
        self, ctx: ScanContext, results: list[AreaResult], rule: Rule, check: ChainCheck
    ) -> None:
        self.ctx = ctx
        self.results = results
        self.rule = rule
        self.check = check
        filesets = ctx.rules.filesets
        self.vendored = GlobSet(
            sorted(set(filesets.get("vendored", [])) | set(filesets.get("context_vendored", [])))
        )
        self.resolver = _Resolver(ctx, self.vendored)
        # Rules run on reached files that their file patterns skip: the content checks
        # of the areas whose code a chain raises (no parsers for other file formats).
        self.extra_rules = [
            r
            for r in ctx.rules.active()
            if r.area in check.recheck_areas and isinstance(r.check, _CONTENT_CHECKS)
        ]
        self.checked: set[str] = set()
        # id(finding) -> chain id of the findings that become part of a chain.
        self.marks: dict[int, str] = {}
        self.chains: list[Finding] = []
        self.count = 0

    def area(self, name: str) -> AreaResult:
        for result in self.results:
            if result.area == name:
                return result
        result = AreaResult(name)
        self.results.append(result)
        return result

    def run(self) -> None:
        for entry in entry_points(self.ctx, self.check, self.vendored):
            trails = self.resolver.trails(entry, self.check.max_hops)
            for path in sorted({p for trail in trails for p in trail[1:]} - self.checked):
                self.checked.add(path)
                self.check_unmatched(path)
            self.chains += self.entry_chains(entry, trails)
        if not self.chains:
            return
        for result in self.results:
            result.findings = [
                replace(f, in_chain=self.marks[id(f)]) if id(f) in self.marks else f
                for f in result.findings
            ]
        self.area(self.rule.area).findings.extend(self.chains)

    def check_unmatched(self, path: str) -> None:
        """Run the content rules whose file patterns skip ``path`` on it: a file that an
        entry point runs is checked like a script, whatever its name or folder."""
        view = FileView(self.resolver.files[path], self.ctx.limits, self.ctx.coverage)
        for rule in self.extra_rules:
            if rule.applies_to(path) or (rule.check.needs_text and view.text() is None):
                continue
            found = rule_findings(rule, view, self.ctx)
            if found:
                self.area(rule.area).findings.extend(found)

    def raised(self, finding: Finding, entry: _Entry) -> Severity:
        """The severity of ``finding`` when an entry point runs it: at least that of the
        entry point's rule for the same code written inline."""
        inline = self.ctx.rules.get(entry.kind.inline) if entry.kind.inline else None
        if inline is not None and set(finding.tags) & set(self.check.raise_tags):
            return max(finding.severity, inline.severity)
        return finding.severity

    def entry_chains(self, entry: _Entry, trails: Sequence[tuple[str, ...]]) -> list[Finding]:
        """One chain per file with dangerous code that the entry point reaches, worst
        first; each through the shortest path to that file."""
        by_path: dict[str, list[Finding]] = {}
        for result in self.results:
            for finding in result.findings:
                if finding.location is not None and finding.chain is None:
                    by_path.setdefault(finding.location.path, []).append(finding)
        endpoints: dict[str, tuple[Finding, tuple[str, ...]]] = {}
        for trail in sorted(trails, key=len):
            for index, path in enumerate(trail[1:], start=2):
                candidates = [f for f in by_path.get(path, []) if self.is_endpoint(f, entry)]
                if not candidates or path in endpoints:
                    continue
                worst = max(
                    candidates, key=lambda f: (self.raised(f, entry), f.severity, f.confidence)
                )
                endpoints[path] = worst, trail[:index]
        ordered = sorted(
            endpoints.values(),
            key=lambda item: (
                -self.raised(item[0], entry),
                -item[0].confidence,
                len(item[1]),
                item[1],
            ),
        )
        return [self.chain(entry, endpoint, steps, by_path) for endpoint, steps in ordered]

    def is_endpoint(self, finding: Finding, entry: _Entry) -> bool:
        return (
            finding.category == "danger"
            and finding.area in self.check.endpoint_areas
            and finding.severity >= Severity.MEDIUM
            and finding.rule_id not in entry.kind.rules
        )

    def chain(
        self,
        entry: _Entry,
        endpoint: Finding,
        steps: tuple[str, ...],
        by_path: Mapping[str, Sequence[Finding]],
    ) -> Finding:
        self.count += 1
        chain_id = f"chain-{self.count}"
        members = [f for f in by_path.get(entry.path, []) if f.rule_id in entry.kind.rules]
        members += [
            f
            for path in steps[1:]
            for f in by_path.get(path, [])
            if f.category == "danger" and f.area in self.check.endpoint_areas
        ]
        members = [f for f in members if id(f) not in self.marks]
        severity = max([self.raised(endpoint, entry), *(f.severity for f in members)])
        for member in members:
            self.marks[id(member)] = chain_id
        entry_line = next(
            (f.location.line for f in members if f.location and f.location.path == entry.path),
            None,
        )
        values = {
            "key": entry.kind.label,
            "match": f"{AREAS[endpoint.area].label} ({endpoint.rule_id})",
            "count": str(len(steps)),
            "value": " -> ".join(steps),
        }
        confidence = min(endpoint.confidence, self.rule.confidence)
        match = Match(entry_line, None, endpoint.evidence, values, confidence, severity)
        finding = make_finding(self.rule, entry.path, match, self.ctx)
        locations = [Location(entry.path, entry_line)]
        locations += [Location(path) for path in steps[1:-1]]
        locations.append(endpoint.location or Location(steps[-1]))
        return replace(finding, severity=severity, chain=Chain(chain_id, tuple(locations)))
