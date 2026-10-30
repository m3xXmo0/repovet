"""Static command references shared by task checks and chain traversal."""

import re
from collections.abc import Iterator, Mapping, Sequence

from repovet.sources.tree import basename

_MAX_DEPTH = 3

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


def split_commands(command: str, *, pipes: bool = True) -> Iterator[str]:
    """Split shell operators outside quoted arguments; never interpret a command."""
    quote = ""
    start, index = 0, 0
    while index < len(command):
        char = command[index]
        if quote:
            if char == "\\" and quote == '"' and index + 1 < len(command):
                index += 2
                continue
            if char == quote:
                quote = ""
        elif char in "\"'":
            quote = char
        elif char in ";&\n" or (char == "|" and (pipes or command[index : index + 2] == "||")):
            yield command[start:index]
            if char in "&|" and command[index : index + 2] == char * 2:
                index += 1
            start = index + 1
        index += 1
    yield command[start:]


def command_text(value: object) -> list[str]:
    """Command strings of a JSON value: a string, an argument list, or (dev containers)
    an object of named commands."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return [" ".join(_quote(v) for v in value)]
    if isinstance(value, dict):
        return [text for v in value.values() for text in command_text(v)]
    return []


def _quote(word: str) -> str:
    return f'"{word}"' if " " in word and '"' not in word else word


def task_commands(task: Mapping[str, object]) -> list[str]:
    commands: list[str] = []
    scopes = [dict(task)]
    scopes.extend(
        dict(task) | override
        for key in ("windows", "linux", "osx")
        if isinstance(override := task.get(key), dict)
    )
    for scope in scopes:
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


def npm_names(command: str) -> list[str]:
    names: list[str] = []
    for segment in split_commands(command):
        words = tokens(segment)
        if len(words) >= 2 and basename(words[0]).lower() in ("npm", "pnpm", "yarn"):
            rest = words[1:]
            if rest[0] in ("run", "run-script") and len(rest) > 1:
                names.append(rest[1])
            elif rest[0] in ("start", "test"):
                names.append(rest[0])
    return names


def tokens(segment: str) -> list[str]:
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
    for segment in split_commands(command):
        words = tokens(segment)
        if not words:
            continue
        name = basename(words[0].replace("\\", "/")).lower().removesuffix(".exe")
        rest = words[1:]
        if name in ("make", "gmake"):
            yield _make_reference(rest)
        elif name in ("npm", "pnpm", "yarn"):
            for script in npm_names(segment):
                yield "npm", "", (script,)
        elif name in _INTERPRETERS:
            yield from _interpreter_reference(name, rest, depth)
        else:
            yield "file", words[0], ()


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
