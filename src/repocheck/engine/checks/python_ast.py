"""Check type ``python_ast``: calls and keyword arguments in Python files.

The file is only parsed with ``ast.parse``; nothing is compiled, imported or run.
Import aliases are resolved (``import subprocess as sp`` -> ``sp.run`` is
``subprocess.run``; ``from os import system`` -> ``system`` is ``os.system``).
"""

import ast
from collections.abc import Iterator

from repocheck.engine.checks.base import (
    BuildEnv,
    Check,
    CheckError,
    FileView,
    Match,
    Params,
    Wildcard,
)


def import_aliases(module: ast.Module) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(module):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
                else:
                    top = alias.name.split(".", 1)[0]
                    aliases[top] = top
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            for alias in node.names:
                if alias.name != "*":
                    aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return aliases


def dotted_name(node: ast.expr) -> str | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return ".".join(reversed(parts))


def resolve(name: str, aliases: dict[str, str]) -> str:
    head, sep, rest = name.partition(".")
    if head in aliases:
        return aliases[head] + sep + rest
    return name


class PythonAstCheck(Check):
    def __init__(
        self, calls: list[Wildcard], keywords: list[Wildcard], in_call: list[Wildcard]
    ) -> None:
        self.calls = calls
        self.keywords = keywords
        self.in_call = in_call

    @staticmethod
    def _any(patterns: list[Wildcard], name: str) -> bool:
        return any(p.matches(name) for p in patterns)

    def matches(self, view: FileView) -> Iterator[Match]:
        module = view.python_module()
        if module is None:
            return
        aliases = import_aliases(module)
        for node in ast.walk(module):
            if not isinstance(node, ast.Call):
                continue
            raw = dotted_name(node.func)
            if raw is None:
                continue
            name = resolve(raw, aliases)
            if self.keywords:
                if self.in_call and not self._any(self.in_call, name):
                    continue
                for keyword in node.keywords:
                    if keyword.arg is not None and self._any(self.keywords, keyword.arg):
                        line = keyword.value.lineno
                        yield Match(
                            line,
                            keyword.value.col_offset + 1,
                            view.line_text(line),
                            {"match": keyword.arg, "key": keyword.arg, "value": name},
                        )
            elif self._any(self.calls, name):
                yield Match(
                    node.lineno,
                    node.col_offset + 1,
                    view.line_text(node.lineno),
                    {"match": name, "value": name},
                )


def build(params: Params, env: BuildEnv) -> Check:
    calls = [Wildcard(c) for c in params.get_str_list("calls")]
    keywords = [Wildcard(k) for k in params.get_str_list("keywords")]
    in_call = [Wildcard(c) for c in params.get_str_list("in_call")]
    params.done()
    if calls and keywords:
        raise CheckError("use either 'calls' or 'keywords' (with optional 'in_call')")
    if not calls and not keywords:
        raise CheckError("'calls' or 'keywords' is required")
    if in_call and not keywords:
        raise CheckError("'in_call' only applies to 'keywords'")
    return PythonAstCheck(calls, keywords, in_call)
