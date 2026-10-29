"""Check type ``filename``: a file exists, optionally with a name matching a regex.

``target: path`` matches the regexes against the whole relative path (folders
included) instead of the file name.
"""

import re
from collections.abc import Iterator

from repocheck.engine.checks.base import BuildEnv, Check, FileView, Match, Params


class FilenameCheck(Check):
    needs_text = False

    def __init__(
        self,
        name_regex: re.Pattern[str] | None,
        not_name_regex: re.Pattern[str] | None,
        whole_path: bool = False,
    ):
        self.name_regex = name_regex
        self.not_name_regex = not_name_regex
        self.whole_path = whole_path

    def matches(self, view: FileView) -> Iterator[Match]:
        name = view.path if self.whole_path else view.name
        if self.name_regex is not None and not self.name_regex.search(name):
            return
        if self.not_name_regex is not None and self.not_name_regex.search(name):
            return
        yield Match(values={"match": name})

    def regexes(self) -> list[re.Pattern[str]]:
        return [r for r in (self.name_regex, self.not_name_regex) if r is not None]


def build(params: Params, env: BuildEnv) -> Check:
    flags = 0 if env.case_sensitive else re.IGNORECASE
    name = params.get_str("name_regex")
    not_name = params.get_str("not_name_regex")
    target = params.get_choice("target", ("name", "path"), default="name")
    params.done()
    return FilenameCheck(
        env.compile(name, flags) if name else None,
        env.compile(not_name, flags) if not_name else None,
        whole_path=target == "path",
    )
