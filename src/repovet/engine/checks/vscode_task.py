"""Check commands reached by automatic VS Code tasks, excluding display metadata."""

import re
from collections.abc import Iterator

from repovet.engine.checks.base import BuildEnv, Check, FileView, Match, Params
from repovet.parsers.commands import references, split_commands, task_commands, tokens
from repovet.parsers.structured import find_line
from repovet.sources.tree import basename


class VscodeTaskCheck(Check):
    def __init__(self, mode: str, pattern: re.Pattern[str] | None) -> None:
        self.mode = mode
        self.pattern = pattern

    def matches(self, view: FileView) -> Iterator[Match]:
        data = view.structured("jsonc")
        tasks = data.get("tasks") if isinstance(data, dict) else None
        if not isinstance(tasks, list):
            return
        labels = {
            t["label"]: t for t in tasks if isinstance(t, dict) and isinstance(t.get("label"), str)
        }
        for index, task in enumerate(tasks):
            if not isinstance(task, dict):
                continue
            options = task.get("runOptions")
            if not isinstance(options, dict) or options.get("runOn") != "folderOpen":
                continue
            commands = task_commands(task)
            pending = [task]
            seen: set[str] = set()
            while pending and len(seen) < 64:
                depends = pending.pop().get("dependsOn", [])
                if not isinstance(depends, str | list):
                    continue
                for label in [depends] if isinstance(depends, str) else depends:
                    if not isinstance(label, str) or label in seen or label not in labels:
                        continue
                    seen.add(label)
                    commands.extend(task_commands(labels[label]))
                    pending.append(labels[label])
            matched = "folderOpen" if self.mode == "inventory" else None
            for command in commands:
                if self.mode == "network" and self.pattern is not None:
                    for segment in split_commands(command):
                        words = tokens(segment)
                        name = basename(words[0]).lower() if words else ""
                        if name in {"echo", "printf", "write-output"} and not (
                            "$(" in segment or "`" in segment
                        ):
                            continue
                        hit = self.pattern.search(segment)
                        if hit:
                            matched = hit.group()
                            break
                if self.mode != "code":
                    continue
                for kind, name, _ in references(command):
                    if kind in ("npm", "make") or (
                        kind == "file"
                        and self.pattern is not None
                        and not name.startswith(("/", "~"))
                        and not name.replace("\\", "/").startswith("../")
                        and ":" not in name
                        and self.pattern.search(name)
                    ):
                        matched = command
                        break
            if matched is None:
                continue
            line = find_line(view.text() or "", ("tasks", index), matched)
            yield Match(
                line=line,
                evidence=view.line_text(line) if line else None,
                values={"match": matched, "value": matched},
            )

    def regexes(self) -> list[re.Pattern[str]]:
        return [self.pattern] if self.pattern else []


def build(params: Params, env: BuildEnv) -> Check:
    mode = params.get_choice("mode", ("inventory", "code", "network"))
    pattern = params.get_str("pattern", required=mode != "inventory")
    params.done()
    return VscodeTaskCheck(mode, env.compile(pattern) if pattern else None)
