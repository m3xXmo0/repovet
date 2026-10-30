"""Workflow checks that keep environment values, guards and commands in their scope."""

import re
from collections.abc import Iterator, Mapping

from repovet.engine.checks.base import BuildEnv, Check, FileView, Match, Params
from repovet.models import CoverageStatus
from repovet.parsers.commands import split_commands
from repovet.parsers.structured import find_line

_ENV = re.compile(r"\$\{\{\s*env\.([A-Za-z_]\w*)\s*\}\}")
_VARIABLE = re.compile(r"\$(?:\{([A-Za-z_]\w*)\}|([A-Za-z_]\w*))")
_EQUALITY = re.compile(r"\A\s*([\w.]+)\s*==\s*([\w.]+|'[^']*'|\"[^\"]*\")\s*\Z")
_MAX_EXPANSION = 20_000


class ExpansionLimit(ValueError):
    """Literal environment expansion would exceed the bounded analysis budget."""


def mapping(value: object) -> dict[str, object]:
    return {k: v for k, v in value.items() if isinstance(k, str)} if isinstance(value, dict) else {}


def environment(value: object) -> dict[str, str]:
    return {k: v for k, v in mapping(value).items() if isinstance(v, str)}


def resolve(text: str, env: Mapping[str, str], *, variables: bool = False) -> str:
    # Only literal environment mappings are substituted; no expression is evaluated.
    def substitute(pattern: re.Pattern[str], value: str) -> str:
        remaining = _MAX_EXPANSION - len(value)
        if remaining < 0:
            raise ExpansionLimit

        def replacement(match: re.Match[str]) -> str:
            nonlocal remaining
            name = match[1] or (match[2] if match.lastindex == 2 else "")
            resolved = env.get(name, match[0])
            remaining -= len(resolved) - len(match[0])
            if remaining < 0:
                raise ExpansionLimit
            return resolved

        return pattern.sub(replacement, value)

    for _ in range(8):
        changed = substitute(_ENV, text)
        if variables:
            changed = substitute(_VARIABLE, changed)
        if changed == text:
            break
        text = changed
    return text


def _split_condition(text: str, operator: str) -> list[str]:
    depth, start, index = 0, 0, 0
    quote = ""
    parts: list[str] = []
    while index < len(text):
        char = text[index]
        if quote:
            if char == quote:
                quote = ""
        elif char in "\"'":
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif depth == 0 and text.startswith(operator, index):
            parts.append(text[start:index])
            index += len(operator)
            start = index
            continue
        index += 1
    return [*parts, text[start:]]


def guard_facts(text: str, depth: int = 0) -> set[str]:
    """Restrictions guaranteed by every branch of a small boolean expression.

    Unknown syntax proves nothing. AND combines restrictions; OR keeps only those
    required on both sides. Thus a guard followed by ``|| ...`` cannot hide a checkout.
    """
    if depth > 30 or len(text) > 10_000:
        return set()
    text = text.strip()
    if text.startswith("${{") and text.endswith("}}"):
        text = text[3:-2].strip()
    # Removing outer parentheses is valid only if they enclose the whole expression.
    while text.startswith("(") and text.endswith(")"):
        balance, quote, closes_early = 0, "", False
        for index, char in enumerate(text):
            if quote:
                if char == quote:
                    quote = ""
            elif char in "\"'":
                quote = char
            elif char == "(":
                balance += 1
            elif char == ")":
                balance -= 1
                if balance == 0 and index != len(text) - 1:
                    closes_early = True
                    break
        if closes_early:
            break
        text = text[1:-1].strip()
    parts = _split_condition(text, "||")
    if len(parts) > 1:
        return set.intersection(*(guard_facts(p, depth + 1) for p in parts))
    parts = _split_condition(text, "&&")
    if len(parts) > 1:
        return set.union(*(guard_facts(p, depth + 1) for p in parts))
    match = _EQUALITY.fullmatch(text)
    if not match:
        return set()
    left, right = match.groups()
    pair = {left, right}
    if pair == {"github.event.workflow_run.head_repository.full_name", "github.repository"}:
        return {"same_repository"}
    if pair == {
        "github.event.workflow_run.head_branch",
        "github.event.repository.default_branch",
    }:
        return {"default_branch"}
    event = "github.event.workflow_run.event"
    other = right if left == event else left if right == event else ""
    if other in {
        "'push'",
        '"push"',
        "'schedule'",
        '"schedule"',
        "'workflow_dispatch'",
        '"workflow_dispatch"',
    }:
        return {"trusted_event"}
    return set()


class WorkflowCheck(Check):
    def __init__(
        self, mode: str, pattern: re.Pattern[str], trigger: re.Pattern[str] | None
    ) -> None:
        self.mode, self.pattern, self.trigger = mode, pattern, trigger

    def matches(self, view: FileView) -> Iterator[Match]:
        data = mapping(view.structured("yaml"))
        if not data:
            return
        # PyYAML's YAML 1.1 resolver reads an unquoted `on` key as True.
        raw_data = view.structured("yaml")
        on = raw_data.get("on", raw_data.get(True)) if isinstance(raw_data, dict) else None
        triggers = list(mapping(on)) if isinstance(on, dict) else on
        if isinstance(triggers, list):
            trigger_text = " ".join(x for x in triggers if isinstance(x, str))
        else:
            trigger_text = triggers if isinstance(triggers, str) else ""
        if mapping(data.get("runs")).get("using") == "composite":
            trigger_text += " using: composite"
        if self.trigger and not self.trigger.search(trigger_text):
            return
        base_env = environment(data.get("env"))
        jobs = mapping(data.get("jobs"))
        if "runs" in data:
            jobs["runs"] = data["runs"]
        for name, raw_job in jobs.items():
            job = mapping(raw_job)
            env = base_env | environment(job.get("env"))
            steps = job.get("steps")
            if not isinstance(steps, list):
                continue
            try:
                if self.mode == "checkout":
                    condition = job.get("if")
                    facts = guard_facts(condition) if isinstance(condition, str) else set()
                    if {"same_repository", "default_branch", "trusted_event"} <= facts:
                        continue
                    yield from self._checkouts(view, name, steps, env)
                else:
                    yield from self._scripts(view, name, steps, env)
            except ExpansionLimit:
                view.note(
                    CoverageStatus.PARTIAL,
                    "Workflow environment expansion exceeds 20,000 characters",
                )

    def _checkouts(
        self, view: FileView, job: str, steps: list[object], env: dict[str, str]
    ) -> Iterator[Match]:
        for index, raw_step in enumerate(steps):
            step = mapping(raw_step)
            scope = env | environment(step.get("env"))
            uses = step.get("uses")
            inputs = mapping(step.get("with"))
            candidates: list[tuple[tuple[str | int, ...], str, str]] = []
            if isinstance(uses, str) and uses.lower().startswith("actions/checkout@"):
                for key in ("ref", "repository"):
                    value = inputs.get(key)
                    if isinstance(value, str):
                        expanded = resolve(value, scope)
                        candidates.append((("with", key), value, f"{key}: {expanded}"))
            run = step.get("run")
            if isinstance(run, str):
                candidates.append((("run",), run, resolve(run, scope, variables=True)))
            for trail, original, candidate in candidates:
                hit = self.pattern.search(candidate)
                if hit:
                    first = original.splitlines()[0] if original else original
                    line = find_line(
                        view.text() or "", ("jobs", job, "steps", index, *trail), first
                    )
                    yield self._match(view, line, hit.group())

    def _scripts(
        self, view: FileView, job: str, steps: list[object], env: dict[str, str]
    ) -> Iterator[Match]:
        scripts: list[str] = []
        positions: list[tuple[int, int | None]] = []
        offset = 0
        for index, raw_step in enumerate(steps):
            step = mapping(raw_step)
            scope = env | environment(step.get("env"))
            run = step.get("run")
            if not isinstance(run, str):
                uses = step.get("uses")
                if not isinstance(uses, str) or not uses.lower().startswith(
                    "actions/github-script@"
                ):
                    continue
                run = mapping(step.get("with")).get("script")
            if not isinstance(run, str):
                continue
            trail: tuple[str | int, ...] = ("jobs", job, "steps", index)
            line = find_line(view.text() or "", (*trail, "run"), run.splitlines()[0] if run else "")
            expanded = resolve(run, scope, variables=True)
            if self.mode == "secrets_upload":
                for command in split_commands(expanded, pipes=False):
                    hit = self.pattern.search(command)
                    if hit:
                        yield self._match(view, line, hit.group())
                continue
            positions.append((offset, line))
            scripts.append(expanded)
            offset += len(expanded) + 1
        if self.mode != "file":
            return
        for hit in self.pattern.finditer("\n".join(scripts)):
            line = next((n for pos, n in reversed(positions) if pos <= hit.start()), None)
            yield self._match(view, line, hit.group())

    @staticmethod
    def _match(view: FileView, line: int | None, text: str) -> Match:
        return Match(
            line=line,
            evidence=view.line_text(line) if line else None,
            values={"match": text, "value": text},
        )

    def regexes(self) -> list[re.Pattern[str]]:
        return [self.pattern, _ENV, _VARIABLE, _EQUALITY] + ([self.trigger] if self.trigger else [])


def build(params: Params, env: BuildEnv) -> Check:
    mode = params.get_choice("mode", ("checkout", "file", "secrets_upload"))
    pattern = env.compile(params.require_str("pattern"))
    trigger = params.get_str("trigger")
    params.done()
    return WorkflowCheck(mode, pattern, env.compile(trigger) if trigger else None)
