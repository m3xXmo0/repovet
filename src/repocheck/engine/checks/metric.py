"""Check type ``metric``: thresholds on facts computed by the analyzers.

``conditions`` is a list of ``{fact, op, value}``; all must hold. ``fact`` is a dotted
path into the facts (``provenance.history.commits``); a missing fact never matches.
``show`` maps the message placeholders ``value``, ``count`` and ``match`` to facts.
"""

from collections.abc import Iterator, Mapping
from dataclasses import dataclass

from repocheck.engine.checks.base import (
    BuildEnv,
    CheckError,
    FactCheck,
    Match,
    Params,
    format_value,
)

OPERATORS = (">", ">=", "<", "<=", "==", "!=")
SHOWN = ("value", "count", "match")
_MISSING = object()


@dataclass(frozen=True)
class Condition:
    fact: str
    op: str
    value: int | float | bool | str


def lookup(facts: Mapping[str, object], path: str) -> object:
    value: object = facts
    for key in path.split("."):
        if not isinstance(value, Mapping) or key not in value:
            return _MISSING
        value = value[key]
    return value


def _holds(condition: Condition, actual: object) -> bool:
    expected, op = condition.value, condition.op
    if actual is _MISSING or actual is None:
        return False
    if op == "==":
        return type(actual) is type(expected) and actual == expected
    if op == "!=":
        return type(actual) is not type(expected) or actual != expected
    numbers = (int, float)
    if (
        isinstance(actual, bool)
        or isinstance(expected, bool)
        or not isinstance(actual, numbers)
        or not isinstance(expected, numbers)
    ):
        return False
    if op == ">":
        return actual > expected
    if op == ">=":
        return actual >= expected
    if op == "<":
        return actual < expected
    return actual <= expected


class MetricCheck(FactCheck):
    def __init__(self, conditions: list[Condition], show: dict[str, str]) -> None:
        self.conditions = conditions
        self.show = show

    def fact_matches(self, facts: Mapping[str, object]) -> Iterator[Match]:
        if not all(_holds(c, lookup(facts, c.fact)) for c in self.conditions):
            return
        values: dict[str, str] = {}
        for placeholder, fact in self.show.items():
            value = lookup(facts, fact)
            text = None if value is _MISSING else format_value(value)
            values[placeholder] = text if text is not None else ""
        if "value" not in values:
            first = lookup(facts, self.conditions[0].fact)
            values["value"] = format_value(first) or ""
        yield Match(values=values)


def _condition(raw: object) -> Condition:
    if not isinstance(raw, Mapping) or set(raw) != {"fact", "op", "value"}:
        raise CheckError("each condition needs exactly 'fact', 'op' and 'value'")
    fact, op, value = raw["fact"], raw["op"], raw["value"]
    if not isinstance(fact, str) or not fact or any(not part for part in fact.split(".")):
        raise CheckError("'fact' must be a dotted name such as provenance.history.commits")
    if op not in OPERATORS:
        raise CheckError(f"'op' must be one of {', '.join(OPERATORS)}")
    if not isinstance(value, int | float | bool | str):
        raise CheckError("'value' must be a number, true/false or a string")
    return Condition(fact, str(op), value)


def build(params: Params, env: BuildEnv) -> FactCheck:
    raw = params.get_raw("conditions")
    if not isinstance(raw, list) or not raw:
        raise CheckError("'conditions' must be a non-empty list")
    conditions = [_condition(item) for item in raw]
    show_raw = params.get_raw("show") or {}
    if not isinstance(show_raw, Mapping) or not all(
        k in SHOWN and isinstance(v, str) and v for k, v in show_raw.items()
    ):
        raise CheckError(f"'show' maps {', '.join(SHOWN)} to fact names")
    params.done()
    return MetricCheck(conditions, {str(k): str(v) for k, v in show_raw.items()})
