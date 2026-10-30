"""Check type ``chain``: an auto-run entry point that runs files of the repository which
reach dangerous code.

This type only holds the configuration. The chains are resolved after all areas ran
(``engine.chains``), because they connect findings of different files and areas.

``entries`` lists the entry points to follow, each with ``kind`` (one of ``KINDS``), a
``label`` for the message, the ``rules`` whose findings report the entry point itself
(they become part of the chain) and optionally ``inline``: the rule that reports the
same code written directly into the entry point. A chain whose endpoint finding has one
of the ``raise_tags`` (code that downloads or executes) gets at least that rule's
severity, because it runs the same way. ``endpoint_areas`` are the areas whose findings
(medium or above) a chain can reach; the content rules of the ``recheck_areas`` also run
on reached files their file patterns skip. ``max_hops`` limits how many files are
followed after the entry point.
"""

from dataclasses import dataclass

from repovet.engine.checks.base import BuildEnv, Check, CheckError, Params, ResultCheck
from repovet.models import AREAS

KINDS = ("vscode_folder_open", "devcontainer_host", "devcontainer_container", "npm_install")
# Files followed after the entry point, at most.
MAX_HOPS = 2
_ENTRY_KEYS = {"kind", "label", "rules", "inline"}


@dataclass(frozen=True)
class EntryKind:
    kind: str
    label: str
    rules: tuple[str, ...]
    inline: str | None


class ChainCheck(ResultCheck):
    def __init__(
        self,
        entries: tuple[EntryKind, ...],
        max_hops: int,
        endpoint_areas: tuple[str, ...],
        raise_tags: tuple[str, ...],
        recheck_areas: tuple[str, ...],
    ) -> None:
        self.entries = entries
        self.max_hops = max_hops
        self.endpoint_areas = endpoint_areas
        self.raise_tags = raise_tags
        self.recheck_areas = recheck_areas


def _areas(params: Params, name: str) -> tuple[str, ...]:
    areas = params.get_str_list(name, required=True)
    unknown = sorted(set(areas) - set(AREAS))
    if unknown:
        raise CheckError(f"'{name}': unknown areas {', '.join(unknown)}")
    return tuple(areas)


def build(params: Params, env: BuildEnv) -> Check:
    raw = params.get_raw("entries")
    if not isinstance(raw, list) or not raw:
        raise CheckError("'entries' must be a non-empty list")
    entries: list[EntryKind] = []
    for item in raw:
        if not isinstance(item, dict) or not {"kind", "label", "rules"} <= set(item) <= _ENTRY_KEYS:
            raise CheckError("each entry needs 'kind', 'label' and 'rules' (and may have 'inline')")
        kind, label, rules, inline = item["kind"], item["label"], item["rules"], item.get("inline")
        if kind not in KINDS:
            raise CheckError(f"unknown entry kind {kind!r} ({', '.join(KINDS)})")
        if not isinstance(label, str) or not label.strip():
            raise CheckError(f"entry {kind}: 'label' must be a non-empty string")
        if not isinstance(rules, list) or not all(isinstance(r, str) and r for r in rules):
            raise CheckError(f"entry {kind}: 'rules' must be a list of rule ids")
        if inline is not None and not isinstance(inline, str):
            raise CheckError(f"entry {kind}: 'inline' must be a rule id")
        entries.append(EntryKind(kind, " ".join(label.split()), tuple(rules), inline))
    max_hops = params.get_int("max_hops", MAX_HOPS, minimum=1)
    if max_hops > MAX_HOPS:
        raise CheckError(f"'max_hops' must be at most {MAX_HOPS}")
    endpoint_areas = _areas(params, "endpoint_areas")
    raise_tags = tuple(params.get_str_list("raise_tags", required=True))
    recheck_areas = _areas(params, "recheck_areas")
    params.done()
    return ChainCheck(tuple(entries), max_hops, endpoint_areas, raise_tags, recheck_areas)
