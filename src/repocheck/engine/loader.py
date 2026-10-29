"""Load and validate YAML rules, named patterns, file sets and unsupported surfaces."""

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path

import yaml

from repocheck.engine.checks import BUILDERS, PLANNED
from repocheck.engine.checks.base import BuildEnv, Check, CheckError, Params
from repocheck.models import AREAS, Confidence, Severity
from repocheck.sources.tree import GlobSet

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
PATTERNS_FILE = "_patterns.yaml"
FILESETS_FILE = "_filesets.yaml"
UNSUPPORTED_FILE = "_unsupported.yaml"

RULE_ID = re.compile(r"RC-([A-Z]+)-\d{3}")
PLACEHOLDER = re.compile(r"\{([a-z]+)\}")
PLACEHOLDERS = frozenset({"path", "line", "match", "key", "value", "decoded", "count"})
PLATFORMS = frozenset({"windows", "macos", "linux"})
DEFAULT_FILESET = "text_files"

_REQUIRED = (
    "id",
    "title",
    "area",
    "severity",
    "confidence",
    "check",
    "message",
    "rationale",
    "recommendation",
)
_OPTIONAL = (
    "files",
    "exclude",
    "references",
    "tags",
    "platforms",
    "case_sensitive",
    "deprecated",
    "since",
)
_UNSUPPORTED_FIELDS = ("scope", "files", "exclude", "contains", "max_size", "reason")


class RuleError(Exception):
    """A rule file is invalid. Leads to exit code 2."""

    def __init__(self, source: str, message: str, rule_id: str | None = None) -> None:
        self.source = source
        self.rule_id = rule_id
        self.detail = message
        where = f"{source}: {rule_id}" if rule_id else source
        super().__init__(f"{where}: {message}")


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    area: str
    category: str
    severity: Severity
    confidence: Confidence
    check: Check
    message: str
    rationale: str
    recommendation: str
    files: GlobSet
    exclude: GlobSet
    references: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    platforms: tuple[str, ...] = ()
    deprecated: bool = False
    since: str | None = None
    source: str = ""

    def applies_to(self, path: str) -> bool:
        return self.files.matches(path) and not self.exclude.matches(path)


@dataclass(frozen=True)
class UnsupportedSurface:
    scope: str
    reason: str
    files: GlobSet
    exclude: GlobSet
    contains: re.Pattern[str] | None
    source: str = ""
    max_size: int | None = None

    def applies_to(self, path: str) -> bool:
        return self.files.matches(path) and not self.exclude.matches(path)


@dataclass
class RuleSet:
    rules: list[Rule]
    unsupported: list[UnsupportedSurface] = field(default_factory=list)
    patterns: dict[str, str] = field(default_factory=dict)
    filesets: dict[str, list[str]] = field(default_factory=dict)

    def active(self, area: str | None = None) -> list[Rule]:
        return [r for r in self.rules if not r.deprecated and (area is None or r.area == area)]

    def get(self, rule_id: str) -> Rule | None:
        return next((r for r in self.rules if r.id == rule_id), None)

    def without(self, rule_ids: Sequence[str]) -> "RuleSet":
        ignored = set(rule_ids)
        return replace(self, rules=[r for r in self.rules if r.id not in ignored])


# --- reading ---------------------------------------------------------------------


def _read_yaml(path: Path) -> object:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise RuleError(str(path), f"cannot read file: {exc}") from None
    try:
        data: object = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise RuleError(str(path), f"invalid YAML: {exc}") from None
    return data


def _as_mapping(data: object, source: str, what: str) -> dict[str, object]:
    if data is None:
        return {}
    if not isinstance(data, dict) or not all(isinstance(k, str) for k in data):
        raise RuleError(source, f"{what} must be a mapping with string keys")
    return dict(data)


def _as_list(data: object, source: str, what: str) -> list[object]:
    if data is None:
        return []
    if not isinstance(data, list):
        raise RuleError(source, f"{what} must be a list")
    return list(data)


def _resolve_patterns(raw: Mapping[str, object], source: str) -> dict[str, str]:
    for name, value in raw.items():
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise RuleError(source, f"invalid pattern name {name!r}")
        if not isinstance(value, str) or not value:
            raise RuleError(source, f"pattern {name!r} must be a non-empty string")
    resolved: dict[str, str] = {}

    def resolve(name: str, stack: tuple[str, ...]) -> str:
        if name in resolved:
            return resolved[name]
        if name in stack:
            raise RuleError(source, f"pattern cycle: {' -> '.join((*stack, name))}")
        value = str(raw[name])
        env = BuildEnv({n: resolve(n, (*stack, name)) for n in _references(value, raw, source)})
        try:
            resolved[name] = env.compile(value).pattern
        except CheckError as exc:
            raise RuleError(source, f"pattern {name!r}: {exc}") from None
        return resolved[name]

    for name in raw:
        resolve(name, ())
    return resolved


def _references(value: str, known: Mapping[str, object], source: str) -> list[str]:
    names = re.findall(r"\{\{([A-Za-z_][A-Za-z0-9_]*)\}\}", value)
    for name in names:
        if name not in known:
            raise RuleError(source, f"unknown pattern '{{{{{name}}}}}'")
    return names


def _validate_filesets(raw: Mapping[str, object], source: str) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for name, value in raw.items():
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise RuleError(source, f"file set {name!r} must be a list of globs")
        try:
            GlobSet(value)
        except ValueError as exc:
            raise RuleError(source, f"file set {name!r}: {exc}") from None
        result[name] = list(value)
    return result


# --- building --------------------------------------------------------------------


class _Builder:
    def __init__(self, patterns: dict[str, str], filesets: dict[str, list[str]]) -> None:
        self.patterns = patterns
        self.filesets = filesets

    def globs(self, value: object, source: str, rule_id: str | None, what: str) -> list[str]:
        items = value if isinstance(value, list) else [value]
        globs: list[str] = []
        for item in items:
            if isinstance(item, str):
                globs.append(item)
            elif isinstance(item, dict) and set(item) == {"set"} and isinstance(item["set"], str):
                name = item["set"]
                if name not in self.filesets:
                    raise RuleError(source, f"unknown file set {name!r} in '{what}'", rule_id)
                globs.extend(self.filesets[name])
            else:
                raise RuleError(
                    source, f"'{what}' entries must be globs or {{set: <name>}}", rule_id
                )
        return globs

    def globset(
        self, value: object, source: str, rule_id: str | None, what: str, case_sensitive: bool
    ) -> GlobSet:
        try:
            return GlobSet(self.globs(value, source, rule_id, what), case_sensitive=case_sensitive)
        except ValueError as exc:
            raise RuleError(source, f"'{what}': {exc}", rule_id) from None

    def rule(self, raw: object, source: str) -> Rule:
        if not isinstance(raw, dict):
            raise RuleError(source, "each rule must be a mapping")
        rule_id = raw.get("id")
        rid = rule_id if isinstance(rule_id, str) else None
        unknown = sorted(set(raw) - set(_REQUIRED) - set(_OPTIONAL))
        if unknown:
            raise RuleError(source, f"unknown field(s): {', '.join(map(str, unknown))}", rid)
        missing = [name for name in _REQUIRED if name not in raw]
        if missing:
            raise RuleError(source, f"missing field(s): {', '.join(missing)}", rid)

        def text(name: str) -> str:
            value = raw[name]
            if not isinstance(value, str) or not value.strip():
                raise RuleError(source, f"'{name}' must be a non-empty string", rid)
            return " ".join(value.split())

        rule_id = text("id")
        id_match = RULE_ID.fullmatch(rule_id)
        if id_match is None:
            raise RuleError(source, "id must look like RC-<AREA>-<NNN>", rule_id)
        area = text("area")
        if area not in AREAS:
            raise RuleError(source, f"unknown area {area!r} ({', '.join(AREAS)})", rule_id)
        if id_match.group(1) != AREAS[area].prefix:
            raise RuleError(
                source, f"id prefix must be RC-{AREAS[area].prefix}- for area {area}", rule_id
            )
        try:
            severity = Severity.parse(text("severity"))
            confidence = Confidence.parse(text("confidence"))
        except ValueError as exc:
            raise RuleError(source, str(exc), rule_id) from None
        message = text("message")
        _check_placeholders(message, source, rule_id)

        case_sensitive = _bool(raw, "case_sensitive", source, rule_id)
        files = self.globset(
            raw.get("files", {"set": DEFAULT_FILESET}), source, rule_id, "files", case_sensitive
        )
        exclude = self.globset(raw.get("exclude", []), source, rule_id, "exclude", case_sensitive)
        check = self.check(raw["check"], source, rule_id, case_sensitive)
        references = _str_tuple(raw, "references", source, rule_id)
        for ref in references:
            if not ref.startswith("https://"):
                raise RuleError(source, f"reference must be an https URL: {ref!r}", rule_id)
        platforms = _str_tuple(raw, "platforms", source, rule_id)
        if not set(platforms) <= PLATFORMS:
            raise RuleError(
                source, f"platforms must be from {', '.join(sorted(PLATFORMS))}", rule_id
            )
        since = raw.get("since")
        if since is not None and not isinstance(since, str | int | float):
            raise RuleError(source, "'since' must be a version string", rule_id)
        return Rule(
            id=rule_id,
            title=text("title"),
            area=area,
            category=AREAS[area].category,
            severity=severity,
            confidence=confidence,
            check=check,
            message=message,
            rationale=text("rationale"),
            recommendation=text("recommendation"),
            files=files,
            exclude=exclude,
            references=references,
            tags=_str_tuple(raw, "tags", source, rule_id),
            platforms=platforms,
            deprecated=_bool(raw, "deprecated", source, rule_id),
            since=None if since is None else str(since),
            source=source,
        )

    def check(self, raw: object, source: str, rule_id: str, case_sensitive: bool) -> Check:
        if not isinstance(raw, dict) or not all(isinstance(k, str) for k in raw):
            raise RuleError(source, "'check' must be a mapping", rule_id)
        check_type = raw.get("type")
        if not isinstance(check_type, str):
            raise RuleError(source, "check 'type' is required", rule_id)
        if check_type in PLANNED:
            raise RuleError(
                source,
                f"check type {check_type!r} is not available yet (milestone {PLANNED[check_type]})",
                rule_id,
            )
        builder = BUILDERS.get(check_type)
        if builder is None:
            raise RuleError(
                source, f"unknown check type {check_type!r} ({', '.join(BUILDERS)})", rule_id
            )
        try:
            return builder(Params(raw), BuildEnv(self.patterns, case_sensitive))
        except CheckError as exc:
            raise RuleError(source, f"check {check_type}: {exc}", rule_id) from None

    def unsupported(self, raw: object, source: str) -> UnsupportedSurface:
        if not isinstance(raw, dict):
            raise RuleError(source, "each entry must be a mapping")
        unknown = sorted(set(raw) - set(_UNSUPPORTED_FIELDS))
        if unknown:
            raise RuleError(source, f"unknown field(s): {', '.join(map(str, unknown))}")
        scope, reason = raw.get("scope"), raw.get("reason")
        if not isinstance(scope, str) or not isinstance(reason, str) or "files" not in raw:
            raise RuleError(source, "entries need 'scope', 'files' and 'reason'")
        contains = raw.get("contains")
        if contains is not None and not isinstance(contains, str):
            raise RuleError(source, f"{scope}: 'contains' must be a regex string")
        try:
            pattern = BuildEnv(self.patterns).compile(contains, re.MULTILINE) if contains else None
        except CheckError as exc:
            raise RuleError(source, f"{scope}: {exc}") from None
        max_size = raw.get("max_size")
        if max_size is not None and (
            not isinstance(max_size, int) or isinstance(max_size, bool) or max_size <= 0
        ):
            raise RuleError(source, f"{scope}: 'max_size' must be a positive number of bytes")
        return UnsupportedSurface(
            scope=scope,
            reason=" ".join(reason.split()),
            files=self.globset(raw["files"], source, None, "files", False),
            exclude=self.globset(raw.get("exclude", []), source, None, "exclude", False),
            contains=pattern,
            source=source,
            max_size=max_size,
        )


def _check_placeholders(message: str, source: str, rule_id: str) -> None:
    rest = PLACEHOLDER.sub("", message)
    if "{" in rest or "}" in rest:
        raise RuleError(source, "message braces must form {placeholder} names", rule_id)
    unknown = sorted(set(PLACEHOLDER.findall(message)) - PLACEHOLDERS)
    if unknown:
        raise RuleError(
            source,
            f"unknown placeholder(s) {', '.join(unknown)} in message "
            f"(allowed: {', '.join(sorted(PLACEHOLDERS))})",
            rule_id,
        )


def _bool(raw: Mapping[str, object], name: str, source: str, rule_id: str | None) -> bool:
    value = raw.get(name, False)
    if not isinstance(value, bool):
        raise RuleError(source, f"'{name}' must be true or false", rule_id)
    return value


def _str_tuple(
    raw: Mapping[str, object], name: str, source: str, rule_id: str | None
) -> tuple[str, ...]:
    value = raw.get(name, [])
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        raise RuleError(source, f"'{name}' must be a list of strings", rule_id)
    return tuple(value)


# --- entry points ----------------------------------------------------------------


def load_rules(extra_dirs: Sequence[Path] = ()) -> RuleSet:
    """Built-in rules plus rules from ``--rules`` folders (never from the scanned repo)."""
    return load_rule_dirs([RULES_DIR, *extra_dirs])


def load_rule_dirs(dirs: Sequence[Path]) -> RuleSet:
    raw_patterns: dict[str, object] = {}
    filesets: dict[str, list[str]] = {}
    rule_files: list[Path] = []
    unsupported_files: list[Path] = []
    for directory in dirs:
        if not directory.is_dir():
            raise RuleError(str(directory), "rules folder not found")
        patterns_file = directory / PATTERNS_FILE
        if patterns_file.is_file():
            data = _as_mapping(_read_yaml(patterns_file), str(patterns_file), "patterns")
            for name in data:
                if name in raw_patterns:
                    raise RuleError(str(patterns_file), f"pattern {name!r} is defined twice")
            raw_patterns.update(data)
        filesets_file = directory / FILESETS_FILE
        if filesets_file.is_file():
            data = _as_mapping(_read_yaml(filesets_file), str(filesets_file), "file sets")
            for name, globs in _validate_filesets(data, str(filesets_file)).items():
                if name in filesets:
                    raise RuleError(str(filesets_file), f"file set {name!r} is defined twice")
                filesets[name] = globs
        if (directory / UNSUPPORTED_FILE).is_file():
            unsupported_files.append(directory / UNSUPPORTED_FILE)
        rule_files.extend(
            p
            for p in sorted(directory.glob("*.yaml"))
            if p.is_file() and not p.name.startswith("_")
        )

    patterns = _resolve_patterns(raw_patterns, "patterns")
    if DEFAULT_FILESET not in filesets:
        raise RuleError("file sets", f"the default file set {DEFAULT_FILESET!r} is missing")
    builder = _Builder(patterns, filesets)

    rules: list[Rule] = []
    seen: dict[str, str] = {}
    for path in rule_files:
        for raw in _as_list(_read_yaml(path), str(path), "a rule file"):
            rule = builder.rule(raw, str(path))
            if rule.id in seen:
                raise RuleError(str(path), f"duplicate id (also in {seen[rule.id]})", rule.id)
            seen[rule.id] = str(path)
            rules.append(rule)
    unsupported = [
        builder.unsupported(raw, str(path))
        for path in unsupported_files
        for raw in _as_list(_read_yaml(path), str(path), "unsupported surfaces")
    ]
    rules.sort(key=lambda r: r.id)
    return RuleSet(rules, unsupported, patterns, filesets)
