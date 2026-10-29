"""Area ``provenance``: what the repository is made of and how it came about.

The profile is facts, not findings: ``facts["provenance"]`` for JSON/SARIF and summary
lines for the terminal. Data (languages, markers, license phrases) lives in
``data/languages.yaml`` and ``data/provenance.yaml``. Findings come only from RC-PROV
rules.
"""

import re
import time
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import cache
from pathlib import Path

import yaml

from repovet.engine.checks.base import FileView
from repovet.engine.context import ScanContext
from repovet.engine.runner import FileObserver, run_rules
from repovet.limits import format_size
from repovet.models import AreaResult, CoverageStatus
from repovet.parsers.structured import ParseError, parse
from repovet.sources import gitmeta
from repovet.sources.tree import GlobSet, RepoFile, basename, decode_text

AREA = "provenance"
DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_BINARY_PROBE = 8192
_HEADER_BYTES = 1024
_LICENSE_BYTES = 256 * 1024
_TOP_LEVEL = 30
_SAMPLE = 5
_SHOWN_LANGUAGES = 5
_CODE_KINDS = ("programming", "markup")
_SPACES = re.compile(r"\s+")


@dataclass(frozen=True)
class Language:
    name: str
    kind: str


@dataclass(frozen=True)
class Marker:
    key: str
    label: str
    globs: GlobSet
    exclude: GlobSet = field(default_factory=lambda: GlobSet([]))

    def matches(self, path: str) -> bool:
        return self.globs.matches(path) and not self.exclude.matches(path)


@dataclass(frozen=True)
class LicenseText:
    spdx: str
    phrases: tuple[str, ...]


@dataclass(frozen=True)
class DeclaredLicense:
    file: str
    fmt: str
    paths: tuple[str, ...]


@dataclass(frozen=True)
class AiMarker:
    tool: str
    message: re.Pattern[str] | None
    author: re.Pattern[str] | None


@dataclass(frozen=True)
class ProfileData:
    by_extension: Mapping[str, Language]
    by_name: Mapping[str, Language]
    markers: tuple[Marker, ...]
    notable: tuple[Marker, ...]
    generated_header: re.Pattern[str]
    licenses: tuple[LicenseText, ...]
    declared: tuple[DeclaredLicense, ...]
    ai_markers: tuple[AiMarker, ...] = ()


def _read_data(name: str) -> dict[str, object]:
    data = yaml.safe_load((DATA_DIR / name).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"data/{name} must be a mapping")
    return data


@cache
def _languages() -> tuple[dict[str, Language], dict[str, Language]]:
    by_extension: dict[str, Language] = {}
    by_name: dict[str, Language] = {}
    for name, spec in _read_data("languages.yaml").items():
        if not isinstance(spec, dict):
            raise ValueError(f"data/languages.yaml: {name!r} must be a mapping")
        language = Language(str(name), str(spec["type"]))
        for ext in spec.get("extensions", []):
            by_extension.setdefault(str(ext).lower(), language)
        for filename in spec.get("filenames", []):
            by_name.setdefault(str(filename).lower(), language)
    return by_extension, by_name


def _globs(raw: object, filesets: Mapping[str, Sequence[str]]) -> GlobSet:
    if not isinstance(raw, list):
        raise ValueError("data/provenance.yaml: 'files' must be a list")
    patterns: list[str] = []
    for item in raw:
        if isinstance(item, dict) and set(item) == {"set"}:
            patterns.extend(filesets.get(str(item["set"]), ()))
        else:
            patterns.append(str(item))
    return GlobSet(patterns)


def _markers(raw: object, filesets: Mapping[str, Sequence[str]]) -> tuple[Marker, ...]:
    if not isinstance(raw, dict):
        raise ValueError("data/provenance.yaml: markers must be a mapping")
    return tuple(
        Marker(
            str(key),
            str(spec["label"]),
            _globs(spec["files"], filesets),
            _globs(spec.get("exclude", []), filesets),
        )
        for key, spec in raw.items()
    )


def _strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError("data/provenance.yaml: expected a list of strings")
    return tuple(str(item) for item in value)


def _list(data: Mapping[str, object], key: str) -> list[dict[str, object]]:
    value = data.get(key, [])
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError(f"data/provenance.yaml: {key} must be a list of mappings")
    return value


def load_profile_data(filesets: Mapping[str, Sequence[str]]) -> ProfileData:
    """Profile data; file sets come from the loaded rules (``{set: name}`` entries)."""
    data = _read_data("provenance.yaml")
    by_extension, by_name = _languages()
    licenses, declared, markers = (
        _list(data, "licenses"),
        _list(data, "declared_license"),
        _list(data, "ai_markers"),
    )
    return ProfileData(
        by_extension=by_extension,
        by_name=by_name,
        markers=_markers(data["markers"], filesets),
        notable=_markers(data["notable"], filesets),
        generated_header=re.compile(str(data["generated_header"])),
        licenses=tuple(LicenseText(str(item["id"]), _strings(item["all"])) for item in licenses),
        declared=tuple(
            DeclaredLicense(str(item["file"]), str(item["format"]), _strings(item["paths"]))
            for item in declared
        ),
        ai_markers=tuple(
            AiMarker(
                str(item["tool"]),
                re.compile(str(item["message"])) if item.get("message") else None,
                re.compile(str(item["author"])) if item.get("author") else None,
            )
            for item in markers
        ),
    )


def language_of(path: str, data: ProfileData) -> Language | None:
    name = basename(path).lower()
    if name in data.by_name:
        return data.by_name[name]
    _, dot, ext = name.rpartition(".")
    return data.by_extension.get(f".{ext}") if dot else None


def detect_license(text: str, data: ProfileData) -> str | None:
    normalized = _SPACES.sub(" ", text.lower())
    for entry in data.licenses:
        if all(phrase in normalized for phrase in entry.phrases):
            return entry.spdx
    return None


@dataclass
class _LanguageStats:
    kind: str
    files: int = 0
    lines: int = 0
    bytes: int = 0


@dataclass
class _Profile:
    files: int = 0
    bytes: int = 0
    text_files: int = 0
    binary_files: int = 0
    unread_files: int = 0
    lines: int = 0
    languages: dict[str, _LanguageStats] = field(default_factory=dict)
    generated: list[tuple[str, int]] = field(default_factory=list)
    markers: dict[str, list[str]] = field(default_factory=dict)
    notable: dict[str, list[str]] = field(default_factory=dict)
    licenses: list[tuple[str, str | None]] = field(default_factory=list)


def _read(file: RepoFile, limit: int) -> bytes | None:
    if file.size > limit:
        return None
    try:
        return file.read_bytes(limit)
    except OSError:
        return None


def _is_license_file(path: str, globs: GlobSet) -> bool:
    return globs.matches(path) and (path.count("/") == 0 or path.lower().startswith("licenses/"))


def is_repository_file(path: str) -> bool:
    """False inside a local folder's ``.git`` (config, hooks): local state, not content.
    Leaving it out keeps folder and URL profiles identical."""
    return ".git" not in path.casefold().split("/")[:-1]


def repository_files(ctx: ScanContext) -> list[RepoFile]:
    return [f for f in ctx.tree.files() if is_repository_file(f.path)]


class FileProfiler:
    """Collects the file profile one file at a time (during the shared file pass)."""

    def __init__(self, ctx: ScanContext, data: ProfileData) -> None:
        self.data = data
        self.profile = _Profile()
        self.generated = GlobSet(
            [*ctx.rules.filesets.get("generated", ()), *ctx.rules.filesets.get("vendored", ())]
        )
        self.license_globs = next(
            (m.globs for m in data.markers if m.key == "license"), GlobSet([])
        )

    def observe(self, view: FileView) -> None:
        file, profile, data, generated = view.file, self.profile, self.data, self.generated
        path = file.path
        if not is_repository_file(path):
            return
        profile.files += 1
        profile.bytes += file.size
        for marker in data.markers:
            if marker.matches(path):
                profile.markers.setdefault(marker.key, []).append(path)
        for marker in data.notable:
            if marker.matches(path):
                profile.notable.setdefault(marker.key, []).append(path)
        language = language_of(path, data)
        content = view.content()
        if content is None:
            profile.unread_files += 1
            is_generated = generated.matches(path)
        elif b"\0" in content[:_BINARY_PROBE]:
            profile.binary_files += 1
            is_generated = generated.matches(path)
        else:
            profile.text_files += 1
            lines = content.count(b"\n") + (0 if not content or content.endswith(b"\n") else 1)
            profile.lines += lines
            header = content[:_HEADER_BYTES].decode("latin-1")
            is_generated = generated.matches(path) or (
                language is not None
                and language.kind != "prose"
                and data.generated_header.search(header) is not None
            )
            if language is not None:
                stats = profile.languages.setdefault(language.name, _LanguageStats(language.kind))
                stats.files += 1
                stats.lines += lines
                stats.bytes += file.size
            if _is_license_file(path, self.license_globs):
                decoded = decode_text(content[:_LICENSE_BYTES])
                profile.licenses.append(
                    (path, detect_license(decoded.text, data) if decoded else None)
                )
        if is_generated:
            profile.generated.append((path, file.size))


def start_observing(ctx: ScanContext) -> FileObserver:
    """Profile the files during the shared pass (``runner.prepare_file_rules``)."""
    profiler = FileProfiler(ctx, load_profile_data(ctx.rules.filesets))
    ctx.observed[AREA] = profiler
    return profiler.observe


def _scan_files(ctx: ScanContext, files: Sequence[RepoFile], data: ProfileData) -> _Profile:
    """The file profile, from the shared pass if there was one, else read now."""
    observed = ctx.observed.get(AREA)
    if isinstance(observed, FileProfiler):
        return observed.profile
    profiler = FileProfiler(ctx, data)
    for file in files:
        if ctx.out_of_time():
            break
        profiler.observe(FileView(file, ctx.limits, ctx.coverage))
    return profiler.profile


def _declared_licenses(
    ctx: ScanContext, files: Sequence[RepoFile], data: ProfileData
) -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    by_path = {f.path.lower(): f for f in files}
    for entry in data.declared:
        file = by_path.get(entry.file.lower())
        content = _read(file, ctx.limits.max_file_size) if file else None
        decoded = decode_text(content) if content is not None else None
        if decoded is None:
            continue
        try:
            parsed = parse(decoded.text, entry.fmt, ctx.limits)
        except ParseError:
            continue
        for dotted in entry.paths:
            value: object = parsed
            for key in dotted.split("."):
                value = value.get(key) if isinstance(value, dict) else None
            if isinstance(value, str) and value.strip():
                found.append({"path": entry.file, "value": value.strip()})
                break
    return found


def _count(number: object, noun: str) -> str:
    value = int(str(number))
    return f"{value:,} {noun}" if value == 1 else f"{value:,} {noun}s"


def _share(part: int, whole: int) -> float:
    return round(part / whole, 4) if whole else 0.0


def _percent(share: float) -> str:
    value = share * 100
    return f"{value:.0f}%" if value >= 1 or value == 0 else "<1%"


def _top_level(ctx: ScanContext, files: Sequence[RepoFile]) -> list[str]:
    entries: set[str] = set()
    for path in [f.path for f in files] + [link.path for link in ctx.tree.links()]:
        head, slash, _ = path.partition("/")
        entries.add(f"{head}/" if slash else head)
    # Folders first, then files, each in name order (case-insensitive).
    return sorted(entries, key=lambda e: (not e.endswith("/"), e.lower(), e))


def file_profile(
    ctx: ScanContext, data: ProfileData
) -> tuple[dict[str, object], list[tuple[str, str]]]:
    """Facts about the files and the matching summary lines."""
    files = repository_files(ctx)
    profile = _scan_files(ctx, files, data)
    code_bytes = sum(s.bytes for s in profile.languages.values() if s.kind in _CODE_KINDS)
    languages: list[dict[str, object]] = [
        {
            "name": name,
            "type": stats.kind,
            "files": stats.files,
            "lines": stats.lines,
            "bytes": stats.bytes,
            # Share of the programming and markup bytes (like GitHub's language bar).
            "share": _share(stats.bytes, code_bytes) if stats.kind in _CODE_KINDS else None,
        }
        for name, stats in sorted(profile.languages.items(), key=lambda kv: (-kv[1].bytes, kv[0]))
    ]
    largest = sorted(files, key=lambda f: (-f.size, f.path))[:_SAMPLE]
    top = _top_level(ctx, files)
    generated_bytes = sum(size for _, size in profile.generated)
    declared = _declared_licenses(ctx, files, data)
    present = [m.key for m in data.markers if m.key in profile.markers]
    missing = [m.key for m in data.markers if m.key not in profile.markers]
    notable = [
        {
            "kind": m.key,
            "label": m.label,
            "count": len(profile.notable[m.key]),
            "sample": sorted(profile.notable[m.key])[:_SAMPLE],
        }
        for m in data.notable
        if m.key in profile.notable
    ]
    facts: dict[str, object] = {
        "files": {
            "count": profile.files,
            "bytes": profile.bytes,
            "text_files": profile.text_files,
            "binary_files": profile.binary_files,
            "unread_files": profile.unread_files,
            "lines": profile.lines,
        },
        "languages": languages,
        "largest_files": [{"path": f.path, "bytes": f.size} for f in largest],
        "top_level": {"entries": top[:_TOP_LEVEL], "count": len(top)},
        "markers": {"present": present, "missing": missing},
        "generated": {
            "files": len(profile.generated),
            "bytes": generated_bytes,
            "file_share": _share(len(profile.generated), profile.files),
            "byte_share": _share(generated_bytes, profile.bytes),
            "sample": sorted(p for p, _ in profile.generated)[:_SAMPLE],
        },
        "license": {
            "files": [{"path": p, "detected": spdx} for p, spdx in sorted(profile.licenses)],
            "declared": declared,
        },
        "notable": notable,
    }
    labels = {m.key: m.label for m in data.markers}
    summary = _summary(profile, languages, largest, top, present, missing, labels)
    summary.append(("License", _license_text(sorted(profile.licenses), declared)))
    notable_paths = {
        m.key: profile.notable[m.key] for m in data.notable if m.key in profile.notable
    }
    summary += _notable_lines(notable_paths, {m.key: m.label for m in data.notable})
    return facts, summary


def _summary(
    profile: _Profile,
    languages: list[dict[str, object]],
    largest: Sequence[RepoFile],
    top: list[str],
    present: list[str],
    missing: list[str],
    labels: Mapping[str, str],
) -> list[tuple[str, str]]:
    lines: list[tuple[str, str]] = [
        (
            "Files",
            f"{_count(profile.files, 'file')}, {format_size(profile.bytes)}; "
            f"{_count(profile.text_files, 'text file')} with {_count(profile.lines, 'line')}, "
            f"{profile.binary_files:,} binary"
            + (f", {profile.unread_files:,} not read (too large)" if profile.unread_files else ""),
        )
    ]
    code = [lang for lang in languages if lang["share"] is not None]
    other = [lang for lang in languages if lang["share"] is None]
    if code:
        shown = ", ".join(
            f"{lang['name']} {_percent(float(str(lang['share'])))} "
            f"({_count(lang['files'], 'file')})"
            for lang in code[:_SHOWN_LANGUAGES]
        )
        more = len(code) - _SHOWN_LANGUAGES
        lines.append(("Languages", shown + (f", +{more} more" if more > 0 else "")))
    if other:
        shown = ", ".join(f"{lang['name']} ({lang['files']})" for lang in other[:_SHOWN_LANGUAGES])
        more = len(other) - _SHOWN_LANGUAGES
        lines.append(("Data, docs", shown + (f", +{more} more" if more > 0 else "")))
    if largest:
        lines.append(
            ("Largest", ", ".join(f"{f.path} ({format_size(f.size)})" for f in largest[:3]))
        )
    if top:
        more = len(top) - 8
        lines.append(("Top level", ", ".join(top[:8]) + (f" (+{more} more)" if more > 0 else "")))
    lines.append(("Present", ", ".join(labels[k] for k in present) or "none of the usual files"))
    if missing:
        lines.append(("Missing", ", ".join(labels[k] for k in missing)))
    if profile.generated:
        files_share = _percent(_share(len(profile.generated), profile.files))
        byte_share = _percent(_share(sum(s for _, s in profile.generated), profile.bytes))
        lines.append(
            (
                "Generated",
                f"{_count(len(profile.generated), 'file')} ({files_share} of files, "
                f"{byte_share} of bytes) are build output, vendored or marked as generated",
            )
        )
    return lines


def _notable_lines(
    notable: Mapping[str, list[str]], labels: Mapping[str, str]
) -> list[tuple[str, str]]:
    lines: list[tuple[str, str]] = []
    for key, paths in notable.items():
        more = f", +{len(paths) - 3} more" if len(paths) > 3 else ""
        text = f"{labels[key]} ({len(paths)}): {', '.join(sorted(paths)[:3])}{more}"
        lines.append(("" if lines else "Notable", text))
    return lines


def _license_text(files: list[tuple[str, str | None]], declared: list[dict[str, str]]) -> str:
    parts = [f"{spdx or 'text not recognized'} ({path}, text match)" for path, spdx in files]
    if not parts:
        parts = ["no license file found"]
    if declared:
        parts.append("declared " + ", ".join(f"{d['value']} ({d['path']})" for d in declared))
    return "; ".join(parts)


# --- history -----------------------------------------------------------------------


_DAY = 86_400
_TOP_AUTHORS = 5
_WEEKDAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
HISTORY_NOTE = (
    "Commit dates and authors are chosen by whoever makes a commit and can be faked; "
    "the history is an indicator, not proof."
)


def _date(timestamp: int) -> str:
    return datetime.fromtimestamp(timestamp, UTC).strftime("%Y-%m-%d")


def _span(seconds: int) -> str:
    days = seconds / _DAY
    if days >= 365:
        return f"{days / 365.25:.1f} years"
    if days >= 1:
        return f"{days:.0f} days"
    hours = seconds / 3600
    return f"{hours:.1f} hours" if hours >= 1 else f"{seconds // 60} minutes"


def _ai_tools(info: gitmeta.CommitInfo, data: ProfileData) -> set[str]:
    return {
        marker.tool
        for marker in data.ai_markers
        if (marker.message is not None and marker.message.search(info.message))
        or (marker.author is not None and marker.author.search(info.author))
    }


def history_profile(
    ctx: ScanContext, data: ProfileData
) -> tuple[dict[str, object] | None, list[tuple[str, str]]]:
    """Facts from the Git history (``None`` if there is none) and summary lines."""
    source = ctx.git
    if source is None:
        ctx.coverage.add("history", CoverageStatus.SKIPPED, ctx.git_note or gitmeta.REASON_NO_GIT)
        return None, []
    history = gitmeta.walk(source, ctx.limits, ctx.deadline)
    commits = history.commits
    if history.truncated:
        ctx.coverage.add(
            "history",
            CoverageStatus.PARTIAL,
            f"History longer than {ctx.limits.max_commits:,} commits or out of time; "
            "only part of it was read",
        )
    if source.shallow or history.missing:
        ctx.coverage.add(
            "history",
            CoverageStatus.PARTIAL,
            "Shallow or incomplete history: older commits are missing",
        )
    if history.unreadable:
        ctx.coverage.add(
            "history",
            CoverageStatus.FAILED,
            "Commits that could not be read (damaged or too large)",
            count=history.unreadable,
        )
    if not commits:
        return None, []

    now = int(time.time())
    names: dict[str, str] = {}
    authors: Counter[str] = Counter()
    domains: Counter[str] = Counter()
    for name, email in gitmeta.identities(commits):
        key = email or name.lower()
        names.setdefault(key, name or email)
        authors[key] += 1
        if "@" in email:
            domains[email.rpartition("@")[2]] += 1
    committers = {c.committer.partition("<")[2].rstrip(">").strip().lower() for c in commits}
    tools: Counter[str] = Counter()
    ai_commits = 0
    by_weekday = [0] * 7
    by_hour = [0] * 24
    for info in commits:
        found = _ai_tools(info, data)
        ai_commits += bool(found)
        tools.update(found)
        local = datetime.fromtimestamp(info.author_time + info.author_tz, UTC)
        by_weekday[local.weekday()] += 1
        by_hour[local.hour] += 1
    author_times = [c.author_time for c in commits]
    commit_times = [c.commit_time for c in commits]
    first = min(history.roots, key=lambda c: (c.author_time, c.sha)) if history.roots else None
    head_files = gitmeta.count_files(source.objects, source.head, ctx.limits.max_files)
    root_files = (
        gitmeta.count_files(source.objects, first.sha, ctx.limits.max_files) if first else None
    )
    root_share = _share(root_files, head_files) if root_files is not None and head_files else None
    signed = sum(c.signed for c in commits)
    tool_list = [tool for tool, _ in gitmeta.top(tools, len(tools))]
    facts: dict[str, object] = {
        "origin": source.origin,
        "head": source.head.decode("ascii"),
        "commits": len(commits),
        "complete": not (history.truncated or history.missing or source.shallow),
        "merges": sum(1 for c in commits if c.parents > 1),
        "root_commits": len(history.roots),
        "first_commit": _date(min(author_times)),
        "last_commit": _date(max(author_times)),
        "author_span_seconds": max(author_times) - min(author_times),
        "author_span_days": round((max(author_times) - min(author_times)) / _DAY, 1),
        "committer_span_seconds": max(commit_times) - min(commit_times),
        "authors": len(authors),
        "committers": len(committers),
        "top_authors": [
            {"name": names[key], "commits": n} for key, n in gitmeta.top(authors, _TOP_AUTHORS)
        ],
        "email_domains": [
            {"domain": domain, "commits": n} for domain, n in gitmeta.top(domains, _TOP_AUTHORS)
        ],
        "signed_commits": signed,
        "signed_share": _share(signed, len(commits)),
        "head_files": head_files,
        "root_files": root_files,
        "root_file_share": root_share,
        "root_file_percent": None if root_share is None else round(root_share * 100),
        "commits_after_root": len(commits) - 1,
        "future_commits": sum(1 for c in commits if max(c.author_time, c.commit_time) > now + _DAY),
        "author_after_commit": sum(1 for c in commits if c.author_time > c.commit_time + _DAY),
        "ai_commits": ai_commits,
        "ai_tools": ", ".join(tool_list),
        "ai_tool_commits": [{"tool": t, "commits": tools[t]} for t in tool_list],
        "by_weekday": dict(zip(_WEEKDAYS, by_weekday, strict=True)),
        "by_hour": by_hour,
    }
    return facts, _history_lines(facts, first, tools)


def _history_lines(
    facts: Mapping[str, object], first: gitmeta.CommitInfo | None, tools: Counter[str]
) -> list[tuple[str, str]]:
    commits = int(str(facts["commits"]))
    complete = "" if facts["complete"] else " (incomplete)"
    span = _span(int(str(facts["author_span_seconds"])))
    lines = [
        (
            "History",
            f"{_count(commits, 'commit')}{complete} from {facts['first_commit']} to "
            f"{facts['last_commit']} ({span}), {_count(facts['merges'], 'merge')}, "
            f"{_count(facts['authors'], 'author')}, "
            f"{_percent(float(str(facts['signed_share'])))} signed",
        )
    ]
    top_authors = facts["top_authors"]
    domains = facts["email_domains"]
    if isinstance(top_authors, list) and isinstance(domains, list):
        people = ", ".join(f"{a['name']} ({a['commits']})" for a in top_authors)
        mail = ", ".join(f"{d['domain']} ({d['commits']})" for d in domains)
        lines.append(("Authors", people + (f"; e-mail domains: {mail}" if mail else "")))
    if first is not None:
        share = facts["root_file_percent"]
        files = facts["root_files"]
        detail = (
            f" with {files} of {facts['head_files']} current files ({share}%)"
            if share is not None
            else ""
        )
        lines.append(
            (
                "Initial",
                f"{first.sha.decode('ascii')[:12]} on {_date(first.author_time)}{detail}",
            )
        )
    if tools:
        named = ", ".join(f"{tool} ({n})" for tool, n in gitmeta.top(tools, len(tools)))
        lines.append(
            (
                "AI tools",
                f"{named} commit(s) name an AI tool as co-author or generator; "
                "an indicator, not proof",
            )
        )
    lines.append(("", HISTORY_NOTE))
    return lines


def profile(ctx: ScanContext) -> tuple[dict[str, object], list[tuple[str, str]]]:
    """``{"provenance": facts}`` for the rules and reports, plus summary lines."""
    data = load_profile_data(ctx.rules.filesets)
    facts, summary = file_profile(ctx, data)
    history, lines = history_profile(ctx, data)
    if history is not None:
        facts["history"] = history
    return {AREA: facts}, summary + lines


def analyze(ctx: ScanContext) -> AreaResult:
    facts, summary = profile(ctx)
    findings = run_rules(ctx.rules.active(AREA), ctx, facts=facts)
    return AreaResult(AREA, findings, facts=facts, summary=summary)
