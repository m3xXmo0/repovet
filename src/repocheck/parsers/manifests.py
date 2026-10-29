"""Dependencies and package sources from Python and npm manifests, without running them.

Supported: requirements files (``*.txt``/``*.in``), ``pyproject.toml`` (PEP 621, PEP 735
dependency groups, Poetry, uv), ``setup.cfg``, ``Pipfile`` and ``package.json``.
``setup.py`` is code and is handled by the autorun area. Line numbers are best effort.
"""

import configparser
import re
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field

from repocheck.parsers.structured import find_line, line_of_offset

type Loader = Callable[[str], object | None]

_NAME = re.compile(r"[ \t]*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)[ \t]*(\[[^\]\n]*\])?")
_SEPARATORS = re.compile(r"[-_.]+")
_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:")
_GIT_HOSTS = re.compile(r"(?:github|gitlab|bitbucket|gist):", re.IGNORECASE)
_NPM_GIT_SHORTHAND = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:#.*)?")
_REQ_OPTION = re.compile(
    r"[ \t]*(-i|--index-url|--extra-index-url|-f|--find-links|--trusted-host)"
    r"(?:[ \t]*=[ \t]*|[ \t]+)(\S+)"
)
_REQ_EDITABLE = re.compile(r"[ \t]*(?:-e|--editable)(?:[ \t]*=[ \t]*|[ \t]+)(\S+)")
_REQ_SKIP = re.compile(r"[ \t]*-")
_COMMENT = re.compile(r"(?:\A|[ \t])#.*")


@dataclass(frozen=True)
class Dependency:
    ecosystem: str  # "pypi" or "npm"
    name: str  # as written (for npm aliases: the real package)
    spec: str  # version specifier, URL, path or Git reference as written
    kind: str  # registry | git | url | path
    line: int | None = None

    @property
    def normalized(self) -> str:
        return normalize(self.ecosystem, self.name)


@dataclass(frozen=True)
class IndexSource:
    """A package index or registry that a manifest tells the installer to use."""

    ecosystem: str
    option: str  # e.g. --extra-index-url, tool.uv.index
    url: str
    line: int | None = None


@dataclass
class Manifest:
    dependencies: list[Dependency] = field(default_factory=list)
    indexes: list[IndexSource] = field(default_factory=list)


def normalize(ecosystem: str, name: str) -> str:
    """PEP 503 for PyPI (case, runs of ``-_.``); npm names are only lower-cased."""
    if ecosystem == "pypi":
        return _SEPARATORS.sub("-", name).lower()
    return name.lower()


def classify_target(target: str) -> str:
    """git, url or path for a direct reference (``name @ <target>``, ``-e <target>``)."""
    lowered = target.strip().lower()
    if lowered.startswith(("git+", "git:", "hg+", "svn+", "bzr+")) or lowered.endswith(".git"):
        return "git"
    if lowered.startswith("file:") or not _SCHEME.match(lowered):
        return "path"
    return "url"


def parse_requirement(text: str) -> tuple[str, str, str] | None:
    """(name, rest, kind) of a PEP 508 requirement; ``None`` if there is no name."""
    match = _NAME.match(text)
    if match is None:
        return None
    rest = text[match.end() :].strip()
    if rest.startswith("@"):
        return match.group(1), rest[1:].strip(), classify_target(rest[1:])
    return match.group(1), rest, "registry"


def _requirements(text: str) -> Manifest:
    manifest = Manifest()
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        number = index + 1
        line = lines[index]
        while line.endswith("\\") and index + 1 < len(lines):
            index += 1
            line = line[:-1] + " " + lines[index]
        index += 1
        line = _COMMENT.sub("", line).strip()
        if not line:
            continue
        option = _REQ_OPTION.match(line)
        if option is not None:
            manifest.indexes.append(IndexSource("pypi", option.group(1), option.group(2), number))
            continue
        editable = _REQ_EDITABLE.match(line)
        if editable is not None:
            target = editable.group(1)
            egg = re.search(r"[#&]egg=([A-Za-z0-9._-]+)", target)
            name = egg.group(1) if egg else target
            manifest.dependencies.append(
                Dependency("pypi", name, target, classify_target(target), number)
            )
            continue
        if _REQ_SKIP.match(line):
            continue  # -r/-c includes and other pip options
        if _SCHEME.match(line) or line.startswith((".", "/")) or line.endswith((".whl", ".zip")):
            kind = classify_target(line)
            manifest.dependencies.append(Dependency("pypi", line, line, kind, number))
            continue
        parsed = parse_requirement(line)
        if parsed is not None:
            manifest.dependencies.append(
                Dependency("pypi", parsed[0], parsed[1], parsed[2], number)
            )
    return manifest


def _string_line(text: str, value: str) -> int | None:
    for quote in ('"', "'"):
        found = text.find(f"{quote}{value}{quote}")
        if found != -1:
            return line_of_offset(text, found)
    return None


def _pep508_list(text: str, values: object, manifest: Manifest) -> None:
    if not isinstance(values, list):
        return
    for value in values:
        if not isinstance(value, str):
            continue
        parsed = parse_requirement(value)
        if parsed is not None:
            line = _string_line(text, value)
            manifest.dependencies.append(Dependency("pypi", parsed[0], parsed[1], parsed[2], line))


def _table(data: object, *keys: str) -> Mapping[str, object]:
    for key in keys:
        if not isinstance(data, dict):
            return {}
        data = data.get(key)
    return data if isinstance(data, dict) else {}


def _list(value: object) -> list[object]:
    return value if isinstance(value, list) else []


def _source_table(name: str, spec: object) -> tuple[str, str] | None:
    """(kind, target) for Poetry/Pipfile/uv tables with git, url, path or file keys."""
    if not isinstance(spec, dict):
        return None
    for key, kind in (("git", "git"), ("url", "url"), ("path", "path"), ("file", "path")):
        target = spec.get(key)
        if isinstance(target, str):
            return (classify_target(target) if key == "file" else kind), target
    return None


def _named_tables(
    text: str, section: str, table: Mapping[str, object], manifest: Manifest, path: list[str]
) -> None:
    for name, spec in table.items():
        if name.lower() == "python":
            continue
        source = _source_table(name, spec)
        line = find_line(text, [*path, name])
        if source is not None:
            manifest.dependencies.append(Dependency("pypi", name, source[1], source[0], line))
        else:
            version = spec if isinstance(spec, str) else str(_table(spec).get("version", ""))
            manifest.dependencies.append(Dependency("pypi", name, version, "registry", line))


def _pyproject(text: str, data: object) -> Manifest:
    manifest = Manifest()
    project = _table(data, "project")
    _pep508_list(text, project.get("dependencies"), manifest)
    for extra in _table(data, "project", "optional-dependencies").values():
        _pep508_list(text, extra, manifest)
    for group in _table(data, "dependency-groups").values():
        _pep508_list(text, group, manifest)
    _pep508_list(text, _table(data, "build-system").get("requires"), manifest)

    poetry = _table(data, "tool", "poetry")
    _named_tables(text, "poetry", _table(poetry, "dependencies"), manifest, ["dependencies"])
    _named_tables(
        text, "poetry", _table(poetry, "dev-dependencies"), manifest, ["dev-dependencies"]
    )
    for group in _table(poetry, "group").values():
        _named_tables(text, "poetry", _table(group, "dependencies"), manifest, ["dependencies"])
    for entry in _list(poetry.get("source")):
        url = entry.get("url") if isinstance(entry, dict) else None
        if isinstance(url, str):
            option = "tool.poetry.source"
            manifest.indexes.append(IndexSource("pypi", option, url, _string_line(text, url)))

    uv = _table(data, "tool", "uv")
    for name, spec in _table(uv, "sources").items():
        source = _source_table(name, spec)
        if source is not None:
            line = find_line(text, ["sources", name])
            manifest.dependencies.append(Dependency("pypi", name, source[1], source[0], line))
    for entry in _list(uv.get("index")):
        url = entry.get("url") if isinstance(entry, dict) else None
        if isinstance(url, str):
            manifest.indexes.append(
                IndexSource("pypi", "tool.uv.index", url, _string_line(text, url))
            )
    for key in ("index-url", "extra-index-url"):
        values = uv.get(key)
        for url in (
            [values] if isinstance(values, str) else values if isinstance(values, list) else []
        ):
            if isinstance(url, str):
                option = f"tool.uv.{key}"
                manifest.indexes.append(IndexSource("pypi", option, url, _string_line(text, url)))
    return manifest


def _setup_cfg(text: str) -> Manifest:
    manifest = Manifest()
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    try:
        parser.read_string(text)
    except configparser.Error as exc:
        raise ValueError(f"invalid setup.cfg: {exc}") from None
    values: list[str] = []
    if parser.has_section("options"):
        for key in ("install_requires", "setup_requires", "tests_require"):
            values.append(parser.get("options", key, fallback=""))
    if parser.has_section("options.extras_require"):
        values.extend(v for _, v in parser.items("options.extras_require"))
    for block in values:
        for raw in block.splitlines():
            requirement = _COMMENT.sub("", raw).strip()
            parsed = parse_requirement(requirement) if requirement else None
            if parsed is not None:
                line = _line_containing(text, requirement)
                manifest.dependencies.append(
                    Dependency("pypi", parsed[0], parsed[1], parsed[2], line)
                )
    return manifest


def _line_containing(text: str, needle: str) -> int | None:
    found = text.find(needle)
    return line_of_offset(text, found) if found != -1 else None


def _pipfile(text: str, data: object) -> Manifest:
    manifest = Manifest()
    for section in ("packages", "dev-packages"):
        _named_tables(text, "pipfile", _table(data, section), manifest, [section])
    sources = data.get("source") if isinstance(data, dict) else None
    for entry in sources if isinstance(sources, list) else []:
        url = entry.get("url") if isinstance(entry, dict) else None
        if isinstance(url, str):
            manifest.indexes.append(
                IndexSource("pypi", "Pipfile source", url, _string_line(text, url))
            )
    return manifest


def classify_npm(spec: str) -> tuple[str, str | None]:
    """(kind, real package name for ``npm:`` aliases) of a package.json version string."""
    value = spec.strip()
    lowered = value.lower()
    if lowered.startswith("npm:"):
        target = value[4:]
        at = target.rfind("@")
        return "registry", target[:at] if at > 0 else target
    if lowered.startswith(("file:", "link:", "portal:", "workspace:")) or lowered.startswith(
        (".", "/", "~")
    ):
        return "path", None
    if lowered.startswith(("git+", "git:")) or _GIT_HOSTS.match(lowered):
        return "git", None
    if lowered.startswith(("http:", "https:")):
        return "url", None
    if _NPM_GIT_SHORTHAND.fullmatch(value) and not value.startswith("@"):
        return "git", None
    return "registry", None


def _package_json(text: str, data: object) -> Manifest:
    manifest = Manifest()
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        for name, spec in _table(data, section).items():
            if not isinstance(spec, str):
                continue
            kind, alias = classify_npm(spec)
            line = find_line(text, [section, name])
            manifest.dependencies.append(Dependency("npm", alias or name, spec, kind, line))
    return manifest


def manifest_type(name: str) -> str | None:
    lowered = name.lower()
    if lowered == "pyproject.toml":
        return "pyproject"
    if lowered == "setup.cfg":
        return "setup_cfg"
    if lowered == "pipfile":
        return "pipfile"
    if lowered == "package.json":
        return "package_json"
    if lowered.endswith((".txt", ".in")):
        return "requirements"
    return None


def parse_manifest(name: str, text: str, load: Loader) -> Manifest | None:
    """Manifest of a file called ``name``. ``load(format)`` returns the parsed TOML/JSON
    data (``None`` if it could not be parsed); ``ValueError`` for broken setup.cfg."""
    kind = manifest_type(name)
    if kind == "requirements":
        return _requirements(text)
    if kind == "setup_cfg":
        return _setup_cfg(text)
    if kind in ("pyproject", "pipfile"):
        data = load("toml")
        if data is None:
            return None
        return _pyproject(text, data) if kind == "pyproject" else _pipfile(text, data)
    if kind == "package_json":
        data = load("json")
        return None if data is None else _package_json(text, data)
    return None


def iter_dependencies(manifest: Manifest, ecosystems: set[str]) -> Iterator[Dependency]:
    return (d for d in manifest.dependencies if d.ecosystem in ecosystems)
