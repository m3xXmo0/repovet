"""Facts about declared local dependency sources; all paths stay lexical.

No target is resolved, opened or tested for existence. ``within_repository`` means
lexical containment of a relative path, not that a package exists or was checked.
Absolute and environment-dependent locations cannot be mapped to a Git tree.
"""

import re
from collections.abc import Iterator
from typing import TypedDict
from urllib.parse import unquote, urlsplit

from repovet.parsers.manifests import Dependency, Manifest

_DRIVE = re.compile(r"\A[A-Za-z]:")
_URI_DRIVE = re.compile(r"\A/[A-Za-z]:")
_VARIABLE = re.compile(r"\$|%[^%/\\]{1,200}%")
_SCHEME = re.compile(r"\A[A-Za-z][A-Za-z0-9+.-]*:")
_MAX_TARGET_LENGTH = 4096
_MAX_SHOWN_LENGTH = 512


class DependencySource(TypedDict):
    manifest: str
    package: str
    source: str
    kind: str
    within_repository: bool | None


def _shown(value: str) -> str:
    return value if len(value) <= _MAX_SHOWN_LENGTH else value[:_MAX_SHOWN_LENGTH] + "…"


def _target(dep: Dependency) -> tuple[str, str, str | None] | None:
    value = dep.spec.strip()
    if dep.ecosystem == "pypi":
        value = re.split(r"\s+;", value, maxsplit=1)[0].strip()
    protocol = value.partition(":")[0].lower()
    if protocol == "workspace":
        return None
    if protocol in {"file", "link", "portal"}:
        try:
            parsed = urlsplit(value)
            target = unquote(parsed.path, errors="strict")
        except (ValueError, UnicodeError):
            return "", "[unresolved local source]", "unresolved"
        host = parsed.netloc.rsplit("@", 1)[-1]
        # User info, queries and fragments are not package locations and may contain
        # credentials. They are intentionally absent from these neutral facts.
        source = (
            f"{protocol}://{host}{parsed.path}"
            if value.lower().startswith(f"{protocol}://")
            else f"{protocol}:{parsed.path}"
        )
        if host and host.lower() != "localhost":
            if _DRIVE.fullmatch(host):
                target = host + target
            else:
                return target, _shown(source), "unc"
        if _URI_DRIVE.match(target):
            target = target[1:]
        return target, _shown(source), None
    if _DRIVE.match(value):
        return value, _shown(value), None
    if _SCHEME.match(value):
        return None
    if dep.kind != "path" and not value.startswith(("\\", "/", "~", ".")):
        return None
    return value, _shown(value), None


def _location(manifest: str, target: str) -> tuple[str, bool | None]:
    if not target or len(target) > _MAX_TARGET_LENGTH:
        return "unresolved", None
    if _VARIABLE.search(target) or target.startswith("~"):
        return "environment", None
    normalized = target.replace("\\", "/")
    if normalized.startswith("//"):
        return "unc", None
    if _DRIVE.match(target):
        return (
            ("windows_absolute", None)
            if normalized[2:].startswith("/")
            else ("windows_drive_relative", None)
        )
    if target.startswith("\\"):
        return "windows_root_relative", None
    if target.startswith("/"):
        return "posix_absolute", None
    parent = manifest.replace("\\", "/").split("/")[:-1]
    if any(part in ("", ".", "..") for part in parent):
        return "unresolved", None
    for part in normalized.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if not parent:
                return "relative", False
            parent.pop()
        else:
            parent.append(part)
    return "relative", True


def local_sources(manifest_path: str, manifest: Manifest) -> Iterator[DependencySource]:
    """Declared local sources, once per package/source pair in this manifest."""
    seen: set[tuple[str, str, str, bool | None]] = set()
    for dep in manifest.dependencies:
        declared = _target(dep)
        if declared is None:
            continue
        target, shown, forced_kind = declared
        kind, inside = (forced_kind, None) if forced_kind else _location(manifest_path, target)
        package = shown if dep.name == dep.spec else _shown(dep.name)
        key = (package, shown, kind, inside)
        if key in seen:
            continue
        seen.add(key)
        yield {
            "manifest": manifest_path,
            "package": package,
            "source": shown,
            "kind": kind,
            "within_repository": inside,
        }
