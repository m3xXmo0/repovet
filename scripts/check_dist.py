"""Check the built wheel and sdist in a dist folder (``uv build``).

Usage: python scripts/check_dist.py [DIST_DIR]

- the wheel contains every module, rule file and data file of ``src/repovet``, the
  ``repovet`` console script, the LICENSE file and the license expression
- the sdist contains the same package files, the tests and the project files, and
  nothing else from the project folder (no local working files or caches)
"""

import sys
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "src" / "repovet"
# Top-level entries an sdist may contain; anything else in the project folder (local
# working files, caches, virtual environments) must stay out.
SDIST_TOP_LEVEL = {
    "src",
    "tests",
    "docs",
    "scripts",
    "README.md",
    "RULES.md",
    "LICENSE",
    "CHANGELOG.md",
    "SECURITY.md",
    "pyproject.toml",
    "uv.lock",
    ".gitignore",
    "PKG-INFO",
}
SDIST_REQUIRED = {
    "README.md",
    "RULES.md",
    "LICENSE",
    "CHANGELOG.md",
    "SECURITY.md",
    "pyproject.toml",
    "tests/conftest.py",
    "docs/report.schema.json",
}
SCRIPT_ENTRY = "repovet = repovet.cli:main"
LICENSE = "MIT"


def package_files() -> set[str]:
    """Files of the package, relative to ``src`` (posix), without caches."""
    return {
        p.relative_to(PACKAGE.parent).as_posix()
        for p in PACKAGE.rglob("*")
        if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc"
    }


def check_wheel(path: Path, expected: set[str]) -> list[str]:
    errors: list[str] = []
    with zipfile.ZipFile(path) as wheel:
        names = set(wheel.namelist())
        info = [n for n in names if n.endswith(".dist-info/entry_points.txt")]
        entry_points = wheel.read(info[0]).decode() if info else ""
        meta = [n for n in names if n.endswith(".dist-info/METADATA")]
        metadata = wheel.read(meta[0]).decode() if meta else ""
    packaged = {n for n in names if n.startswith("repovet/")}
    errors += [f"wheel: missing {n}" for n in sorted(expected - packaged)]
    errors += [f"wheel: unexpected {n}" for n in sorted(packaged - expected)]
    if SCRIPT_ENTRY not in entry_points:
        errors.append(f"wheel: console script '{SCRIPT_ENTRY}' missing")
    if not any(n.endswith(".dist-info/licenses/LICENSE") for n in names):
        errors.append("wheel: LICENSE missing")
    if f"License-Expression: {LICENSE}" not in metadata.splitlines():
        errors.append(f"wheel: metadata does not declare License-Expression: {LICENSE}")
    return errors


def check_sdist(path: Path, expected: set[str]) -> list[str]:
    errors: list[str] = []
    with tarfile.open(path) as sdist:
        # Only the member names are read; nothing is extracted.
        names = {PurePosixPath(*PurePosixPath(n).parts[1:]).as_posix() for n in sdist.getnames()}
    packaged = {n.removeprefix("src/") for n in names if n.startswith("src/repovet/")}
    errors += [f"sdist: missing src/{n}" for n in sorted(expected - packaged)]
    errors += [f"sdist: missing {n}" for n in sorted(SDIST_REQUIRED - names)]
    for name in sorted(names):
        parts = PurePosixPath(name).parts
        if (parts and parts[0] not in SDIST_TOP_LEVEL) or "__pycache__" in parts:
            errors.append(f"sdist: must not contain {name}")
    return errors


def main(argv: list[str]) -> int:
    dist = Path(argv[1]) if len(argv) > 1 else ROOT / "dist"
    wheels = sorted(dist.glob("repovet-*.whl"))
    sdists = sorted(dist.glob("repovet-*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        print(f"expected one wheel and one sdist in {dist}", file=sys.stderr)
        return 2
    expected = package_files()
    errors = check_wheel(wheels[0], expected) + check_sdist(sdists[0], expected)
    for error in errors:
        print(error, file=sys.stderr)
    if not errors:
        print(f"ok: {wheels[0].name}, {sdists[0].name} ({len(expected)} package files)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
