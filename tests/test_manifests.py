import json
import tomllib

import pytest

from repovet.parsers.manifests import (
    Manifest,
    classify_npm,
    classify_target,
    normalize,
    parse_manifest,
    parse_requirement,
)


def parse(name: str, text: str) -> Manifest:
    def load(fmt: str) -> object:
        return tomllib.loads(text) if fmt == "toml" else json.loads(text)

    manifest = parse_manifest(name, text, load)
    assert manifest is not None
    return manifest


def deps(manifest: Manifest) -> list[tuple[str, str, int | None]]:
    return [(d.name, d.kind, d.line) for d in manifest.dependencies]


def test_normalize() -> None:
    assert normalize("pypi", "Typing_Extensions") == "typing-extensions"
    assert normalize("pypi", "zope.interface") == "zope-interface"
    assert normalize("npm", "@Types/Node") == "@types/node"


def test_parse_requirement() -> None:
    assert parse_requirement("requests[socks]>=2 ; python_version>'3'") == (
        "requests",
        ">=2 ; python_version>'3'",
        "registry",
    )
    assert parse_requirement("tool @ git+https://example.invalid/t.git") == (
        "tool",
        "git+https://example.invalid/t.git",
        "git",
    )
    assert parse_requirement("x @ file:///tmp/x") == ("x", "file:///tmp/x", "path")
    assert parse_requirement(">=1") is None


def test_classify() -> None:
    assert classify_target("https://example.invalid/a.tar.gz") == "url"
    assert classify_target("https://example.invalid/a.git") == "git"
    assert classify_target("../lib") == "path"
    assert classify_npm("^1.0.0") == ("registry", None)
    assert classify_npm("npm:real-name@^2") == ("registry", "real-name")
    assert classify_npm("npm:@scope/real@1") == ("registry", "@scope/real")
    assert classify_npm("user/repo#v1") == ("git", None)
    assert classify_npm("github:user/repo") == ("git", None)
    assert classify_npm("https://example.invalid/x.tgz") == ("url", None)
    assert classify_npm("workspace:^") == ("path", None)
    assert classify_npm("link:../x") == ("path", None)


def test_requirements_file() -> None:
    text = (
        "# comment\n"
        "requests==2.31 # pinned\n"
        "--extra-index-url=https://pkgs.example.invalid/simple\n"
        "-i https://pypi.org/simple\n"
        "-r other.txt\n"
        "-e git+https://example.invalid/t.git#egg=tool\n"
        "numpy \\\n"
        "  >=1.26\n"
        "https://example.invalid/pkg-1.0.whl\n"
        "./local/pkg\n"
    )
    manifest = parse("requirements.txt", text)
    assert deps(manifest) == [
        ("requests", "registry", 2),
        ("tool", "git", 6),
        ("numpy", "registry", 7),
        ("https://example.invalid/pkg-1.0.whl", "url", 9),
        ("./local/pkg", "path", 10),
    ]
    assert [(i.option, i.url, i.line) for i in manifest.indexes] == [
        ("--extra-index-url", "https://pkgs.example.invalid/simple", 3),
        ("-i", "https://pypi.org/simple", 4),
    ]


def test_pyproject() -> None:
    text = """
[build-system]
requires = ["hatchling"]

[project]
dependencies = ["httpx>=0.27", "pkg @ https://example.invalid/pkg.tar.gz"]

[project.optional-dependencies]
dev = ["pytest"]

[dependency-groups]
lint = ["ruff", {include-group = "dev"}]

[tool.poetry.dependencies]
python = "^3.12"
lib = { git = "https://example.invalid/lib.git" }
rich = "^13"

[tool.poetry.group.test.dependencies]
hypothesis = { version = "^6" }

[tool.uv.sources]
mylib = { path = "../mylib" }

[[tool.uv.index]]
url = "https://pkgs.example.invalid/simple"
"""
    manifest = parse("pyproject.toml", text)
    found = {(name, kind) for name, kind, _ in deps(manifest)}
    assert found == {
        ("hatchling", "registry"),
        ("httpx", "registry"),
        ("pkg", "url"),
        ("pytest", "registry"),
        ("ruff", "registry"),
        ("lib", "git"),
        ("rich", "registry"),
        ("hypothesis", "registry"),
        ("mylib", "path"),
    }
    lines = {name: line for name, _, line in deps(manifest)}
    assert lines["httpx"] == 6
    assert lines["lib"] == 16
    assert [(i.option, i.line) for i in manifest.indexes] == [("tool.uv.index", 26)]


def test_setup_cfg_and_pipfile() -> None:
    cfg = (
        "[options]\ninstall_requires =\n    click>=8\n    attrs\n"
        "[options.extras_require]\nx = rich\n"
    )
    assert deps(parse("setup.cfg", cfg)) == [
        ("click", "registry", 3),
        ("attrs", "registry", 4),
        ("rich", "registry", 6),
    ]
    with pytest.raises(ValueError, match=r"setup\.cfg"):
        parse("setup.cfg", "no section header\n")
    pipfile = (
        '[[source]]\nurl = "https://pkgs.example.invalid/simple"\n'
        '[packages]\nrequests = "*"\ntool = {git = "https://example.invalid/t.git"}\n'
    )
    manifest = parse("Pipfile", pipfile)
    assert deps(manifest) == [("requests", "registry", 4), ("tool", "git", 5)]
    assert [i.url for i in manifest.indexes] == ["https://pkgs.example.invalid/simple"]


def test_package_json() -> None:
    text = (
        '{\n  "dependencies": {\n    "a": "^1",\n    "b": "npm:real@2"\n  },\n'
        '  "devDependencies": {"c": "github:u/c"}\n}'
    )
    assert deps(parse("package.json", text)) == [
        ("a", "registry", 3),
        ("real", "registry", 4),
        ("c", "git", 6),
    ]


def test_unparseable_and_unknown_files() -> None:
    assert parse_manifest("package.json", "{broken", lambda fmt: None) is None
    assert parse_manifest("README.md", "x", lambda fmt: None) is None
