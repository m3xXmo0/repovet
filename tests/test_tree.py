import pytest

from repovet.sources.tree import GlobSet, basename, decode_text, validate_glob


@pytest.mark.parametrize(
    ("pattern", "path", "expected"),
    [
        ("**/package.json", "package.json", True),
        ("**/package.json", "a/b/package.json", True),
        ("**/package.json", "a/b/package.json.bak", False),
        ("package.json", "a/package.json", False),
        (".cursor/rules/**", ".cursor/rules/x.mdc", True),
        (".cursor/rules/**", ".cursor/rules/sub/x.mdc", True),
        (".cursor/rules/**", ".cursor/rules", False),
        ("*.md", "README.md", True),
        ("*.md", "docs/README.md", False),
        ("**/*.md", "docs/deep/README.md", True),
        ("file?.txt", "file1.txt", True),
        ("file?.txt", "file/.txt", False),
        ("**", "anything/at/all", True),
        ("**/node_modules/**", "a/node_modules/b/c.json", True),
        ("a.b", "aXb", False),
    ],
)
def test_glob_matching(pattern: str, path: str, expected: bool) -> None:
    assert GlobSet([pattern]).matches(path) is expected


def test_glob_case_sensitivity() -> None:
    assert GlobSet(["**/CLAUDE.md"]).matches("docs/claude.md")
    assert not GlobSet(["**/CLAUDE.md"], case_sensitive=True).matches("docs/claude.md")


def test_empty_globset_matches_nothing() -> None:
    assert not GlobSet([]).matches("a")
    assert not GlobSet([])


@pytest.mark.parametrize("pattern", ["", "/abs", "a\\b", "a//b", "../x", "a/./b", "a**/b"])
def test_invalid_globs(pattern: str) -> None:
    with pytest.raises(ValueError, match="glob"):
        validate_glob(pattern)


def test_basename() -> None:
    assert basename("a/b/c.txt") == "c.txt"
    assert basename("c.txt") == "c.txt"


def test_decode_utf8_with_and_without_bom() -> None:
    plain = decode_text("grüße".encode())
    bom = decode_text(b"\xef\xbb\xbf" + "grüße".encode())
    assert plain is not None and plain.text == "grüße" and not plain.fallback
    assert bom is not None and bom.text == "grüße"


def test_decode_utf16_with_bom() -> None:
    decoded = decode_text("hello\u202e".encode("utf-16"))
    assert decoded is not None and decoded.text == "hello\u202e"


def test_decode_binary_and_latin1_fallback() -> None:
    assert decode_text(b"MZ\x00\x00\x90") is None
    latin = decode_text(b"caf\xe9")
    assert latin is not None and latin.fallback and latin.text == "café"
