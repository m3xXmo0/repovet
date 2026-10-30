import pytest

from repovet.parsers.codelex import family_of, literal_spans


def _kinds(text: str, path: str) -> list[tuple[str, str]]:
    spans = literal_spans(text, path)
    assert spans is not None
    return [(k, text[s:e]) for s, e, k in zip(spans.starts, spans.ends, spans.kinds, strict=True)]


@pytest.mark.parametrize(
    ("path", "family"),
    [
        ("src/a.ts", "c"),
        ("x/y.PY", "python"),
        ("Dockerfile", "shell"),
        ("run.ps1", "powershell"),
        ("a.cmd", "batch"),
        ("README.md", None),
        ("Makefile", None),
    ],
)
def test_family_of(path: str, family: str | None) -> None:
    assert family_of(path) == family


def test_c_family() -> None:
    text = "a = \"x // y\"; // c1\nb = `t\nu`; /* c2\n*/ c = 'q'"
    assert _kinds(text, "a.js") == [
        ("s", '"x // y"'),
        ("c", "// c1"),
        ("s", "`t\nu`"),
        ("c", "/* c2\n*/"),
        ("s", "'q'"),
    ]


def test_python_family() -> None:
    text = 'x = """doc\n# not a comment\n"""  # real\ny = f"a#b"\n'
    assert _kinds(text, "a.py") == [
        ("s", '"""doc\n# not a comment\n"""'),
        ("c", "# real"),
        ("s", '"a#b"'),
    ]


def test_shell_hash_only_after_space() -> None:
    assert _kinds('echo $# "${#a}" # c\n', "a.sh") == [("s", '"${#a}"'), ("c", "# c")]


def test_unclosed_literals_end_at_the_line_or_text_end() -> None:
    assert _kinds("a = 'open\nb = 1 /* open", "a.c") == [("s", "'open"), ("c", "/* open")]
    assert _kinds('x = """open', "a.py") == [("s", '"""open')]


def test_other_families() -> None:
    assert _kinds("<# block #> $a = 'x' # c", "a.ps1") == [
        ("c", "<# block #>"),
        ("s", "'x'"),
        ("c", "# c"),
    ]
    assert _kinds('--[[ a ]] x = "s" -- c', "a.lua") == [
        ("c", "--[[ a ]]"),
        ("s", '"s"'),
        ("c", "-- c"),
    ]
    assert _kinds('REM c\necho "x"\n:: c2', "a.bat") == [
        ("c", "REM c"),
        ("s", '"x"'),
        ("c", ":: c2"),
    ]
    assert _kinds("x = \"it's\" ' c", "a.vbs") == [("s", '"it\'s"'), ("c", "' c")]


def test_kind_at() -> None:
    text = 'f("ab") // c'
    spans = literal_spans(text, "a.ts")
    assert spans is not None
    assert spans.kind_at(0) is None
    assert spans.kind_at(3) == ("s", 2)
    assert spans.kind_at(text.index("c")) == ("c", text.index("//"))
    assert literal_spans(text, "notes.txt") is None
