import pytest

from repovet.limits import DEFAULT_LIMITS, Limits
from repovet.parsers.structured import ParseError, find_line, parse


def test_parse_each_format() -> None:
    assert parse('{"a": [1]}', "json", DEFAULT_LIMITS) == {"a": [1]}
    assert parse('{"a": 1, // c\n}', "jsonc", DEFAULT_LIMITS) == {"a": 1}
    assert parse('[build-system]\nbuild-backend = "x"\n', "toml", DEFAULT_LIMITS) == {
        "build-system": {"build-backend": "x"}
    }
    assert parse("a:\n  - b\n", "yaml", DEFAULT_LIMITS) == {"a": ["b"]}


@pytest.mark.parametrize(
    ("text", "fmt"),
    [
        ("{", "json"),
        ("[" * 100_000 + "]" * 100_000, "json"),
        ("a = ", "toml"),
        ("a: [", "yaml"),
        ("!!python/object/apply:os.getcwd []", "yaml"),
        ("a: 1\n---\nb: 2\n", "yaml"),
    ],
)
def test_parse_errors(text: str, fmt: str) -> None:
    with pytest.raises(ParseError):
        parse(text, fmt, DEFAULT_LIMITS)


def test_yaml_alias_bomb_is_refused() -> None:
    # "Billion laughs": few aliases, but 9**9 nodes once expanded.
    lines = ['a: &a ["x", "x", "x", "x", "x", "x", "x", "x", "x"]']
    previous = "a"
    for name in "bcdefghi":
        lines.append(f"{name}: &{name} [{', '.join(['*' + previous] * 9)}]")
        previous = name
    with pytest.raises(ParseError, match="aliases expanded"):
        parse("\n".join(lines), "yaml", DEFAULT_LIMITS)


def test_yaml_alias_count_limit() -> None:
    text = "a: &a 1\nb: [" + ", ".join(["*a"] * 20) + "]\n"
    with pytest.raises(ParseError, match="aliases"):
        parse(text, "yaml", Limits(yaml_max_aliases=10))


def test_yaml_recursive_alias_is_refused() -> None:
    with pytest.raises(ParseError, match="recursive"):
        parse("a: &a [*a]\n", "yaml", DEFAULT_LIMITS)


def test_yaml_shared_aliases_within_limits_are_fine() -> None:
    assert parse("a: &a [1, 2]\nb: *a\nc: [*a, *a]\n", "yaml", DEFAULT_LIMITS) == {
        "a": [1, 2],
        "b": [1, 2],
        "c": [[1, 2], [1, 2]],
    }


def test_yaml_node_limit() -> None:
    text = "\n".join(f"k{i}: v" for i in range(100))
    with pytest.raises(ParseError, match="nodes"):
        parse(text, "yaml", Limits(yaml_max_nodes=50))


def test_find_line_follows_key_path_and_prefers_value_line() -> None:
    text = """{
  "tasks": [
    {"label": "a", "runOptions": {"runOn": "default"}},
    {"label": "b",
     "runOptions": {"runOn": "folderOpen"}}
  ]
}"""
    assert find_line(text, ("tasks", 1, "runOptions", "runOn"), "folderOpen") == 5
    assert find_line(text, ("tasks", 0, "runOptions", "runOn"), "default") == 3
    assert find_line(text, ("missing",), None) is None


def test_find_line_toml_table_header() -> None:
    text = 'name = "x"\n\n[build-system]\nbuild-backend = "evil"\n'
    assert find_line(text, ("build-system", "build-backend"), "evil") == 4


def test_find_line_prefers_the_exact_quoted_value() -> None:
    text = '{\n  "allow": [\n    "Bash(uv run *)",\n    "Read",\n    "Bash"\n  ]\n}'
    assert find_line(text, ("allow", 2), "Bash") == 5
    assert find_line(text, ("allow", 0), "Bash(uv run *)") == 3
