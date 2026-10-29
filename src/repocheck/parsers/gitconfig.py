"""Git config files (``.git/config``) into nested data, without running git.

``[core]`` + ``hooksPath = x`` becomes ``{"core": {"hookspath": "x"}}``;
``[filter "lfs"]`` becomes ``{"filter": {"lfs": {...}}}``. Section and key names are
lower-cased (git treats them case-insensitively), subsection names keep their case.
A key without ``=`` is ``True``; a key given several times becomes a list.
"""

import re

_HEADER = re.compile(r'\[[ \t]*([A-Za-z0-9.-]+)(?:[ \t]+"((?:[^"\\\n]|\\.)*)")?[ \t]*\]')
_KEY = re.compile(r"([A-Za-z][A-Za-z0-9-]*)[ \t]*(?:=(.*))?")
_ESCAPES = {"n": "\n", "t": "\t", "b": "\b", '"': '"', "\\": "\\"}


def _unescape_subsection(raw: str) -> str:
    return re.sub(r"\\(.)", r"\1", raw)


def _section(data: dict[str, object], name: str, sub: str | None) -> dict[str, object]:
    name = name.lower()
    if sub is None and "." in name:
        name, sub = name.split(".", 1)
    node = data.get(name)
    if not isinstance(node, dict):
        node = {}
        data[name] = node
    if sub is None:
        return node
    child = node.get(sub)
    if not isinstance(child, dict):
        child = {}
        node[sub] = child
    return child


def _parse_value(first: str, lines: list[str], index: int) -> tuple[str, int]:
    """Value after ``=``: quotes removed, escapes resolved, comments dropped, lines ending
    in a backslash continued. Returns the value and the index of the next line."""
    out: list[str] = []
    quoted = False
    text = first
    while True:
        pos = 0
        continued = False
        while pos < len(text):
            char = text[pos]
            if char == "\\":
                if pos + 1 == len(text):
                    continued = True
                    break
                out.append(_ESCAPES.get(text[pos + 1], text[pos + 1]))
                pos += 2
                continue
            if char == '"':
                quoted = not quoted
            elif not quoted and char in "#;":
                break
            else:
                out.append(char)
            pos += 1
        if continued and index < len(lines):
            text = lines[index]
            index += 1
            continue
        return "".join(out).strip(), index


def _store(section: dict[str, object], key: str, value: object) -> None:
    if key not in section:
        section[key] = value
        return
    previous = section[key]
    if isinstance(previous, dict):
        return  # a subsection with the same name; keep the subsection
    if isinstance(previous, list):
        previous.append(value)
    else:
        section[key] = [previous, value]


def loads_gitconfig(text: str) -> dict[str, object]:
    data: dict[str, object] = {}
    section: dict[str, object] | None = None
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        number = index + 1
        line = lines[index].strip()
        index += 1
        if not line or line[0] in "#;":
            continue
        if line.startswith("["):
            header = _HEADER.match(line)
            if header is None:
                raise ValueError(f"invalid section header on line {number}")
            sub = header.group(2)
            section = _section(
                data, header.group(1), None if sub is None else _unescape_subsection(sub)
            )
            line = line[header.end() :].strip()
            if not line or line[0] in "#;":
                continue
        if section is None:
            raise ValueError(f"key outside of a section on line {number}")
        entry = _KEY.match(line)
        rest = line[entry.end() :] if entry else ""
        if entry is None or (entry.group(2) is None and rest and rest[0] not in "#;"):
            raise ValueError(f"invalid line {number}")
        key = entry.group(1).lower()
        if entry.group(2) is None:
            _store(section, key, True)
            continue
        value, index = _parse_value(entry.group(2), lines, index)
        _store(section, key, value)
    return data
