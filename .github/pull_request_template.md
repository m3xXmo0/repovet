## What and why

<!-- What does this change, and why? Link the issue if there is one. -->

## Checklist

- [ ] Nothing from a checked repository is run, imported or written to (no
      `subprocess`, `eval`/`exec`, `git` binary, package managers).
- [ ] New or changed rules have at least one positive and one harmless negative case in
      `tests/rule_cases/`, and `RULES.md` is regenerated
      (`uv run repovet rules list --markdown`).
- [ ] Test data is harmless (placeholder domains such as `example.invalid`, dummy
      payloads; invisible characters only as escapes).
- [ ] Reports never call a repository safe, clean or secure.
- [ ] No new runtime dependency (or the reason is explained above).
- [ ] `uv run pytest`, `uv run mypy src tests scripts`, `uv run ruff check` and
      `uv run ruff format --check` pass.
- [ ] `CHANGELOG.md` has an entry under "Unreleased" if users notice the change.
