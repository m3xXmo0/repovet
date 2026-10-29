# Changelog

All notable changes to repovet are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). Rule IDs are never renamed or reused; the
exit codes and the JSON report (`schema_version`) are stable interfaces.

## [Unreleased]

### Added

- The terminal report honours `FORCE_COLOR`: when it is set to a non-empty value,
  colors are kept even when the output is piped, for example into `less -R`. `NO_COLOR`
  and `--no-color` still take precedence, and reports written with `-o` never contain
  colors.
- A demo GIF on the README (`docs/demo.gif`), rendered from `docs/demo.tape` with
  [VHS](https://github.com/charmbracelet/vhs). The manual workflow
  `.github/workflows/demo.yml` (trigger: `workflow_dispatch`) installs repovet from
  source, renders the tape against the public demo repository and uploads the GIF as an
  artifact; it commits nothing.

### Changed

- Reworked the README into a short introduction for new users (tagline, badges, the demo
  GIF, why it matters, a quick start and a one-line-per-area overview) followed by the
  existing detailed sections, now with a table of contents.

## [0.1.0] - 2026-10-29

First release.

### Added

- `repovet scan PATH|URL` statically checks a local folder or a public GitHub
  repository (`https://github.com/<owner>/<repo>`, optional `--ref`) without running
  anything from it. URL targets are fetched as Git objects only, with dulwich, into a
  temporary folder that is deleted after the scan.
- 126 detection rules in eight areas, defined as YAML data: auto-run code (`RC-AUTO`),
  AI agent instructions and configuration (`RC-AGENT`), obfuscation (`RC-OBF`),
  download-and-execute (`RC-DLX`), binaries and file-system tricks (`RC-BIN`),
  dependencies (`RC-DEP`), provenance indicators (`RC-PROV`) and trust indicators
  (`RC-TRUST`).
- Every finding has a rule ID, severity, confidence, file and line where it applies,
  a reason and a recommendation. Gaps in coverage are listed under "Not checked".
- Provenance profile from the files and the Git history, and a trust profile from the
  GitHub REST API (optional token from `GITHUB_TOKEN` or `GH_TOKEN`; `--offline` turns
  the API off).
- Reports for the terminal, as JSON (`schema_version` 1.2) and as SARIF 2.1.0. Text from
  the checked repository is masked before output.
- Options to filter (`--min-severity`), set the failure threshold (`--fail-on`), skip
  rules (`--ignore-rule`), add rule folders (`--rules`) and set size and time limits.
- `repovet rules list` (with `--area` and `--markdown`).
- Exit codes: 0 no findings at or above the threshold, 1 findings at or above the
  threshold, 2 usage error, 3 analysis aborted.
- Windows, macOS and Linux with Python 3.12 and 3.13.

[Unreleased]: https://github.com/m3xXmo0/repovet/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/m3xXmo0/repovet/releases/tag/v0.1.0
