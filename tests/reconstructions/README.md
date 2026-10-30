# Reconstructions of documented attack techniques

Each file describes one publicly documented supply-chain incident or repository-based
attack technique and rebuilds only its *shape* as inline fixture files. The files are
created in a temporary folder during the test and scanned offline; nothing is run.

- Hosts are placeholders (`example.invalid`); commands are harmless; there are no
  working payloads and no real indicators (hashes, command-and-control hosts, wallets).
- `sources` link to public, verifiable reports (advisories, CVEs, post-mortems).
- `must_fire` / `must_not_fire` are checked by `tests/test_reconstructions.py`.
- `known_gaps` are rules that should fire but do not. They are kept as written instead
  of weakening the expectation; the test fails as soon as a gap closes, so it can be
  moved to `must_fire`.
- `not_covered` names parts of a technique that are outside what repovet checks.
- `variants` are hand-written rewrites of one or more fixture files that use an evasion
  technique (a variable, a helper script, another downloader, a split string, plain
  prose ...): each has an `id`, a one-line `technique` and `files` that replace the
  canonical files of the same name (`null` removes one) or add new ones. A variant must
  reach, in the files it rewrites, at least the highest severity that the canonical
  fixture's expected findings reach there (a chain counts for every file on its path).
  A variant that stays below is listed under `known_gaps` as `{variant: ID, reason: ...}`;
  the test fails when a variant falls below without such an entry, or when a listed
  variant is detected.

Run `uv run python scripts/reconstructions.py` for an overview.
