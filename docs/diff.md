# Compare two Git revisions

Run `repovet diff PATH --base REV --head REV` against a local Git repository.
`--head` defaults to `HEAD`; Base is required. Both revisions are scanned with the
same current rules and limits. The scanner reads Git objects through dulwich: it
does not check out files, run Git, start hooks, run package managers or execute code
from either revision. The local working folder is not part of the comparison.

Supported revision names are `HEAD`, complete commit IDs, branch names, tags and
full `refs/...` names. Revision expressions such as `HEAD~1` are not supported.
Base must be a proven ancestor of Head. A shallow clone is sufficient if its present
objects prove that relationship; missing history is never fetched implicitly.
An unknown or invalid revision is a usage error. Missing, damaged, oversized or
unrelated history makes the comparison incomplete.

## Findings and the gate

Findings are compared as occurrences, not only as totals. A versioned fingerprint
groups the same rule and normalized match content. Ordinary fingerprints exclude
line numbers and paths, so a justified rename or line shift can retain a finding.
Repeated occurrences preserve their multiplicity. Paths, positions and file identities
help disambiguate them; equal plausibility remains explicit rather than being resolved
arbitrarily. Ordered chain steps include their paths and file contents, so a changed
intermediate file does not disappear behind an unchanged endpoint line.

The displayed states are `new`, `unchanged`, `updated` and `absent`. The last means
that a finding was no longer detected in a comparable checked scope, not a guarantee
that a problem is fixed. Increases in severity and promotion from a test, docs,
example or vendored context to ordinary code count as worsened. Parts of a chain
continue to count through their chain finding.

| Exit | Meaning for diff |
|---|---|
| 0 | No new or worsened finding reached `--fail-on` in a complete comparison. |
| 1 | A new or worsened finding reached `--fail-on`. |
| 2 | Invalid arguments, revision or saved baseline. |
| 3 | Incomplete comparison, lost coverage or ambiguous assignment. |

`--fail-on` defaults to high. `--min-severity` only filters the displayed changes;
it does not change the gate. The JSON summary and nested complete scan reports
retain the full comparison. An unchanged critical finding can return 0.

A green diff means "nothing new that the rules could see at the chosen threshold".
It does not replace a full scan. A changed implementation below an unchanged
`postinstall` line is visible only within the existing bounded chain analysis.
Fingerprints reduce matching noise; they are not a tamper-proof content attestation.

## Coverage decisions

- A changed file that exceeds a size, line, parse or match limit is unknown and
  blocks with exit 3, even if Base only had low findings in that file.
- Exception: a changed or new image is listed under "Not checked" without blocking.
  Its first bytes must carry a PNG, JPEG, GIF, WebP, BMP or ICO signature that matches
  its extension, it may only be unchecked because it is binary or larger than the
  size limit, and it must have no finding in Head. Only the file header is read, so
  this does not depend on the file size. A wrong extension, an unknown binary or an
  image that a rule flags still blocks.
- A previous finding outside the current rule's scope is unknown, not absent.
- Equal unchecked scopes with unchanged contents are warnings and do not block.
- Growing coverage can expose an old finding; it is conservatively treated as new.
- External package contents are not checked. That general dependency limitation is
  distinct from a failed analysis of the local manifest itself.
- Missing Git objects, unproven ancestry and genuine matching ambiguity block the gate.

## Report formats and stored baselines

Use `--format text`, `json` or `sarif`. With `-o FILE`, the output must be outside
the checked repository. Repository strings are sanitized before display. JSON includes
lossless canonical URI paths for matching as well as shorter human-readable paths;
these have different purposes and consumers should not use display paths as identity.

Scan JSON uses schema 1.5 and diff JSON schema 1.0. The complete current ruleset digest
and tool version accompany the results. The definitions are in `report.schema.json`
and `diff.schema.json`. SARIF remains 2.1.0 and uses `baselineState` and
`partialFingerprints.primaryLocationLineHash`; that hash combines the fingerprint with
the file, so code scanning keeps one alert per file and treats a moved finding as a new
alert, while `diff` still reports it as updated. Unknown results are never marked
absent, and an incomplete SARIF invocation is not reported as successful.

`--base-report FILE` is an explicit fallback for a saved unfiltered offline Git scan
report or the Head side of a previous JSON diff. The commit, snapshot and identities
must be present, and the snapshot's root must match its local Git commit. Base is
still required to be an ancestor of Head. Filtered, online, old-schema and working
folder reports cannot provide this baseline. Tool-version or ruleset-digest changes
are warned: their deltas may be detector changes rather than code changes. Rescanning
both commits remains the default and avoids this mismatch.

The pinned GitHub upload action preserves an existing `primaryLocationLineHash` but
can warn that its own context hash differs. That implementation behavior was checked
at commit `6f2ac81f5cd81fe351a197ba0b00d91d03cd2aee`; future action changes need review.

## Corpus and benchmark regression data

Corpus baseline format 2.0 stores compact individual finding fingerprints, coverage,
snapshots and real tool/ruleset metadata. Foreign message, evidence and reference text
is omitted, and coverage reason text is hashed. Counts are derived from the stored
findings. The old counts-only format is incompatible: regenerate the full baseline
deliberately with `uv run python scripts/corpus_counts.py --update-baseline`.

`scripts/fp_benchmark.py --compare FILE` uses the same matcher for repositories that
were successfully measured on both sides. Different commits are explicitly warned;
skipped repositories are not treated as fixed. Historical aggregate-only files support
only an aggregate comparison, not reconstructed individual identities.

The dependency extension stops at named coverage boundaries and neutral local-source
facts. Additional lockfile detection remains deferred until a real case justifies it.
