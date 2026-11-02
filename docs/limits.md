# Scope and limits

<!-- scope:start -->
repovet checks what a repository can do to you before you run it, and how it declares
its dependencies: whether a package name is plausible and where a package comes from. It
does not check whether a pinned version has known vulnerabilities; for that, use
[pip-audit](https://github.com/pypa/pip-audit),
[npm audit](https://docs.npmjs.com/cli/commands/npm-audit) or
[OSV-Scanner](https://github.com/google/osv-scanner). The analysis is offline because
of this scope: checking a repository must not run anything from it or send anything
about it elsewhere. repovet never calls a repository safe; it reports what its rules
detect and lists under "Not checked" what it could not look at.
<!-- scope:end -->

## What it does not do

repovet **never runs anything** from the repository, so it cannot be tricked into
executing a payload while it checks for one.

And **"no findings" does not mean "safe".** It means only that none of the rules matched
in the part of the repository that was checked. repovet looks for known patterns with
few false alarms; it never gives a safe/unsafe verdict or a score. Always read the
"Not checked" section of the report.

## Limits: what is not checked

**"No findings" does not mean "safe".** It only means that none of the rules matched in
the part of the repository that was checked. repovet looks for known patterns with few
false alarms; an attacker who knows the rules can avoid them.

Not checked today:

- **Trust** needs the GitHub API: with `--offline`, for a folder without a GitHub remote,
  or when the API cannot be reached or its rate limit is used up, the report lists it
  under "Not checked" (the scan itself continues).
- **Provenance profile:** languages are recognized by file extension or name only, and
  licenses by distinctive phrases of common license texts; neither is a code or legal
  review. A local folder's `.git` folder is not part of the profile.
- **Git history** is read only from a URL clone or a local `.git` folder that has no
  links, no alternates and no `commondir` (otherwise it is listed under "Not checked"); at
  most 100,000 commits. Commit dates, authors and trailers are free text chosen by whoever
  commits, so all history facts are indicators. AI indicators only show that a tool was
  named, not who or what wrote the code. SHA-256 repositories and reftable refs are not
  supported.
- **Dependencies** are checked by name and declared source only, offline: names are
  compared with lists of the most downloaded PyPI and npm packages shipped with repovet
  (see `src/repovet/data/SOURCES.md`). The code and install scripts of dependencies, known
  vulnerabilities and transitive dependencies are not checked; Rust, Go, Ruby, PHP and
  Java dependencies are not checked at all.
- **Binary files** are recognized by their signature only: archives are not unpacked,
  programs and documents are not analyzed. Content of Git submodules and Git LFS objects is
  not checked; both are listed under "Not checked".
- **Obfuscation and download-and-execute** are only checked in source and script files
  (not in Markdown, JSON or notebooks; decode-and-run pipelines also in autotools files),
  not in test modules (`test_*.py`, `*.test.ts`,
  `testdata/`, `fixtures/`, ...) and, for the noisier rules, not in build output (`dist/`,
  `build/`, `*.min.js`, ...). Code in comment lines is ignored. A download kept in a
  variable is recognized when it is run within the next five lines; across files only
  through a chain from an auto-run entry point (at most two files). Encoded strings split
  into parts are recognized only when the parts are constants of the same file. Strings
  assembled at run time (host names, flags kept in variables) are not reconstructed.
- **Auto-run surfaces that are recognized but not analyzed:** Maven, `go:generate`, CMake,
  JetBrains `.idea/` settings. Others are only partly checked: GitHub Actions workflows for
  `pull_request_target` checkouts, untrusted event text in scripts, encoded commands and
  secrets sent to request catchers, MSBuild files for `Exec`, build events, `DownloadFile`
  and inline tasks, Rust `build.rs` for network access, Composer for install
  hooks and downloads, Gradle for external commands, downloads and the wrapper URL, Ruby
  gemspecs, Rakefiles and Gemfiles for native extensions and downloads. If present, they
  are listed under "Not checked".
- **URL targets:** only public repositories on `https://github.com/<owner>/<repo>`; other
  hosts and SSH, `git://` or `file://` URLs are rejected. Git submodules are listed, never
  fetched. The default limits are 500 MB download and 300 seconds.
- **Skipped files:** files larger than `--max-file-size` (default 2 MB), environment and
  tool cache folders unless `--include-env-dirs` is given, symlinks and junctions (listed,
  never followed), files that cannot be read or parsed. All of them appear under "Not
  checked".
- **Line numbers** in JSON, TOML and YAML files are best effort.
- **Plain-text instructions** in agent files are matched by combinations of words in one
  sentence (run a command, send data to an address, keep it from the user), not by
  understanding the text; reworded instructions can slip through, and quoted examples are
  reported as low.
- **Out of scope by design:** running, sandboxing or dynamic analysis of repository code;
  known vulnerabilities (CVE) in dependencies (use pip-audit, npm audit or OSV-Scanner);
  leaked secrets; antivirus signatures; a total score or a safe/unsafe verdict.

Read the "Not checked" section of every report. Gaps in coverage do not change the exit
code of `repovet scan`; for `repovet diff`, see [the diff guide](diff.md#coverage-decisions).
