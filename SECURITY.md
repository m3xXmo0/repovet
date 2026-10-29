# Security policy

repovet reads repositories that may have been written by an attacker. Bugs that let
such a repository break repovet's own guarantees are security issues, and I would like
to hear about them privately first.

## Supported versions

Only the latest release on PyPI gets security fixes.

## Reporting a vulnerability

Please do **not** open a public issue, pull request or discussion for a vulnerability.

Report it privately through GitHub instead:

1. Open <https://github.com/m3xXmo0/repovet/security/advisories/new>
   (or the repository's **Security** tab, then **Report a vulnerability**).
2. Describe the problem, the repovet version, your operating system and Python
   version, and the steps or a minimal repository that shows it. Use harmless
   placeholders instead of working malware.

You will get an answer in the advisory. repovet is maintained in spare time, so please
allow about a week for a first reply. Once a fix is released, the advisory is
published, and you are credited unless you prefer not to be.

## What counts as a vulnerability

Anything where a checked repository, a crafted URL or a GitHub API answer makes
repovet:

- run code, scripts, hooks, filters or programs from the checked repository, or start
  any other process;
- write, change or delete files outside the report file you asked for, follow a
  symlink, junction or reparse point, or change the checked folder;
- connect to hosts other than `github.com` (for URL targets) and `api.github.com`
  (trust area), or connect at all with `--offline` for a local folder;
- reveal the GitHub token in output, logs, error messages or requests to other hosts;
- write unmasked control or invisible characters to the terminal, JSON or SARIF
  output (for example ANSI escape sequences that change the terminal);
- hang, run out of memory or fill the disk on a small input, beyond the documented
  limits (for example a pathological regular expression or a decompression bomb).

Not a vulnerability: a malicious repository that repovet does not report. A finding
that is missing is a gap in the rules; please open a normal issue for it, with a
harmless example. If the example would teach a new evasion technique that is not
public yet, report it privately as described above.
