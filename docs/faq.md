# FAQ

**Does repovet upload my code?** No. The analysis runs on your computer and makes no
network connections. There are only two: downloading a repository you gave as a GitHub
URL (from github.com), and the trust check, which asks the public GitHub API about the
repository and its owner (`api.github.com`; not your files). `--offline` turns the API
off; a local folder with `--offline` makes no connection at all.

**Does "no findings" mean the repository is safe?** No. It means that none of repovet's
rules matched in the part that was checked. repovet looks for known patterns and keeps
false alarms low; someone who knows the rules can avoid them. Read "Not checked" in every
report and stay careful.

**What do I do with a false positive?** Read the `Why` of the finding: some findings are
right but harmless in your case (an official installer that pipes `curl` into `sh`, for
example). To hide a rule in your own runs, use `--ignore-rule RC-...`; repovet never reads
such settings from the checked repository. If a rule is plainly wrong, please
[report it](https://github.com/m3xXmo0/repovet/issues/new/choose) with a small, harmless
example – it helps everyone.

**Does it run on Windows, macOS and Linux?** Yes, with Python 3.12 or newer (uv takes
care of that).

**Can repovet itself be attacked through a repository?** It is built not to be: it never
runs, imports or builds anything from the repository, never calls the `git` program, and
masks invisible and control characters before printing. See
[Security model](security-model.md); please report problems privately
([SECURITY.md](../SECURITY.md)).

**Does repovet find known vulnerabilities in my dependencies?** No, by design; see
[Scope and limits](limits.md).
