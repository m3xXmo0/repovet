# repovet rules

All detection rules that ship with repovet, grouped by area. Each rule is a YAML entry
in `src/repovet/rules/` with an ID, severity, confidence, file patterns, a check, and
texts for message, reason and recommendation. Rule IDs are never renamed or reused.

Severity says how bad it is if the finding means what the rule claims; confidence says
how likely that is. `critical` and `high` mean code runs automatically during normal use
(install, build, opening the folder, starting an agent) or something is clearly
disguised.

The tables below are generated with `uv run repovet rules list --markdown`; a test
fails if they are out of date.

<!-- rules-table:start -->
#### Auto-run code (`autorun`, 49 rules)

| ID | Severity | Description |
|----|----------|-------------|
| RC-AUTO-001 | medium | npm install lifecycle script present |
| RC-AUTO-002 | low | npm prepare or prepack script present |
| RC-AUTO-003 | high | npm lifecycle script downloads or executes code |
| RC-AUTO-004 | medium | Yarn runs JavaScript from the repository (yarnPath or plugins) |
| RC-AUTO-005 | high | npm configuration runs a custom shell or preloads code |
| RC-AUTO-006 | high | pnpm hook file (.pnpmfile.cjs) |
| RC-AUTO-010 | low | setup.py present |
| RC-AUTO-011 | high | setup.py starts processes, uses the network, runs or decodes code |
| RC-AUTO-012 | medium | setup.py overrides setup commands (cmdclass) |
| RC-AUTO-013 | medium | Unknown Python build backend |
| RC-AUTO-014 | high | Python build backend loaded from the repository (backend-path) |
| RC-AUTO-015 | medium | Custom build hooks in pyproject.toml |
| RC-AUTO-016 | high | .pth file with code |
| RC-AUTO-017 | high | sitecustomize.py or usercustomize.py in the repository |
| RC-AUTO-020 | high | VS Code task runs when the folder is opened |
| RC-AUTO-021 | critical | VS Code task that runs on folder open downloads or executes code |
| RC-AUTO-022 | high | VS Code settings point an interpreter, tool or shell into the repository |
| RC-AUTO-025 | high | Dev container runs initializeCommand on the host |
| RC-AUTO-026 | low | Dev container lifecycle commands |
| RC-AUTO-030 | high | Active Git hook in the repository |
| RC-AUTO-031 | high | Git config runs commands |
| RC-AUTO-032 | critical | Git config sets core.fsmonitor to a command |
| RC-AUTO-033 | low | .gitattributes assigns a custom filter, diff or merge driver |
| RC-AUTO-040 | high | Makefile or justfile downloads and runs code |
| RC-AUTO-041 | medium | direnv file (.envrc) |
| RC-AUTO-042 | medium | mise hooks or sourced scripts |
| RC-AUTO-050 | high | Windows shell file points to a remote location |
| RC-AUTO-051 | medium | Windows shortcut in the repository |
| RC-AUTO-052 | high | Linux desktop entry downloads or decodes code |
| RC-AUTO-053 | medium | macOS Terminal script (.command) |
| RC-AUTO-054 | high | macOS Terminal settings file runs a command |
| RC-AUTO-055 | medium | macOS location file opens something other than a web page |
| RC-AUTO-056 | medium | macOS application bundle in the repository |
| RC-AUTO-060 | medium | GitHub workflow runs pull request code with pull_request_target |
| RC-AUTO-061 | medium | GitHub workflow runs an encoded command |
| RC-AUTO-062 | medium | GitHub workflow puts untrusted event text into a shell command |
| RC-AUTO-070 | medium | MSBuild project runs a command on build |
| RC-AUTO-071 | high | MSBuild project downloads or decodes code during the build |
| RC-AUTO-072 | high | MSBuild inline task with code |
| RC-AUTO-080 | medium | Composer install or update script present |
| RC-AUTO-081 | high | Composer script downloads or executes code |
| RC-AUTO-082 | low | Rust build script present |
| RC-AUTO-083 | medium | Rust build script downloads code or starts a download tool |
| RC-AUTO-084 | medium | Gradle build starts external commands |
| RC-AUTO-085 | high | Gradle build downloads and runs code |
| RC-AUTO-086 | medium | Gradle wrapper downloads Gradle from an unofficial location |
| RC-AUTO-087 | low | Ruby gem builds a native extension on install |
| RC-AUTO-088 | high | Ruby install or build script downloads and runs code |
| RC-AUTO-090 | critical | Auto-run entry point reaches dangerous code in another file |

#### AI agent instructions and configuration (`agents`, 28 rules)

| ID | Severity | Description |
|----|----------|-------------|
| RC-AGENT-001 | info | AI agent file present |
| RC-AGENT-002 | high | Hidden Unicode tag characters in an AI agent file |
| RC-AGENT-003 | high | Hidden Unicode tag characters in a text file |
| RC-AGENT-004 | high | Bidirectional control characters in an AI agent file |
| RC-AGENT-005 | medium | Zero-width characters in an AI agent file |
| RC-AGENT-006 | high | Run of Unicode variation selectors (hidden bytes) |
| RC-AGENT-010 | medium | HTML comment in an AI agent file |
| RC-AGENT-011 | medium | Hidden Markdown or HTML content in an AI agent file |
| RC-AGENT-012 | medium | Instructions for AI tools hidden in an HTML comment |
| RC-AGENT-020 | high | Instruction to override rules or hide actions from the user |
| RC-AGENT-021 | high | Agent instruction to download and run code |
| RC-AGENT-022 | medium | AI agent file refers to secrets or credentials |
| RC-AGENT-023 | high | Exfiltration target in an AI agent file |
| RC-AGENT-024 | high | Agent safety checks switched off |
| RC-AGENT-025 | high | Agent instruction loads further instructions from the web |
| RC-AGENT-026 | high | Agent file imports files from outside the repository |
| RC-AGENT-027 | medium | Code starts an AI coding agent with approvals or sandbox switched off |
| RC-AGENT-028 | high | Plain-text instruction to run commands, send data away or act behind the user's back |
| RC-AGENT-030 | high | Claude Code hooks in project settings |
| RC-AGENT-031 | high | Broad agent permissions in project settings |
| RC-AGENT-032 | critical | Claude Code API traffic redirected or API key helper set |
| RC-AGENT-033 | high | Claude Code settings run helper commands |
| RC-AGENT-034 | medium | Claude Code plugins or marketplaces in project settings |
| RC-AGENT-040 | medium | MCP server starts a local program |
| RC-AGENT-041 | high | MCP server runs a repository script, an unpinned package or a download |
| RC-AGENT-042 | low | MCP server at a remote URL |
| RC-AGENT-050 | medium | Slash command or skill runs shell commands |
| RC-AGENT-060 | high | Other AI agents set to run commands without asking |

#### Obfuscated code (`obfuscation`, 12 rules)

| ID | Severity | Description |
|----|----------|-------------|
| RC-OBF-001 | medium | Long encoded blob in source code |
| RC-OBF-002 | high | Encoded blob in source code decodes to code or commands |
| RC-OBF-003 | high | Code is decoded and executed in one step |
| RC-OBF-004 | high | JavaScript obfuscator or packer output |
| RC-OBF-005 | high | String built from a long chain of character codes |
| RC-OBF-006 | medium | Very long line in source code |
| RC-OBF-007 | high | Code pushed out of view by a long run of spaces |
| RC-OBF-008 | high | Bidirectional control characters in source code (Trojan Source) |
| RC-OBF-009 | medium | Invisible characters in source code |
| RC-OBF-010 | medium | Name mixes Latin letters with look-alike letters from another script |
| RC-OBF-011 | high | Decrypted data is compiled and run as code |
| RC-OBF-012 | high | Encoded string split into constants is joined, decoded and run |

#### Download-and-execute (`download_exec`, 7 rules)

| ID | Severity | Description |
|----|----------|-------------|
| RC-DLX-001 | medium | Script downloads code and pipes it into an interpreter |
| RC-DLX-002 | high | Windows system tool used to download or run remote code |
| RC-DLX-003 | high | Code from a web request is executed |
| RC-DLX-004 | high | Script downloads a file into a temporary folder and runs it |
| RC-DLX-005 | medium | Code contacts a webhook, tunnel, paste or file-sharing service or a raw IP |
| RC-DLX-006 | high | GitHub workflow sends secrets to a request catcher or paste service |
| RC-DLX-007 | medium | Script stores a download in a variable and runs it |

#### Binaries, archives, file-system tricks (`binaries`, 14 rules)

| ID | Severity | Description |
|----|----------|-------------|
| RC-BIN-001 | high | Executable program in the repository |
| RC-BIN-002 | high | Executable disguised as a document, image or text file |
| RC-BIN-003 | high | File name with a double extension |
| RC-BIN-004 | high | Invisible or control characters in a file or folder name |
| RC-BIN-005 | medium | Compiled code that cannot be reviewed |
| RC-BIN-006 | low | Archive in the repository |
| RC-BIN-007 | medium | Password-protected archive |
| RC-BIN-008 | medium | Office document with macros |
| RC-BIN-009 | medium | File name that Windows reserves or cannot store |
| RC-BIN-010 | medium | Paths that differ only in upper and lower case |
| RC-BIN-011 | medium | Link that points outside the repository |
| RC-BIN-012 | high | Git submodule with a dangerous URL or path |
| RC-BIN-013 | medium | Python bytecode cache without its source file |
| RC-BIN-014 | critical | Bidirectional control character in a file or folder name |

#### Suspicious dependencies (`dependencies`, 7 rules)

| ID | Severity | Description |
|----|----------|-------------|
| RC-DEP-001 | high | Dependency name one typo away from a very popular package |
| RC-DEP-002 | medium | Dependency name one typo away from a popular package |
| RC-DEP-003 | medium | Long dependency name close to a very popular package |
| RC-DEP-010 | medium | Dependency installed from Git or a URL |
| RC-DEP-011 | high | Additional or replaced Python package index |
| RC-DEP-012 | high | npm or Yarn registry replaced |
| RC-DEP-013 | medium | Lockfile installs packages from outside the default registry |

#### Languages, structure, history (`provenance`, 8 rules)

| ID | Severity | Description |
|----|----------|-------------|
| RC-PROV-001 | info | Most files arrived in one initial commit |
| RC-PROV-002 | low | Commit dates in the future |
| RC-PROV-003 | low | Author dates later than commit dates |
| RC-PROV-004 | info | History committed in one go |
| RC-PROV-005 | info | Many commits authored within minutes |
| RC-PROV-010 | info | Commits name an AI tool as co-author or generator |
| RC-PROV-011 | info | Text says it was generated with an AI tool |
| RC-PROV-012 | info | AI coding session history committed |

#### Trust signals from the GitHub API (`trust`, 10 rules)

| ID | Severity | Description |
|----|----------|-------------|
| RC-TRUST-001 | medium | Very new owner account with a popular repository |
| RC-TRUST-002 | low | Young repository with many stars |
| RC-TRUST-003 | low | Most stars arrived within one day |
| RC-TRUST-004 | medium | Fork of a much more popular repository |
| RC-TRUST-005 | medium | Release offers programs or archives, but the repository has hardly any code |
| RC-TRUST-006 | info | Repository is archived |
| RC-TRUST-007 | info | No commits for more than two years |
| RC-TRUST-008 | low | Local HEAD commit not found in the named GitHub repository |
| RC-TRUST-009 | medium | Manifest names another owner's repository as the project's source |
| RC-TRUST-010 | medium | Older, more popular repository with the same name and description |
<!-- rules-table:end -->
