"""Interactive mode: ``repovet`` without arguments on a terminal shows a numbered menu.

Only used when stdin and stdout are both terminals and ``CI`` is not set, so scripts,
pipes and CI runs keep the plain command-line behaviour. Answers are read with
``readline`` from stdin; nothing typed here is ever run. Leaving through the menu or
with end-of-input returns the exit code of the last scan (0 without a scan); Ctrl+C is
handled by the caller like everywhere else.
"""

from collections.abc import Callable, Mapping
from pathlib import Path
from typing import TextIO

from repovet import __version__
from repovet.github.client import TOKEN_VARIABLES, token_from_env
from repovet.models import Finding, Severity
from repovet.report import formats, terminal
from repovet.report.common import visible_findings
from repovet.report.sanitize import sanitize, sanitize_path
from repovet.scanning import (
    Scanned,
    ScanOptions,
    UsageError,
    fails,
    is_url,
    local_root,
    output_path,
    scan,
    write_report,
)
from repovet.sources.gitobjects import GitObjectError
from repovet.sources.remote import SUPPORTED, CloneError

EXIT_OK = 0
EXIT_FINDINGS = 1
FAIL_ON = Severity.HIGH
SAVE_FORMATS = (("html", "HTML page"), ("json", "JSON"), ("sarif", "SARIF 2.1.0"), ("text", "text"))

type Scanner = Callable[[ScanOptions, Callable[[str], None]], Scanned]


def _is_terminal(stream: object) -> bool:
    isatty = getattr(stream, "isatty", None)
    return callable(isatty) and bool(isatty())


def can_ask(stdin: object, environ: Mapping[str, str]) -> bool:
    """Questions only when someone can answer: stdin is a terminal, not in CI."""
    return not environ.get("CI") and _is_terminal(stdin)


def wanted(stdin: object, stdout: object, environ: Mapping[str, str]) -> bool:
    """Interactive mode only when stdin and stdout are terminals and not in CI."""
    return can_ask(stdin, environ) and _is_terminal(stdout)


class Session:
    def __init__(
        self,
        stdin: TextIO,
        stdout: TextIO,
        environ: Mapping[str, str],
        scanner: Scanner = scan,
    ) -> None:
        self.stdin = stdin
        self.out = stdout
        self.environ = environ
        self.scanner = scanner
        self.offline = False
        self.exit_code = EXIT_OK
        self.color = terminal.color_wanted(environ, stdout)
        self.unicode = terminal.supports_unicode(stdout)

    # --- input and output --------------------------------------------------------

    def say(self, text: str = "") -> None:
        self.out.write(text + "\n")
        self.out.flush()

    def ask(self, prompt: str) -> str:
        """One line of input without surrounding blanks; EOFError at end of input."""
        self.out.write(prompt)
        self.out.flush()
        line = self.stdin.readline()
        if not line:
            raise EOFError
        return line.strip()

    def choose(self, title: str, options: list[str]) -> int:
        """Show a numbered menu until a valid number is typed; returns 1..len(options)."""
        while True:
            self.say()
            if title:
                self.say(title)
            for number, option in enumerate(options, 1):
                self.say(f"  {number}  {option}")
            answer = self.ask(f"Choose 1-{len(options)}: ")
            if answer.isdigit() and 1 <= int(answer) <= len(options):
                return int(answer)
            self.say(f"Please type a number from 1 to {len(options)}.")

    # --- menus -----------------------------------------------------------------------

    def run(self) -> int:
        self.say(f"repovet {__version__} - check a Git repository before you run anything from it.")
        self.say("Nothing from the checked repository is run.")
        try:
            while True:
                choice = self.choose(
                    "What do you want to do?",
                    [
                        "Check a GitHub repository (URL)",
                        "Check a folder on this computer",
                        "Settings",
                        "Exit",
                    ],
                )
                if choice == 4:
                    return self.exit_code
                if choice == 3:
                    self.settings()
                    continue
                scanned = self.check_url() if choice == 1 else self.check_folder()
                if scanned is not None and not self.after_scan(scanned):
                    return self.exit_code
        except EOFError:
            self.say()
            return self.exit_code

    def settings(self) -> None:
        while True:
            token, problem = token_from_env(self.environ)
            if token is not None:
                state = f"set (from {token.source}); the value is never shown"
            elif problem is not None:
                state = f"not used: {problem}"
            else:
                state = f"not set (optional: set {' or '.join(TOKEN_VARIABLES)})"
            self.say()
            self.say(f"GitHub token:  {state}")
            mode = "on (no GitHub API queries)" if self.offline else "off"
            self.say(f"Offline mode:  {mode}")
            toggle = "Turn offline mode off" if self.offline else "Turn offline mode on"
            if self.choose("", [toggle, "Back"]) == 2:
                return
            self.offline = not self.offline

    def check_url(self) -> Scanned | None:
        url = self.ask(f"GitHub repository URL ({SUPPORTED}), empty to go back: ")
        if not url:
            return None
        if not is_url(url):
            self.say(f"That is not a URL. Expected {SUPPORTED}.")
            return None
        self.say("Downloading and checking; large repositories take a while ...")
        return self.run_scan(url)

    def check_folder(self) -> Scanned | None:
        folder = self.ask("Folder to check, empty to go back: ").strip("\"'")
        if not folder:
            return None
        try:
            local_root(str(Path(folder).expanduser()))
        except UsageError as exc:
            self.error(str(exc))
            return None
        self.say("Checking ...")
        return self.run_scan(str(Path(folder).expanduser()))

    def run_scan(self, target: str) -> Scanned | None:
        options = ScanOptions(target, offline=self.offline, environ=dict(self.environ))
        try:
            scanned = self.scanner(options, self.note)
        except (UsageError, CloneError, GitObjectError) as exc:
            self.error(str(exc))
            return None
        self.exit_code = EXIT_FINDINGS if fails(scanned.result, FAIL_ON) else EXIT_OK
        self.say()
        self.out.write(terminal.render(scanned.result, color=self.color, unicode=self.unicode))
        return scanned

    def after_scan(self, scanned: Scanned) -> bool:
        """The menu after a scan; False when the user wants to leave."""
        while True:
            choice = self.choose(
                "What next?",
                [
                    "Show the details of a finding",
                    "Save the report (HTML, JSON, SARIF or text)",
                    "Check another repository",
                    "Exit",
                ],
            )
            if choice == 1:
                self.details(visible_findings(scanned.result, Severity.INFO))
            elif choice == 2:
                self.save(scanned)
            else:
                return choice == 3

    def details(self, findings: list[Finding]) -> None:
        if not findings:
            self.say("There are no findings to show.")
            return
        self.say()
        for number, finding in enumerate(findings, 1):
            loc = finding.location
            place = "(repository)" if loc is None else sanitize_path(loc.path)
            if loc is not None and loc.line:
                place = f"{place}:{loc.line}"
            label = f" [{finding.context}]" if finding.context else ""
            self.say(
                f"  {number:>3}  {finding.severity.label.upper():<9} {finding.rule_id:<13} "
                f"{place}{label}"
            )
        while True:
            answer = self.ask(f"Finding number (1-{len(findings)}), empty to go back: ")
            if not answer:
                return
            if answer.isdigit() and 1 <= int(answer) <= len(findings):
                self.say()
                self.out.write(terminal.render_finding(findings[int(answer) - 1], color=self.color))
                return
            self.say(f"Please type a number from 1 to {len(findings)}.")

    def save(self, scanned: Scanned) -> None:
        choice = self.choose("Report format:", [label for _fmt, label in SAVE_FORMATS])
        fmt = SAVE_FORMATS[choice - 1][0]
        default = f"repovet-report.{formats.EXTENSIONS[fmt]}"
        name = self.ask(f"File name [{default}]: ").strip("\"'") or default
        try:
            path = output_path(name, scanned.root)
        except UsageError as exc:
            self.error(str(exc))
            return
        if path.exists() and self.ask(f"{path} exists. Overwrite? [y/N] ").lower() not in (
            "y",
            "yes",
        ):
            self.say("Not saved.")
            return
        report = formats.render(fmt, scanned.result, scanned.rules.active())
        try:
            write_report(path, report)
        except UsageError as exc:
            self.error(str(exc))
            return
        self.say(f"Saved: {sanitize(str(path), None)}")

    def note(self, message: str) -> None:
        self.say(f"repovet: {sanitize(message, None)}")

    def error(self, message: str) -> None:
        self.say(f"repovet: error: {sanitize(message, None)}")


def run(stdin: TextIO, stdout: TextIO, environ: Mapping[str, str]) -> int:
    return Session(stdin, stdout, environ).run()
