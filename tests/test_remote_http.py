"""The real HTTP clone path against a dulwich smart-HTTP server on 127.0.0.1.

Uses the ``loopback_network`` fixture: sockets work for loopback only.
"""

import json
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest
import urllib3
from dulwich.client import GitClient, Urllib3HttpGitClient
from dulwich.repo import Repo
from dulwich.server import BackendRepo, DictBackend
from dulwich.web import WSGIRequestHandlerLogger, WSGIServerLogger, make_server, make_wsgi_chain

from gitrepo import CommitSpec, build_repo
from repovet.cli import EXIT_ABORTED, EXIT_FINDINGS, main
from repovet.sources import remote
from repovet.sources.remote import GitHubRepo

Capture = pytest.CaptureFixture[str]


class _QuietHandler(WSGIRequestHandlerLogger):
    def log_message(self, format: str, *args: object) -> None:
        pass


@pytest.fixture
def server(tmp_path: Path, loopback_network: None) -> Iterator[str]:
    origin = tmp_path / "origin.git"
    build_repo(
        origin,
        [
            CommitSpec({"README.md": "# demo\n"}),
            CommitSpec(
                {
                    "README.md": "# demo\n",
                    ".vscode/tasks.json": '{"tasks": [{"label": "x", "command": "make",'
                    ' "runOptions": {"runOn": "folderOpen"}}]}',
                }
            ),
        ],
    )
    repo = Repo(str(origin))
    repos: dict[str, BackendRepo] = {"/octo/demo.git": repo}
    app = make_wsgi_chain(DictBackend(repos))
    httpd = make_server(
        "127.0.0.1", 0, app, handler_class=_QuietHandler, server_class=WSGIServerLogger
    )
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}/"
    finally:
        httpd.shutdown()
        httpd.server_close()
        repo.close()


@pytest.fixture
def http_transport(server: str, monkeypatch: pytest.MonkeyPatch) -> None:
    def transport(repo: GitHubRepo, timeout: float) -> tuple[GitClient, str]:
        # An explicit pool manager: no proxy from the environment for loopback.
        client = Urllib3HttpGitClient(
            server,
            dumb=False,
            config=None,
            timeout=timeout,
            quiet=True,
            pool_manager=urllib3.PoolManager(),
        )
        return client, repo.path

    monkeypatch.setattr(remote, "github_transport", transport)


def test_scan_over_http(http_transport: None, capsys: Capture) -> None:
    code = main(["scan", "https://github.com/octo/demo", "--format", "json"])
    report = json.loads(capsys.readouterr().out)
    assert code == EXIT_FINDINGS
    assert [f["rule_id"] for f in report["findings"]] == ["RC-AUTO-020"]
    assert report["facts"]["source"]["ref"] == "main"


def test_size_limit_over_http(http_transport: None, capsys: Capture) -> None:
    code = main(["scan", "https://github.com/octo/demo", "--max-clone-size", "100"])
    assert code == EXIT_ABORTED
    assert "clone limit" in capsys.readouterr().err


def test_unknown_repository_over_http(http_transport: None, capsys: Capture) -> None:
    assert main(["scan", "https://github.com/octo/missing"]) == EXIT_ABORTED
    assert "analysis aborted" in capsys.readouterr().err
