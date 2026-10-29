"""The test session blocks the network, and a local scan works without it."""

import socket
from pathlib import Path

import pytest

from conftest import NetworkBlockedError
from helpers import materialize
from repocheck.cli import main


def test_socket_creation_is_blocked() -> None:
    with pytest.raises(NetworkBlockedError):
        socket.socket(socket.AF_INET, socket.SOCK_STREAM)


def test_connections_and_lookups_are_blocked() -> None:
    with pytest.raises(NetworkBlockedError):
        socket.create_connection(("example.invalid", 443))
    with pytest.raises(NetworkBlockedError):
        socket.getaddrinfo("example.invalid", 443)


def test_local_offline_scan_needs_no_network(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = materialize(tmp_path / "repo", {"package.json": '{"scripts": {"install": "x"}}'})
    assert main(["scan", str(repo), "--offline", "--no-color"]) == 0
    assert "RC-AUTO-001" in capsys.readouterr().out


def test_loopback_fixture_allows_only_loopback(loopback_network: None) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        with socket.create_connection(("127.0.0.1", port), timeout=5):
            pass
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as other:
            with pytest.raises(NetworkBlockedError):
                other.connect(("192.0.2.1", 443))
            with pytest.raises(NetworkBlockedError):
                other.bind(("0.0.0.0", 0))  # noqa: S104 - must be refused
    with pytest.raises(NetworkBlockedError):
        socket.getaddrinfo("example.invalid", 443)
    with pytest.raises(NetworkBlockedError):
        socket.create_connection(("example.invalid", 443))


def test_lock_is_back_after_the_loopback_test() -> None:
    with pytest.raises(NetworkBlockedError):
        socket.socket(socket.AF_INET, socket.SOCK_STREAM)
