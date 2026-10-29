"""Test setup: no test may touch the network.

The only exception is the opt-in fixture ``loopback_network``: tests of the HTTP clone
path run a Git server on 127.0.0.1 and may connect to it, but to nothing else.
"""

import socket
from collections.abc import Iterator
from typing import Any, NoReturn

import pytest

_monkeypatch = pytest.MonkeyPatch()
_REAL_SOCKET = socket.socket
_REAL_GETADDRINFO = socket.getaddrinfo
_REAL_CREATE_CONNECTION = socket.create_connection
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1"})


class NetworkBlockedError(RuntimeError):
    pass


def _blocked(*args: Any, **kwargs: Any) -> NoReturn:
    raise NetworkBlockedError("network access is blocked in tests")


class _BlockedSocket(socket.socket):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        _blocked()


def _check_loopback(address: object) -> None:
    host = address[0] if isinstance(address, tuple) and address else address
    if host not in LOOPBACK_HOSTS:
        raise NetworkBlockedError(f"only loopback is allowed in this test, not {host!r}")


class _LoopbackSocket(_REAL_SOCKET):
    """A real socket that may only bind to and connect to loopback addresses."""

    def bind(self, address: Any, /) -> None:
        _check_loopback(address)
        super().bind(address)

    def connect(self, address: Any, /) -> None:
        _check_loopback(address)
        super().connect(address)

    def connect_ex(self, address: Any, /) -> int:
        _check_loopback(address)
        return super().connect_ex(address)

    def sendto(self, *args: Any) -> int:
        _blocked()


def _loopback_getaddrinfo(host: Any, *args: Any, **kwargs: Any) -> Any:
    _check_loopback(host)
    return _REAL_GETADDRINFO(host, *args, **kwargs)


def pytest_configure(config: pytest.Config) -> None:
    _monkeypatch.setattr(socket, "socket", _BlockedSocket)
    _monkeypatch.setattr(socket, "create_connection", _blocked)
    _monkeypatch.setattr(socket, "getaddrinfo", _blocked)
    _monkeypatch.setattr(socket, "socketpair", _blocked)


def pytest_unconfigure(config: pytest.Config) -> None:
    _monkeypatch.undo()


@pytest.fixture
def loopback_network(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Allow sockets on 127.0.0.1/::1 for one test; everything else stays blocked."""
    monkeypatch.setattr(socket, "socket", _LoopbackSocket)
    monkeypatch.setattr(socket, "getaddrinfo", _loopback_getaddrinfo)
    # socket.create_connection looks up getaddrinfo and socket in the module at call
    # time, so it inherits both restrictions.
    monkeypatch.setattr(socket, "create_connection", _REAL_CREATE_CONNECTION)
    yield
