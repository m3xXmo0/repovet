"""The only connection to the GitHub API: HTTPS to api.github.com with urllib.

The opener has just two handlers: proxies from the environment (company networks) and
HTTPS with certificate checks. Without an HTTP, file, FTP or data handler it cannot
open anything else, and without a redirect handler every redirect comes back to the
client, which follows it only within https://api.github.com.
"""

import http.client
import ssl
import urllib.error
import urllib.request

from repovet.github.client import API_ROOT, Request, Response, TooLarge, TransportError


class UrllibTransport:
    def __init__(self) -> None:
        self._opener = urllib.request.OpenerDirector()
        self._opener.add_handler(urllib.request.ProxyHandler())
        self._opener.add_handler(urllib.request.HTTPSHandler(context=ssl.create_default_context()))

    def __call__(self, request: Request, max_bytes: int) -> Response:
        if not request.url.startswith(f"{API_ROOT}/"):
            raise TransportError("only https://api.github.com is contacted")
        # The URL was checked above, and the opener can only speak HTTPS.
        req = urllib.request.Request(  # noqa: S310
            request.url, headers=dict(request.headers), method="GET"
        )
        try:
            response = self._opener.open(req, timeout=request.timeout)
            if response is None:
                raise TransportError("no handler for this URL")
            with response:
                body = response.read(max_bytes + 1)
                status = int(response.status)
                headers = {name.lower(): value for name, value in response.headers.items()}
        except TransportError:
            raise
        except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
            raise TransportError(_describe(exc)) from None
        if len(body) > max_bytes:
            raise TooLarge(f"answer larger than {max_bytes // 1024} KiB")
        return Response(status, headers, body)


def _describe(exc: BaseException) -> str:
    if isinstance(exc, urllib.error.URLError) and not isinstance(exc.reason, str):
        exc = exc.reason if isinstance(exc.reason, BaseException) else exc
    if isinstance(exc, TimeoutError):
        return "timed out"
    text = str(exc).strip()
    return f"{type(exc).__name__}: {text}"[:200] if text else type(exc).__name__
