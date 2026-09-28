"""Small shared helpers for network configuration."""

from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from collections.abc import Iterator
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sentinelforge.core.config import ConfigManager


def ssl_context(config: "ConfigManager") -> ssl.SSLContext:
    """Create a context honoring the configured TLS verification policy.

    Verification is enabled by default.  Disabling it is an explicit,
    per-request configuration choice for assessment targets using private or
    self-signed certificates.
    """
    if config.get("network.verify_ssl", True):
        return ssl.create_default_context()
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


@contextmanager
def open_url(
    request: str | urllib.request.Request,
    config: "ConfigManager",
    *,
    timeout: float | None = None,
    context: ssl.SSLContext | None = None,
    retryable: bool = True,
) -> Iterator[object]:
    """Open a URL with bounded retries for transient network failures."""
    retries = int(config.get("general.retries", 0)) if retryable else 0
    timeout = timeout or float(config.get("general.timeout", 30))
    context = context or ssl_context(config)

    follow_redirects = bool(config.get("scanning.follow_redirects", True))
    max_redirects = int(config.get("scanning.max_redirects", 10))

    class _RedirectHandler(urllib.request.HTTPRedirectHandler):
        def __init__(self):
            super().__init__()
            self.max_redirections = max_redirects

        def redirect_request(self, req, fp, code, msg, headers, newurl):
            if not follow_redirects:
                return None
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    opener = None
    if not follow_redirects or max_redirects != 10:
        opener = urllib.request.build_opener(
            _RedirectHandler(),
            urllib.request.HTTPSHandler(context=context),
        )

    for attempt in range(retries + 1):
        try:
            if opener is None:
                response = urllib.request.urlopen(
                    request, timeout=timeout, context=context
                )
            else:
                response = opener.open(request, timeout=timeout)
            try:
                yield response
            finally:
                response.close()
            return
        except urllib.error.HTTPError as exc:
            if exc.code not in {429, 500, 502, 503, 504} or attempt >= retries:
                raise
        except (urllib.error.URLError, TimeoutError, ConnectionResetError, OSError):
            if attempt >= retries:
                raise
        time.sleep(min(0.25 * (2**attempt), 2.0))