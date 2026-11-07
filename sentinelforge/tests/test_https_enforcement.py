from email.message import Message
from io import BytesIO
from urllib.error import HTTPError, URLError

from sentinelforge.core.config import ConfigManager
from sentinelforge.core.target import Target, TargetType
from sentinelforge.modules.vulnerability import VulnerabilityModule


def make_module():
    module = VulnerabilityModule(ConfigManager())
    target = Target(
        raw="https://example.test",
        kind=TargetType.URL,
        host="example.test",
        scheme="https",
    )
    return module, target


def mock_response(monkeypatch, status=200, location=None):
    headers = Message()
    if location:
        headers["Location"] = location

    class Response:
        def getcode(self):
            return status

        def close(self):
            pass

        @property
        def headers(self):
            return headers

    class Opener:
        def open(self, request, timeout=None):
            return Response()

    monkeypatch.setattr(
        "urllib.request.build_opener", lambda *args, **kwargs: Opener()
    )


def mock_redirect(monkeypatch, location):
    headers = Message()
    headers["Location"] = location

    class Opener:
        def open(self, request, timeout=None):
            raise HTTPError(
                request.full_url, 301, "Moved Permanently", headers, BytesIO()
            )

    monkeypatch.setattr(
        "urllib.request.build_opener", lambda *args, **kwargs: Opener()
    )


def test_http_response_without_https_redirect_is_reported(monkeypatch):
    module, target = make_module()
    mock_response(monkeypatch, status=200)

    findings = module._check_https_enforcement("https://example.test", target)

    assert any(f.title == "HTTPS Not Enforced" for f in findings)


def test_same_host_https_redirect_is_not_reported(monkeypatch):
    module, target = make_module()
    mock_redirect(monkeypatch, "https://example.test/login")

    findings = module._check_https_enforcement("https://example.test", target)

    assert not any(f.title == "HTTPS Not Enforced" for f in findings)


def test_redirect_to_unrelated_host_is_inconclusive(monkeypatch):
    module, target = make_module()
    mock_redirect(monkeypatch, "https://other.example.org/")

    findings = module._check_https_enforcement("https://example.test", target)

    assert not any(f.title == "HTTPS Not Enforced" for f in findings)


def test_unreachable_http_endpoint_is_not_reported(monkeypatch):
    module, target = make_module()

    class Opener:
        def open(self, request, timeout=None):
            raise URLError("connection refused")

    monkeypatch.setattr(
        "urllib.request.build_opener", lambda *args, **kwargs: Opener()
    )

    findings = module._check_https_enforcement("https://example.test", target)

    assert not any(f.title == "HTTPS Not Enforced" for f in findings)


def test_same_host_http_redirect_is_reported(monkeypatch):
    module, target = make_module()
    mock_redirect(monkeypatch, "http://example.test/login")

    findings = module._check_https_enforcement("https://example.test", target)

    assert any(f.title == "HTTPS Not Enforced" for f in findings)


def test_custom_https_port_still_probes_standard_http_port(monkeypatch):
    module, target = make_module()
    requested_urls = []

    class Opener:
        def open(self, request, timeout=None):
            requested_urls.append(request.full_url)
            return type(
                "Response",
                (),
                {
                    "getcode": lambda self: 200,
                    "headers": Message(),
                    "close": lambda self: None,
                },
            )()

    monkeypatch.setattr(
        "urllib.request.build_opener", lambda *args, **kwargs: Opener()
    )

    findings = module._check_https_enforcement(
        "https://example.test:8443", target
    )

    assert requested_urls == ["http://example.test/"]
    assert any(f.title == "HTTPS Not Enforced" for f in findings)
