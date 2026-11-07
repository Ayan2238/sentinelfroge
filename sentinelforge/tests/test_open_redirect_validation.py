from email.message import Message
from io import BytesIO
from urllib.error import HTTPError

from sentinelforge.core.config import ConfigManager
from sentinelforge.core.target import Target, TargetType
from sentinelforge.modules.exploit import ExploitValidationModule


def make_module():
    module = ExploitValidationModule(ConfigManager())
    target = Target(
        raw="https://example.test/?next=/home",
        kind=TargetType.URL,
        host="example.test",
        scheme="https",
    )
    return module, target


def mock_redirect(monkeypatch, location):
    class FakeOpener:
        def open(self, request, timeout=None):
            headers = Message()
            headers["Location"] = location
            raise HTTPError(
                request.full_url, 302, "Found", headers, BytesIO()
            )

    monkeypatch.setattr(
        "urllib.request.build_opener",
        lambda *args, **kwargs: FakeOpener(),
    )


def test_external_redirect_is_detected(monkeypatch):
    module, target = make_module()
    mock_redirect(
        monkeypatch, "https://redirect-check.sentinelforge.test/"
    )

    findings = module._check_open_redirect(
        "https://example.test/?next=/home", target
    )

    assert any(f.title == "Open Redirect Vulnerability" for f in findings)


def test_internal_redirect_is_not_reported(monkeypatch):
    module, target = make_module()
    mock_redirect(monkeypatch, "/account")

    findings = module._check_open_redirect(
        "https://example.test/?next=/home", target
    )

    assert not any(f.title == "Open Redirect Vulnerability" for f in findings)


def test_unrelated_external_host_is_not_reported(monkeypatch):
    module, target = make_module()
    mock_redirect(monkeypatch, "https://trusted.example.org/account")

    findings = module._check_open_redirect(
        "https://example.test/?next=/home", target
    )

    assert not any(f.title == "Open Redirect Vulnerability" for f in findings)
