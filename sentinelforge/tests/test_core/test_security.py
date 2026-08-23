"""Regression tests for secret redaction and protected session data."""
from __future__ import annotations

import logging
from pathlib import Path

from sentinelforge.core.config import ConfigManager
from sentinelforge.core.security import redact_text, redact_value
from sentinelforge.core.session import Session, SessionManager
from sentinelforge.logging.logger import SentinelFormatter, SentinelLogger


def test_redacts_common_secret_forms() -> None:
    text = "Authorization: Bearer top-secret-token password=hunter2"
    redacted = redact_text(text)
    assert "top-secret-token" not in redacted
    assert "hunter2" not in redacted
    assert "[REDACTED]" in redacted


def test_redacts_sensitive_mapping_keys() -> None:
    result = redact_value({"api_key": "key-value", "nested": {"cookie": "session-value"}})
    assert result == {"api_key": "[REDACTED]", "nested": {"cookie": "[REDACTED]"}}


def test_session_serialization_redacts_metadata_and_restricts_permissions(tmp_path: Path) -> None:
    session = Session(
        targets=["example.com"],
        metadata={"password": "secret-value", "note": "safe diagnostic"},
    )
    manager = SessionManager(tmp_path / "sessions")
    manager.save(session)
    raw = (tmp_path / "sessions" / f"{session.session_id}.json").read_text()
    assert "secret-value" not in raw
    assert "safe diagnostic" in raw
    assert oct((tmp_path / "sessions" / f"{session.session_id}.json").stat().st_mode & 0o777) == "0o600"


def test_logger_redacts_context_and_exception(caplog) -> None:
    logger = SentinelLogger("redaction-test", level="INFO")
    record = logging.LogRecord(
        "redaction-test", logging.ERROR, "", 0,
        "request failed password=secret-value", (), None,
    )
    rendered = SentinelFormatter().format(record)
    assert "secret-value" not in rendered
    with caplog.at_level(logging.INFO, logger="redaction-test"):
        logger.info("authorization failed", token="secret-token")
    assert "secret-token" not in caplog.text


def test_config_diagnostic_view_redacts_credentials(tmp_path: Path) -> None:
    config = tmp_path / "config.yaml"
    config.write_text("integrations:\n  shodan:\n    api_key: real-key\n")
    assert "real-key" not in str(ConfigManager(config_path=config).redacted_data)