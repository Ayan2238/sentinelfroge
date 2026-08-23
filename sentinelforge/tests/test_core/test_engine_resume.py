"""Regression tests for resumable session behavior."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinelforge.core.engine import ScanError, SentinelEngine
from sentinelforge.core.session import Session, SessionManager, SessionStatus


def _engine(tmp_path: Path) -> SentinelEngine:
    return SentinelEngine(output_dir=tmp_path, quiet=True)


def test_resume_uses_saved_targets(tmp_path: Path, monkeypatch) -> None:
    engine = _engine(tmp_path)
    session = engine._session_mgr.create(["example.com"])
    session.pause()
    engine._session_mgr.save(session)
    captured = {}

    def fake_validate(targets, loaded):
        captured["targets"] = targets
        return []

    monkeypatch.setattr(engine, "_validate_targets", fake_validate)
    monkeypatch.setattr(engine, "_scan_target", lambda target, session: [])
    result = engine.scan(["ignored.example"], resume_session_id=session.session_id)
    assert captured["targets"] == ["example.com"]
    assert result["session_id"] == session.session_id


def test_resume_missing_state_fails(tmp_path: Path) -> None:
    with pytest.raises(ScanError, match="not found"):
        _engine(tmp_path).scan([], resume_session_id="missing")


def test_resume_invalid_state_fails(tmp_path: Path) -> None:
    session_path = tmp_path / "sessions" / "bad.json"
    session_path.parent.mkdir()
    session_path.write_text("{not-json")
    with pytest.raises(ScanError, match="invalid state"):
        _engine(tmp_path).scan([], resume_session_id="bad")


def test_resume_completed_state_fails(tmp_path: Path) -> None:
    manager = SessionManager(tmp_path / "sessions")
    session = manager.create(["example.com"])
    session.complete()
    manager.save(session)
    with pytest.raises(ScanError, match="completed"):
        _engine(tmp_path).scan([], resume_session_id=session.session_id)