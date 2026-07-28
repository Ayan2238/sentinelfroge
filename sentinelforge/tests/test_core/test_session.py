"""Tests for Session and SessionManager."""
from __future__ import annotations

from pathlib import Path

import pytest

from sentinelforge.core.session import Session, SessionManager, SessionStatus


class TestSession:
    def test_create_defaults(self) -> None:
        s = Session(targets=["example.com"])
        assert s.status == SessionStatus.PENDING
        assert s.targets == ["example.com"]
        assert s.started_at is None
        assert len(s.session_id) == 36  # UUID

    def test_start(self) -> None:
        s = Session(targets=["example.com"])
        s.start()
        assert s.status == SessionStatus.RUNNING
        assert s.started_at is not None

    def test_complete(self) -> None:
        s = Session(targets=["example.com"])
        s.start()
        s.complete()
        assert s.status == SessionStatus.COMPLETED
        assert s.finished_at is not None

    def test_fail(self) -> None:
        s = Session(targets=["example.com"])
        s.fail("network error")
        assert s.status == SessionStatus.FAILED
        assert s.metadata.get("failure_reason") == "network error"

    def test_cancel(self) -> None:
        s = Session(targets=["example.com"])
        s.cancel()
        assert s.status == SessionStatus.CANCELLED

    def test_short_id(self) -> None:
        s = Session(targets=["example.com"])
        assert len(s.short_id) == 8
        assert s.short_id == s.session_id[:8]

    def test_duration_none_before_start(self) -> None:
        s = Session(targets=["example.com"])
        assert s.duration_seconds is None

    def test_duration_after_complete(self) -> None:
        import time
        s = Session(targets=["example.com"])
        s.start()
        time.sleep(0.01)
        s.complete()
        assert s.duration_seconds is not None
        assert s.duration_seconds >= 0

    def test_add_finding(self) -> None:
        s = Session(targets=["example.com"])
        s.add_finding({"title": "XSS", "severity": "high"})
        assert len(s.findings) == 1

    def test_module_state(self) -> None:
        s = Session(targets=["example.com"])
        s.set_module_state("recon", {"status": "success"})
        assert s.get_module_state("recon") == {"status": "success"}
        assert s.get_module_state("missing") == {}

    def test_serialisation_roundtrip(self) -> None:
        s = Session(targets=["example.com"], profile="deep")
        s.start()
        s.add_finding({"title": "test", "severity": "low"})
        d = s.to_dict()
        s2 = Session.from_dict(d)
        assert s2.session_id == s.session_id
        assert s2.targets == s.targets
        assert s2.profile == s.profile
        assert s2.status == s.status
        assert len(s2.findings) == 1


class TestSessionManager:
    @pytest.fixture
    def mgr(self, tmp_path: Path) -> SessionManager:
        return SessionManager(sessions_dir=tmp_path / "sessions")

    def test_create_and_load(self, mgr: SessionManager) -> None:
        s = mgr.create(targets=["example.com"], profile="fast")
        loaded = mgr.load(s.session_id)
        assert loaded.session_id == s.session_id
        assert loaded.targets == ["example.com"]

    def test_save_persists_state(self, mgr: SessionManager) -> None:
        s = mgr.create(targets=["example.com"])
        s.start()
        mgr.save(s)
        loaded = mgr.load(s.session_id)
        assert loaded.status == SessionStatus.RUNNING

    def test_load_missing_raises(self, mgr: SessionManager) -> None:
        with pytest.raises(FileNotFoundError):
            mgr.load("nonexistent-session-id")

    def test_delete(self, mgr: SessionManager) -> None:
        s = mgr.create(targets=["example.com"])
        mgr.delete(s.session_id)
        with pytest.raises(FileNotFoundError):
            mgr.load(s.session_id)

    def test_list_sessions(self, mgr: SessionManager) -> None:
        mgr.create(targets=["a.com"])
        mgr.create(targets=["b.com"])
        sessions = mgr.list_sessions()
        assert len(sessions) == 2

    def test_list_sessions_filter_by_status(self, mgr: SessionManager) -> None:
        s1 = mgr.create(targets=["a.com"])
        s1.complete()
        mgr.save(s1)
        s2 = mgr.create(targets=["b.com"])
        s2.fail("error")
        mgr.save(s2)

        completed = mgr.list_sessions(status=SessionStatus.COMPLETED)
        assert len(completed) == 1
        assert completed[0].session_id == s1.session_id

    def test_find_resumable(self, mgr: SessionManager) -> None:
        s = mgr.create(targets=["a.com"])
        s.status = SessionStatus.PAUSED
        mgr.save(s)
        resumable = mgr.find_resumable()
        assert any(r.session_id == s.session_id for r in resumable)
