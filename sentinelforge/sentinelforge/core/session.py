"""
Session Manager
~~~~~~~~~~~~~~~
Handles persistent scan sessions: creation, state serialisation,
resume, history, and cleanup.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from sentinelforge.core.security import redact_value


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------


class SessionStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


# ---------------------------------------------------------------------------
# Session data-class
# ---------------------------------------------------------------------------


@dataclass
class Session:
    """
    Represents one scan session.

    Attributes
    ----------
    session_id:
        Unique UUID for the session.
    targets:
        List of target strings included in this session.
    profile:
        Scan profile used (e.g. ``"normal"``).
    status:
        Current lifecycle status.
    created_at:
        ISO-8601 UTC timestamp of session creation.
    started_at:
        ISO-8601 UTC timestamp when scanning began; ``None`` if not yet started.
    finished_at:
        ISO-8601 UTC timestamp when scanning ended; ``None`` if still running.
    findings:
        List of raw finding dicts accumulated during the scan.
    module_state:
        Per-module resume state (module name → arbitrary dict).
    metadata:
        Free-form metadata (config snapshot, CLI args, etc.).
    """

    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    targets: list[str] = field(default_factory=list)
    profile: str = "normal"
    status: SessionStatus = SessionStatus.PENDING
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    started_at: str | None = None
    finished_at: str | None = None
    findings: list[dict[str, Any]] = field(default_factory=list)
    module_state: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Lifecycle helpers
    # ------------------------------------------------------------------

    def start(self) -> None:
        self.status = SessionStatus.RUNNING
        self.started_at = datetime.now(timezone.utc).isoformat()

    def pause(self) -> None:
        self.status = SessionStatus.PAUSED

    def complete(self) -> None:
        self.status = SessionStatus.COMPLETED
        self.finished_at = datetime.now(timezone.utc).isoformat()

    def fail(self, reason: str = "") -> None:
        reason = redact_value(reason)
        self.status = SessionStatus.FAILED
        self.finished_at = datetime.now(timezone.utc).isoformat()
        if reason:
            self.metadata["failure_reason"] = reason

    def cancel(self) -> None:
        self.status = SessionStatus.CANCELLED
        self.finished_at = datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        d = redact_value(asdict(self))
        d["status"] = self.status.value
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Session":
        data = dict(data)
        data["status"] = SessionStatus(data.get("status", "pending"))
        return cls(**data)

    @property
    def short_id(self) -> str:
        """First 8 characters of the session UUID."""
        return self.session_id[:8]

    @property
    def duration_seconds(self) -> float | None:
        """Elapsed time in seconds, or ``None`` if not started."""
        if not self.started_at:
            return None
        start = datetime.fromisoformat(self.started_at)
        end_str = self.finished_at or datetime.now(timezone.utc).isoformat()
        end = datetime.fromisoformat(end_str)
        return (end - start).total_seconds()

    def add_finding(self, finding: dict[str, Any]) -> None:
        self.findings.append(finding)

    def set_module_state(self, module: str, state: dict[str, Any]) -> None:
        self.module_state[module] = state

    def get_module_state(self, module: str) -> dict[str, Any]:
        return self.module_state.get(module, {})

    def __repr__(self) -> str:
        return (
            f"<Session id={self.short_id!r} "
            f"status={self.status.value!r} "
            f"targets={self.targets!r}>"
        )


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


class SessionManager:
    """
    Persists and retrieves scan sessions on disk.

    Each session is stored as a JSON file under ``<sessions_dir>/<session_id>.json``.

    Parameters
    ----------
    sessions_dir:
        Directory where session files are stored.
        Defaults to ``output/sessions/``.
    """

    def __init__(self, sessions_dir: str | Path = "output/sessions") -> None:
        self._dir = Path(sessions_dir)
        self._dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def create(
        self,
        targets: list[str],
        profile: str = "normal",
        metadata: dict[str, Any] | None = None,
    ) -> Session:
        """Create and persist a new session."""
        session = Session(
            targets=targets,
            profile=profile,
            metadata=metadata or {},
        )
        self._save(session)
        return session

    def load(self, session_id: str) -> Session:
        """Load a session by ID.

        Raises
        ------
        FileNotFoundError
            If no session with *session_id* exists on disk.
        """
        path = self._path(session_id)
        if not path.exists():
            raise FileNotFoundError(f"Session not found: {session_id}")
        with path.open() as fh:
            return Session.from_dict(json.load(fh))

    def save(self, session: Session) -> None:
        """Persist the current state of *session* to disk."""
        self._save(session)

    def delete(self, session_id: str) -> None:
        """Remove a session file."""
        path = self._path(session_id)
        if path.exists():
            path.unlink()

    # ------------------------------------------------------------------
    # Listing / history
    # ------------------------------------------------------------------

    def list_sessions(
        self,
        status: SessionStatus | None = None,
        limit: int = 50,
    ) -> list[Session]:
        """
        Return sessions sorted newest-first.

        Parameters
        ----------
        status:
            Filter by status; ``None`` returns all sessions.
        limit:
            Maximum number of sessions to return.
        """
        sessions: list[Session] = []
        for path in sorted(self._dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
            try:
                with path.open() as fh:
                    s = Session.from_dict(json.load(fh))
                if status is None or s.status == status:
                    sessions.append(s)
                    if len(sessions) >= limit:
                        break
            except (json.JSONDecodeError, KeyError, TypeError):
                continue
        return sessions

    def find_resumable(self) -> list[Session]:
        """Return paused or running sessions that can be resumed."""
        return self.list_sessions(status=SessionStatus.PAUSED) + \
               self.list_sessions(status=SessionStatus.RUNNING)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _path(self, session_id: str) -> Path:
        if not session_id or Path(session_id).name != session_id or not re.fullmatch(
            r"[A-Za-z0-9_-]{1,64}", session_id
        ):
            raise ValueError("Invalid session identifier.")
        exact = self._dir / f"{session_id}.json"
        if exact.exists() or len(session_id) != 8:
            return exact
        matches = list(self._dir.glob(f"{session_id}*.json"))
        if len(matches) == 1:
            return matches[0]
        return exact

    def _save(self, session: Session) -> None:
        path = self._path(session.session_id)
        with path.open("w", encoding="utf-8") as fh:
            json.dump(session.to_dict(), fh, indent=2, default=str)
        path.chmod(0o600)
