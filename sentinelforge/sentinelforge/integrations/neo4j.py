from __future__ import annotations

import hashlib
import json
from typing import Any

from sentinelforge.core.config import ConfigManager
from sentinelforge.logging.logger import get_logger

try:
    from neo4j import Driver, GraphDatabase
except ImportError:  # pragma: no cover - exercised when optional dependency is absent
    Driver = Any  # type: ignore[misc,assignment]
    GraphDatabase = None  # type: ignore[assignment]


class Neo4jIntegration:
    """Persist completed SentinelForge scan sessions in Neo4j.

    Neo4j is an optional persistence backend. A missing driver, disabled
    configuration, unavailable database, or write failure must never make
    the local scan fail.
    """

    def __init__(
        self,
        config: ConfigManager,
        logger: Any | None = None,
    ) -> None:
        self._config = config
        self._log = logger or get_logger(__name__)

        self._enabled = bool(
            self._config.get("integrations.neo4j.enabled", False)
        )
        self._uri = self._config.get("integrations.neo4j.uri")
        self._user = self._config.get("integrations.neo4j.user")
        self._password = self._config.get("integrations.neo4j.password")
        self._database = self._config.get(
            "integrations.neo4j.database", "neo4j"
        )

        self._driver: Driver | None = None

    @property
    def enabled(self) -> bool:
        """Whether Neo4j persistence is explicitly enabled."""
        return self._enabled

    def status(self) -> dict[str, Any]:
        """Return a safe, non-secret integration status."""
        if not self._enabled:
            return {
                "status": "disabled",
                "reason": "Neo4j integration is disabled.",
            }

        if GraphDatabase is None:
            return {
                "status": "unavailable",
                "reason": "Neo4j Python driver is not installed.",
            }

        if not self._uri or not self._user or not self._password:
            return {
                "status": "unavailable",
                "reason": "Neo4j connection configuration is incomplete.",
            }

        return {
            "status": "configured",
            "database": self._database,
        }

    def connect(self) -> dict[str, Any]:
        """Create and verify the Neo4j driver connection."""
        current = self.status()
        if current["status"] != "configured":
            return current

        try:
            self._driver = GraphDatabase.driver(
                self._uri,
                auth=(self._user, self._password),
            )
            self._driver.verify_connectivity()

            return {
                "status": "connected",
                "database": self._database,
            }
        except Exception as exc:
            self._close_driver()
            self._log.warning(
                "Neo4j connection unavailable",
                error=type(exc).__name__,
            )
            return {
                "status": "unavailable",
                "reason": "Neo4j connection could not be established.",
            }

    def persist_session(self, session: Any) -> dict[str, Any]:
        """Persist a completed Session and its findings.

        Returns a safe status dictionary. Database errors are isolated from
        the local scan/reporting workflow.
        """
        if not self._enabled:
            return {
                "status": "disabled",
                "persisted": False,
            }

        connection = self.connect()
        if connection["status"] != "connected":
            return {
                **connection,
                "persisted": False,
            }

        try:
            session_data = session.to_dict()
            session_id = str(session_data["session_id"])

            with self._driver.session(database=self._database) as db:
                db.execute_write(
                    self._write_session,
                    session_data,
                )

            return {
                "status": "success",
                "persisted": True,
                "session_id": session_id,
                "findings": len(session_data.get("findings", [])),
            }
        except Exception as exc:
            self._log.warning(
                "Neo4j session persistence failed",
                error=type(exc).__name__,
            )
            return {
                "status": "failed",
                "persisted": False,
                "reason": "Neo4j persistence failed.",
            }
        finally:
            self._close_driver()

    @staticmethod
    def _write_session(tx: Any, session_data: dict[str, Any]) -> None:
        session_id = str(session_data["session_id"])

        tx.run(
            """
            MERGE (s:ScanSession {session_id: $session_id})
            SET s.profile = $profile,
                s.status = $status,
                s.created_at = $created_at,
                s.started_at = $started_at,
                s.finished_at = $finished_at,
                s.duration_seconds = $duration_seconds,
                s.metadata_json = $metadata_json
            """,
            session_id=session_id,
            profile=session_data.get("profile"),
            status=session_data.get("status"),
            created_at=session_data.get("created_at"),
            started_at=session_data.get("started_at"),
            finished_at=session_data.get("finished_at"),
            duration_seconds=session_data.get("duration_seconds"),
            metadata_json=Neo4jIntegration._json_value(
                session_data.get("metadata", {})
            ),
        )

        for target_value in session_data.get("targets", []):
            target = str(target_value)

            tx.run(
                """
                MERGE (t:Target {value: $target})
                WITH t
                MATCH (s:ScanSession {session_id: $session_id})
                MERGE (s)-[:TARGETS]->(t)
                """,
                target=target,
                session_id=session_id,
            )

        for index, finding in enumerate(session_data.get("findings", [])):
            if not isinstance(finding, dict):
                continue

            finding_id = Neo4jIntegration._finding_id(
                session_id,
                index,
                finding,
            )

            target = str(finding.get("target", ""))

            tx.run(
                """
                MERGE (f:Finding {finding_id: $finding_id})
                SET f.module = $module,
                    f.title = $title,
                    f.severity = $severity,
                    f.target = $target,
                    f.description = $description,
                    f.evidence_json = $evidence_json,
                    f.recommendation = $recommendation,
                    f.references_json = $references_json,
                    f.confidence = $confidence,
                    f.cve_json = $cve_json,
                    f.cvss = $cvss,
                    f.tags_json = $tags_json
                WITH f
                MATCH (s:ScanSession {session_id: $session_id})
                MERGE (s)-[:HAS_FINDING]->(f)
                WITH f
                OPTIONAL MATCH (t:Target {value: $target})
                FOREACH (_ IN CASE WHEN t IS NULL THEN [] ELSE [1] END |
                    MERGE (t)-[:HAS_FINDING]->(f)
                )
                """,
                finding_id=finding_id,
                session_id=session_id,
                module=finding.get("module"),
                title=finding.get("title"),
                severity=finding.get("severity"),
                target=target,
                description=finding.get("description"),
                evidence_json=Neo4jIntegration._json_value(
                    finding.get("evidence", [])
                ),
                recommendation=finding.get("recommendation"),
                references_json=Neo4jIntegration._json_value(
                    finding.get("references", [])
                ),
                confidence=finding.get("confidence"),
                cve_json=Neo4jIntegration._json_value(
                    finding.get("cve", [])
                ),
                cvss=finding.get("cvss"),
                tags_json=Neo4jIntegration._json_value(
                    finding.get("tags", [])
                ),
            )

    @staticmethod
    def _finding_id(
        session_id: str,
        index: int,
        finding: dict[str, Any],
    ) -> str:
        payload = {
            "session_id": session_id,
            "index": index,
            "module": finding.get("module"),
            "title": finding.get("title"),
            "target": finding.get("target"),
            "severity": finding.get("severity"),
        }
        digest = hashlib.sha256(
            json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            ).encode("utf-8")
        ).hexdigest()[:24]
        return f"{session_id}:{digest}"

    @staticmethod
    def _json_value(value: Any) -> str:
        return json.dumps(value, ensure_ascii=False, default=str)

    def _close_driver(self) -> None:
        if self._driver is not None:
            try:
                self._driver.close()
            except Exception:
                pass
            finally:
                self._driver = None
