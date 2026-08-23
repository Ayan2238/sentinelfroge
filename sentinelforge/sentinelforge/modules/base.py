"""
Base Module Interface
~~~~~~~~~~~~~~~~~~~~~
Every scan module MUST subclass :class:`BaseModule` and implement all
abstract methods. The engine only interacts with this interface, so
modules are completely interchangeable.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, TYPE_CHECKING

from sentinelforge.core.security import redact_value

if TYPE_CHECKING:
    from sentinelforge.core.config import ConfigManager
    from sentinelforge.core.target import Target
    from sentinelforge.core.session import Session


# ---------------------------------------------------------------------------
# Severity enum
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    NONE = "none"

    @property
    def score(self) -> int:
        return {
            "critical": 10, "high": 8, "medium": 5,
            "low": 3, "info": 1, "none": 0,
        }[self.value]

    def __lt__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.score < other.score

    def __le__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.score <= other.score


# ---------------------------------------------------------------------------
# Finding data-class
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """
    A single security finding produced by a module or plugin.

    All fields are serialisable to JSON / YAML so the reporting
    engine can process them uniformly.
    """

    module: str
    title: str
    severity: Severity
    target: str
    description: str = ""
    evidence: list[str] = field(default_factory=list)
    recommendation: str = ""
    references: list[str] = field(default_factory=list)
    confidence: float = 1.0         # 0.0 – 1.0
    cve: list[str] = field(default_factory=list)
    cvss: float | None = None
    tags: list[str] = field(default_factory=list)
    raw_data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return redact_value({
            "module": self.module,
            "title": self.title,
            "severity": self.severity.value,
            "target": self.target,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "references": self.references,
            "confidence": self.confidence,
            "cve": self.cve,
            "cvss": self.cvss,
            "tags": self.tags,
        })


# ---------------------------------------------------------------------------
# Module result
# ---------------------------------------------------------------------------


@dataclass
class ModuleResult:
    """
    Structured result returned by every module after execution.

    Attributes
    ----------
    module_name:
        Identifies which module produced this result.
    status:
        ``"success"`` | ``"partial"`` | ``"failed"`` | ``"skipped"``
    elapsed:
        Wall-clock execution time in seconds.
    findings:
        Security findings discovered during the run.
    error:
        Human-readable error description if status is ``"failed"``.
    metadata:
        Arbitrary module-specific supplementary data.
    """

    module_name: str
    status: str = "success"
    elapsed: float = 0.0
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return redact_value({
            "module_name": self.module_name,
            "status": self.status,
            "elapsed": round(self.elapsed, 3),
            "findings": [f.to_dict() for f in self.findings],
            "error": self.error,
            "metadata": self.metadata,
        })

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def highest_severity(self) -> Severity:
        if not self.findings:
            return Severity.NONE
        return max((f.severity for f in self.findings), key=lambda s: s.score)


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------


class BaseModule(ABC):
    """
    Abstract base class for all SentinelForge scan modules.

    Subclasses must set the class-level attributes and implement all
    abstract methods.

    Class Attributes
    ----------------
    name:
        Unique identifier used in the registry and CLI output.
    description:
        One-sentence description shown in help and reports.
    category:
        Logical grouping (``"recon"`` / ``"vuln"`` / ``"exploit"`` / etc.).
    """

    name: str = "unnamed"
    description: str = ""
    category: str = "general"
    author: str = "SentinelForge"
    version: str = "1.0.0"

    def __init__(self, config: "ConfigManager") -> None:
        self._config = config
        self._result: ModuleResult = ModuleResult(module_name=self.name)

    # ------------------------------------------------------------------
    # Lifecycle — must be implemented by every module
    # ------------------------------------------------------------------

    @abstractmethod
    def initialize(self) -> None:
        """One-time initialisation: load wordlists, set up clients, etc."""

    @abstractmethod
    def validate(self, target: "Target") -> bool:
        """
        Return ``True`` if this module can run against *target*.
        Return ``False`` to gracefully skip (not an error).
        """

    @abstractmethod
    def run(self, target: "Target", session: "Session") -> ModuleResult:
        """Execute the module and return a :class:`ModuleResult`."""

    @abstractmethod
    def cleanup(self) -> None:
        """Release resources: close connections, delete temp files, etc."""

    # ------------------------------------------------------------------
    # Optional hook
    # ------------------------------------------------------------------

    def report(self, result: ModuleResult) -> dict[str, Any]:
        """Return a report-friendly dict for *result*. Override to customise."""
        return result.to_dict()

    # ------------------------------------------------------------------
    # Execution harness (called by the engine — do not override)
    # ------------------------------------------------------------------

    def execute(self, target: "Target", session: "Session") -> ModuleResult:
        """
        Engine entry point: wraps ``run()`` with timing, error isolation,
        and state persistence.
        """
        result = ModuleResult(module_name=self.name)
        start = time.perf_counter()
        try:
            self.initialize()
            if not self.validate(target):
                result.status = "skipped"
                return result
            result = self.run(target, session)
        except Exception as exc:  # noqa: BLE001
            result.status = "failed"
            result.error = f"{type(exc).__name__}: {exc}"
        finally:
            result.elapsed = time.perf_counter() - start
            try:
                self.cleanup()
            except Exception:  # noqa: BLE001
                pass
            session.set_module_state(self.name, {"status": result.status})
        return result

    # ------------------------------------------------------------------
    # Convenience helpers for subclasses
    # ------------------------------------------------------------------

    def _finding(
        self,
        title: str,
        severity: Severity,
        target: "Target",
        description: str = "",
        evidence: list[str] | None = None,
        recommendation: str = "",
        references: list[str] | None = None,
        **kwargs: Any,
    ) -> Finding:
        return Finding(
            module=self.name,
            title=title,
            severity=severity,
            target=str(target),
            description=description,
            evidence=evidence or [],
            recommendation=recommendation,
            references=references or [],
            **kwargs,
        )

    def _cfg(self, key: str, default: Any = None) -> Any:
        return self._config.get(key, default)

    def __repr__(self) -> str:
        return f"<Module {self.name!r} v{self.version}>"
