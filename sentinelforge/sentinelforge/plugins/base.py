"""
Base Plugin Interface
~~~~~~~~~~~~~~~~~~~~~
Plugins are lightweight, single-purpose scanning capabilities that the
engine composes dynamically. They are lighter-weight than full modules —
a plugin typically covers one protocol or service (DNS, SSL, HTTP headers,
cloud API checks, etc.) and is enabled / disabled per scan profile.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

from sentinelforge.modules.base import Finding, Severity
from sentinelforge.core.security import redact_value

if TYPE_CHECKING:
    from sentinelforge.core.config import ConfigManager
    from sentinelforge.core.target import Target


@dataclass
class PluginResult:
    """Structured result returned by every plugin."""

    plugin_name: str
    status: str = "success"   # success | partial | failed | skipped | unavailable
    elapsed: float = 0.0
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def to_dict(self) -> dict[str, Any]:
        return redact_value({
            "plugin_name": self.plugin_name,
            "status": self.status,
            "elapsed": round(self.elapsed, 3),
            "findings": [f.to_dict() for f in self.findings],
            "error": self.error,
            "metadata": self.metadata,
        })


class BasePlugin(ABC):
    """
    Abstract base class for all SentinelForge plugins.

    Class Attributes
    ----------------
    name:
        Unique identifier (registry key, CLI name).
    description:
        One-sentence description displayed in ``sf plugin list``.
    category:
        Logical category (dns / http / ssl / osint / cloud / network / …).
    """

    name: str = "unnamed_plugin"
    description: str = ""
    category: str = "general"
    author: str = "SentinelForge"
    version: str = "1.0.0"

    def __init__(self, config: "ConfigManager") -> None:
        self._config = config

    # ------------------------------------------------------------------
    # Lifecycle — implement all in subclasses
    # ------------------------------------------------------------------

    @abstractmethod
    def initialize(self) -> None:
        """One-time setup: load wordlists, create client objects, etc."""

    @abstractmethod
    def can_run(self, target: "Target") -> bool:
        """Return True if this plugin supports the given target type."""

    @abstractmethod
    def run(self, target: "Target") -> PluginResult:
        """Execute the plugin and return a :class:`PluginResult`."""

    @abstractmethod
    def cleanup(self) -> None:
        """Release resources."""

    # ------------------------------------------------------------------
    # Engine entry point — do not override
    # ------------------------------------------------------------------

    def execute(self, target: "Target") -> PluginResult:
        """Wraps ``run()`` with timing and error isolation."""
        result = PluginResult(plugin_name=self.name)
        start = time.perf_counter()
        try:
            self.initialize()
            if not self.can_run(target):
                result.status = "skipped"
                return result
            result = self.run(target)
        except Exception as exc:  # noqa: BLE001
            result.status = "failed"
            result.error = f"{type(exc).__name__}: {exc}"
        finally:
            result.elapsed = time.perf_counter() - start
            try:
                self.cleanup()
            except Exception:  # noqa: BLE001
                pass
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
            module=f"plugin:{self.name}",
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
        return f"<Plugin {self.name!r} v{self.version} [{self.category}]>"
