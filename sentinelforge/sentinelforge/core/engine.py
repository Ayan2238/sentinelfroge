"""
SentinelEngine — Central Orchestrator
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Every scan passes through here. No module executes independently.

Workflow
--------
1. load_config
2. configure_logging
3. load_plugins + load_modules
4. create / resume session
5. validate targets
6. execute modules + plugins per target (via Scheduler)
7. correlate findings
8. generate reports
9. cleanup
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from sentinelforge.core.config import ConfigManager
from sentinelforge.core.module_loader import ModuleLoader
from sentinelforge.core.plugin_loader import PluginLoader
from sentinelforge.core.scheduler import Scheduler
from sentinelforge.core.session import Session, SessionManager, SessionStatus
from sentinelforge.core.target import Target, TargetManager
from sentinelforge.correlation.engine import CorrelationEngine, CorrelatedReport
from sentinelforge.logging.logger import SentinelLogger, configure_logging
from sentinelforge.modules.base import Finding
from sentinelforge.reporting.engine import ReportEngine


class ScanError(Exception):
    """Fatal scan error that cannot be recovered from."""


class SentinelEngine:
    """
    Central engine that owns the complete scan lifecycle.

    Parameters
    ----------
    config_path:
        Optional path to a custom YAML config file.
    profile:
        Scan profile name (fast / normal / deep / stealth / web / cloud).
    output_dir:
        Directory for reports and session files.
    verbose:
        Enable DEBUG-level logging.
    quiet:
        Suppress all output except errors.
    """

    VERSION = "1.0.0"

    def __init__(
        self,
        config_path: str | Path | None = None,
        profile: str | None = None,
        output_dir: str | Path = "output",
        verbose: bool = False,
        quiet: bool = False,
    ) -> None:
        self._output_dir = Path(output_dir)

        # ── Config ────────────────────────────────────────────────────────
        self._config = ConfigManager(config_path=config_path, profile=profile)

        # ── Logging ───────────────────────────────────────────────────────
        log_level = "DEBUG" if verbose else ("ERROR" if quiet else self._config.get("general.log_level", "INFO"))
        self._log = configure_logging(
            level=log_level,
            log_dir=self._output_dir / "logs",
        )

        # ── Sub-components ────────────────────────────────────────────────
        self._target_mgr = TargetManager(resolve=True)
        self._session_mgr = SessionManager(sessions_dir=self._output_dir / "sessions")
        self._module_loader = ModuleLoader()
        self._plugin_loader = PluginLoader(
            enabled=self._config.get("plugins.enabled"),
            disabled=self._config.get("plugins.disabled", []),
            extra_paths=self._plugin_paths(),
        )
        self._scheduler = Scheduler(
            max_workers=self._config.get("general.max_threads", 10),
            rate_limit=self._config.get("network.rate_limit", 0),
            timeout=self._config.get("general.timeout", 30),
        )
        self._correlation = CorrelationEngine()
        self._report_engine = ReportEngine(
            output_dir=self._output_dir / "reports",
            formats=self._config.get("reporting.formats", ["html", "json"]),
        )

        # Discover all modules and plugins
        self._module_loader.discover()
        self._plugin_loader.discover()

        self._log.info(
            "SentinelForge engine initialised",
            version=self.VERSION,
            profile=self._config.profile,
            modules=len(self._module_loader.list()),
            plugins=len(self._plugin_loader.list_active()),
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(
        self,
        targets: list[str] | str,
        resume_session_id: str | None = None,
        extra_metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Run a complete scan against *targets*.

        Parameters
        ----------
        targets:
            One or more target strings (domain, IP, CIDR, URL).
        resume_session_id:
            If given, load an existing session and continue from where it stopped.
        extra_metadata:
            Arbitrary metadata to attach to the session and reports.

        Returns
        -------
        dict
            Summary: session_id, risk_score, finding_counts, report_paths.
        """
        if isinstance(targets, str):
            targets = [targets]

        start_wall = time.perf_counter()

        # ── Session ───────────────────────────────────────────────────────
        if resume_session_id:
            session = self._resume_session(resume_session_id)
            targets = session.targets
        else:
            session = self._session_mgr.create(
                targets=targets,
                profile=self._config.profile,
                metadata=extra_metadata or {},
            )

        session.start()
        self._session_mgr.save(session)
        self._log.info("Scan started", session=session.short_id, targets=targets)

        try:
            # ── Target validation ─────────────────────────────────────────
            parsed_targets = self._validate_targets(targets, session)

            # ── Module + Plugin execution ─────────────────────────────────
            all_findings: list[Finding] = []
            for target in parsed_targets:
                findings = self._scan_target(target, session)
                all_findings.extend(findings)

            # Module and plugin execution persists findings as each target is
            # completed, which also makes them available to post-exploit
            # analysis on the next target.
            self._session_mgr.save(session)

            # ── Correlation ───────────────────────────────────────────────
            self._log.info("Correlating findings", count=len(all_findings))
            correlated: CorrelatedReport = self._correlation.correlate(all_findings)

            # ── Reporting ─────────────────────────────────────────────────
            session.complete()
            self._session_mgr.save(session)

            report_paths = self._report_engine.generate(
                report=correlated,
                session=session,
                metadata=extra_metadata or {},
            )
            elapsed = time.perf_counter() - start_wall

            self._log.success(
                "Scan complete",
                session=session.short_id,
                risk_score=correlated.risk_score,
                findings=len(correlated.findings),
                elapsed=f"{elapsed:.1f}s",
            )
            for fmt, path in report_paths.items():
                self._log.info("Report written", format=fmt, path=str(path))

            return {
                "session_id": session.session_id,
                "risk_score": correlated.risk_score,
                "severity_distribution": correlated.severity_distribution,
                "attack_chains": len(correlated.attack_chains),
                "total_findings": len(correlated.findings),
                "report_paths": {fmt: str(p) for fmt, p in report_paths.items()},
                "elapsed_seconds": round(elapsed, 2),
            }

        except Exception as exc:
            session.fail(reason=str(exc))
            self._session_mgr.save(session)
            self._log.error("Scan failed", exc_info=True, error=str(exc))
            raise ScanError(str(exc)) from exc

    def doctor(self) -> dict[str, Any]:
        """Check the environment and return a diagnostic report."""
        checks: dict[str, Any] = {
            "version": self.VERSION,
            "python": _python_version(),
            "config_valid": True,
            "modules": self._module_loader.list(),
            "active_plugins": self._plugin_loader.list_active(),
            "all_plugins": self._plugin_loader.list_all(),
            "output_dir": str(self._output_dir.resolve()),
            "profile": self._config.profile,
            "optional_deps": _check_optional_deps(),
        }
        return checks

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _validate_targets(
        self, raw_targets: list[str], session: Session
    ) -> list[Target]:
        """Parse and validate targets; attach them to the session."""
        validated: list[Target] = []
        for raw in raw_targets:
            try:
                t = self._target_mgr.add(raw)
                validated.append(t)
                self._log.debug("Target validated", target=raw, kind=t.kind.value)
            except Exception as exc:
                self._log.warning("Invalid target skipped", target=raw, error=str(exc))
        if not validated:
            raise ScanError("No valid targets to scan.")
        return validated

    def _scan_target(
        self, target: Target, session: Session
    ) -> list[Finding]:
        """Run all active modules and plugins against a single target."""
        self._log.info("Scanning target", target=str(target), kind=target.kind.value)
        findings: list[Finding] = []
        regular_findings: list[Finding] = []

        # ── Modules ───────────────────────────────────────────────────────
        module_instances = self._module_loader.instantiate_all(self._config)
        regular_modules = [m for m in module_instances if m.name != "post_exploit"]
        analysis_modules = [m for m in module_instances if m.name == "post_exploit"]
        module_tasks = [
            (f"module:{m.name}", m.execute, (target, session), {})
            for m in regular_modules
        ]
        module_results = self._scheduler.run(
            module_tasks,
            progress_callback=lambda name, r: self._log.debug(
                "Module done",
                name=name,
                status=r.result.status if r.success else "failed",
                findings=len(r.result.findings) if r.success else 0,
            ),
        )
        for task_result in module_results:
            if task_result.success and task_result.result:
                findings.extend(task_result.result.findings)
                regular_findings.extend(task_result.result.findings)
                for finding in task_result.result.findings:
                    session.add_finding(finding.to_dict())
            elif not task_result.success:
                self._log.warning(
                    "Module execution failed", name=task_result.name, error=task_result.error
                )

        # Post-exploitation analysis consumes findings from the preceding
        # modules, so it runs after those results have been attached to the
        # session rather than concurrently with them.
        analysis_tasks = [
            (f"module:{m.name}", m.execute, (target, session), {})
            for m in analysis_modules
        ]
        analysis_results = self._scheduler.run(analysis_tasks)
        for task_result in analysis_results:
            if task_result.success and task_result.result:
                findings.extend(task_result.result.findings)
            elif not task_result.success:
                self._log.warning(
                    "Module execution failed", name=task_result.name, error=task_result.error
                )

        # ── Plugins ───────────────────────────────────────────────────────
        plugin_instances = self._plugin_loader.instantiate_active(self._config)
        plugin_tasks = [
            (f"plugin:{p.name}", p.execute, (target,), {})
            for p in plugin_instances
        ]
        plugin_results = self._scheduler.run(
            plugin_tasks,
            progress_callback=lambda name, r: self._log.debug(
                "Plugin done",
                name=name,
                status=r.result.status if r.success else "failed",
            ),
        )
        for task_result in plugin_results:
            if task_result.success and task_result.result:
                findings.extend(task_result.result.findings)
            elif not task_result.success:
                self._log.warning(
                    "Plugin execution failed", name=task_result.name, error=task_result.error
                )

        for finding in findings[len(regular_findings):]:
            session.add_finding(finding.to_dict())

        self._log.info(
            "Target scan complete",
            target=str(target),
            findings=len(findings),
        )
        return findings

    def _resume_session(self, session_id: str) -> Session:
        try:
            session = self._session_mgr.load(session_id)
            if session.status == SessionStatus.COMPLETED:
                raise ScanError(f"Cannot resume completed session '{session_id}'.")
            if session.status not in (
                SessionStatus.PAUSED,
                SessionStatus.RUNNING,
                SessionStatus.FAILED,
            ):
                raise ScanError(
                    f"Cannot resume session '{session_id}' from status "
                    f"'{session.status.value}'."
                )
            session.status = SessionStatus.RUNNING
            self._log.info("Resuming session", session=session.short_id)
            return session
        except FileNotFoundError as exc:
            raise ScanError(f"Cannot resume: session '{session_id}' not found.") from exc
        except (ValueError, TypeError, KeyError) as exc:
            raise ScanError(f"Cannot resume: session '{session_id}' has invalid state.") from exc

    def _plugin_paths(self) -> list[str]:
        configured = self._config.get("plugins.plugin_dir")
        if not configured:
            return []
        paths = configured if isinstance(configured, list) else [configured]
        return [str(Path(path)) for path in paths if Path(path).is_dir()]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _python_version() -> str:
    import sys
    v = sys.version_info
    return f"{v.major}.{v.minor}.{v.micro}"


def _check_optional_deps() -> dict[str, bool]:
    deps = ["dnspython", "requests", "rich", "click", "yaml", "jinja2"]
    result = {}
    for dep in deps:
        try:
            import importlib
            importlib.import_module(dep.replace("yaml", "yaml").replace("dnspython", "dns"))
            result[dep] = True
        except ImportError:
            result[dep] = False
    return result
