"""
SentinelForge CLI
~~~~~~~~~~~~~~~~~
Professional command-line interface for the SentinelForge security framework.

Usage examples::

    sf scan example.com
    sf scan example.com --profile deep --output ./results
    sf scan example.com -f html json csv -v
    sf report --session abc12345
    sf plugin list
    sf plugin enable cloud
    sf history
    sf resume abc12345
    sf doctor
    sf version
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

# Use click for the CLI; fall back gracefully if not installed
try:
    import click
    _HAS_CLICK = True
except ImportError:
    _HAS_CLICK = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    _HAS_RICH = True
    _console = Console()
except ImportError:
    _HAS_RICH = False
    _console = None  # type: ignore[assignment]

_BANNER = r"""
  ____            _   _            _ _____
 / ___|  ___ _ __| |_(_)_ __   ___| |  ___|__  _ __ __ _  ___
 \___ \ / _ \ '_ \ __| | '_ \ / _ \ | |_ / _ \| '__/ _` |/ _ \
  ___) |  __/ | | | |_| | | | |  __/ |  _| (_) | | | (_| |  __/
 |____/ \___|_| |_|\__|_|_| |_|\___|_|_|  \___/|_|  \__, |\___|
                                                      |___/
"""

_VERSION = "2.0.0"


def _print_banner() -> None:
    if _HAS_RICH:
        _console.print(f"[bold cyan]{_BANNER}[/bold cyan]")
        _console.print(
            f"  [dim]v{_VERSION}  ·  Professional Security Assessment Framework[/dim]\n"
        )
    else:
        print(_BANNER)
        print(f"  v{_VERSION}  ·  Professional Security Assessment Framework\n")


def _err(msg: str) -> None:
    from sentinelforge.core.security import redact_text
    msg = redact_text(msg)
    if _HAS_RICH:
        _console.print(f"[bold red]✗ Error:[/bold red] {msg}", file=sys.stderr)
    else:
        print(f"[ERROR] {msg}", file=sys.stderr)


def _ok(msg: str) -> None:
    if _HAS_RICH:
        _console.print(f"[bold green]✓[/bold green] {msg}")
    else:
        print(f"[OK] {msg}")


def _info(msg: str) -> None:
    if _HAS_RICH:
        _console.print(f"[dim]{msg}[/dim]")
    else:
        print(msg)


if _HAS_CLICK:
    # ──────────────────────────────────────────────────────────────────────
    # CLI definition
    # ──────────────────────────────────────────────────────────────────────

    @click.group(invoke_without_command=True)
    @click.pass_context
    @click.version_option(version=_VERSION, prog_name="SentinelForge")
    def cli(ctx: click.Context) -> None:
        """
        \b
        SentinelForge — Professional Security Assessment Framework
        For authorised penetration testing and security auditing only.
        """
        if ctx.invoked_subcommand is None:
            _print_banner()
            click.echo(ctx.get_help())

    # ── scan ──────────────────────────────────────────────────────────────

    @cli.command()
    @click.argument("targets", nargs=-1, required=True)
    @click.option(
        "--profile", "-p",
        default="normal",
        type=click.Choice(["fast", "normal", "deep", "stealth", "web", "cloud", "network"]),
        help="Scan profile to use.",
        show_default=True,
    )
    @click.option(
        "--output", "-o",
        default="output",
        type=click.Path(),
        help="Output directory for reports and session files.",
        show_default=True,
    )
    @click.option(
        "--format", "-f",
        "formats",
        multiple=True,
        default=["html", "json"],
        type=click.Choice(["html", "json", "markdown", "csv", "pdf"]),
        help="Report output format(s). Repeat to enable multiple.",
    )
    @click.option("--config", "-c", default=None, type=click.Path(exists=True), help="Custom config YAML.")
    @click.option("--verbose", "-v", is_flag=True, help="Enable debug output.")
    @click.option("--quiet", "-q", is_flag=True, help="Suppress output except errors.")
    @click.option("--resume", default=None, help="Resume an interrupted session by ID.")
    def scan(
        targets: tuple[str, ...],
        profile: str,
        output: str,
        formats: tuple[str, ...],
        config: Optional[str],
        verbose: bool,
        quiet: bool,
        resume: Optional[str],
    ) -> None:
        """
        Run a security assessment against one or more targets.

        \b
        Examples:
          sf scan example.com
          sf scan example.com --profile deep
          sf scan 10.0.0.0/24 --profile network
          sf scan https://example.com/app --format html json csv
        """
        if not quiet:
            _print_banner()

        _info(f"Targets:  {', '.join(targets)}")
        _info(f"Profile:  {profile}")
        _info(f"Output:   {output}")
        _info(f"Formats:  {', '.join(formats)}")
        print()

        try:
            from sentinelforge.core.engine import SentinelEngine
            engine = SentinelEngine(
                config_path=config,
                profile=profile,
                output_dir=output,
                verbose=verbose,
                quiet=quiet,
            )

            # CLI formats must update the already-created report engine too.
            engine._config.set("reporting.formats", list(formats))
            engine._report_engine._formats = list(formats)

            result = engine.scan(
                targets=list(targets),
                resume_session_id=resume,
            )

            if not quiet:
                _print_scan_summary(result)

            sys.exit(0)

        except Exception as exc:  # noqa: BLE001
            _err(str(exc))
            if verbose:
                import traceback
                traceback.print_exc()
            sys.exit(1)

    # ── report ────────────────────────────────────────────────────────────

    @cli.command()
    @click.option("--session", "-s", required=True, help="Session ID to generate report for.")
    @click.option("--output", "-o", default="output", type=click.Path(), help="Output directory.")
    @click.option("--format", "-f", "formats", multiple=True, default=["html"],
                  type=click.Choice(["html", "json", "markdown", "csv", "pdf"]))
    def report(session: str, output: str, formats: tuple[str, ...]) -> None:
        """Re-generate a report from an existing scan session."""
        try:
            from sentinelforge.core.session import SessionManager
            from sentinelforge.correlation.engine import CorrelationEngine
            from sentinelforge.modules.base import Finding, Severity
            from sentinelforge.reporting.engine import ReportEngine

            mgr = SessionManager(sessions_dir=Path(output) / "sessions")
            sess = mgr.load(session)
            findings = [
                Finding(
                    module=f.get("module", ""),
                    title=f.get("title", ""),
                    severity=Severity(f.get("severity", "info")),
                    target=f.get("target", ""),
                    description=f.get("description", ""),
                    evidence=f.get("evidence", []),
                    recommendation=f.get("recommendation", ""),
                    references=f.get("references", []),
                    confidence=f.get("confidence", 1.0),
                )
                for f in sess.findings
            ]
            correlated = CorrelationEngine().correlate(findings)
            engine = ReportEngine(
                output_dir=Path(output) / "reports",
                formats=list(formats),
            )
            paths = engine.generate(correlated, sess)
            for fmt, path in paths.items():
                _ok(f"Report written: {path}")
        except Exception as exc:  # noqa: BLE001
            _err(str(exc))
            sys.exit(1)

    # ── plugin ────────────────────────────────────────────────────────────

    @cli.group()
    def plugin() -> None:
        """Manage SentinelForge plugins."""

    @plugin.command("list")
    def plugin_list() -> None:
        """List all available plugins and their status."""
        from sentinelforge.core.plugin_loader import PluginLoader
        from sentinelforge.core.config import ConfigManager
        cfg = ConfigManager()
        loader = PluginLoader(
            enabled=cfg.get("plugins.enabled"),
            disabled=cfg.get("plugins.disabled", []),
        )
        loader.discover()
        active = set(loader.list_active())

        if _HAS_RICH:
            table = Table(title="Installed Plugins", show_lines=True)
            table.add_column("Name", style="bold")
            table.add_column("Status")
            table.add_column("Category")
            for name in loader.list_all():
                cls = loader.get(name)
                status = "[green]● active[/green]" if name in active else "[dim]○ disabled[/dim]"
                table.add_row(name, status, getattr(cls, "category", "—"))
            _console.print(table)
        else:
            for name in loader.list_all():
                status = "active" if name in active else "disabled"
                print(f"  {name:20s} [{status}]")

    @plugin.command("enable")
    @click.argument("name")
    @click.option("--config", "-c", default=None, type=click.Path(exists=True), help="Custom config YAML.")
    def plugin_enable(name: str, config: Optional[str]) -> None:
        """Enable a plugin by name."""
        from sentinelforge.core.config import ConfigManager
        from sentinelforge.core.plugin_loader import PluginLoader, PluginLoadError
        cfg = ConfigManager(config_path=config)
        loader = PluginLoader(
            enabled=cfg.get("plugins.enabled"),
            disabled=cfg.get("plugins.disabled", []),
            extra_paths=[cfg.get("plugins.plugin_dir")] if cfg.get("plugins.plugin_dir") else [],
        )
        loader.discover()
        if name not in loader.list_all():
            raise click.ClickException(f"Unknown plugin '{name}'. Available: {', '.join(loader.list_all())}")
        cfg.persist_plugin_state(name, True, config)
        _ok(f"Plugin '{name}' enabled and persisted.")

    @plugin.command("disable")
    @click.argument("name")
    @click.option("--config", "-c", default=None, type=click.Path(exists=True), help="Custom config YAML.")
    def plugin_disable(name: str, config: Optional[str]) -> None:
        """Disable a plugin by name."""
        from sentinelforge.core.config import ConfigManager
        cfg = ConfigManager(config_path=config)
        from sentinelforge.core.plugin_loader import PluginLoader
        loader = PluginLoader(
            enabled=cfg.get("plugins.enabled"),
            disabled=cfg.get("plugins.disabled", []),
            extra_paths=[cfg.get("plugins.plugin_dir")] if cfg.get("plugins.plugin_dir") else [],
        )
        loader.discover()
        if name not in loader.list_all():
            raise click.ClickException(f"Unknown plugin '{name}'. Available: {', '.join(loader.list_all())}")
        cfg.persist_plugin_state(name, False, config)
        _ok(f"Plugin '{name}' disabled and persisted.")

    # ── profile ───────────────────────────────────────────────────────────

    @cli.command()
    def profile() -> None:
        """List available scan profiles."""
        profiles = {
            "fast":    "Quick, low-noise scan. Skips brute force and deep checks.",
            "normal":  "Balanced scan. Recommended for most assessments.",
            "deep":    "Thorough scan. All modules at maximum depth.",
            "stealth": "Low-rate, passive-first scan to avoid detection.",
            "web":     "Web-focused: headers, XSS, SQLi, cookies, CORS.",
            "network": "Network-focused: ports, banners, service fingerprinting.",
            "cloud":   "Cloud-focused: S3 and Azure Blob checks.",
        }
        if _HAS_RICH:
            table = Table(title="Scan Profiles", show_lines=True)
            table.add_column("Profile", style="bold cyan")
            table.add_column("Description")
            for name, desc in profiles.items():
                table.add_row(name, desc)
            _console.print(table)
        else:
            for name, desc in profiles.items():
                print(f"  {name:12s}  {desc}")

    # ── history ───────────────────────────────────────────────────────────

    @cli.command()
    @click.option("--output", "-o", default="output", type=click.Path())
    @click.option("--limit", default=20, show_default=True)
    def history(output: str, limit: int) -> None:
        """Show recent scan history."""
        from sentinelforge.core.session import SessionManager
        mgr = SessionManager(sessions_dir=Path(output) / "sessions")
        sessions = mgr.list_sessions(limit=limit)

        if not sessions:
            _info("No scan history found.")
            return

        if _HAS_RICH:
            table = Table(title="Scan History", show_lines=True)
            table.add_column("Session", style="bold")
            table.add_column("Targets")
            table.add_column("Profile")
            table.add_column("Status")
            table.add_column("Started")
            for s in sessions:
                status_colour = {
                    "completed": "green", "failed": "red",
                    "running": "yellow", "cancelled": "dim",
                }.get(s.status.value, "white")
                table.add_row(
                    s.short_id,
                    ", ".join(s.targets[:3]),
                    s.profile,
                    f"[{status_colour}]{s.status.value}[/{status_colour}]",
                    (s.started_at or "")[:16],
                )
            _console.print(table)
        else:
            for s in sessions:
                print(f"  {s.short_id}  {', '.join(s.targets)}  [{s.status.value}]  {(s.started_at or '')[:16]}")

    # ── resume ────────────────────────────────────────────────────────────

    @cli.command()
    @click.argument("session_id")
    @click.option("--output", "-o", default="output", type=click.Path())
    def resume(session_id: str, output: str) -> None:
        """Resume an interrupted scan session."""
        _info(f"Resuming session: {session_id}")
        ctx = click.get_current_context()
        ctx.invoke(
            scan,
            targets=(session_id,),  # engine uses the session ID to load the saved targets
            profile="normal",
            output=output,
            formats=("html", "json"),
            config=None,
            verbose=False,
            quiet=False,
            resume=session_id,
        )

    # ── doctor ────────────────────────────────────────────────────────────

    @cli.command()
    def doctor() -> None:
        """Run diagnostics and check the SentinelForge environment."""
        from sentinelforge.core.engine import SentinelEngine
        engine = SentinelEngine(quiet=True)
        info = engine.doctor()

        if _HAS_RICH:
            _console.print(Panel.fit("[bold cyan]SentinelForge Doctor[/bold cyan]"))
            _console.print(f"Version:        [bold]{info['version']}[/bold]")
            _console.print(f"Python:         {info['python']}")
            _console.print(f"Profile:        {info['profile']}")
            _console.print(f"Output dir:     {info['output_dir']}")
            _console.print(f"Modules loaded: [bold]{len(info['modules'])}[/bold]  ({', '.join(info['modules'])})")
            _console.print(f"Active plugins: [bold]{len(info['active_plugins'])}[/bold]  ({', '.join(info['active_plugins'])})")
            _console.print("\n[bold]Optional Dependencies:[/bold]")
            for dep, installed in info["optional_deps"].items():
                status = "[green]✓ installed[/green]" if installed else "[dim]○ not installed[/dim]"
                _console.print(f"  {dep:15s}  {status}")
        else:
            for k, v in info.items():
                print(f"  {k}: {v}")

    # ── version ───────────────────────────────────────────────────────────

    @cli.command()
    def version() -> None:
        """Show version information."""
        click.echo(f"SentinelForge v{_VERSION}")

    # ── config ────────────────────────────────────────────────────────────

    @cli.command("config")
    @click.option("--show", is_flag=True, help="Print the active configuration.")
    def config_cmd(show: bool) -> None:
        """Show or validate the active configuration."""
        from sentinelforge.core.config import ConfigManager
        import json
        cfg = ConfigManager()
        if show:
            print(json.dumps(cfg.redacted_data, indent=2, default=str))
        else:
            _ok(f"Configuration valid. Active profile: {cfg.profile}")

    # ── update ────────────────────────────────────────────────────────────

    @cli.command()
    def update() -> None:
        """Check PyPI for an available update."""
        _info("Checking for updates…")
        from sentinelforge.core.updater import check_for_update, upgrade_command

        result = check_for_update()
        if result["error"]:
            _err(result["error"])
            sys.exit(1)
        if result["update_available"]:
            _info(
                f"Update available: {result['current_version']} → "
                f"{result['latest_version']}"
            )
            _info(f"Run: {upgrade_command()}")
        else:
            _ok(f"SentinelForge {result['current_version']} is up to date.")

    # ──────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────

    def _print_scan_summary(result: dict) -> None:
        if _HAS_RICH:
            dist = result.get("severity_distribution", {})
            score = result.get("risk_score", 0)
            score_colour = "red" if score >= 70 else "yellow" if score >= 40 else "green"

            table = Table(title="Scan Summary", show_lines=True)
            table.add_column("Metric", style="bold")
            table.add_column("Value")
            table.add_row("Session ID", result["session_id"][:8])
            table.add_row("Risk Score", f"[{score_colour}][bold]{score:.0f} / 100[/bold][/{score_colour}]")
            table.add_row("🔴 Critical", str(dist.get("critical", 0)))
            table.add_row("🟠 High", str(dist.get("high", 0)))
            table.add_row("🟡 Medium", str(dist.get("medium", 0)))
            table.add_row("🟢 Low", str(dist.get("low", 0)))
            table.add_row("🔵 Info", str(dist.get("info", 0)))
            table.add_row("Total Findings", str(result.get("total_findings", 0)))
            table.add_row("Attack Chains", str(result.get("attack_chains", 0)))
            table.add_row("Duration", f"{result.get('elapsed_seconds', 0):.1f}s")
            _console.print(table)
            for fmt, path in result.get("report_paths", {}).items():
                _console.print(f"  [green]→[/green] {fmt.upper()} report: [underline]{path}[/underline]")
        else:
            print("\n=== Scan Summary ===")
            for k, v in result.items():
                print(f"  {k}: {v}")

    def main() -> None:
        """Entry point for the ``sf`` command."""
        cli()


else:
    # Minimal fallback if Click is not installed
    def main() -> None:  # type: ignore[misc]
        """Minimal CLI when click is not installed."""
        print("SentinelForge CLI requires 'click'. Install with: pip install sentinelforge[cli]")
        sys.exit(1)


if __name__ == "__main__":
    main()
