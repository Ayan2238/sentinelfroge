"""End-to-end tests for repaired CLI configuration behavior."""
from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from sentinelforge.cli.main import cli
from sentinelforge.core.config import ConfigManager


def test_cli_plugin_enable_disable_persists(tmp_path: Path, monkeypatch) -> None:
    user_config = tmp_path / "user.yaml"
    monkeypatch.setattr(ConfigManager, "_USER_CONFIG", user_config)
    runner = CliRunner()

    enabled = runner.invoke(cli, ["plugin", "enable", "cloud"])
    assert enabled.exit_code == 0, enabled.output
    assert "cloud" in ConfigManager().get("plugins.enabled")

    disabled = runner.invoke(cli, ["plugin", "disable", "cloud"])
    assert disabled.exit_code == 0, disabled.output
    cfg = ConfigManager()
    assert "cloud" not in cfg.get("plugins.enabled")
    assert "cloud" in cfg.get("plugins.disabled")


def test_cli_unknown_plugin_returns_error(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(ConfigManager, "_USER_CONFIG", tmp_path / "user.yaml")
    result = CliRunner().invoke(cli, ["plugin", "enable", "does-not-exist"])
    assert result.exit_code != 0
    assert "Unknown plugin" in result.output