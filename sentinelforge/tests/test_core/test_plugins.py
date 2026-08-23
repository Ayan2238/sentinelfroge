"""Regression tests for plugin persistence and custom discovery."""
from __future__ import annotations

from pathlib import Path

from sentinelforge.core.config import ConfigManager
from sentinelforge.core.plugin_loader import PluginLoader


def test_plugin_state_persists_and_is_honored(tmp_path: Path, monkeypatch) -> None:
    user_config = tmp_path / "config.yaml"
    monkeypatch.setattr(ConfigManager, "_USER_CONFIG", user_config)
    cfg = ConfigManager()
    cfg.persist_plugin_state("cloud", True)
    reloaded = ConfigManager()
    assert "cloud" in reloaded.get("plugins.enabled")
    assert "dns" in reloaded.get("plugins.enabled")

    ConfigManager().persist_plugin_state("cloud", False)
    reloaded = ConfigManager()
    assert "cloud" not in reloaded.get("plugins.enabled")
    assert "cloud" in reloaded.get("plugins.disabled")


def test_custom_plugin_directory_is_discovered(tmp_path: Path) -> None:
    plugin_file = tmp_path / "custom_check.py"
    plugin_file.write_text(
        """
from sentinelforge.plugins.base import BasePlugin, PluginResult

class CustomCheck(BasePlugin):
    name = "custom_check"
    def initialize(self): pass
    def can_run(self, target): return False
    def run(self, target): return PluginResult(plugin_name=self.name)
    def cleanup(self): pass
"""
    )
    loader = PluginLoader(extra_paths=[str(tmp_path)])
    loader.discover()
    assert "custom_check" in loader.list_all()