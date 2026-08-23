"""Tests for ConfigManager."""
from __future__ import annotations

import os
import textwrap
from pathlib import Path

import pytest
import yaml

from sentinelforge.core.config import ConfigManager, ConfigError


class TestConfigDefaults:
    def test_defaults_loaded(self) -> None:
        cfg = ConfigManager()
        assert cfg.get("general.log_level") == "INFO"
        assert cfg.get("general.max_threads") == 10
        assert cfg.get("scanning.profile") == "normal"

    def test_get_nested_key(self) -> None:
        cfg = ConfigManager()
        assert cfg.get("network.rate_limit") == 10

    def test_get_missing_key_returns_default(self) -> None:
        cfg = ConfigManager()
        assert cfg.get("nonexistent.key", "fallback") == "fallback"

    def test_set_runtime_override(self) -> None:
        cfg = ConfigManager()
        cfg.set("general.log_level", "DEBUG")
        assert cfg.get("general.log_level") == "DEBUG"


class TestConfigFromFile:
    def test_load_yaml_override(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            textwrap.dedent("""\
                general:
                  log_level: DEBUG
                  max_threads: 5
            """)
        )
        cfg = ConfigManager(config_path=config_file)
        assert cfg.get("general.log_level") == "DEBUG"
        assert cfg.get("general.max_threads") == 5
        # Unset keys still return defaults
        assert cfg.get("scanning.profile") == "normal"

    def test_missing_required_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="not found"):
            ConfigManager(config_path=tmp_path / "nonexistent.yaml")

    def test_invalid_yaml_raises(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text("{{invalid: yaml: content")
        with pytest.raises(ConfigError):
            ConfigManager(config_path=bad)

    def test_non_mapping_yaml_raises(self, tmp_path: Path) -> None:
        bad = tmp_path / "list.yaml"
        bad.write_text("- item1\n- item2\n")
        with pytest.raises(ConfigError, match="must be a YAML mapping"):
            ConfigManager(config_path=bad)


class TestConfigValidation:
    def test_invalid_log_level_raises(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.yaml"
        f.write_text("general:\n  log_level: NONSENSE\n")
        with pytest.raises(ConfigError, match="Invalid log_level"):
            ConfigManager(config_path=f)

    def test_invalid_max_threads_raises(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.yaml"
        f.write_text("general:\n  max_threads: 0\n")
        with pytest.raises(ConfigError, match="positive integer"):
            ConfigManager(config_path=f)

    def test_invalid_report_format_raises(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.yaml"
        f.write_text("reporting:\n  formats:\n    - xml\n")
        with pytest.raises(ConfigError, match="Unknown report format"):
            ConfigManager(config_path=f)

    @pytest.mark.parametrize(
        "yaml_text, message",
        [
            ("general:\n  timeout: 0\n", "general.timeout"),
            ("general:\n  retries: 11\n", "general.retries"),
            ("network:\n  verify_ssl: maybe\n", "network.verify_ssl"),
            ("plugins:\n  enabled: dns\n", "plugins.enabled"),
            ("plugins:\n  enabled: [dns]\n  disabled: [dns]\n", "cannot"),
            ("reporting:\n  formats: []\n", "reporting.formats"),
        ],
    )
    def test_invalid_operational_values_raise(
        self, tmp_path: Path, yaml_text: str, message: str
    ) -> None:
        config = tmp_path / "invalid.yaml"
        config.write_text(yaml_text)
        with pytest.raises(ConfigError, match=message):
            ConfigManager(config_path=config)


class TestConfigEnvOverride:
    def test_env_log_level_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SF_LOG_LEVEL", "DEBUG")
        cfg = ConfigManager()
        assert cfg.get("general.log_level") == "DEBUG"

    def test_env_max_threads_coercion(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SF_MAX_THREADS", "20")
        cfg = ConfigManager()
        assert cfg.get("general.max_threads") == 20

    def test_env_shodan_key_enables_integration(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SF_SHODAN_API_KEY", "test_key_abc123")
        cfg = ConfigManager()
        assert cfg.get("integrations.shodan.api_key") == "test_key_abc123"
        assert cfg.get("integrations.shodan.enabled") is True


class TestConfigDeepMerge:
    def test_deep_merge_preserves_unset_keys(self, tmp_path: Path) -> None:
        f = tmp_path / "partial.yaml"
        f.write_text("general:\n  max_threads: 25\n")
        cfg = ConfigManager(config_path=f)
        # log_level was not overridden → should still be default
        assert cfg.get("general.log_level") == "INFO"
        assert cfg.get("general.max_threads") == 25


class TestConfigProfile:
    def test_profile_property(self) -> None:
        cfg = ConfigManager(profile="fast")
        # Fast profile sets max_threads to 15
        assert cfg.get("general.max_threads") == 15

    def test_unknown_profile_silent_fallback(self) -> None:
        # Should not raise — just fall back to normal
        cfg = ConfigManager(profile="nonexistent_profile")
        assert cfg.profile in ("nonexistent_profile", "normal")
