"""
Configuration Manager
~~~~~~~~~~~~~~~~~~~~~
Loads, validates, and provides access to all SentinelForge configuration.
Supports YAML config files, scan profiles, and environment variable overrides.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

_DEFAULT_CONFIG: dict[str, Any] = {
    "version": "1.0.0",
    "general": {
        "output_dir": "output",
        "log_level": "INFO",
        "max_threads": 10,
        "timeout": 30,
        "retries": 3,
        "user_agent": "SentinelForge/1.0 (Security Scanner)",
    },
    "network": {
        "proxy": None,
        "verify_ssl": True,
        "rate_limit": 10,          # requests per second
        "connect_timeout": 10,
        "read_timeout": 30,
    },
    "plugins": {
        "enabled": ["dns", "http", "ssl", "web", "osint"],
        "disabled": [],
        "plugin_dir": None,         # None → built-in only
    },
    "scanning": {
        "profile": "normal",
        "max_depth": 3,
        "follow_redirects": True,
        "max_redirects": 10,
        "scope": "domain",          # domain | subdomain | ip | cidr
    },
    "reporting": {
        "formats": ["html", "json"],
        "include_evidence": True,
        "include_raw_requests": False,
        "severity_threshold": "info",
    },
    "integrations": {
        "shodan": {"enabled": False, "api_key": None},
        "neo4j": {
            "enabled": False,
            "uri": "bolt://localhost:7687",
            "user": "neo4j",
            "password": None,
        },
    },
}

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ConfigError(Exception):
    """Raised when the configuration is invalid or cannot be loaded."""


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


class ConfigManager:
    """
    Manages all SentinelForge configuration.

    Priority (highest wins):
        1. Environment variables (``SF_*``)
        2. User config file (``~/.config/sentinelforge/config.yaml``)
        3. Project config file (``configs/config.yaml``)
        4. Built-in defaults

    Parameters
    ----------
    config_path:
        Explicit path to a YAML config file. When ``None`` the manager
        searches the standard locations.
    profile:
        Name of a scan profile to merge on top of base config (e.g.
        ``"fast"``, ``"deep"``).
    """

    _PACKAGE_CONFIG_DIR = Path(__file__).parent.parent.parent / "configs"
    _SYSTEM_CONFIG_DIR = Path("/etc/sentinelforge")
    _PROJECT_CONFIG = Path("configs/config.yaml")
    _USER_CONFIG = Path.home() / ".config" / "sentinelforge" / "config.yaml"

    def __init__(
        self,
        config_path: str | Path | None = None,
        profile: str | None = None,
    ) -> None:
        self._data: dict[str, Any] = self._deep_copy(_DEFAULT_CONFIG)
        self._profile_name: str | None = None

        # Load file layers
        self._merge(self._load_default_config())
        self._merge(self._load_yaml(self._USER_CONFIG))
        if config_path:
            self._merge(self._load_yaml(Path(config_path), required=True))

        # Load profile overlay
        active_profile = profile or self._data["scanning"].get("profile", "normal")
        self._apply_profile(active_profile)

        # Override from environment
        self._apply_env_overrides()

        # Final validation
        self._validate()

    # ------------------------------------------------------------------
    # Public accessors
    # ------------------------------------------------------------------

    def get(self, key: str, default: Any = None) -> Any:
        """
        Retrieve a configuration value using dot-notation.

        Examples
        --------
        >>> cfg.get("general.log_level")
        'INFO'
        >>> cfg.get("integrations.shodan.api_key")
        None
        """
        parts = key.split(".")
        node: Any = self._data
        for part in parts:
            if not isinstance(node, dict):
                return default
            node = node.get(part, default)
        return node

    def set(self, key: str, value: Any) -> None:
        """Write a value using dot-notation (runtime override, not persisted)."""
        parts = key.split(".")
        node = self._data
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = value

    def persist_plugin_state(
        self, name: str, enabled: bool, path: str | Path | None = None
    ) -> Path:
        """Persist one plugin state in the user configuration file.

        Only the plugin section is changed.  Project configuration remains
        untouched, while the normal configuration precedence makes this
        override effective for subsequent CLI invocations.
        """
        destination = Path(path) if path else self._USER_CONFIG
        data = self._load_yaml(destination)
        plugins = data.setdefault("plugins", {})
        # Start from the effective configuration, not an empty user file.
        # Otherwise the first CLI override would accidentally disable all
        # built-in plugins not repeated in that file.
        enabled_names = set(self.get("plugins.enabled") or [])
        disabled_names = set(self.get("plugins.disabled") or [])
        enabled_names.update(plugins.get("enabled") or [])
        disabled_names.update(plugins.get("disabled") or [])
        if enabled:
            enabled_names.add(name)
            disabled_names.discard(name)
        else:
            enabled_names.discard(name)
            disabled_names.add(name)
        plugins["enabled"] = sorted(enabled_names)
        plugins["disabled"] = sorted(disabled_names)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("w", encoding="utf-8") as fh:
            yaml.safe_dump(data, fh, sort_keys=False)
        destination.chmod(0o600)
        return destination

    @property
    def data(self) -> dict[str, Any]:
        """Return a shallow copy of the full configuration dict."""
        return dict(self._data)

    @property
    def redacted_data(self) -> dict[str, Any]:
        """Return configuration suitable for display or diagnostics."""
        from sentinelforge.core.security import redact_value
        return redact_value(self._data)

    @property
    def profile(self) -> str:
        return self._profile_name or self._data["scanning"].get("profile", "normal")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_yaml(
        self, path: Path, required: bool = False
    ) -> dict[str, Any]:
        """Load a YAML file. Returns ``{}`` if the file is missing and
        ``required`` is ``False``."""
        if not path.exists():
            if required:
                raise ConfigError(f"Config file not found: {path}")
            return {}
        try:
            with path.open() as fh:
                content = yaml.safe_load(fh) or {}
            if not isinstance(content, dict):
                raise ConfigError(
                    f"Config file must be a YAML mapping, got {type(content).__name__}: {path}"
                )
            return content
        except yaml.YAMLError as exc:
            raise ConfigError(f"Failed to parse config file {path}: {exc}") from exc

    def _load_default_config(self) -> dict[str, Any]:
        """Load the first available project/package/system config layer.

        The checkout uses ``configs/config.yaml`` while installed Docker
        images place the same files under ``/etc/sentinelforge``.
        """
        candidates = (
            self._PROJECT_CONFIG,
            self._PACKAGE_CONFIG_DIR / "config.yaml",
            self._SYSTEM_CONFIG_DIR / "config.yaml",
        )
        for path in candidates:
            if path.exists():
                return self._load_yaml(path)
        return {}

    def _apply_profile(self, name: str) -> None:
        """Merge a scan profile on top of the current config."""
        profile_paths = (
            self._PROJECT_CONFIG.parent / "profiles" / f"{name}.yaml",
            self._PACKAGE_CONFIG_DIR / "profiles" / f"{name}.yaml",
            self._SYSTEM_CONFIG_DIR / "profiles" / f"{name}.yaml",
        )
        for profile_path in profile_paths:
            if profile_path.exists():
                self._merge(self._load_yaml(profile_path))
                self._profile_name = name
                return
        # Unknown profile — leave the base configuration unchanged.

    def _apply_env_overrides(self) -> None:
        """
        Map ``SF_*`` environment variables onto config keys.

        Naming convention:  ``SF_GENERAL_LOG_LEVEL`` → ``general.log_level``
        """
        mapping: dict[str, str] = {
            "SF_LOG_LEVEL": "general.log_level",
            "SF_OUTPUT_DIR": "general.output_dir",
            "SF_MAX_THREADS": "general.max_threads",
            "SF_TIMEOUT": "general.timeout",
            "SF_PROXY": "network.proxy",
            "SF_SHODAN_API_KEY": "integrations.shodan.api_key",
            "SF_NEO4J_URI": "integrations.neo4j.uri",
            "SF_NEO4J_USER": "integrations.neo4j.user",
            "SF_NEO4J_PASSWORD": "integrations.neo4j.password",
            "SF_PROFILE": "scanning.profile",
        }
        for env_key, config_key in mapping.items():
            value = os.getenv(env_key)
            if value is not None:
                # Coerce numeric strings
                if re.fullmatch(r"\d+", value):
                    self.set(config_key, int(value))
                elif value.lower() in ("true", "false"):
                    self.set(config_key, value.lower() == "true")
                else:
                    self.set(config_key, value)

        # Enable Shodan if key was provided
        if self.get("integrations.shodan.api_key"):
            self.set("integrations.shodan.enabled", True)

    def _validate(self) -> None:
        """Raise ``ConfigError`` if critical fields are invalid."""
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        log_level = str(self.get("general.log_level", "INFO")).upper()
        if log_level not in valid_levels:
            raise ConfigError(
                f"Invalid log_level '{log_level}'. Must be one of {valid_levels}."
            )

        max_threads = self.get("general.max_threads", 10)
        if isinstance(max_threads, bool) or not isinstance(max_threads, int) or not 1 <= max_threads <= 256:
            raise ConfigError("general.max_threads must be a positive integer.")

        for key, minimum, maximum in (
            ("general.timeout", 1, 3600),
            ("general.retries", 0, 10),
            ("network.connect_timeout", 1, 3600),
            ("network.read_timeout", 1, 3600),
            ("network.rate_limit", 0, 1000),
            ("scanning.max_depth", 0, 100),
            ("scanning.max_redirects", 0, 100),
        ):
            value = self.get(key)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not minimum <= value <= maximum:
                raise ConfigError(f"{key} must be between {minimum} and {maximum}.")

        valid_formats = {"html", "json", "markdown", "csv", "pdf"}
        formats = self.get("reporting.formats", [])
        if not isinstance(formats, list) or not formats:
            raise ConfigError("reporting.formats must be a non-empty list.")
        for fmt in formats:
            if not isinstance(fmt, str):
                raise ConfigError("reporting.formats entries must be strings.")
            if fmt not in valid_formats:
                raise ConfigError(
                    f"Unknown report format '{fmt}'. Valid: {valid_formats}."
                )
        if not isinstance(self.get("network.verify_ssl", True), bool):
            raise ConfigError("network.verify_ssl must be true or false.")
        for key in ("scanning.follow_redirects", "reporting.include_evidence", "reporting.include_raw_requests"):
            if not isinstance(self.get(key), bool):
                raise ConfigError(f"{key} must be true or false.")

        for key in ("plugins.enabled", "plugins.disabled"):
            value = self.get(key, [])
            if not isinstance(value, list) or any(not isinstance(item, str) or not item.strip() for item in value):
                raise ConfigError(f"{key} must be a list of plugin names.")
        enabled = set(self.get("plugins.enabled", []))
        disabled = set(self.get("plugins.disabled", []))
        if enabled & disabled:
            raise ConfigError("plugins.enabled and plugins.disabled cannot contain the same plugin.")

        plugin_dir = self.get("plugins.plugin_dir")
        if plugin_dir is not None and (
            not isinstance(plugin_dir, (str, list))
            or (isinstance(plugin_dir, list) and any(not isinstance(item, str) for item in plugin_dir))
        ):
            raise ConfigError("plugins.plugin_dir must be a path string or list of path strings.")

        valid_scopes = {"strict", "domain", "subdomain", "ip", "cidr"}
        if self.get("scanning.scope") not in valid_scopes:
            raise ConfigError(f"scanning.scope must be one of {sorted(valid_scopes)}.")
        valid_thresholds = {"info", "low", "medium", "high", "critical"}
        if self.get("reporting.severity_threshold") not in valid_thresholds:
            raise ConfigError(
                f"reporting.severity_threshold must be one of {sorted(valid_thresholds)}."
            )

    def _merge(self, override: dict[str, Any]) -> None:
        """Deep-merge *override* into ``self._data``."""
        self._data = self._deep_merge(self._data, override)

    @staticmethod
    def _deep_merge(base: dict, override: dict) -> dict:
        result = dict(base)
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = ConfigManager._deep_merge(result[key], value)
            else:
                result[key] = value
        return result

    @staticmethod
    def _deep_copy(obj: Any) -> Any:
        """Minimal deep-copy (avoids importing copy at import time)."""
        if isinstance(obj, dict):
            return {k: ConfigManager._deep_copy(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [ConfigManager._deep_copy(v) for v in obj]
        return obj

    def __repr__(self) -> str:  # pragma: no cover
        return f"<ConfigManager profile={self.profile!r}>"
