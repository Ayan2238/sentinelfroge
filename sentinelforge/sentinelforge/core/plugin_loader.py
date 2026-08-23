"""
Plugin Loader
~~~~~~~~~~~~~
Discovers, validates, enables/disables, and provides access to scan plugins.
Plugins are lightweight wrappers around specific scanning capabilities
(DNS, HTTP, SSL, OSINT, Cloud, …) that the engine composes at runtime.
"""

from __future__ import annotations

import importlib
import importlib.util
import inspect
import pkgutil
from pathlib import Path
from typing import TYPE_CHECKING, Type

if TYPE_CHECKING:
    from sentinelforge.plugins.base import BasePlugin


class PluginLoadError(Exception):
    """Raised when a plugin cannot be loaded."""


class PluginLoader:
    """
    Manages the full plugin lifecycle.

    Parameters
    ----------
    enabled:
        Explicit allowlist of plugin names to load. ``None`` → load all.
    disabled:
        Names of plugins to skip even if they appear in *enabled*.
    extra_paths:
        Additional Python package paths to search for plugins.
    """

    _BUILTIN_PACKAGE = "sentinelforge.plugins"

    def __init__(
        self,
        enabled: list[str] | None = None,
        disabled: list[str] | None = None,
        extra_paths: list[str] | None = None,
    ) -> None:
        self._enabled: set[str] | None = set(enabled) if enabled else None
        self._disabled: set[str] = set(disabled or [])
        self._extra_paths: list[str] = extra_paths or []
        self._registry: dict[str, Type["BasePlugin"]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def discover(self) -> None:
        """Scan built-in and extra packages and register valid plugins."""
        self._discover_package(self._BUILTIN_PACKAGE)
        for path_or_package in self._extra_paths:
            if Path(path_or_package).is_dir():
                self._discover_directory(Path(path_or_package))
            else:
                self._discover_package(path_or_package)

    def get(self, name: str) -> Type["BasePlugin"]:
        if name not in self._registry:
            raise PluginLoadError(
                f"Plugin '{name}' not found. Available: {list(self._registry)}"
            )
        return self._registry[name]

    def list_all(self) -> list[str]:
        return sorted(self._registry)

    def list_active(self) -> list[str]:
        """Return the names of plugins that will actually run."""
        return [
            name
            for name in self._registry
            if self._is_active(name)
        ]

    def instantiate_active(self, config: object) -> list["BasePlugin"]:
        """Return instances of every active plugin."""
        instances: list["BasePlugin"] = []
        for name, cls in self._registry.items():
            if not self._is_active(name):
                continue
            try:
                instances.append(cls(config))
            except Exception as exc:  # noqa: BLE001
                raise PluginLoadError(
                    f"Failed to instantiate plugin '{name}': {exc}"
                ) from exc
        return instances

    def enable(self, name: str) -> None:
        self._disabled.discard(name)
        if self._enabled is not None:
            self._enabled.add(name)

    def disable(self, name: str) -> None:
        self._disabled.add(name)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _is_active(self, name: str) -> bool:
        if name in self._disabled:
            return False
        if self._enabled is not None:
            return name in self._enabled
        return True

    def _discover_package(self, package_name: str) -> None:
        try:
            package = importlib.import_module(package_name)
        except ImportError as exc:
            raise PluginLoadError(
                f"Cannot import plugin package '{package_name}': {exc}"
            ) from exc

        pkg_path = getattr(package, "__path__", [])
        for _, mod_name, _ in pkgutil.walk_packages(
            path=pkg_path, prefix=f"{package_name}."
        ):
            try:
                mod = importlib.import_module(mod_name)
            except ImportError:
                continue
            for _, obj in inspect.getmembers(mod, inspect.isclass):
                if self._is_valid_plugin(obj):
                    plugin_name = getattr(obj, "name", obj.__name__.lower())
                    self._registry[plugin_name] = obj

    def _discover_directory(self, directory: Path) -> None:
        """Load plugin Python files from a configured filesystem directory."""
        for path in sorted(directory.glob("*.py")):
            if path.name.startswith("_"):
                continue
            module_name = f"_sentinelforge_custom_plugin_{path.stem}"
            try:
                spec = importlib.util.spec_from_file_location(module_name, path)
                if spec is None or spec.loader is None:
                    continue
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
            except (ImportError, OSError, SyntaxError):
                continue
            self._register_module(module)

    def _register_module(self, mod: object) -> None:
        for _, obj in inspect.getmembers(mod, inspect.isclass):
            if self._is_valid_plugin(obj):
                plugin_name = getattr(obj, "name", obj.__name__.lower())
                self._registry[plugin_name] = obj

    @staticmethod
    def _is_valid_plugin(cls: type) -> bool:
        try:
            from sentinelforge.plugins.base import BasePlugin
        except ImportError:
            return False
        return (
            inspect.isclass(cls)
            and issubclass(cls, BasePlugin)
            and cls is not BasePlugin
            and not getattr(cls, "__abstractmethods__", None)
        )
