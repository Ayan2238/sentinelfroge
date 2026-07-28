"""
Module Loader
~~~~~~~~~~~~~
Discovers, imports, validates, and provides access to scan modules.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from typing import TYPE_CHECKING, Type

if TYPE_CHECKING:
    from sentinelforge.modules.base import BaseModule


class ModuleLoadError(Exception):
    """Raised when a module cannot be loaded or fails its interface check."""


class ModuleLoader:
    """
    Discovers built-in scan modules and any extras provided by the caller.

    Parameters
    ----------
    extra_paths:
        Additional Python package paths to search for modules.
    """

    _BUILTIN_PACKAGE = "sentinelforge.modules"

    def __init__(self, extra_paths: list[str] | None = None) -> None:
        self._extra_paths: list[str] = extra_paths or []
        self._registry: dict[str, Type["BaseModule"]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def discover(self) -> None:
        """Scan built-in and extra packages and register all valid modules."""
        self._discover_package(self._BUILTIN_PACKAGE)
        for pkg in self._extra_paths:
            self._discover_package(pkg)

    def get(self, name: str) -> Type["BaseModule"]:
        """Return the module class for *name*.

        Raises
        ------
        ModuleLoadError
            If *name* is not registered.
        """
        if name not in self._registry:
            raise ModuleLoadError(
                f"Module '{name}' not found. Available: {list(self._registry)}"
            )
        return self._registry[name]

    def list(self) -> list[str]:
        """Return sorted list of registered module names."""
        return sorted(self._registry)

    def instantiate_all(self, config: object) -> list["BaseModule"]:
        """Return instances of every registered module, passing *config*."""
        instances = []
        for cls in self._registry.values():
            try:
                instances.append(cls(config))
            except Exception as exc:  # noqa: BLE001
                raise ModuleLoadError(
                    f"Failed to instantiate module '{cls.name}': {exc}"
                ) from exc
        return instances

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _discover_package(self, package_name: str) -> None:
        """Import all sub-modules in *package_name* and collect BaseModule subclasses."""
        try:
            package = importlib.import_module(package_name)
        except ImportError as exc:
            raise ModuleLoadError(
                f"Cannot import module package '{package_name}': {exc}"
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
                if self._is_valid_module(obj):
                    module_name = getattr(obj, "name", obj.__name__.lower())
                    self._registry[module_name] = obj

    @staticmethod
    def _is_valid_module(cls: type) -> bool:
        """Return True if *cls* is a concrete subclass of BaseModule."""
        try:
            from sentinelforge.modules.base import BaseModule  # local import avoids cycles
        except ImportError:
            return False
        return (
            inspect.isclass(cls)
            and issubclass(cls, BaseModule)
            and cls is not BaseModule
            and not getattr(cls, "__abstractmethods__", None)
        )
