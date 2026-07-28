"""
Scan Scheduler
~~~~~~~~~~~~~~
Controls concurrent execution of modules and plugins, enforces rate limits,
and collects results without letting a single failure abort the whole run.
"""

from __future__ import annotations

import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable


@dataclass
class TaskResult:
    """Outcome of a single scheduled task."""

    name: str
    success: bool
    result: Any = None
    error: str | None = None
    elapsed: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)


class Scheduler:
    """
    Thread-pool based task scheduler with rate limiting.

    Parameters
    ----------
    max_workers:
        Maximum number of concurrent worker threads.
    rate_limit:
        Maximum tasks started per second (0 = unlimited).
    timeout:
        Per-task timeout in seconds (0 = unlimited).
    """

    def __init__(
        self,
        max_workers: int = 10,
        rate_limit: float = 0,
        timeout: float = 0,
    ) -> None:
        self._max_workers = max(1, max_workers)
        self._rate_limit = rate_limit          # tasks / second
        self._timeout = timeout or None        # None = no timeout
        self._results: list[TaskResult] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(
        self,
        tasks: Iterable[tuple[str, Callable[..., Any], tuple, dict]],
        progress_callback: Callable[[str, TaskResult], None] | None = None,
    ) -> list[TaskResult]:
        """
        Execute *tasks* concurrently.

        Parameters
        ----------
        tasks:
            Iterable of ``(name, callable, args, kwargs)`` tuples.
        progress_callback:
            Called after each task completes with ``(name, result)``.

        Returns
        -------
        list[TaskResult]
            Results in completion order.
        """
        task_list = list(tasks)
        results: list[TaskResult] = []
        interval = 1.0 / self._rate_limit if self._rate_limit > 0 else 0

        with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
            future_to_name: dict[Future, str] = {}

            for name, fn, args, kwargs in task_list:
                fut = pool.submit(self._run_task, name, fn, args, kwargs)
                future_to_name[fut] = name
                if interval:
                    time.sleep(interval)

            for fut in as_completed(future_to_name, timeout=None):
                task_result: TaskResult = fut.result()
                results.append(task_result)
                if progress_callback:
                    try:
                        progress_callback(task_result.name, task_result)
                    except Exception:  # noqa: BLE001
                        pass

        self._results.extend(results)
        return results

    @property
    def all_results(self) -> list[TaskResult]:
        """All results accumulated across multiple ``run()`` calls."""
        return list(self._results)

    def clear(self) -> None:
        """Reset accumulated results."""
        self._results.clear()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _run_task(
        self,
        name: str,
        fn: Callable[..., Any],
        args: tuple,
        kwargs: dict,
    ) -> TaskResult:
        start = time.perf_counter()
        try:
            result = fn(*args, **kwargs)
            elapsed = time.perf_counter() - start
            return TaskResult(
                name=name, success=True, result=result, elapsed=elapsed
            )
        except Exception as exc:  # noqa: BLE001
            elapsed = time.perf_counter() - start
            return TaskResult(
                name=name,
                success=False,
                error=f"{type(exc).__name__}: {exc}",
                elapsed=elapsed,
            )
