"""Deterministic bounded ordered thread execution."""

from collections import deque
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Callable, Iterable, Iterator, TypeVar

from assetguard.resource_limits import ResourceBudget

_Item = TypeVar("_Item")
_Result = TypeVar("_Result")

MIN_WORKERS = 1
MAX_WORKERS = 32

_ACTIVE_BUDGET: ContextVar[ResourceBudget | None] = ContextVar(
    "assetguard_parallel_resource_budget", default=None
)


@contextmanager
def resource_budget_context(budget: ResourceBudget) -> Iterator[None]:
    """Install the scan budget for coordinator submission and collection checks."""

    token = _ACTIVE_BUDGET.set(budget)
    try:
        yield
    finally:
        _ACTIVE_BUDGET.reset(token)


def ordered_bounded_map(
    function: Callable[[_Item], _Result],
    items: Iterable[_Item],
    workers: int,
) -> list[_Result]:
    """Apply *function* with bounded submission and return input-ordered results."""

    budget = _ACTIVE_BUDGET.get()
    maximum_workers = MAX_WORKERS if budget is None else budget.limits.max_workers
    if not MIN_WORKERS <= workers <= maximum_workers:
        raise ValueError(f"workers must be between {MIN_WORKERS} and {maximum_workers}")
    if workers == 1:
        results: list[_Result] = []
        try:
            for item in items:
                if budget is not None:
                    budget.check_deadline()
                results.append(function(item))
                if budget is not None:
                    budget.check_deadline()
        except BaseException as exc:
            if budget is not None:
                budget.request_stop(exc)
            raise
        return results

    iterator = iter(items)
    pending: deque[Future[_Result]] = deque()
    results: list[_Result] = []
    executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="assetguard")

    try:
        in_flight = 2 * workers if budget is None else budget.limits.in_flight_per_worker * workers
        for _ in range(in_flight):
            if budget is not None:
                budget.check_deadline()
            try:
                item = next(iterator)
            except StopIteration:
                break
            pending.append(executor.submit(function, item))

        while pending:
            if budget is not None:
                budget.check_deadline()
            future = pending.popleft()
            results.append(future.result())
            if budget is not None:
                budget.check_deadline()
            try:
                item = next(iterator)
            except StopIteration:
                continue
            if budget is not None:
                budget.check_deadline()
            pending.append(executor.submit(function, item))
    except BaseException as exc:
        if budget is not None:
            budget.request_stop(exc)
        for future in pending:
            future.cancel()
        executor.shutdown(wait=True, cancel_futures=True)
        raise

    executor.shutdown(wait=True)
    return results
