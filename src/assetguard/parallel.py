"""Deterministic bounded ordered thread execution."""

from collections import deque
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Callable, Iterable, TypeVar

_Item = TypeVar("_Item")
_Result = TypeVar("_Result")

MIN_WORKERS = 1
MAX_WORKERS = 32


def ordered_bounded_map(
    function: Callable[[_Item], _Result],
    items: Iterable[_Item],
    workers: int,
) -> list[_Result]:
    """Apply *function* with bounded submission and return input-ordered results."""

    if not MIN_WORKERS <= workers <= MAX_WORKERS:
        raise ValueError(f"workers must be between {MIN_WORKERS} and {MAX_WORKERS}")
    if workers == 1:
        return [function(item) for item in items]

    iterator = iter(items)
    pending: deque[Future[_Result]] = deque()
    results: list[_Result] = []
    executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="assetguard")

    try:
        for _ in range(2 * workers):
            try:
                item = next(iterator)
            except StopIteration:
                break
            pending.append(executor.submit(function, item))

        while pending:
            future = pending.popleft()
            results.append(future.result())
            try:
                item = next(iterator)
            except StopIteration:
                continue
            pending.append(executor.submit(function, item))
    except BaseException:
        for future in pending:
            future.cancel()
        executor.shutdown(wait=True, cancel_futures=True)
        raise

    executor.shutdown(wait=True)
    return results
