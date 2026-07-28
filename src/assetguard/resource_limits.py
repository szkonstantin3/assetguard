"""Fixed resource policy and cooperative per-scan accounting.

The production policy in this module is intentionally independent of project
configuration, environment variables, and command-line options.  Tests may
construct a smaller frozen policy and pass it only through private APIs.
"""

from __future__ import annotations

import hashlib
import io
import json
import math
import threading
import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict, dataclass
from pathlib import PurePosixPath
from typing import Callable, Iterator


@dataclass(frozen=True, slots=True)
class ResourceLimits:
    """Immutable inclusive ceilings for one AssetGuard scan."""

    rules_bytes: int = 1_048_576
    yaml_nodes: int = 50_000
    yaml_depth: int = 64
    directory_entries: int = 20_000
    tree_entries: int = 200_000
    regular_files: int = 100_000
    relative_path_bytes: int = 4_096
    relative_depth: int = 64
    file_bytes: int = 8_589_934_592
    aggregate_file_bytes: int = 68_719_476_736
    texture_pixels: int = 67_108_864
    obj_file_bytes: int = 536_870_912
    obj_line_bytes: int = 1_048_576
    obj_index_chars: int = 32
    obj_face_corners: int = 65_536
    obj_lines: int = 2_000_000
    obj_total_corners: int = 5_000_000
    obj_materials: int = 65_536
    issues: int = 10_000
    duplicate_members: int = 10_000
    issue_payload_bytes: int = 33_554_432
    json_bytes: int = 67_108_864
    html_bytes: int = 134_217_728
    cache_bytes: int = 268_435_456
    runtime_seconds: int = 1_800
    max_workers: int = 32
    in_flight_per_worker: int = 2

    def __post_init__(self) -> None:
        for name, value in asdict(self).items():
            if type(value) is not int or value < 0:
                raise ValueError(
                    f"resource limit '{name}' must be a non-negative integer"
                )
        for name in ("runtime_seconds", "max_workers", "in_flight_per_worker"):
            if getattr(self, name) == 0:
                raise ValueError(f"resource limit '{name}' must be positive")

    @property
    def fingerprint(self) -> str:
        """Return the canonical SHA-256 fingerprint of every policy value."""

        canonical = json.dumps(
            asdict(self),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        return hashlib.sha256(b"AssetGuard resource policy v1\0" + canonical).hexdigest()


PRODUCTION_LIMITS = ResourceLimits()
RESOURCE_POLICY_FINGERPRINT = PRODUCTION_LIMITS.fingerprint

_ACTIVE_SCAN_BUDGET: ContextVar[ResourceBudget | None]


def _format_number(value: int | float) -> str:
    if type(value) is int:
        return str(value)
    if not math.isfinite(value):
        return str(value)
    return format(value, ".6f").rstrip("0").rstrip(".")


def _safe_relative_path(path: str | None) -> str | None:
    if path is None:
        return None
    normalized = path.replace("\\", "/")
    pure = PurePosixPath(normalized)
    if pure.is_absolute() or not normalized or ".." in pure.parts:
        raise ValueError("resource error paths must be normalized project-relative paths")
    return pure.as_posix()


class ResourceLimitError(Exception):
    """One deterministic typed failure for every resource-policy violation."""

    def __init__(
        self,
        resource: str,
        observed: int | float,
        limit: int | float,
        unit: str,
        *,
        path: str | None = None,
    ) -> None:
        self.resource = resource
        self.observed = observed
        self.limit = limit
        self.unit = unit
        self.path = _safe_relative_path(path)
        location = "" if self.path is None else f" for '{self.path}'"
        super().__init__(
            f"resource limit exceeded: {resource}{location} observed "
            f"{_format_number(observed)} {unit}; inclusive limit "
            f"{_format_number(limit)} {unit}"
        )


class ResourceBudget:
    """Mutable cooperative accounting shared by one scan and its workers."""

    __slots__ = (
        "limits",
        "_clock",
        "_started",
        "_stop",
        "_failure",
        "_lock",
        "tree_entries",
        "regular_files",
        "aggregate_file_bytes",
        "issue_count",
        "issue_payload_bytes",
    )

    def __init__(
        self,
        limits: ResourceLimits = PRODUCTION_LIMITS,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.limits = limits
        self._clock = clock
        self._started = clock()
        self._stop = threading.Event()
        self._failure: BaseException | None = None
        self._lock = threading.Lock()
        self.tree_entries = 0
        self.regular_files = 0
        self.aggregate_file_bytes = 0
        self.issue_count = 0
        self.issue_payload_bytes = 0

    @property
    def elapsed(self) -> float:
        return max(0.0, self._clock() - self._started)

    def check_deadline(self) -> None:
        """Fail once elapsed monotonic time is strictly greater than the ceiling."""

        self.raise_if_stopped()
        elapsed = self.elapsed
        if elapsed > self.limits.runtime_seconds:
            error = ResourceLimitError(
                "cooperative scan runtime",
                elapsed,
                self.limits.runtime_seconds,
                "seconds",
            )
            self.request_stop(error)
            raise error

    def check_value(
        self,
        resource: str,
        observed: int,
        limit: int,
        unit: str,
        *,
        path: str | None = None,
    ) -> None:
        if observed > limit:
            raise ResourceLimitError(resource, observed, limit, unit, path=path)

    def add_tree_entry(self, *, path: str) -> None:
        self.tree_entries += 1
        self.check_value(
            "total inspected tree entries",
            self.tree_entries,
            self.limits.tree_entries,
            "entries",
            path=path,
        )

    def add_regular_file(self, size: int, *, path: str) -> None:
        self.regular_files += 1
        self.check_value(
            "total regular files",
            self.regular_files,
            self.limits.regular_files,
            "files",
            path=path,
        )
        self.check_value(
            "one candidate file",
            size,
            self.limits.file_bytes,
            "bytes",
            path=path,
        )
        aggregate = self.aggregate_file_bytes + size
        self.check_value(
            "aggregate logical candidate bytes",
            aggregate,
            self.limits.aggregate_file_bytes,
            "bytes",
            path=path,
        )
        self.aggregate_file_bytes = aggregate

    def reserve_issue(self, payload_bytes: int, *, path: str | None = None) -> None:
        next_count = self.issue_count + 1
        self.check_value(
            "accumulated issues",
            next_count,
            self.limits.issues,
            "issues",
            path=path,
        )
        next_payload = self.issue_payload_bytes + payload_bytes
        self.check_value(
            "cumulative issue payload",
            next_payload,
            self.limits.issue_payload_bytes,
            "UTF-8 bytes",
            path=path,
        )
        self.issue_count = next_count
        self.issue_payload_bytes = next_payload

    def request_stop(self, failure: BaseException) -> None:
        with self._lock:
            if self._failure is None:
                self._failure = failure
            self._stop.set()

    def raise_if_stopped(self) -> None:
        if not self._stop.is_set():
            return
        failure = self._failure
        if failure is None:
            raise RuntimeError("resource budget stopped without a failure")
        raise failure


_ACTIVE_SCAN_BUDGET = ContextVar("assetguard_active_scan_budget", default=None)


@contextmanager
def resource_budget_scope(budget: ResourceBudget) -> Iterator[None]:
    """Make one budget available across compatibility-preserving public calls."""

    token = _ACTIVE_SCAN_BUDGET.set(budget)
    try:
        yield
    finally:
        _ACTIVE_SCAN_BUDGET.reset(token)


def active_resource_budget(limits: ResourceLimits = PRODUCTION_LIMITS) -> ResourceBudget:
    """Return the active per-scan budget or create one for a standalone call."""

    budget = _ACTIVE_SCAN_BUDGET.get()
    return budget if budget is not None else ResourceBudget(limits)


def derive_cache_content_key(
    content_sha256: str,
    limits: ResourceLimits = PRODUCTION_LIMITS,
) -> str:
    """Bind a content digest to the complete resource-policy fingerprint."""

    if len(content_sha256) != 64 or any(
        character not in "0123456789abcdef" for character in content_sha256
    ):
        raise ValueError("content digest must be lowercase SHA-256")
    material = (
        "AssetGuard cache key v1\0" + limits.fingerprint + "\0" + content_sha256
    ).encode("ascii")
    return hashlib.sha256(material).hexdigest()


class BoundedTextBuilder:
    """Build exact text while enforcing an encoded UTF-8 byte ceiling."""

    __slots__ = ("_buffer", "_budget", "_resource", "_limit", "_bytes")

    def __init__(
        self,
        budget: ResourceBudget,
        *,
        resource: str,
        limit: int,
    ) -> None:
        self._buffer = io.StringIO()
        self._budget = budget
        self._resource = resource
        self._limit = limit
        self._bytes = 0

    @property
    def encoded_bytes(self) -> int:
        return self._bytes

    def write(self, text: str) -> None:
        self._budget.check_deadline()
        encoded_length = len(text.encode("utf-8"))
        observed = self._bytes + encoded_length
        self._budget.check_value(
            self._resource,
            observed,
            self._limit,
            "UTF-8 bytes",
        )
        self._buffer.write(text)
        self._bytes = observed

    def finish(self) -> str:
        self._budget.check_deadline()
        return self._buffer.getvalue()
