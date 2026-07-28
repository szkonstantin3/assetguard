"""Deterministic and atomic JSON report output."""

import json
import os
import tempfile
from pathlib import Path

from assetguard.models import Report
from assetguard.path_security import (
    PathSecurityError,
    prepare_secure_destination,
    validate_secure_path,
)
from assetguard.resource_limits import (
    PRODUCTION_LIMITS,
    BoundedTextBuilder,
    ResourceBudget,
    ResourceLimitError,
    ResourceLimits,
    active_resource_budget,
)


class ReportWriteError(Exception):
    """Raised when a report cannot be serialized or written."""


def serialize_report(
    report: Report,
    *,
    _budget: ResourceBudget | None = None,
    _limits: ResourceLimits = PRODUCTION_LIMITS,
) -> str:
    """Serialize a report with a stable encoding and final newline."""

    budget = _budget or active_resource_budget(_limits)
    payload = report.model_dump(mode="json", exclude_none=True)
    encoder = json.JSONEncoder(ensure_ascii=False, indent=2)
    builder = BoundedTextBuilder(
        budget,
        resource="encoded JSON report",
        limit=budget.limits.json_bytes,
    )
    for chunk in encoder.iterencode(payload):
        builder.write(chunk)
    builder.write("\n")
    return builder.finish()


def validate_report_output_path(destination: Path) -> Path:
    """Normalize and validate a JSON report destination without creating it."""

    try:
        return validate_secure_path(destination, description="JSON report output")
    except PathSecurityError as exc:
        raise ReportWriteError(str(exc)) from exc


def write_report(
    report: Report,
    destination: Path,
    *,
    _budget: ResourceBudget | None = None,
    _limits: ResourceLimits = PRODUCTION_LIMITS,
    _serialized: str | None = None,
    _stage_only: bool = False,
) -> Path | None:
    """Atomically write a report in its destination directory."""

    budget = _budget or active_resource_budget(_limits)
    serialized = (
        serialize_report(report, _budget=budget)
        if _serialized is None
        else _serialized
    )
    budget.check_value(
        "encoded JSON report",
        len(serialized.encode("utf-8")),
        budget.limits.json_bytes,
        "UTF-8 bytes",
    )
    budget.check_deadline()
    temporary_path: Path | None = None
    try:
        destination = prepare_secure_destination(
            destination, description="JSON report output"
        )
        validate_secure_path(destination, description="JSON report output")
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)
            for offset in range(0, len(serialized), 256 * 1024):
                budget.check_deadline()
                temporary_file.write(serialized[offset : offset + 256 * 1024])
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        budget.check_deadline()
        validate_secure_path(temporary_path, description="JSON report temporary file")
        validate_secure_path(destination, description="JSON report output")
        budget.check_deadline()
        if _stage_only:
            return temporary_path
        os.replace(temporary_path, destination)
        return None
    except ResourceLimitError:
        if temporary_path is not None:
            try:
                validate_secure_path(
                    temporary_path, description="JSON report temporary file"
                )
                temporary_path.unlink(missing_ok=True)
            except (OSError, PathSecurityError):
                pass
        raise
    except (OSError, PathSecurityError, TypeError, ValueError) as exc:
        if temporary_path is not None:
            try:
                validate_secure_path(
                    temporary_path, description="JSON report temporary file"
                )
                temporary_path.unlink(missing_ok=True)
            except (OSError, PathSecurityError):
                pass
        raise ReportWriteError(f"cannot write report '{destination}': {exc}") from exc


def publish_staged_report(temporary_path: Path, destination: Path) -> None:
    """Atomically publish a fully written report without another resource check."""

    try:
        validate_secure_path(temporary_path, description="JSON report temporary file")
        validate_secure_path(destination, description="JSON report output")
        os.replace(temporary_path, destination)
    except (OSError, PathSecurityError) as exc:
        raise ReportWriteError(f"cannot write report '{destination}': {exc}") from exc


def discard_staged_report(temporary_path: Path | None) -> None:
    """Remove an unpublished JSON temporary file after a failed scan."""

    if temporary_path is None:
        return
    try:
        validate_secure_path(temporary_path, description="JSON report temporary file")
        temporary_path.unlink(missing_ok=True)
    except (OSError, PathSecurityError):
        pass
