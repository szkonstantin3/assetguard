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


class ReportWriteError(Exception):
    """Raised when a report cannot be serialized or written."""


def serialize_report(report: Report) -> str:
    """Serialize a report with a stable encoding and final newline."""

    payload = report.model_dump(mode="json", exclude_none=True)
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def validate_report_output_path(destination: Path) -> Path:
    """Normalize and validate a JSON report destination without creating it."""

    try:
        return validate_secure_path(destination, description="JSON report output")
    except PathSecurityError as exc:
        raise ReportWriteError(str(exc)) from exc


def write_report(report: Report, destination: Path) -> None:
    """Atomically write a report in its destination directory."""

    temporary_path: Path | None = None
    try:
        destination = prepare_secure_destination(
            destination, description="JSON report output"
        )
        serialized = serialize_report(report)
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
            temporary_file.write(serialized)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        validate_secure_path(temporary_path, description="JSON report temporary file")
        validate_secure_path(destination, description="JSON report output")
        os.replace(temporary_path, destination)
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
