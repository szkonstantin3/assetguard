"""Deterministic and atomic JSON report output."""

import json
import os
import tempfile
from pathlib import Path

from assetguard.models import Report


class ReportWriteError(Exception):
    """Raised when a report cannot be serialized or written."""


def serialize_report(report: Report) -> str:
    """Serialize a report with a stable encoding and final newline."""

    payload = report.model_dump(mode="json", exclude_none=True)
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def write_report(report: Report, destination: Path) -> None:
    """Atomically write a report in its destination directory."""

    temporary_path: Path | None = None
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        serialized = serialize_report(report)
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
        os.replace(temporary_path, destination)
    except (OSError, TypeError, ValueError) as exc:
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass
        raise ReportWriteError(f"cannot write report '{destination}': {exc}") from exc

