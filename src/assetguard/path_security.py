"""Lexical, non-following filesystem path security checks."""

from __future__ import annotations

import os
import stat
from pathlib import Path

FILE_ATTRIBUTE_REPARSE_POINT = 0x0400


class PathSecurityError(Exception):
    """Raised when a path crosses a symbolic link or reparse point."""


def lexical_absolute_path(path: Path) -> Path:
    """Return a normalized absolute path without resolving filesystem links."""

    try:
        return Path(os.path.abspath(os.path.normpath(os.fspath(path))))
    except (OSError, TypeError, ValueError) as exc:
        raise PathSecurityError("path could not be normalized") from exc


def _is_link_or_reparse(metadata: os.stat_result) -> bool:
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    return stat.S_ISLNK(metadata.st_mode) or bool(
        attributes & FILE_ATTRIBUTE_REPARSE_POINT
    )


def _existing_components(path: Path) -> list[Path]:
    return [*reversed(path.parents), path]


def validate_secure_path(path: Path, *, description: str) -> Path:
    """Reject any existing link or reparse component in a lexical path."""

    absolute = lexical_absolute_path(path)
    missing_parent = False
    for component in _existing_components(absolute):
        if missing_parent:
            continue
        try:
            metadata = component.lstat()
        except FileNotFoundError:
            missing_parent = True
            continue
        except OSError as exc:
            raise PathSecurityError(
                f"cannot inspect {description} path component '{component}'"
            ) from exc
        if _is_link_or_reparse(metadata):
            raise PathSecurityError(
                f"{description} path must not contain a symbolic link or reparse point: "
                f"'{component}'"
            )
    return absolute


def prepare_secure_destination(path: Path, *, description: str) -> Path:
    """Validate, create, and revalidate a destination's lexical parent chain."""

    destination = validate_secure_path(path, description=description)
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise PathSecurityError(
            f"cannot create {description} parent directory '{destination.parent}'"
        ) from exc
    return validate_secure_path(destination, description=description)


def validate_existing_entry(path: Path, *, description: str) -> os.stat_result:
    """Return non-following metadata for one entry, rejecting links/reparse points."""

    try:
        metadata = path.lstat()
    except OSError as exc:
        raise PathSecurityError(f"cannot inspect {description} '{path}'") from exc
    if _is_link_or_reparse(metadata):
        raise PathSecurityError(
            f"{description} must not be a symbolic link or reparse point: '{path}'"
        )
    return metadata
