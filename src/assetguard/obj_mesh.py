"""Small deterministic OBJ parser for Phase 02 mesh metrics."""

import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from assetguard.resource_limits import (
    PRODUCTION_LIMITS,
    ResourceBudget,
    ResourceLimits,
    active_resource_budget,
)

DEFAULT_MATERIAL_SLOT = "__default__"


class ObjParseError(Exception):
    """Raised when a configured OBJ cannot be read or parsed."""


@dataclass(frozen=True, slots=True)
class ObjMeshMetrics:
    face_count: int
    triangle_count: int
    non_triangulated_face_count: int
    face_corner_count: int
    face_corners_with_uv: int
    material_slot_count: int


def _parse_nonzero_index(
    value: str,
    line_number: int,
    component: str,
    budget: ResourceBudget,
    relative_path: str | None,
) -> None:
    budget.check_value(
        "one numeric OBJ index token",
        len(value),
        budget.limits.obj_index_chars,
        "ASCII characters",
        path=relative_path,
    )
    try:
        index = int(value)
    except ValueError as exc:
        raise ObjParseError(
            f"line {line_number}: {component} index must be a non-zero integer"
        ) from exc
    if index == 0:
        raise ObjParseError(f"line {line_number}: {component} index must not be zero")


def _face_token_has_uv(
    token: str,
    line_number: int,
    budget: ResourceBudget,
    relative_path: str | None,
) -> bool:
    components = token.split("/", 3)
    if len(components) == 1:
        if not components[0]:
            raise ObjParseError(f"line {line_number}: malformed face token")
        _parse_nonzero_index(
            components[0], line_number, "vertex", budget, relative_path
        )
        return False

    if len(components) == 2:
        vertex, uv = components
        if not vertex or not uv:
            raise ObjParseError(f"line {line_number}: malformed face token")
        _parse_nonzero_index(vertex, line_number, "vertex", budget, relative_path)
        _parse_nonzero_index(uv, line_number, "UV", budget, relative_path)
        return True

    if len(components) == 3:
        vertex, uv, normal = components
        if not vertex or not normal:
            raise ObjParseError(f"line {line_number}: malformed face token")
        _parse_nonzero_index(vertex, line_number, "vertex", budget, relative_path)
        if uv:
            _parse_nonzero_index(uv, line_number, "UV", budget, relative_path)
        _parse_nonzero_index(normal, line_number, "normal", budget, relative_path)
        return bool(uv)

    raise ObjParseError(f"line {line_number}: malformed face token")


def _whitespace_tokens(value: str) -> Iterator[str]:
    """Yield whitespace-delimited tokens without allocating an unrestricted list."""

    index = 0
    length = len(value)
    while index < length:
        while index < length and value[index].isspace():
            index += 1
        start = index
        while index < length and not value[index].isspace():
            index += 1
        if start < index:
            yield value[start:index]


def parse_obj(
    path: Path,
    *,
    _budget: ResourceBudget | None = None,
    _limits: ResourceLimits = PRODUCTION_LIMITS,
    _relative_path: str | None = None,
    _expected_size: int | None = None,
) -> ObjMeshMetrics:
    """Parse an OBJ incrementally and return the metrics needed for validation."""

    budget = _budget or active_resource_budget(_limits)
    budget.check_deadline()
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ObjParseError("file could not be read") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise ObjParseError("file is not a regular file")
    if _expected_size is not None and metadata.st_size != _expected_size:
        raise ObjParseError("file changed after resource preflight")
    budget.check_value(
        "one OBJ file",
        metadata.st_size,
        budget.limits.obj_file_bytes,
        "bytes",
        path=_relative_path,
    )

    face_count = 0
    triangle_count = 0
    non_triangulated_face_count = 0
    face_corner_count = 0
    face_corners_with_uv = 0
    active_material: str | None = None
    used_materials: set[str] = set()

    try:
        with path.open("rb") as source:
            line_number = 0
            while True:
                budget.check_deadline()
                raw_line = source.readline(budget.limits.obj_line_bytes + 1)
                if not raw_line:
                    break
                line_number += 1
                budget.check_value(
                    "OBJ logical lines",
                    line_number,
                    budget.limits.obj_lines,
                    "lines",
                    path=_relative_path,
                )
                budget.check_value(
                    "one raw OBJ logical line",
                    len(raw_line),
                    budget.limits.obj_line_bytes,
                    "bytes",
                    path=_relative_path,
                )
                encoding = "utf-8-sig" if line_number == 1 else "utf-8"
                raw_text = raw_line.decode(encoding)
                content = raw_text.partition("#")[0].strip()
                if not content:
                    continue

                parts = content.split(maxsplit=1)
                statement = parts[0]
                arguments = parts[1].strip() if len(parts) == 2 else ""

                if statement == "usemtl":
                    if not arguments:
                        raise ObjParseError(
                            f"line {line_number}: usemtl requires a material name"
                        )
                    active_material = arguments
                    continue

                if statement != "f":
                    continue

                corner_count = 0
                corners_with_uv = 0
                for token in _whitespace_tokens(arguments):
                    corner_count += 1
                    budget.check_value(
                        "corners in one OBJ face",
                        corner_count,
                        budget.limits.obj_face_corners,
                        "corners",
                        path=_relative_path,
                    )
                    budget.check_value(
                        "total OBJ face corners",
                        face_corner_count + corner_count,
                        budget.limits.obj_total_corners,
                        "corners",
                        path=_relative_path,
                    )
                    corners_with_uv += _face_token_has_uv(
                        token, line_number, budget, _relative_path
                    )
                if corner_count < 3:
                    raise ObjParseError(
                        f"line {line_number}: face requires at least three vertices"
                    )

                material = active_material or DEFAULT_MATERIAL_SLOT
                if material not in used_materials:
                    budget.check_value(
                        "unique OBJ materials",
                        len(used_materials) + 1,
                        budget.limits.obj_materials,
                        "materials",
                        path=_relative_path,
                    )
                    used_materials.add(material)
                face_count += 1
                triangle_count += corner_count - 2
                non_triangulated_face_count += corner_count > 3
                face_corner_count += corner_count
                face_corners_with_uv += corners_with_uv
    except UnicodeDecodeError as exc:
        raise ObjParseError("file is not valid UTF-8") from exc
    except OSError as exc:
        raise ObjParseError("file could not be read") from exc

    return ObjMeshMetrics(
        face_count=face_count,
        triangle_count=triangle_count,
        non_triangulated_face_count=non_triangulated_face_count,
        face_corner_count=face_corner_count,
        face_corners_with_uv=face_corners_with_uv,
        material_slot_count=len(used_materials),
    )


def validate_obj_resources(
    path: Path,
    *,
    budget: ResourceBudget,
    relative_path: str,
    expected_size: int,
) -> ObjMeshMetrics:
    """Enforce all OBJ content budgets even when metrics may be cached."""

    return parse_obj(
        path,
        _budget=budget,
        _relative_path=relative_path,
        _expected_size=expected_size,
    )
