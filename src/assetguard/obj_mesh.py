"""Small deterministic OBJ parser for Phase 02 mesh metrics."""

from dataclasses import dataclass
from pathlib import Path

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


def _parse_nonzero_index(value: str, line_number: int, component: str) -> None:
    try:
        index = int(value)
    except ValueError as exc:
        raise ObjParseError(
            f"line {line_number}: {component} index must be a non-zero integer"
        ) from exc
    if index == 0:
        raise ObjParseError(f"line {line_number}: {component} index must not be zero")


def _face_token_has_uv(token: str, line_number: int) -> bool:
    components = token.split("/")
    if len(components) == 1:
        if not components[0]:
            raise ObjParseError(f"line {line_number}: malformed face token")
        _parse_nonzero_index(components[0], line_number, "vertex")
        return False

    if len(components) == 2:
        vertex, uv = components
        if not vertex or not uv:
            raise ObjParseError(f"line {line_number}: malformed face token")
        _parse_nonzero_index(vertex, line_number, "vertex")
        _parse_nonzero_index(uv, line_number, "UV")
        return True

    if len(components) == 3:
        vertex, uv, normal = components
        if not vertex or not normal:
            raise ObjParseError(f"line {line_number}: malformed face token")
        _parse_nonzero_index(vertex, line_number, "vertex")
        if uv:
            _parse_nonzero_index(uv, line_number, "UV")
        _parse_nonzero_index(normal, line_number, "normal")
        return bool(uv)

    raise ObjParseError(f"line {line_number}: malformed face token")


def parse_obj(path: Path) -> ObjMeshMetrics:
    """Parse an OBJ incrementally and return the metrics needed for validation."""

    face_count = 0
    triangle_count = 0
    non_triangulated_face_count = 0
    face_corner_count = 0
    face_corners_with_uv = 0
    active_material: str | None = None
    used_materials: set[str] = set()

    try:
        with path.open("r", encoding="utf-8-sig") as source:
            for line_number, raw_line in enumerate(source, start=1):
                content = raw_line.partition("#")[0].strip()
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

                face_tokens = arguments.split()
                if len(face_tokens) < 3:
                    raise ObjParseError(
                        f"line {line_number}: face requires at least three vertices"
                    )

                corners_with_uv = sum(
                    _face_token_has_uv(token, line_number) for token in face_tokens
                )
                corner_count = len(face_tokens)
                face_count += 1
                triangle_count += corner_count - 2
                non_triangulated_face_count += corner_count > 3
                face_corner_count += corner_count
                face_corners_with_uv += corners_with_uv
                used_materials.add(active_material or DEFAULT_MATERIAL_SLOT)
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
