from pathlib import Path

from assetguard.config import (
    AssetGuardConfig,
    DuplicateConfig,
    MeshConfig,
    NamingConfig,
    ScanConfig,
    Severity,
    TextureConfig,
)
from assetguard.obj_mesh import parse_obj
from assetguard.scanner import scan_directory

TRIANGLE_WITH_UV = """\
v 0 0 0
v 1 0 0
v 0 1 0
vt 0 0
vt 1 0
vt 0 1
f 1/1 2/2 3/3
"""

QUAD_WITH_UV = """\
v 0 0 0
v 1 0 0
v 1 1 0
v 0 1 0
vt 0 0
vt 1 0
vt 1 1
vt 0 1
f 1/1 2/2 3/3 4/4
"""


def write_obj(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    return path


def mesh_rules(
    *,
    severity: Severity = "error",
    require_triangulated: bool = True,
    require_uv: bool = True,
    max_triangles: int = 100000,
    max_material_slots: int = 8,
) -> AssetGuardConfig:
    return AssetGuardConfig(
        version=1,
        scan=ScanConfig(),
        naming=NamingConfig(enabled=False),
        textures=TextureConfig(enabled=False),
        meshes=MeshConfig(
            enabled=True,
            severity=severity,
            require_triangulated=require_triangulated,
            require_uv=require_uv,
            max_triangles=max_triangles,
            max_material_slots=max_material_slots,
        ),
        duplicates=DuplicateConfig(enabled=False),
    )


def test_valid_triangulated_obj_with_uvs_passes(tmp_path: Path) -> None:
    path = write_obj(
        tmp_path / "SM_valid.obj",
        "o Mesh\ng Group\ns 1\nmtllib mesh.mtl\n" + TRIANGLE_WITH_UV,
    )

    metrics = parse_obj(path)
    report = scan_directory(tmp_path, mesh_rules())

    assert metrics.face_count == 1
    assert metrics.triangle_count == 1
    assert metrics.face_corner_count == metrics.face_corners_with_uv == 3
    assert metrics.material_slot_count == 1
    assert report.scan.meshes_checked == 1
    assert report.issues == []


def test_quad_emits_non_triangulated_issue_and_counts_two_triangles(tmp_path: Path) -> None:
    path = write_obj(tmp_path / "SM_quad.obj", QUAD_WITH_UV)

    metrics = parse_obj(path)
    report = scan_directory(tmp_path, mesh_rules())

    assert metrics.triangle_count == 2
    assert metrics.non_triangulated_face_count == 1
    assert [issue.code for issue in report.issues] == ["MESH_NON_TRIANGULATED_FACE"]
    assert report.issues[0].details == {"non_triangulated_faces": 1}


def test_triangle_limit_breach_emits_expected_issue(tmp_path: Path) -> None:
    write_obj(tmp_path / "SM_large.obj", QUAD_WITH_UV)

    report = scan_directory(
        tmp_path,
        mesh_rules(require_triangulated=False, max_triangles=1),
    )

    assert [issue.code for issue in report.issues] == ["MESH_TRIANGLE_COUNT_EXCEEDED"]
    assert report.issues[0].details == {"triangle_count": 2, "max_triangles": 1}


def test_face_tokens_without_uv_emit_missing_uv_issue(tmp_path: Path) -> None:
    write_obj(
        tmp_path / "SM_no_uv.obj",
        "v 0 0 0\nv 1 0 0\nv 0 1 0\nvn 0 0 1\nf 1//1 2//1 3//1\n",
    )

    report = scan_directory(tmp_path, mesh_rules())

    assert [issue.code for issue in report.issues] == ["MESH_MISSING_UV"]
    assert report.issues[0].details == {
        "face_corners": 3,
        "face_corners_with_uv": 0,
        "missing_uv_corners": 3,
    }


def test_mixed_uv_corners_emit_one_deterministic_issue(tmp_path: Path) -> None:
    write_obj(
        tmp_path / "SM_mixed.obj",
        "v 0 0 0\nv 1 0 0\nv 0 1 0\nvt 0 0\nvt 1 0\nf 1/1 2 3/2\n",
    )

    report = scan_directory(tmp_path, mesh_rules())

    assert [issue.code for issue in report.issues] == ["MESH_MISSING_UV"]
    assert report.issues[0].details == {
        "face_corners": 3,
        "face_corners_with_uv": 2,
        "missing_uv_corners": 1,
    }


def test_excess_material_slots_emit_expected_issue(tmp_path: Path) -> None:
    write_obj(
        tmp_path / "SM_materials.obj",
        TRIANGLE_WITH_UV
        + "usemtl First\nf 1/1 2/2 3/3\n"
        + "usemtl Second\nf 1/1 2/2 3/3\n",
    )

    report = scan_directory(tmp_path, mesh_rules(max_material_slots=1))

    assert [issue.code for issue in report.issues] == ["MESH_MATERIAL_SLOTS_EXCEEDED"]
    assert report.issues[0].details == {"material_slots": 3, "max_material_slots": 1}


def test_faces_without_material_use_one_implicit_slot(tmp_path: Path) -> None:
    path = write_obj(tmp_path / "SM_default.obj", "f 1 2 3\nf 1 3 4\n")

    assert parse_obj(path).material_slot_count == 1


def test_reusing_material_name_does_not_add_a_slot(tmp_path: Path) -> None:
    path = write_obj(
        tmp_path / "SM_reused.obj",
        "usemtl Shared\nf 1 2 3\nusemtl Shared\nf 1 3 4\n",
    )

    assert parse_obj(path).material_slot_count == 1


def test_empty_obj_is_checked_without_mesh_issues(tmp_path: Path) -> None:
    write_obj(tmp_path / "SM_empty.OBJ", "# no faces\nusemtl Unused\n")

    report = scan_directory(tmp_path, mesh_rules())

    assert report.scan.meshes_checked == 1
    assert report.issues == []
    assert parse_obj(tmp_path / "SM_empty.OBJ").material_slot_count == 0


def test_negative_indexes_and_inline_comments_parse_successfully(tmp_path: Path) -> None:
    path = write_obj(
        tmp_path / "SM_negative.obj",
        TRIANGLE_WITH_UV.replace("f 1/1 2/2 3/3", "f -3/-3 -2/-2 -1/-1 # triangle"),
    )

    metrics = parse_obj(path)

    assert metrics.triangle_count == 1
    assert metrics.face_corners_with_uv == 3


def test_all_supported_face_token_forms_parse_with_utf8_bom(tmp_path: Path) -> None:
    path = write_obj(
        tmp_path / "SM_forms.obj",
        "\ufeffvt 0 0\nvt 1 0\nvt 0 1\nvn 0 0 1\n"
        "f 1 2 3\n"
        "f 1/1 2/2 3/3\n"
        "f 1//1 2//1 3//1\n"
        "f 1/1/1 2/2/1 3/3/1\n",
    )

    metrics = parse_obj(path)

    assert metrics.face_count == 4
    assert metrics.triangle_count == 4
    assert metrics.face_corner_count == 12
    assert metrics.face_corners_with_uv == 6
