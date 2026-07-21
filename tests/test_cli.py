import json
from pathlib import Path

from click.testing import Result
import pytest
from typer.testing import CliRunner

from assetguard.cli import app

runner = CliRunner()


def write_rules(
    path: Path,
    *,
    exclude: str = "[]",
    textures_enabled: bool = False,
) -> Path:
    path.write_text(
        f"""\
version: 1
scan:
  exclude_directories: {exclude}
naming:
  enabled: true
  severity: error
  allowed_prefixes: [T_]
textures:
  enabled: {str(textures_enabled).lower()}
  severity: error
  extensions: [.png, .tga]
  require_power_of_two: true
  max_width: 4096
  max_height: 4096
duplicates:
  enabled: true
  severity: warning
""",
        encoding="utf-8",
    )
    return path


def write_mesh_rules(
    path: Path,
    *,
    severity: str = "error",
    require_triangulated: bool = True,
    max_triangles: int = 100000,
    max_material_slots: int = 8,
) -> Path:
    path.write_text(
        f"""\
version: 1
scan:
  exclude_directories: []
naming:
  enabled: true
  severity: error
  allowed_prefixes: [SM_]
textures:
  enabled: false
  severity: error
  extensions: [.png, .tga]
  require_power_of_two: true
  max_width: 4096
  max_height: 4096
meshes:
  enabled: true
  severity: {severity}
  extensions: [.obj]
  require_triangulated: {str(require_triangulated).lower()}
  require_uv: true
  max_triangles: {max_triangles}
  max_material_slots: {max_material_slots}
duplicates:
  enabled: false
  severity: warning
""",
        encoding="utf-8",
    )
    return path


def invoke_scan(assets: Path, config: Path, output: Path) -> Result:
    return runner.invoke(
        app,
        ["scan", str(assets), "--config", str(config), "--output", str(output)],
    )


def test_valid_scan_returns_exit_code_zero(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "T_valid.bin").write_bytes(b"valid")
    output = tmp_path / "reports" / "report.json"

    result = invoke_scan(assets, write_rules(tmp_path / "rules.yaml"), output)

    assert result.exit_code == 0
    assert "Files scanned: 1" in result.stdout
    assert output.exists()


def test_validation_errors_return_exit_code_one(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "invalid.bin").write_bytes(b"invalid")

    result = invoke_scan(
        assets,
        write_rules(tmp_path / "rules.yaml"),
        tmp_path / "report.json",
    )

    assert result.exit_code == 1
    assert "Errors: 1" in result.stdout


def test_warning_only_scan_returns_exit_code_zero(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "T_first.bin").write_bytes(b"duplicate")
    (assets / "T_second.bin").write_bytes(b"duplicate")
    output = tmp_path / "report.json"

    result = invoke_scan(assets, write_rules(tmp_path / "rules.yaml"), output)
    report = json.loads(output.read_text(encoding="utf-8"))

    assert result.exit_code == 0
    assert report["summary"] == {"errors": 0, "warnings": 1, "passed": True}


def test_corrupt_configured_texture_returns_exit_code_two(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "T_corrupt.png").write_bytes(b"not an image")
    output = tmp_path / "report.json"

    result = invoke_scan(
        assets,
        write_rules(tmp_path / "rules.yaml", textures_enabled=True),
        output,
    )

    assert result.exit_code == 2
    assert "cannot read texture" in result.stderr
    assert "Traceback" not in result.stderr
    assert not output.exists()


def test_report_write_failure_returns_exit_code_two(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "T_valid.bin").write_bytes(b"valid")
    output_directory = tmp_path / "output-directory"
    output_directory.mkdir()

    result = invoke_scan(
        assets,
        write_rules(tmp_path / "rules.yaml"),
        output_directory,
    )

    assert result.exit_code == 2
    assert "cannot write report" in result.stderr
    assert "Traceback" not in result.stderr


def test_invalid_directory_and_configuration_return_exit_code_two(tmp_path: Path) -> None:
    valid_config = write_rules(tmp_path / "rules.yaml")
    missing_result = invoke_scan(
        tmp_path / "missing",
        valid_config,
        tmp_path / "missing-report.json",
    )

    bad_config = tmp_path / "bad.yaml"
    bad_config.write_text("version: [invalid\n", encoding="utf-8")
    assets = tmp_path / "assets"
    assets.mkdir()
    bad_config_result = invoke_scan(assets, bad_config, tmp_path / "bad-report.json")

    assert missing_result.exit_code == 2
    assert "Error:" in missing_result.stderr
    assert bad_config_result.exit_code == 2
    assert "Error:" in bad_config_result.stderr
    assert "Traceback" not in missing_result.stderr + bad_config_result.stderr


def test_identical_scans_write_byte_identical_reports_and_exclude_output(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "T_valid.bin").write_bytes(b"valid")
    config = write_rules(tmp_path / "rules.yaml")
    output = assets / "T_report.json"

    first = invoke_scan(assets, config, output)
    first_bytes = output.read_bytes()
    second = invoke_scan(assets, config, output)
    second_bytes = output.read_bytes()

    assert first.exit_code == second.exit_code == 0
    assert first_bytes == second_bytes
    assert json.loads(second_bytes)["scan"]["files_scanned"] == 1


def test_excluded_directories_are_not_scanned(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    excluded = assets / "ignored"
    excluded.mkdir(parents=True)
    (assets / "T_kept.bin").write_bytes(b"kept")
    (excluded / "bad.bin").write_bytes(b"ignored")
    output = tmp_path / "report.json"

    result = invoke_scan(
        assets,
        write_rules(tmp_path / "rules.yaml", exclude="[ignored]"),
        output,
    )
    report = json.loads(output.read_text(encoding="utf-8"))

    assert result.exit_code == 0
    assert report["scan"]["files_scanned"] == 1
    assert report["issues"] == []


def test_mesh_error_returns_one_and_summary_contains_mesh_count(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "SM_quad.obj").write_text(
        "vt 0 0\nvt 1 0\nvt 1 1\nvt 0 1\nf 1/1 2/2 3/3 4/4\n",
        encoding="utf-8",
    )
    output = tmp_path / "report.json"

    result = invoke_scan(assets, write_mesh_rules(tmp_path / "rules.yaml"), output)
    report = json.loads(output.read_text(encoding="utf-8"))

    assert result.exit_code == 1
    assert "Meshes checked: 1" in result.stdout
    assert report["scan"]["meshes_checked"] == 1
    assert [issue["code"] for issue in report["issues"]] == ["MESH_NON_TRIANGULATED_FACE"]


def test_mesh_warning_only_returns_zero(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "SM_quad.obj").write_text(
        "vt 0 0\nvt 1 0\nvt 1 1\nvt 0 1\nf 1/1 2/2 3/3 4/4\n",
        encoding="utf-8",
    )

    result = invoke_scan(
        assets,
        write_mesh_rules(tmp_path / "rules.yaml", severity="warning"),
        tmp_path / "report.json",
    )

    assert result.exit_code == 0
    assert "Warnings: 1" in result.stdout


@pytest.mark.parametrize(
    ("content", "error_text"),
    [
        ("f 1/1/1/1 2 3\n", "malformed face token"),
        ("f 1 2\n", "face requires at least three vertices"),
        ("f 0 1 2\n", "vertex index must not be zero"),
        ("usemtl # no material\n", "usemtl requires a material name"),
    ],
)
def test_malformed_obj_returns_two_without_traceback(
    tmp_path: Path,
    content: str,
    error_text: str,
) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "SM_bad.obj").write_text(content, encoding="utf-8")
    output = tmp_path / "report.json"

    result = invoke_scan(assets, write_mesh_rules(tmp_path / "rules.yaml"), output)

    assert result.exit_code == 2
    assert "SM_bad.obj" in result.stderr
    assert error_text in result.stderr
    assert "Traceback" not in result.stderr
    assert not output.exists()


def test_invalid_utf8_obj_returns_two_without_report(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "SM_invalid_utf8.obj").write_bytes(b"f 1 2 3\n\xff")
    output = tmp_path / "report.json"

    result = invoke_scan(assets, write_mesh_rules(tmp_path / "rules.yaml"), output)

    assert result.exit_code == 2
    assert "file is not valid UTF-8" in result.stderr
    assert "Traceback" not in result.stderr
    assert not output.exists()


def test_equivalent_mesh_scans_write_byte_identical_reports(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "SM_valid.obj").write_text(
        "vt 0 0\nvt 1 0\nvt 0 1\nf 1/1 2/2 3/3\n",
        encoding="utf-8",
    )
    config = write_mesh_rules(tmp_path / "rules.yaml")
    first_output = tmp_path / "first.json"
    second_output = tmp_path / "second.json"

    first = invoke_scan(assets, config, first_output)
    second = invoke_scan(assets, config, second_output)

    assert first.exit_code == second.exit_code == 0
    assert first_output.read_bytes() == second_output.read_bytes()
