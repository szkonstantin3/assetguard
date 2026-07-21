import hashlib
import json
import os
import sqlite3
from contextlib import closing
from pathlib import Path

from PIL import Image
import pytest
from typer.testing import CliRunner, Result

import assetguard.scanner as scanner_module
from assetguard.cache import (
    CACHE_SCHEMA_VERSION,
    OBJ_METRICS_VERSION,
    OBJ_VALIDATOR_KIND,
    TEXTURE_METRICS_VERSION,
    TEXTURE_VALIDATOR_KIND,
    AssetMetricsCache,
    CacheError,
    TextureMetrics,
    cache_related_paths,
)
from assetguard.cli import app
from assetguard.config import AssetGuardConfig, load_config
from assetguard.obj_mesh import ObjMeshMetrics
from assetguard.scanner import scan_directory, scan_directory_with_cache

runner = CliRunner()

VALID_OBJ = """\
v 0 0 0
v 1 0 0
v 0 1 0
vt 0 0
vt 1 0
vt 0 1
f 1/1 2/2 3/3
"""

QUAD_OBJ = """\
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


def write_rules(
    path: Path,
    *,
    textures_enabled: bool = True,
    meshes_enabled: bool = True,
    texture_severity: str = "error",
    mesh_severity: str = "error",
    require_power_of_two: bool = True,
    max_width: int = 4096,
    max_height: int = 4096,
    require_triangulated: bool = True,
    require_uv: bool = True,
    max_triangles: int = 100000,
    max_material_slots: int = 8,
    naming_enabled: bool = False,
    duplicates_enabled: bool = False,
) -> Path:
    path.write_text(
        f"""\
version: 1
scan:
  exclude_directories: []
naming:
  enabled: {str(naming_enabled).lower()}
  severity: error
  allowed_prefixes: [T_, SM_]
textures:
  enabled: {str(textures_enabled).lower()}
  severity: {texture_severity}
  extensions: [.png, .tga]
  require_power_of_two: {str(require_power_of_two).lower()}
  max_width: {max_width}
  max_height: {max_height}
meshes:
  enabled: {str(meshes_enabled).lower()}
  severity: {mesh_severity}
  extensions: [.obj]
  require_triangulated: {str(require_triangulated).lower()}
  require_uv: {str(require_uv).lower()}
  max_triangles: {max_triangles}
  max_material_slots: {max_material_slots}
duplicates:
  enabled: {str(duplicates_enabled).lower()}
  severity: warning
""",
        encoding="utf-8",
    )
    return path


def invoke_scan(
    assets: Path,
    config: Path,
    output: Path,
    cache: Path | None = None,
) -> Result:
    arguments = ["scan", str(assets), "--config", str(config), "--output", str(output)]
    if cache is not None:
        arguments.extend(["--cache", str(cache)])
    return runner.invoke(app, arguments)


def create_png(path: Path, size: tuple[int, int] = (64, 64)) -> Path:
    Image.new("RGBA", size, (20, 40, 60, 255)).save(path)
    return path


def cache_rows(cache: Path) -> list[tuple[object, ...]]:
    with closing(sqlite3.connect(cache)) as connection:
        return connection.execute(
            """
            SELECT content_sha256, validator_kind, validator_version, payload, payload_sha256
            FROM metric_entries
            ORDER BY content_sha256, validator_kind, validator_version
            """
        ).fetchall()


def test_scan_without_cache_preserves_behavior_and_creates_no_cache(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    create_png(assets / "T_valid.png")
    cache = tmp_path / "unused.sqlite3"

    result = invoke_scan(
        assets,
        write_rules(tmp_path / "rules.yaml", meshes_enabled=False),
        tmp_path / "report.json",
    )

    assert result.exit_code == 0
    assert not cache.exists()
    assert "Cache hits:" not in result.stdout
    assert "Cache misses:" not in result.stdout


def test_missing_cache_is_initialized_with_assetguard_ownership(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    cache = tmp_path / "nested" / "cache.sqlite3"

    result = invoke_scan(
        assets,
        write_rules(tmp_path / "rules.yaml", textures_enabled=False, meshes_enabled=False),
        tmp_path / "report.json",
        cache,
    )

    assert result.exit_code == 0
    assert cache.exists()
    with closing(sqlite3.connect(cache)) as connection:
        metadata = dict(connection.execute("SELECT key, value FROM assetguard_metadata"))
        user_version = connection.execute("PRAGMA user_version").fetchone()[0]
    assert metadata == {"owner": "AssetGuard", "schema_version": str(CACHE_SCHEMA_VERSION)}
    assert user_version == CACHE_SCHEMA_VERSION


def test_texture_miss_then_hit_preserves_report_contract_and_skips_parser(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    create_png(assets / "T_valid.png")
    config = write_rules(tmp_path / "rules.yaml", meshes_enabled=False)
    cache = tmp_path / "cache.sqlite3"
    first_output = tmp_path / "first.json"
    second_output = tmp_path / "second.json"

    first = invoke_scan(assets, config, first_output, cache)
    monkeypatch.setattr(
        scanner_module,
        "_read_texture_metrics",
        lambda *_args: pytest.fail("texture parser executed on a cache hit"),
    )
    second = invoke_scan(assets, config, second_output, cache)

    report = json.loads(first_output.read_text(encoding="utf-8"))
    assert first.exit_code == second.exit_code == 0
    assert "Cache hits: 0" in first.stdout
    assert "Cache misses: 1" in first.stdout
    assert "Cache hits: 1" in second.stdout
    assert "Cache misses: 0" in second.stdout
    assert first_output.read_bytes() == second_output.read_bytes()
    assert list(report) == ["schema_version", "tool", "scan", "summary", "issues"]
    assert list(report["scan"]) == [
        "root",
        "files_scanned",
        "textures_checked",
        "meshes_checked",
        "duplicate_groups",
    ]
    assert "cache" not in first_output.read_text(encoding="utf-8").lower()


def test_obj_miss_then_hit_skips_parser(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "SM_valid.obj").write_text(VALID_OBJ, encoding="utf-8")
    config = write_rules(tmp_path / "rules.yaml", textures_enabled=False)
    cache = tmp_path / "cache.sqlite3"

    first = invoke_scan(assets, config, tmp_path / "first.json", cache)
    monkeypatch.setattr(
        scanner_module,
        "_read_mesh_metrics",
        lambda *_args: pytest.fail("OBJ parser executed on a cache hit"),
    )
    second = invoke_scan(assets, config, tmp_path / "second.json", cache)

    assert first.exit_code == second.exit_code == 0
    assert "Cache misses: 1" in first.stdout
    assert "Cache hits: 1" in second.stdout


def test_texture_threshold_change_reuses_metrics_and_reapplies_rules(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    create_png(assets / "T_texture.png", (64, 64))
    cache = tmp_path / "cache.sqlite3"
    first_rules = write_rules(
        tmp_path / "first.yaml",
        meshes_enabled=False,
        max_width=64,
    )
    second_rules = write_rules(
        tmp_path / "second.yaml",
        meshes_enabled=False,
        max_width=32,
    )

    first = invoke_scan(assets, first_rules, tmp_path / "first.json", cache)
    second_output = tmp_path / "second.json"
    second = invoke_scan(assets, second_rules, second_output, cache)
    second_report = json.loads(second_output.read_text(encoding="utf-8"))

    assert first.exit_code == 0
    assert second.exit_code == 1
    assert "Cache hits: 1" in second.stdout
    assert [issue["code"] for issue in second_report["issues"]] == [
        "TEXTURE_WIDTH_EXCEEDED"
    ]


def test_mesh_threshold_change_reuses_metrics_and_reapplies_rules(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "SM_quad.obj").write_text(QUAD_OBJ, encoding="utf-8")
    cache = tmp_path / "cache.sqlite3"
    first_rules = write_rules(
        tmp_path / "first.yaml",
        textures_enabled=False,
        require_triangulated=False,
        max_triangles=2,
    )
    second_rules = write_rules(
        tmp_path / "second.yaml",
        textures_enabled=False,
        require_triangulated=False,
        max_triangles=1,
    )

    first = invoke_scan(assets, first_rules, tmp_path / "first.json", cache)
    second_output = tmp_path / "second.json"
    second = invoke_scan(assets, second_rules, second_output, cache)
    report = json.loads(second_output.read_text(encoding="utf-8"))

    assert first.exit_code == 0
    assert second.exit_code == 1
    assert "Cache hits: 1" in second.stdout
    assert [issue["code"] for issue in report["issues"]] == [
        "MESH_TRIANGLE_COUNT_EXCEEDED"
    ]


def test_severity_change_reuses_metrics_and_changes_exit_code(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    create_png(assets / "T_odd.png", (63, 64))
    cache = tmp_path / "cache.sqlite3"
    error_rules = write_rules(
        tmp_path / "error.yaml",
        meshes_enabled=False,
        texture_severity="error",
    )
    warning_rules = write_rules(
        tmp_path / "warning.yaml",
        meshes_enabled=False,
        texture_severity="warning",
    )

    error_result = invoke_scan(assets, error_rules, tmp_path / "error.json", cache)
    warning_output = tmp_path / "warning.json"
    warning_result = invoke_scan(assets, warning_rules, warning_output, cache)
    warning_report = json.loads(warning_output.read_text(encoding="utf-8"))

    assert error_result.exit_code == 1
    assert warning_result.exit_code == 0
    assert "Cache misses: 1" in error_result.stdout
    assert "Cache hits: 1" in warning_result.stdout
    assert warning_report["issues"][0]["severity"] == "warning"


def test_rename_reuses_metrics_but_reapplies_naming(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    original = create_png(assets / "T_valid.png")
    config = write_rules(
        tmp_path / "rules.yaml",
        meshes_enabled=False,
        naming_enabled=True,
    )
    cache = tmp_path / "cache.sqlite3"

    first = invoke_scan(assets, config, tmp_path / "first.json", cache)
    original.rename(assets / "invalid.png")
    second_output = tmp_path / "second.json"
    second = invoke_scan(assets, config, second_output, cache)
    report = json.loads(second_output.read_text(encoding="utf-8"))

    assert first.exit_code == 0
    assert second.exit_code == 1
    assert "Cache hits: 1" in second.stdout
    assert [issue["code"] for issue in report["issues"]] == ["NAMING_INVALID_PREFIX"]
    assert report["issues"][0]["path"] == "invalid.png"


def test_same_length_content_change_with_restored_mtime_is_a_miss(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    obj = assets / "SM_mutable.obj"
    first_content = "f 1 2 3\n"
    second_content = "f 1 3 2\n"
    assert len(first_content) == len(second_content)
    obj.write_text(first_content, encoding="utf-8")
    config = write_rules(
        tmp_path / "rules.yaml",
        textures_enabled=False,
        require_uv=False,
    )
    cache = tmp_path / "cache.sqlite3"

    first = invoke_scan(assets, config, tmp_path / "first.json", cache)
    original_stat = obj.stat()
    obj.write_text(second_content, encoding="utf-8")
    os.utime(obj, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
    second = invoke_scan(assets, config, tmp_path / "second.json", cache)

    assert first.exit_code == second.exit_code == 0
    assert obj.stat().st_size == original_stat.st_size
    assert obj.stat().st_mtime_ns == original_stat.st_mtime_ns
    assert "Cache misses: 1" in second.stdout
    assert len(cache_rows(cache)) == 2


def test_identical_content_at_different_paths_reuses_one_entry(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    first = create_png(assets / "T_first.png")
    (assets / "T_second.png").write_bytes(first.read_bytes())
    cache = tmp_path / "cache.sqlite3"

    result = invoke_scan(
        assets,
        write_rules(tmp_path / "rules.yaml", meshes_enabled=False),
        tmp_path / "report.json",
        cache,
    )

    assert result.exit_code == 0
    assert "Cache hits: 1" in result.stdout
    assert "Cache misses: 1" in result.stdout
    assert len(cache_rows(cache)) == 1


def test_different_validator_kinds_do_not_collide_for_same_digest(tmp_path: Path) -> None:
    cache = tmp_path / "cache.sqlite3"
    digest = hashlib.sha256(b"shared content key").hexdigest()
    obj_metrics = ObjMeshMetrics(
        face_count=1,
        triangle_count=1,
        non_triangulated_face_count=0,
        face_corner_count=3,
        face_corners_with_uv=3,
        material_slot_count=1,
    )

    with AssetMetricsCache(cache) as metrics_cache:
        metrics_cache.store_texture(digest, TextureMetrics(width=32, height=64))
        metrics_cache.store_obj(digest, obj_metrics)
        metrics_cache.commit()

    rows = cache_rows(cache)
    assert [(row[1], row[2]) for row in rows] == [
        (OBJ_VALIDATOR_KIND, OBJ_METRICS_VERSION),
        (TEXTURE_VALIDATOR_KIND, TEXTURE_METRICS_VERSION),
    ]


def test_old_validator_version_is_a_miss(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    texture = create_png(assets / "T_valid.png", (32, 32))
    digest = hashlib.sha256(texture.read_bytes()).hexdigest()
    cache = tmp_path / "cache.sqlite3"
    with AssetMetricsCache(cache) as metrics_cache:
        metrics_cache.commit()
    payload = '{"height":32,"width":32}'
    checksum = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    with closing(sqlite3.connect(cache)) as connection:
        connection.execute(
            """
            INSERT INTO metric_entries VALUES (?, ?, ?, ?, ?)
            """,
            (digest, TEXTURE_VALIDATOR_KIND, 0, payload, checksum),
        )
        connection.commit()

    result = invoke_scan(
        assets,
        write_rules(tmp_path / "rules.yaml", meshes_enabled=False),
        tmp_path / "report.json",
        cache,
    )

    assert result.exit_code == 0
    assert "Cache misses: 1" in result.stdout
    assert sorted(row[2] for row in cache_rows(cache)) == [0, TEXTURE_METRICS_VERSION]


def test_duplicate_detection_and_metric_cache_share_one_digest_per_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    texture = create_png(assets / "T_valid.png")
    config_path = write_rules(
        tmp_path / "rules.yaml",
        meshes_enabled=False,
        duplicates_enabled=True,
    )
    config: AssetGuardConfig = load_config(config_path)
    cache = tmp_path / "cache.sqlite3"
    calls: list[Path] = []
    original_sha256 = scanner_module._sha256

    def counting_sha256(path: Path) -> str:
        calls.append(path)
        return original_sha256(path)

    monkeypatch.setattr(scanner_module, "_sha256", counting_sha256)
    with AssetMetricsCache(cache) as metrics_cache:
        result = scan_directory_with_cache(assets, config, metrics_cache)
        metrics_cache.commit()

    assert calls == [texture]
    assert result.cache_misses == 1


def test_duplicate_group_remains_correct_with_cache(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    first = create_png(assets / "T_first.png")
    (assets / "T_second.png").write_bytes(first.read_bytes())
    output = tmp_path / "report.json"

    result = invoke_scan(
        assets,
        write_rules(
            tmp_path / "rules.yaml",
            meshes_enabled=False,
            duplicates_enabled=True,
        ),
        output,
        tmp_path / "cache.sqlite3",
    )
    report = json.loads(output.read_text(encoding="utf-8"))

    assert result.exit_code == 0
    assert report["scan"]["duplicate_groups"] == 1
    assert [issue["code"] for issue in report["issues"]] == ["DUPLICATE_CONTENT"]
    assert "Cache hits: 1" in result.stdout
    assert "Cache misses: 1" in result.stdout


def test_no_hash_is_added_when_duplicates_and_cache_are_disabled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "note.bin").write_bytes(b"not a validator candidate")
    config = load_config(
        write_rules(
            tmp_path / "rules.yaml",
            textures_enabled=False,
            meshes_enabled=False,
        )
    )
    monkeypatch.setattr(
        scanner_module,
        "_sha256",
        lambda _path: pytest.fail("unexpected SHA-256 calculation"),
    )

    report = scan_directory(tmp_path, config)

    assert report.scan.files_scanned == 2


def test_cache_and_sidecar_names_are_excluded_and_count_is_stable(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    create_png(assets / "T_valid.png")
    config_path = write_rules(tmp_path / "rules.yaml", meshes_enabled=False)
    cache = assets / "metrics.sqlite3"
    first_output = tmp_path / "first.json"
    second_output = tmp_path / "second.json"

    first = invoke_scan(assets, config_path, first_output, cache)
    second = invoke_scan(assets, config_path, second_output, cache)
    first_report = json.loads(first_output.read_text(encoding="utf-8"))
    second_report = json.loads(second_output.read_text(encoding="utf-8"))

    assert first.exit_code == second.exit_code == 0
    assert first_report["scan"]["files_scanned"] == 1
    assert second_report["scan"]["files_scanned"] == 1

    sidecars = cache_related_paths(cache)[1:]
    for sidecar in sidecars:
        sidecar.write_bytes(b"sidecar")
    config = load_config(config_path)
    report_with_sidecars = scan_directory(
        assets,
        config,
        excluded_files=cache_related_paths(cache),
    )
    assert report_with_sidecars.scan.files_scanned == 1


def test_cache_report_collision_returns_two(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    collision = tmp_path / "same-path"

    result = invoke_scan(
        assets,
        write_rules(tmp_path / "rules.yaml"),
        collision,
        collision,
    )

    assert result.exit_code == 2
    assert "same as the report output" in result.stderr
    assert "Traceback" not in result.stderr
    assert not collision.exists()


def test_cache_config_collision_returns_two_without_modifying_config(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    config = write_rules(tmp_path / "rules.yaml")
    before = config.read_bytes()

    result = invoke_scan(assets, config, tmp_path / "report.json", config)

    assert result.exit_code == 2
    assert "same as the configuration" in result.stderr
    assert config.read_bytes() == before
    assert "Traceback" not in result.stderr


def test_cache_directory_path_returns_two(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    cache_directory = tmp_path / "cache-dir"
    cache_directory.mkdir()

    result = invoke_scan(
        assets,
        write_rules(tmp_path / "rules.yaml"),
        tmp_path / "report.json",
        cache_directory,
    )

    assert result.exit_code == 2
    assert "cache path is a directory" in result.stderr
    assert "Traceback" not in result.stderr


def test_arbitrary_non_sqlite_file_is_unchanged_and_rejected(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    cache = tmp_path / "not-a-cache.bin"
    cache.write_bytes(b"arbitrary user data")
    before = cache.read_bytes()

    result = invoke_scan(
        assets,
        write_rules(tmp_path / "rules.yaml"),
        tmp_path / "report.json",
        cache,
    )

    assert result.exit_code == 2
    assert cache.read_bytes() == before
    assert "Traceback" not in result.stderr


def test_unrelated_sqlite_database_is_unchanged_and_rejected(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    cache = tmp_path / "unrelated.sqlite3"
    with closing(sqlite3.connect(cache)) as connection:
        connection.execute("CREATE TABLE user_data (value TEXT)")
        connection.execute("INSERT INTO user_data VALUES (?)", ("preserve me",))
        connection.commit()
    before = cache.read_bytes()

    result = invoke_scan(
        assets,
        write_rules(tmp_path / "rules.yaml"),
        tmp_path / "report.json",
        cache,
    )

    assert result.exit_code == 2
    assert "not owned by AssetGuard" in result.stderr
    assert cache.read_bytes() == before
    with closing(sqlite3.connect(cache)) as connection:
        assert connection.execute("SELECT value FROM user_data").fetchone() == ("preserve me",)


def test_unsupported_assetguard_schema_returns_two(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    cache = tmp_path / "cache.sqlite3"
    with AssetMetricsCache(cache) as metrics_cache:
        metrics_cache.commit()
    with closing(sqlite3.connect(cache)) as connection:
        connection.execute(
            "UPDATE assetguard_metadata SET value = ? WHERE key = ?",
            ("2", "schema_version"),
        )
        connection.execute("PRAGMA user_version = 2")
        connection.commit()

    result = invoke_scan(
        assets,
        write_rules(tmp_path / "rules.yaml"),
        tmp_path / "report.json",
        cache,
    )

    assert result.exit_code == 2
    assert "unsupported AssetGuard cache schema version 2" in result.stderr
    assert "Traceback" not in result.stderr


def test_corrupted_sqlite_cache_returns_two(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    cache = tmp_path / "cache.sqlite3"
    with AssetMetricsCache(cache) as metrics_cache:
        metrics_cache.commit()
    content = bytearray(cache.read_bytes())
    content[:16] = b"CORRUPTED-CACHE!"
    cache.write_bytes(content)

    result = invoke_scan(
        assets,
        write_rules(tmp_path / "rules.yaml"),
        tmp_path / "report.json",
        cache,
    )

    assert result.exit_code == 2
    assert "Traceback" not in result.stderr


def _populate_texture_cache(tmp_path: Path) -> tuple[Path, Path, Path]:
    assets = tmp_path / "assets"
    assets.mkdir()
    create_png(assets / "T_valid.png", (32, 32))
    config = write_rules(tmp_path / "rules.yaml", meshes_enabled=False)
    cache = tmp_path / "cache.sqlite3"
    result = invoke_scan(assets, config, tmp_path / "first.json", cache)
    assert result.exit_code == 0
    return assets, config, cache


def test_payload_checksum_mismatch_returns_two(tmp_path: Path) -> None:
    assets, config, cache = _populate_texture_cache(tmp_path)
    with closing(sqlite3.connect(cache)) as connection:
        connection.execute("UPDATE metric_entries SET payload_sha256 = ?", ("0" * 64,))
        connection.commit()
    output = tmp_path / "second.json"

    result = invoke_scan(assets, config, output, cache)

    assert result.exit_code == 2
    assert "payload checksum mismatch" in result.stderr
    assert "Traceback" not in result.stderr
    assert not output.exists()


@pytest.mark.parametrize(
    ("payload", "error_text"),
    [
        ("{invalid", "invalid JSON"),
        ('{"height":32,"path":"asset.png","width":32}', "invalid fields"),
        ('{"height":32,"width":"32"}', "invalid value types"),
    ],
)
def test_invalid_typed_payload_returns_two(
    tmp_path: Path,
    payload: str,
    error_text: str,
) -> None:
    assets, config, cache = _populate_texture_cache(tmp_path)
    checksum = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    with closing(sqlite3.connect(cache)) as connection:
        connection.execute(
            "UPDATE metric_entries SET payload = ?, payload_sha256 = ?",
            (payload, checksum),
        )
        connection.commit()
    output = tmp_path / "second.json"

    result = invoke_scan(assets, config, output, cache)

    assert result.exit_code == 2
    assert error_text in result.stderr
    assert "Traceback" not in result.stderr
    assert not output.exists()


@pytest.mark.parametrize("asset_kind", ["texture", "obj"])
def test_malformed_asset_is_not_cached_and_writes_no_report(
    tmp_path: Path,
    asset_kind: str,
) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    if asset_kind == "texture":
        (assets / "T_bad.png").write_bytes(b"not an image")
        config = write_rules(tmp_path / "rules.yaml", meshes_enabled=False)
    else:
        (assets / "SM_bad.obj").write_text("f 1/1/1/1 2 3\n", encoding="utf-8")
        config = write_rules(tmp_path / "rules.yaml", textures_enabled=False)
    cache = tmp_path / "cache.sqlite3"
    output = tmp_path / "report.json"

    result = invoke_scan(assets, config, output, cache)

    assert result.exit_code == 2
    assert not output.exists()
    assert cache_rows(cache) == []
    assert "Traceback" not in result.stderr


def test_cache_commit_failure_rolls_back_before_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    create_png(assets / "T_valid.png")
    output = tmp_path / "report.json"

    def fail_commit(_cache: AssetMetricsCache) -> None:
        raise CacheError("simulated cache commit failure")

    monkeypatch.setattr(AssetMetricsCache, "commit", fail_commit)
    result = invoke_scan(
        assets,
        write_rules(tmp_path / "rules.yaml", meshes_enabled=False),
        output,
        tmp_path / "cache.sqlite3",
    )

    assert result.exit_code == 2
    assert "simulated cache commit failure" in result.stderr
    assert "Traceback" not in result.stderr
    assert not output.exists()


def test_locked_cache_returns_two_without_traceback(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    cache = tmp_path / "cache.sqlite3"
    with AssetMetricsCache(cache) as metrics_cache:
        metrics_cache.commit()
    lock_connection = sqlite3.connect(cache)
    lock_connection.execute("BEGIN EXCLUSIVE")
    try:
        result = invoke_scan(
            assets,
            write_rules(tmp_path / "rules.yaml"),
            tmp_path / "report.json",
            cache,
        )
    finally:
        lock_connection.rollback()
        lock_connection.close()

    assert result.exit_code == 2
    assert "Traceback" not in result.stderr


def test_cache_parent_directories_are_created(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    cache = tmp_path / "deep" / "cache" / "metrics.sqlite3"

    result = invoke_scan(
        assets,
        write_rules(tmp_path / "rules.yaml"),
        tmp_path / "report.json",
        cache,
    )

    assert result.exit_code == 0
    assert cache.is_file()


def test_canonical_payloads_contain_metrics_only_and_no_paths(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    create_png(assets / "T_valid.png", (32, 64))
    (assets / "SM_valid.obj").write_text(VALID_OBJ, encoding="utf-8")
    cache = tmp_path / "cache.sqlite3"

    result = invoke_scan(
        assets,
        write_rules(tmp_path / "rules.yaml"),
        tmp_path / "report.json",
        cache,
    )

    assert result.exit_code == 0
    rows = cache_rows(cache)
    assert len(rows) == 2
    payloads = {row[1]: row[3] for row in rows}
    assert payloads[TEXTURE_VALIDATOR_KIND] == '{"height":64,"width":32}'
    assert json.loads(payloads[OBJ_VALIDATOR_KIND]) == {
        "face_corner_count": 3,
        "face_corners_with_uv": 3,
        "face_count": 1,
        "material_slot_count": 1,
        "non_triangulated_face_count": 0,
        "triangle_count": 1,
    }
    for payload in payloads.values():
        assert str(tmp_path) not in payload
        assert ".png" not in payload
        assert ".obj" not in payload
