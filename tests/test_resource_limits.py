from __future__ import annotations

from contextlib import closing
from dataclasses import fields, replace
import hashlib
import json
import os
from pathlib import Path
import sqlite3

from PIL import Image
import pytest
from typer.testing import CliRunner

from assetguard.cache import (
    TEXTURE_METRICS_VERSION,
    TEXTURE_VALIDATOR_KIND,
    AssetMetricsCache,
    cache_related_paths,
    validate_cache_path,
)
from assetguard.cli import app
from assetguard.config import AssetGuardConfig, load_config, _validate_yaml_structure
from assetguard.html_reporting import render_html_report
from assetguard.models import Issue, Report, ScanInfo, Summary, ToolInfo
from assetguard.obj_mesh import parse_obj
from assetguard.parallel import ordered_bounded_map, resource_budget_context
from assetguard.reporting import serialize_report, write_report
from assetguard.resource_limits import (
    BoundedTextBuilder,
    PRODUCTION_LIMITS,
    RESOURCE_POLICY_FINGERPRINT,
    ResourceBudget,
    ResourceLimitError,
    ResourceLimits,
    derive_cache_content_key,
)
from assetguard.scanner import ScanError, scan_directory, scan_directory_with_cache
import assetguard.scanner as scanner_module


VALID_YAML = """version: 1
scan:
  exclude_directories: []
naming:
  enabled: false
  severity: error
  allowed_prefixes: []
textures:
  enabled: false
  severity: error
  extensions: [.png]
  require_power_of_two: true
  max_width: 4096
  max_height: 4096
meshes:
  enabled: false
  severity: error
  extensions: [.obj]
  require_triangulated: true
  require_uv: true
  max_triangles: 100000
  max_material_slots: 8
duplicates:
  enabled: false
  severity: warning
"""


def limits(**changes: int) -> ResourceLimits:
    return replace(PRODUCTION_LIMITS, **changes)


def rules(
    *,
    naming: bool = False,
    textures: bool = False,
    meshes: bool = False,
    duplicates: bool = False,
) -> AssetGuardConfig:
    return AssetGuardConfig.model_validate(
        {
            "version": 1,
            "scan": {"exclude_directories": []},
            "naming": {
                "enabled": naming,
                "severity": "error",
                "allowed_prefixes": ["T_"] if naming else [],
            },
            "textures": {
                "enabled": textures,
                "severity": "error",
                "extensions": [".png"],
                "require_power_of_two": False,
                "max_width": 4096,
                "max_height": 4096,
            },
            "meshes": {
                "enabled": meshes,
                "severity": "error",
                "extensions": [".obj"],
                "require_triangulated": False,
                "require_uv": False,
                "max_triangles": 100000,
                "max_material_slots": 100,
            },
            "duplicates": {"enabled": duplicates, "severity": "warning"},
        }
    )


def report_with_issues(issues: list[Issue] | None = None) -> Report:
    issue_list = issues or []
    return Report(
        tool=ToolInfo(version="0.1.0"),
        scan=ScanInfo(
            files_scanned=len(issue_list),
            textures_checked=0,
            meshes_checked=0,
            duplicate_groups=0,
        ),
        summary=Summary(
            errors=sum(issue.severity == "error" for issue in issue_list),
            warnings=sum(issue.severity == "warning" for issue in issue_list),
            passed=not any(issue.severity == "error" for issue in issue_list),
        ),
        issues=issue_list,
    )


def sparse_file(path: Path, size: int) -> Path:
    with path.open("wb") as destination:
        if size:
            destination.seek(size - 1)
            destination.write(b"\0")
    return path


class GateClock:
    def __init__(self) -> None:
        self.expired = False

    def __call__(self) -> float:
        return 2.0 if self.expired else 0.0


class StepClock:
    def __init__(self, expire_call: int) -> None:
        self.calls = 0
        self.expire_call = expire_call

    def __call__(self) -> float:
        self.calls += 1
        return 2.0 if self.calls >= self.expire_call else 0.0


@pytest.mark.parametrize("field_name", [field.name for field in fields(ResourceLimits)])
def test_every_policy_ceiling_is_inclusive(field_name: str) -> None:
    maximum = getattr(PRODUCTION_LIMITS, field_name)
    budget = ResourceBudget(PRODUCTION_LIMITS, clock=lambda: 0.0)
    budget.check_value(field_name, maximum, maximum, "units")
    with pytest.raises(ResourceLimitError) as captured:
        budget.check_value(field_name, maximum + 1, maximum, "units")
    assert captured.value.observed == maximum + 1
    assert captured.value.limit == maximum


def test_policy_is_frozen_canonical_and_all_fields_affect_fingerprint() -> None:
    assert RESOURCE_POLICY_FINGERPRINT == PRODUCTION_LIMITS.fingerprint
    assert len(RESOURCE_POLICY_FINGERPRINT) == 64
    with pytest.raises(AttributeError):
        PRODUCTION_LIMITS.rules_bytes = 1  # type: ignore[misc]
    for field in fields(ResourceLimits):
        changed = replace(
            PRODUCTION_LIMITS,
            **{field.name: getattr(PRODUCTION_LIMITS, field.name) + 1},
        )
        assert changed.fingerprint != RESOURCE_POLICY_FINGERPRINT


def test_cache_key_binds_content_to_complete_policy() -> None:
    digest = hashlib.sha256(b"asset").hexdigest()
    first = derive_cache_content_key(digest)
    assert first == derive_cache_content_key(digest)
    assert first != digest
    assert first != derive_cache_content_key(digest, limits(texture_pixels=1))


def test_resource_contract_validation_stop_state_and_bounded_builder() -> None:
    with pytest.raises(ValueError, match="non-negative integer"):
        replace(PRODUCTION_LIMITS, rules_bytes=-1)
    with pytest.raises(ValueError, match="must be positive"):
        replace(PRODUCTION_LIMITS, runtime_seconds=0)

    infinite = ResourceLimitError(
        "cooperative scan runtime",
        float("inf"),
        1,
        "seconds",
    )
    assert "observed inf seconds" in str(infinite)
    with pytest.raises(ValueError, match="normalized project-relative"):
        ResourceLimitError("resource", 2, 1, "units", path="../escape")
    with pytest.raises(ValueError, match="lowercase SHA-256"):
        derive_cache_content_key("A" * 64)

    failure = ResourceLimitError("resource", 2, 1, "units")
    stopped = ResourceBudget(PRODUCTION_LIMITS, clock=lambda: 0.0)
    stopped.request_stop(failure)
    with pytest.raises(ResourceLimitError) as captured:
        stopped.raise_if_stopped()
    assert captured.value is failure

    orphaned = ResourceBudget(PRODUCTION_LIMITS, clock=lambda: 0.0)
    orphaned._stop.set()  # type: ignore[attr-defined]
    with pytest.raises(RuntimeError, match="stopped without a failure"):
        orphaned.raise_if_stopped()

    builder = BoundedTextBuilder(
        ResourceBudget(limits(json_bytes=1), clock=lambda: 0.0),
        resource="encoded JSON report",
        limit=1,
    )
    assert builder.encoded_bytes == 0
    builder.write("x")
    assert builder.encoded_bytes == 1


def test_direct_json_report_write_is_atomic_and_exact(tmp_path: Path) -> None:
    report = report_with_issues()
    destination = tmp_path / "report.json"
    assert write_report(report, destination) is None
    assert destination.read_text(encoding="utf-8") == serialize_report(report)
    assert not list(tmp_path.glob(".report.json.*.tmp"))


def test_rules_raw_bytes_exact_and_plus_one(tmp_path: Path) -> None:
    path = tmp_path / "rules.yaml"
    payload = VALID_YAML.encode("utf-8")
    path.write_bytes(payload)
    assert load_config(path, _limits=limits(rules_bytes=len(payload))).version == 1
    path.write_bytes(payload + b"#")
    with pytest.raises(ResourceLimitError, match="rules YAML raw bytes"):
        load_config(path, _limits=limits(rules_bytes=len(payload)))


def test_yaml_node_depth_boundaries_and_alias_semantics() -> None:
    node_text = "a: b\n"
    _validate_yaml_structure(
        node_text,
        ResourceBudget(limits(yaml_nodes=3), clock=lambda: 0.0),
    )
    with pytest.raises(ResourceLimitError, match="YAML composed nodes"):
        _validate_yaml_structure(
            node_text,
            ResourceBudget(limits(yaml_nodes=2), clock=lambda: 0.0),
        )

    depth_text = "a:\n  - b\n"
    _validate_yaml_structure(
        depth_text,
        ResourceBudget(limits(yaml_depth=3), clock=lambda: 0.0),
    )
    with pytest.raises(ResourceLimitError, match="YAML nesting depth"):
        _validate_yaml_structure(
            depth_text,
            ResourceBudget(limits(yaml_depth=2), clock=lambda: 0.0),
        )

    alias_text = "a: &shared [one]\nb: *shared\n"
    _validate_yaml_structure(
        alias_text,
        ResourceBudget(PRODUCTION_LIMITS, clock=lambda: 0.0),
    )


def test_directory_breadth_exact_and_plus_one(tmp_path: Path) -> None:
    for index in range(2):
        (tmp_path / f"file-{index}").write_bytes(b"")
    exact = limits(directory_entries=2)
    assert scan_directory(tmp_path, rules(), _limits=exact).scan.files_scanned == 2
    (tmp_path / "file-2").write_bytes(b"")
    with pytest.raises(ResourceLimitError, match="entries within one directory"):
        scan_directory(tmp_path, rules(), _limits=exact)


def test_total_entries_many_empty_directories_and_regular_files(tmp_path: Path) -> None:
    for index in range(3):
        (tmp_path / f"empty-{index}").mkdir()
    exact_entries = limits(tree_entries=3)
    assert scan_directory(tmp_path, rules(), _limits=exact_entries).scan.files_scanned == 0
    (tmp_path / "empty-3").mkdir()
    with pytest.raises(ResourceLimitError, match="total inspected tree entries"):
        scan_directory(tmp_path, rules(), _limits=exact_entries)

    files = tmp_path / "files"
    files.mkdir()
    (files / "a").write_bytes(b"")
    (files / "b").write_bytes(b"")
    exact_files = limits(regular_files=2)
    assert scan_directory(files, rules(), _limits=exact_files).scan.files_scanned == 2
    (files / "c").write_bytes(b"")
    with pytest.raises(ResourceLimitError, match="total regular files"):
        scan_directory(files, rules(), _limits=exact_files)


def test_depth_convention_and_multibyte_relative_paths(tmp_path: Path) -> None:
    child = tmp_path / "child"
    child.mkdir()
    assert scan_directory(
        tmp_path, rules(), _limits=limits(relative_depth=1)
    ).scan.files_scanned == 0
    grandchild = child / "grandchild"
    grandchild.mkdir()
    with pytest.raises(ResourceLimitError, match="relative directory depth"):
        scan_directory(tmp_path, rules(), _limits=limits(relative_depth=1))

    unicode_root = tmp_path / "unicode"
    unicode_root.mkdir()
    name = "é.bin"
    (unicode_root / name).write_bytes(b"")
    encoded = len(name.encode("utf-8"))
    assert scan_directory(
        unicode_root, rules(), _limits=limits(relative_path_bytes=encoded)
    ).scan.files_scanned == 1
    with pytest.raises(ResourceLimitError, match="relative path UTF-8 bytes"):
        scan_directory(
            unicode_root, rules(), _limits=limits(relative_path_bytes=encoded - 1)
        )


def test_file_and_aggregate_logical_sizes_count_hardlinks_lexically(tmp_path: Path) -> None:
    first = (tmp_path / "first.bin")
    first.write_bytes(b"ab")
    second = tmp_path / "second.bin"
    try:
        os.link(first, second)
    except OSError as exc:
        pytest.skip(f"hardlinks unavailable: {exc}")

    exact = limits(file_bytes=2, aggregate_file_bytes=4)
    assert scan_directory(tmp_path, rules(), _limits=exact).scan.files_scanned == 2
    with pytest.raises(ResourceLimitError, match="aggregate logical candidate bytes"):
        scan_directory(
            tmp_path,
            rules(),
            _limits=limits(file_bytes=2, aggregate_file_bytes=3),
        )
    first.write_bytes(b"abc")
    with pytest.raises(ResourceLimitError, match="one candidate file"):
        scan_directory(tmp_path, rules(), _limits=exact)


@pytest.mark.parametrize("replacement", [False, True])
def test_growth_and_replacement_after_preflight_are_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replacement: bool,
) -> None:
    asset = tmp_path / "asset.bin"
    asset.write_bytes(b"same")
    original = scanner_module._sha256
    changed = False

    def mutate(path: Path) -> str:
        nonlocal changed
        if not changed:
            changed = True
            if replacement:
                substitute = tmp_path / "substitute.bin"
                substitute.write_bytes(b"same")
                os.replace(substitute, path)
            else:
                path.write_bytes(b"growth")
        return original(path)

    monkeypatch.setattr(scanner_module, "_sha256", mutate)
    with pytest.raises(ScanError, match="changed after resource preflight|grew"):
        scan_directory(tmp_path, rules(duplicates=True))


def test_texture_pixel_boundary_and_bomb_conversion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    texture = tmp_path / "T_texture.png"
    Image.new("RGB", (2, 2)).save(texture)
    assert scan_directory(
        tmp_path, rules(textures=True), _limits=limits(texture_pixels=4)
    ).scan.textures_checked == 1
    with pytest.raises(ResourceLimitError, match="texture pixels"):
        scan_directory(
            tmp_path, rules(textures=True), _limits=limits(texture_pixels=3)
        )

    def bomb(_path: Path) -> object:
        raise Image.DecompressionBombWarning("100 pixels")

    monkeypatch.setattr(scanner_module.Image, "open", bomb)
    with pytest.raises(ResourceLimitError, match="observed 100 pixels"):
        scan_directory(
            tmp_path, rules(textures=True), _limits=limits(texture_pixels=50)
        )


def test_obj_file_line_crlf_unterminated_and_multibyte_boundaries(tmp_path: Path) -> None:
    obj = tmp_path / "mesh.obj"
    payload = b"f 1 2 3"
    obj.write_bytes(payload)
    assert parse_obj(
        obj,
        _limits=limits(obj_file_bytes=len(payload), obj_line_bytes=len(payload)),
    ).face_count == 1
    with pytest.raises(ResourceLimitError, match="one OBJ file"):
        parse_obj(obj, _limits=limits(obj_file_bytes=len(payload) - 1))
    with pytest.raises(ResourceLimitError, match="one raw OBJ logical line"):
        parse_obj(obj, _limits=limits(obj_line_bytes=len(payload) - 1))

    crlf = b"f 1 2 3\r\n"
    obj.write_bytes(crlf)
    assert parse_obj(obj, _limits=limits(obj_line_bytes=len(crlf))).face_count == 1
    with pytest.raises(ResourceLimitError, match="one raw OBJ logical line"):
        parse_obj(obj, _limits=limits(obj_line_bytes=len(crlf) - 1))

    multibyte = "#é".encode("utf-8")
    obj.write_bytes(multibyte)
    assert parse_obj(obj, _limits=limits(obj_line_bytes=len(multibyte))).face_count == 0
    with pytest.raises(ResourceLimitError, match="one raw OBJ logical line"):
        parse_obj(obj, _limits=limits(obj_line_bytes=len(multibyte) - 1))


def test_obj_token_face_line_corner_and_material_boundaries(tmp_path: Path) -> None:
    obj = tmp_path / "mesh.obj"
    index = "1" * 32
    obj.write_text(f"f {index} 2 3\n", encoding="utf-8")
    assert parse_obj(obj, _limits=limits(obj_index_chars=32)).face_count == 1
    with pytest.raises(ResourceLimitError, match="numeric OBJ index token"):
        parse_obj(obj, _limits=limits(obj_index_chars=31))

    obj.write_text("f 1 2 3\n", encoding="utf-8")
    assert parse_obj(obj, _limits=limits(obj_face_corners=3)).face_corner_count == 3
    obj.write_text("f 1 2 3 4\n", encoding="utf-8")
    with pytest.raises(ResourceLimitError, match="corners in one OBJ face"):
        parse_obj(obj, _limits=limits(obj_face_corners=3))

    obj.write_text("# one\n# two\n", encoding="utf-8")
    assert parse_obj(obj, _limits=limits(obj_lines=2)).face_count == 0
    obj.write_text("# one\n# two\n# three\n", encoding="utf-8")
    with pytest.raises(ResourceLimitError, match="OBJ logical lines"):
        parse_obj(obj, _limits=limits(obj_lines=2))

    obj.write_text("f 1 2 3\nf 1 2 3\n", encoding="utf-8")
    assert parse_obj(obj, _limits=limits(obj_total_corners=6)).face_corner_count == 6
    obj.write_text("f 1 2 3\nf 1 2 3 4\n", encoding="utf-8")
    with pytest.raises(ResourceLimitError, match="total OBJ face corners"):
        parse_obj(obj, _limits=limits(obj_total_corners=6))

    obj.write_text(
        "usemtl one\nf 1 2 3\nusemtl two\nf 1 2 3\n",
        encoding="utf-8",
    )
    assert parse_obj(obj, _limits=limits(obj_materials=2)).material_slot_count == 2
    obj.write_text(
        "usemtl one\nf 1 2 3\nusemtl two\nf 1 2 3\n"
        "usemtl three\nf 1 2 3\n",
        encoding="utf-8",
    )
    with pytest.raises(ResourceLimitError, match="unique OBJ materials"):
        parse_obj(obj, _limits=limits(obj_materials=2))


def test_issue_duplicate_payload_and_report_boundaries(tmp_path: Path) -> None:
    for index in range(2):
        (tmp_path / f"bad-{index}.bin").write_bytes(b"x")
    exact_issues = limits(issues=2)
    assert len(scan_directory(tmp_path, rules(naming=True), _limits=exact_issues).issues) == 2
    (tmp_path / "bad-2.bin").write_bytes(b"y")
    with pytest.raises(ResourceLimitError, match="accumulated issues"):
        scan_directory(tmp_path, rules(naming=True), _limits=exact_issues)

    duplicate_root = tmp_path / "duplicates"
    duplicate_root.mkdir()
    (duplicate_root / "a").write_bytes(b"same")
    (duplicate_root / "b").write_bytes(b"same")
    assert scan_directory(
        duplicate_root,
        rules(duplicates=True),
        _limits=limits(duplicate_members=2),
    ).scan.duplicate_groups == 1
    (duplicate_root / "c").write_bytes(b"same")
    with pytest.raises(ResourceLimitError, match="members in one duplicate group"):
        scan_directory(
            duplicate_root,
            rules(duplicates=True),
            _limits=limits(duplicate_members=2),
        )

    payload_budget = ResourceBudget(
        limits(issue_payload_bytes=5), clock=lambda: 0.0
    )
    payload_budget.reserve_issue(5)
    with pytest.raises(ResourceLimitError, match="cumulative issue payload"):
        payload_budget.reserve_issue(1)

    report = report_with_issues()
    json_text = serialize_report(report)
    html_text = render_html_report(report)
    assert serialize_report(
        report, _limits=limits(json_bytes=len(json_text.encode("utf-8")))
    ) == json_text
    with pytest.raises(ResourceLimitError, match="encoded JSON report"):
        serialize_report(
            report, _limits=limits(json_bytes=len(json_text.encode("utf-8")) - 1)
        )
    assert render_html_report(
        report, _limits=limits(html_bytes=len(html_text.encode("utf-8")))
    ) == html_text
    with pytest.raises(ResourceLimitError, match="encoded HTML report"):
        render_html_report(
            report, _limits=limits(html_bytes=len(html_text.encode("utf-8")) - 1)
        )


@pytest.mark.parametrize("sidecar_index", [0, 1, 2, 3])
def test_cache_main_and_each_sidecar_exact_and_plus_one(
    tmp_path: Path,
    sidecar_index: int,
) -> None:
    cache = tmp_path / "cache.sqlite3"
    related = cache_related_paths(cache)
    sparse_file(related[sidecar_index], 2)
    validate_cache_path(
        cache,
        tmp_path / "rules.yaml",
        tmp_path / "report.json",
        _limits=limits(cache_bytes=2),
    )
    with pytest.raises(ResourceLimitError, match="existing cache DB plus journal/WAL/SHM"):
        validate_cache_path(
            cache,
            tmp_path / "rules.yaml",
            tmp_path / "report.json",
            _limits=limits(cache_bytes=1),
        )


def test_legacy_cache_is_safe_miss_and_cache_no_cache_reports_match(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    texture = assets / "T_texture.png"
    Image.new("RGB", (2, 2)).save(texture)
    config = rules(textures=True)
    cache_path = tmp_path / "cache.sqlite3"
    with AssetMetricsCache(cache_path) as cache:
        cache.commit()

    digest = hashlib.sha256(texture.read_bytes()).hexdigest()
    payload = '{"height":2,"width":2}'
    checksum = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    with closing(sqlite3.connect(cache_path)) as connection:
        connection.execute(
            "INSERT INTO metric_entries VALUES (?, ?, ?, ?, ?)",
            (digest, TEXTURE_VALIDATOR_KIND, TEXTURE_METRICS_VERSION, payload, checksum),
        )
        connection.commit()

    without_cache = scan_directory(assets, config)
    with AssetMetricsCache(cache_path) as cache:
        cached = scan_directory_with_cache(assets, config, cache)
        cache.commit()
    assert cached.cache_hits == 0
    assert cached.cache_misses == 1
    assert serialize_report(cached.report) == serialize_report(without_cache)
    with closing(sqlite3.connect(cache_path)) as connection:
        keys = [row[0] for row in connection.execute("SELECT content_sha256 FROM metric_entries")]
    assert digest in keys
    assert derive_cache_content_key(digest) in keys


def test_resource_failure_restores_existing_cache_bytes(tmp_path: Path) -> None:
    cache_path = tmp_path / "cache.sqlite3"
    with AssetMetricsCache(cache_path) as cache:
        cache.commit()
    before = {
        path: path.read_bytes() if path.exists() else None
        for path in cache_related_paths(cache_path)
    }
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "bad-one").write_bytes(b"1")
    (assets / "bad-two").write_bytes(b"2")
    budget = ResourceBudget(limits(issues=1), clock=lambda: 0.0)
    with pytest.raises(ResourceLimitError, match="accumulated issues"):
        with AssetMetricsCache(cache_path, _budget=budget) as cache:
            scan_directory_with_cache(
                assets,
                rules(naming=True),
                cache,
                _budget=budget,
            )
    after = {
        path: path.read_bytes() if path.exists() else None
        for path in cache_related_paths(cache_path)
    }
    assert after == before


def test_cache_growth_exact_ceiling_and_plus_one_restore(tmp_path: Path) -> None:
    cache_path = tmp_path / "cache.sqlite3"
    with AssetMetricsCache(cache_path) as cache:
        cache.commit()
    exact_size = sum(
        path.stat().st_size for path in cache_related_paths(cache_path) if path.exists()
    )
    before = cache_path.read_bytes()
    exact_budget = ResourceBudget(
        limits(cache_bytes=exact_size), clock=lambda: 0.0
    )
    with AssetMetricsCache(cache_path, _budget=exact_budget) as cache:
        cache.commit()

    digest = hashlib.sha256(b"growth").hexdigest()
    growth_budget = ResourceBudget(
        limits(cache_bytes=exact_size), clock=lambda: 0.0
    )
    with pytest.raises(
        ResourceLimitError,
        match="existing cache DB plus journal/WAL/SHM",
    ):
        with AssetMetricsCache(cache_path, _budget=growth_budget) as cache:
            from assetguard.cache import TextureMetrics

            cache.store_texture(digest, TextureMetrics(width=1, height=1))
            cache.commit()
    assert cache_path.read_bytes() == before
    assert all(not path.exists() for path in cache_related_paths(cache_path)[1:])


def test_cli_resource_error_is_concise_and_side_effect_free(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    asset = assets / "T_asset.bin"
    asset.write_bytes(b"immutable")
    rules_path = tmp_path / "rules.yaml"
    rules_path.write_bytes(b"#" * (PRODUCTION_LIMITS.rules_bytes + 1))
    output = tmp_path / "report.json"
    html = tmp_path / "report.html"
    cache = tmp_path / "cache.sqlite3"
    before = {asset: asset.read_bytes(), rules_path: rules_path.read_bytes()}

    result = CliRunner().invoke(
        app,
        [
            "scan",
            str(assets),
            "--config",
            str(rules_path),
            "--output",
            str(output),
            "--html-output",
            str(html),
            "--cache",
            str(cache),
        ],
    )

    assert result.exit_code == 2
    assert result.stdout == ""
    assert result.stderr.count("Error:") == 1
    assert "rules YAML raw bytes" in result.stderr
    assert "observed 1048577 bytes" in result.stderr
    assert "inclusive limit 1048576 bytes" in result.stderr
    assert "Traceback" not in result.stderr
    assert not output.exists() and not html.exists()
    assert all(not path.exists() for path in cache_related_paths(cache))
    assert not list(tmp_path.rglob("*.tmp"))
    assert {asset: asset.read_bytes(), rules_path: rules_path.read_bytes()} == before


def test_deadline_during_traversal_hashing_parsing_reporting_and_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    traversal_root = tmp_path / "traversal"
    traversal_root.mkdir()
    (traversal_root / "file").write_bytes(b"x")
    traversal_clock = GateClock()
    real_scandir = scanner_module.os.scandir

    def expiring_scandir(path: Path) -> object:
        result = real_scandir(path)
        traversal_clock.expired = True
        return result

    monkeypatch.setattr(scanner_module.os, "scandir", expiring_scandir)
    with pytest.raises(ResourceLimitError, match="cooperative scan runtime"):
        scan_directory(
            traversal_root,
            rules(),
            _limits=limits(runtime_seconds=1),
            _clock=traversal_clock,
        )
    monkeypatch.setattr(scanner_module.os, "scandir", real_scandir)

    hash_root = tmp_path / "hash"
    hash_root.mkdir()
    (hash_root / "file").write_bytes(b"x")
    hash_clock = GateClock()
    original_sha = scanner_module._sha256

    def expiring_hash(path: Path) -> str:
        hash_clock.expired = True
        return original_sha(path)

    monkeypatch.setattr(scanner_module, "_sha256", expiring_hash)
    with pytest.raises(ResourceLimitError, match="cooperative scan runtime"):
        scan_directory(
            hash_root,
            rules(duplicates=True),
            _limits=limits(runtime_seconds=1),
            _clock=hash_clock,
        )
    monkeypatch.setattr(scanner_module, "_sha256", original_sha)

    obj = tmp_path / "deadline.obj"
    obj.write_text("# one\n# two\n", encoding="utf-8")
    with pytest.raises(ResourceLimitError, match="cooperative scan runtime"):
        parse_obj(
            obj,
            _budget=ResourceBudget(
                limits(runtime_seconds=1), clock=StepClock(expire_call=4)
            ),
        )

    report_clock = GateClock()
    report_budget = ResourceBudget(limits(runtime_seconds=1), clock=report_clock)
    report_clock.expired = True
    with pytest.raises(ResourceLimitError, match="cooperative scan runtime"):
        serialize_report(report_with_issues(), _budget=report_budget)

    cache_path = tmp_path / "deadline-cache.sqlite3"
    cache_clock = GateClock()
    cache_budget = ResourceBudget(limits(runtime_seconds=1), clock=cache_clock)
    digest = hashlib.sha256(b"data").hexdigest()
    with pytest.raises(ResourceLimitError, match="cooperative scan runtime"):
        with AssetMetricsCache(cache_path, _budget=cache_budget) as cache:
            from assetguard.cache import TextureMetrics

            cache.store_texture(digest, TextureMetrics(width=1, height=1))
            cache_clock.expired = True
            cache.commit()
    assert all(not path.exists() for path in cache_related_paths(cache_path))


def test_deadline_during_ordered_worker_collection() -> None:
    clock = StepClock(expire_call=7)
    budget = ResourceBudget(limits(runtime_seconds=1), clock=clock)
    with pytest.raises(ResourceLimitError, match="cooperative scan runtime"):
        with resource_budget_context(budget):
            ordered_bounded_map(lambda item: item, [1, 2], workers=2)


def test_worker_boundaries_and_simultaneous_error_precedence(tmp_path: Path) -> None:
    (tmp_path / "a").write_bytes(b"xx")
    (tmp_path / "b").write_bytes(b"xx")
    messages: list[str] = []
    for workers in (1, 4, PRODUCTION_LIMITS.max_workers):
        with pytest.raises(ResourceLimitError) as captured:
            scan_directory(
                tmp_path,
                rules(duplicates=True),
                workers=workers,
                _limits=limits(file_bytes=1, aggregate_file_bytes=1),
            )
        messages.append(str(captured.value))
    assert len(set(messages)) == 1
    assert "one candidate file" in messages[0]
