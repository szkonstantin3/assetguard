import json
import os
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from typing import Callable, Iterator

from PIL import Image
import pytest
from typer.testing import CliRunner, Result

import assetguard.parallel as parallel_module
import assetguard.scanner as scanner_module
from assetguard.cache import AssetMetricsCache, cache_related_paths
from assetguard.cli import app
from assetguard.config import (
    AssetGuardConfig,
    DuplicateConfig,
    MeshConfig,
    NamingConfig,
    ScanConfig,
    TextureConfig,
)
from assetguard.parallel import ordered_bounded_map
from assetguard.reporting import serialize_report
from assetguard.scanner import ScanError, scan_directory, scan_directory_with_cache

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


def create_png(path: Path, size: tuple[int, int] = (64, 64), color: int = 1) -> Path:
    Image.new("RGBA", size, (color, color, color, 255)).save(path)
    return path


def rules(
    *,
    textures: bool = True,
    meshes: bool = True,
    duplicates: bool = False,
    naming: bool = False,
    texture_severity: str = "error",
    max_width: int = 4096,
    require_uv: bool = True,
) -> AssetGuardConfig:
    return AssetGuardConfig(
        version=1,
        scan=ScanConfig(),
        naming=NamingConfig(
            enabled=naming,
            severity="error",
            allowed_prefixes=["T_", "SM_"] if naming else [],
        ),
        textures=TextureConfig(
            enabled=textures,
            severity=texture_severity,
            max_width=max_width,
        ),
        meshes=MeshConfig(enabled=meshes, require_uv=require_uv),
        duplicates=DuplicateConfig(enabled=duplicates),
    )


def write_rules(
    path: Path,
    *,
    duplicates: bool = False,
    naming: bool = False,
    texture_severity: str = "error",
    max_width: int = 4096,
    require_uv: bool = True,
) -> Path:
    path.write_text(
        f"""\
version: 1
scan:
  exclude_directories: []
naming:
  enabled: {str(naming).lower()}
  severity: error
  allowed_prefixes: [T_, SM_]
textures:
  enabled: true
  severity: {texture_severity}
  extensions: [.png, .tga]
  require_power_of_two: true
  max_width: {max_width}
  max_height: 4096
meshes:
  enabled: true
  severity: error
  extensions: [.obj]
  require_triangulated: true
  require_uv: {str(require_uv).lower()}
  max_triangles: 100000
  max_material_slots: 8
duplicates:
  enabled: {str(duplicates).lower()}
  severity: warning
""",
        encoding="utf-8",
    )
    return path


def invoke_scan(
    assets: Path,
    config: Path,
    output: Path,
    *,
    cache: Path | None = None,
    workers: str | None = None,
    short_option: bool = False,
) -> Result:
    arguments = ["scan", str(assets), "--config", str(config), "--output", str(output)]
    if cache is not None:
        arguments.extend(["--cache", str(cache)])
    if workers is not None:
        arguments.extend(["-j" if short_option else "--workers", workers])
    return runner.invoke(app, arguments)


def metric_row_count(cache: Path) -> int:
    with closing(sqlite3.connect(cache)) as connection:
        return connection.execute("SELECT COUNT(*) FROM metric_entries").fetchone()[0]


def test_omitted_workers_uses_synchronous_phase03_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    create_png(assets / "T_valid.png")
    observed: list[int] = []
    original = scanner_module.ordered_bounded_map

    def recording_map(function: Callable[..., object], items: object, workers: int) -> list[object]:
        observed.append(workers)
        return original(function, items, workers)

    monkeypatch.setattr(scanner_module, "ordered_bounded_map", recording_map)
    result = invoke_scan(
        assets,
        write_rules(tmp_path / "rules.yaml"),
        tmp_path / "report.json",
    )

    assert result.exit_code == 0
    assert observed and set(observed) == {1}


def test_workers_one_and_short_j_four_succeed(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    create_png(assets / "T_valid.png")
    config = write_rules(tmp_path / "rules.yaml")

    sequential = invoke_scan(
        assets,
        config,
        tmp_path / "one.json",
        workers="1",
    )
    parallel = invoke_scan(
        assets,
        config,
        tmp_path / "four.json",
        workers="4",
        short_option=True,
    )

    assert sequential.exit_code == parallel.exit_code == 0


@pytest.mark.parametrize("value", ["0", "-1", "33", "not-an-integer"])
def test_invalid_worker_values_return_two_without_traceback(
    tmp_path: Path,
    value: str,
) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()

    result = invoke_scan(
        assets,
        write_rules(tmp_path / "rules.yaml"),
        tmp_path / "report.json",
        workers=value,
    )

    assert result.exit_code == 2
    assert "Traceback" not in result.stderr
    assert not (tmp_path / "report.json").exists()


def test_worker_one_and_four_no_cache_reports_are_byte_identical(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    first = create_png(assets / "T_first.png", (63, 64), 10)
    (assets / "T_duplicate.png").write_bytes(first.read_bytes())
    (assets / "SM_valid.obj").write_text(VALID_OBJ, encoding="utf-8")
    config = write_rules(tmp_path / "rules.yaml", duplicates=True)
    one_output = tmp_path / "one.json"
    four_output = tmp_path / "four.json"

    one = invoke_scan(assets, config, one_output, workers="1")
    four = invoke_scan(assets, config, four_output, workers="4")

    assert one.exit_code == four.exit_code == 1
    assert one_output.read_bytes() == four_output.read_bytes()
    report = json.loads(four_output.read_text(encoding="utf-8"))
    assert {issue["code"] for issue in report["issues"]} == {
        "DUPLICATE_CONTENT",
        "TEXTURE_NON_POWER_OF_TWO",
    }
    assert "workers" not in four_output.read_text(encoding="utf-8").lower()
    assert "cache" not in four_output.read_text(encoding="utf-8").lower()


def test_parallel_cache_miss_then_hit_preserves_report_and_statistics(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    create_png(assets / "T_valid.png")
    (assets / "SM_valid.obj").write_text(VALID_OBJ, encoding="utf-8")
    config = write_rules(tmp_path / "rules.yaml")
    cache = tmp_path / "cache.sqlite3"
    first_output = tmp_path / "first.json"
    second_output = tmp_path / "second.json"

    first = invoke_scan(assets, config, first_output, cache=cache, workers="4")
    second = invoke_scan(assets, config, second_output, cache=cache, workers="4")

    assert first.exit_code == second.exit_code == 0
    assert "Cache hits: 0" in first.stdout
    assert "Cache misses: 2" in first.stdout
    assert "Cache hits: 2" in second.stdout
    assert "Cache misses: 0" in second.stdout
    assert first_output.read_bytes() == second_output.read_bytes()
    report_text = second_output.read_text(encoding="utf-8")
    assert "cache" not in report_text.lower()
    assert "workers" not in report_text.lower()


def test_workers_one_executes_helper_synchronously(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    caller_thread = threading.get_ident()
    observed: list[int] = []

    class ForbiddenExecutor:
        def __init__(self, **_kwargs: object) -> None:
            pytest.fail("thread pool created for workers=1")

    monkeypatch.setattr(parallel_module, "ThreadPoolExecutor", ForbiddenExecutor)

    result = ordered_bounded_map(
        lambda item: (observed.append(threading.get_ident()), item * 2)[1],
        [1, 2, 3],
        1,
    )

    assert result == [2, 4, 6]
    assert observed == [caller_thread, caller_thread, caller_thread]


def test_ordered_results_ignore_worker_completion_order() -> None:
    later_finished = threading.Event()

    def work(item: int) -> int:
        if item == 0:
            assert later_finished.wait(5)
        else:
            later_finished.set()
        return item

    assert ordered_bounded_map(work, [0, 1], 2) == [0, 1]


def test_submission_is_bounded_and_not_eager(monkeypatch: pytest.MonkeyPatch) -> None:
    holder: dict[str, RecordingExecutor] = {}

    class RecordingFuture:
        def __init__(
            self,
            executor: "RecordingExecutor",
            function: Callable[[int], int],
            item: int,
        ) -> None:
            self.executor = executor
            self.function = function
            self.item = item

        def result(self) -> int:
            try:
                return self.function(self.item)
            finally:
                self.executor.outstanding -= 1
                self.executor.results_consumed += 1

        def cancel(self) -> bool:
            self.executor.outstanding -= 1
            return True

    class RecordingExecutor:
        def __init__(self, *, max_workers: int, thread_name_prefix: str) -> None:
            assert thread_name_prefix == "assetguard"
            self.max_workers = max_workers
            self.outstanding = 0
            self.max_outstanding = 0
            self.results_consumed = 0
            self.shutdown_calls: list[tuple[bool, bool]] = []
            holder["executor"] = self

        def submit(
            self,
            function: Callable[[int], int],
            item: int,
        ) -> RecordingFuture:
            self.outstanding += 1
            self.max_outstanding = max(self.max_outstanding, self.outstanding)
            return RecordingFuture(self, function, item)

        def shutdown(self, *, wait: bool, cancel_futures: bool = False) -> None:
            self.shutdown_calls.append((wait, cancel_futures))

    def items() -> Iterator[int]:
        for item in range(10):
            if item == 4:
                assert holder["executor"].results_consumed > 0
            yield item

    monkeypatch.setattr(parallel_module, "ThreadPoolExecutor", RecordingExecutor)
    result = ordered_bounded_map(lambda item: item, items(), 2)

    executor = holder["executor"]
    assert result == list(range(10))
    assert executor.max_outstanding == 4
    assert executor.shutdown_calls == [(True, False)]


def test_multiple_worker_failures_select_earliest_input() -> None:
    later_failed = threading.Event()

    def fail(item: int) -> int:
        if item == 0:
            assert later_failed.wait(5)
            raise ScanError("earliest deterministic failure")
        later_failed.set()
        raise ScanError("later completion failure")

    with pytest.raises(ScanError, match="earliest deterministic failure"):
        ordered_bounded_map(fail, [0, 1], 2)


def test_helper_rejects_out_of_range_worker_count() -> None:
    with pytest.raises(ValueError, match="workers must be between 1 and 32"):
        ordered_bounded_map(lambda item: item, [], 33)


def test_parallel_hashing_uses_multiple_worker_threads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for index in range(4):
        (tmp_path / f"T_{index}.bin").write_bytes(bytes([index]))
    original = scanner_module._sha256
    barrier = threading.Barrier(2)
    thread_ids: set[int] = set()
    lock = threading.Lock()

    def instrumented(path: Path) -> str:
        with lock:
            thread_ids.add(threading.get_ident())
        barrier.wait(5)
        return original(path)

    monkeypatch.setattr(scanner_module, "_sha256", instrumented)
    scan_directory(
        tmp_path,
        rules(textures=False, meshes=False, duplicates=True),
        workers=2,
    )

    assert len(thread_ids) >= 2


def test_parallel_parsers_overlap_without_timing_assertions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    create_png(tmp_path / "T_first.png", color=10)
    create_png(tmp_path / "T_second.png", color=20)
    original = scanner_module._read_texture_metrics
    barrier = threading.Barrier(2)
    thread_ids: set[int] = set()
    lock = threading.Lock()

    def instrumented(relative_path: str, path: Path) -> object:
        with lock:
            thread_ids.add(threading.get_ident())
        barrier.wait(5)
        return original(relative_path, path)

    monkeypatch.setattr(scanner_module, "_read_texture_metrics", instrumented)
    report = scan_directory(
        tmp_path,
        rules(meshes=False),
        workers=2,
    )

    assert report.scan.textures_checked == 2
    assert len(thread_ids) >= 2


def test_hashing_failure_selects_earliest_path_and_prevents_parsing_and_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    create_png(assets / "T_a.png", color=1)
    create_png(assets / "T_b.png", color=2)
    later_failed = threading.Event()

    def fail_hash(path: Path) -> str:
        if path.name == "T_a.png":
            assert later_failed.wait(5)
            raise RuntimeError("first")
        later_failed.set()
        raise RuntimeError("second")

    monkeypatch.setattr(scanner_module, "_sha256", fail_hash)
    monkeypatch.setattr(
        scanner_module,
        "_read_texture_metrics",
        lambda *_args: pytest.fail("parsing continued after hashing failure"),
    )
    output = tmp_path / "report.json"
    result = invoke_scan(
        assets,
        write_rules(tmp_path / "rules.yaml", duplicates=True),
        output,
        workers="2",
    )

    assert result.exit_code == 2
    assert "T_a.png" in result.stderr
    assert "Traceback" not in result.stderr
    assert not output.exists()


def test_hash_worker_wraps_file_read_failure_with_relative_path(tmp_path: Path) -> None:
    asset = scanner_module._ScannedFile(
        relative_path="T_missing.bin",
        path=tmp_path / "T_missing.bin",
        is_texture=False,
        is_mesh=False,
    )

    with pytest.raises(ScanError, match="T_missing.bin.*file could not be read"):
        scanner_module._hash_scanned_file(asset)


def test_unexpected_executor_failures_use_operational_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    create_png(tmp_path / "T_valid.png")

    def fail_hash_executor(*_args: object) -> list[object]:
        raise RuntimeError("executor unavailable")

    monkeypatch.setattr(scanner_module, "ordered_bounded_map", fail_hash_executor)
    with pytest.raises(ScanError, match="parallel hashing failed"):
        scan_directory(
            tmp_path,
            rules(meshes=False, duplicates=True),
            workers=4,
        )

    calls = 0

    def fail_parser_executor(*_args: object) -> list[object]:
        nonlocal calls
        calls += 1
        if calls == 1:
            return []
        raise RuntimeError("executor unavailable")

    monkeypatch.setattr(scanner_module, "ordered_bounded_map", fail_parser_executor)
    with pytest.raises(ScanError, match="parallel parser execution failed"):
        scan_directory(tmp_path, rules(meshes=False), workers=4)


def test_parser_worker_converts_unexpected_exception_and_rejects_unknown_kind(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    texture_work = scanner_module._ParseWork(
        relative_path="T_broken.png",
        path=tmp_path / "T_broken.png",
        validator_kind="texture",
        content_digest=None,
    )

    def fail_parser(*_args: object) -> object:
        raise RuntimeError("unexpected")

    monkeypatch.setattr(scanner_module, "_read_texture_metrics", fail_parser)
    with pytest.raises(ScanError, match="T_broken.png.*unexpected parser failure"):
        scanner_module._parse_asset_metrics(texture_work)

    unknown_work = scanner_module._ParseWork(
        relative_path="asset.unknown",
        path=tmp_path / "asset.unknown",
        validator_kind="unknown",
        content_digest=None,
    )
    with pytest.raises(ScanError, match="unsupported validator kind 'unknown'"):
        scanner_module._parse_asset_metrics(unknown_work)


def test_parser_failure_rolls_back_new_cache_metrics_and_writes_no_report(
    tmp_path: Path,
) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "SM_bad.obj").write_text("f 1/1/1/1 2 3\n", encoding="utf-8")
    create_png(assets / "T_valid.png")
    cache = tmp_path / "cache.sqlite3"
    output = tmp_path / "report.json"

    result = invoke_scan(
        assets,
        write_rules(tmp_path / "rules.yaml"),
        output,
        cache=cache,
        workers="4",
    )

    assert result.exit_code == 2
    assert "SM_bad.obj" in result.stderr
    assert "Traceback" not in result.stderr
    assert not output.exists()
    assert all(not path.exists() for path in cache_related_paths(cache))


def test_cache_reads_and_writes_stay_on_coordinator_thread(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    create_png(tmp_path / "T_first.png", color=10)
    create_png(tmp_path / "T_second.png", color=20)
    (tmp_path / "SM_first.obj").write_text(VALID_OBJ, encoding="utf-8")
    coordinator = threading.get_ident()
    cache_path = tmp_path / "cache.sqlite3"
    observed: list[int] = []

    with AssetMetricsCache(cache_path) as cache:
        for name in ("get_texture", "get_obj", "store_texture", "store_obj"):
            original = getattr(cache, name)

            def wrapped(*args: object, _original: Callable[..., object] = original) -> object:
                observed.append(threading.get_ident())
                return _original(*args)

            monkeypatch.setattr(cache, name, wrapped)
        result = scan_directory_with_cache(
            tmp_path,
            rules(),
            cache,
            excluded_files=(cache_path, *cache_related_paths(cache_path)[1:]),
            workers=4,
        )
        cache.commit()

    assert result.cache_misses == 3
    assert observed and set(observed) == {coordinator}


def test_sqlite_default_same_thread_protection_remains_enabled(tmp_path: Path) -> None:
    with AssetMetricsCache(tmp_path / "cache.sqlite3") as cache:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(lambda: cache._db.execute("SELECT 1").fetchone())
            with pytest.raises(sqlite3.ProgrammingError, match="same thread"):
                future.result()


def test_parallel_cache_hits_skip_both_parsers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    create_png(tmp_path / "T_valid.png")
    (tmp_path / "SM_valid.obj").write_text(VALID_OBJ, encoding="utf-8")
    cache_path = tmp_path / "cache.sqlite3"
    exclusions = cache_related_paths(cache_path)

    with AssetMetricsCache(cache_path) as cache:
        first = scan_directory_with_cache(
            tmp_path,
            rules(),
            cache,
            excluded_files=exclusions,
            workers=4,
        )
        cache.commit()
    monkeypatch.setattr(
        scanner_module,
        "_read_texture_metrics",
        lambda *_args: pytest.fail("texture parser ran on cache hit"),
    )
    monkeypatch.setattr(
        scanner_module,
        "_read_mesh_metrics",
        lambda *_args: pytest.fail("OBJ parser ran on cache hit"),
    )
    with AssetMetricsCache(cache_path) as cache:
        second = scan_directory_with_cache(
            tmp_path,
            rules(),
            cache,
            excluded_files=exclusions,
            workers=4,
        )
        cache.commit()

    assert first.cache_misses == 2
    assert second.cache_hits == 2
    assert second.cache_misses == 0


def test_duplicates_and_cache_hash_each_file_once_in_parallel(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    texture = create_png(tmp_path / "T_valid.png")
    cache_path = tmp_path / "cache.sqlite3"
    calls: list[Path] = []
    original = scanner_module._sha256

    def counting(path: Path) -> str:
        calls.append(path)
        return original(path)

    monkeypatch.setattr(scanner_module, "_sha256", counting)
    with AssetMetricsCache(cache_path) as cache:
        result = scan_directory_with_cache(
            tmp_path,
            rules(meshes=False, duplicates=True),
            cache,
            excluded_files=cache_related_paths(cache_path),
            workers=4,
        )
        cache.commit()

    assert calls == [texture]
    assert result.cache_misses == 1


def test_parallel_cache_reapplies_threshold_and_severity(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    create_png(assets / "T_valid.png", (64, 64))
    cache = tmp_path / "cache.sqlite3"

    first = invoke_scan(
        assets,
        write_rules(tmp_path / "first.yaml", max_width=64),
        tmp_path / "first.json",
        cache=cache,
        workers="4",
    )
    error = invoke_scan(
        assets,
        write_rules(tmp_path / "error.yaml", max_width=32),
        tmp_path / "error.json",
        cache=cache,
        workers="4",
    )
    warning = invoke_scan(
        assets,
        write_rules(
            tmp_path / "warning.yaml",
            max_width=32,
            texture_severity="warning",
        ),
        tmp_path / "warning.json",
        cache=cache,
        workers="4",
    )

    assert first.exit_code == 0
    assert error.exit_code == 1
    assert warning.exit_code == 0
    assert "Cache hits: 1" in error.stdout
    assert "Cache hits: 1" in warning.stdout


def test_parallel_cache_detects_same_size_change_with_restored_mtime(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    mesh = assets / "SM_mutable.obj"
    first_content = "f 1 2 3\n"
    second_content = "f 1 3 2\n"
    assert len(first_content) == len(second_content)
    mesh.write_text(first_content, encoding="utf-8")
    config = write_rules(tmp_path / "rules.yaml", require_uv=False)
    cache = tmp_path / "cache.sqlite3"

    first = invoke_scan(
        assets,
        config,
        tmp_path / "first.json",
        cache=cache,
        workers="4",
    )
    original_stat = mesh.stat()
    mesh.write_text(second_content, encoding="utf-8")
    os.utime(mesh, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
    second = invoke_scan(
        assets,
        config,
        tmp_path / "second.json",
        cache=cache,
        workers="4",
    )

    assert first.exit_code == second.exit_code == 0
    assert mesh.stat().st_size == original_stat.st_size
    assert mesh.stat().st_mtime_ns == original_stat.st_mtime_ns
    assert "Cache misses: 1" in second.stdout
    assert metric_row_count(cache) == 2


def test_filename_validation_changes_on_parallel_cache_hit(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    original = create_png(assets / "T_valid.png")
    config = write_rules(tmp_path / "rules.yaml", naming=True)
    cache = tmp_path / "cache.sqlite3"

    first = invoke_scan(
        assets,
        config,
        tmp_path / "first.json",
        cache=cache,
        workers="4",
    )
    original.rename(assets / "invalid.png")
    second_output = tmp_path / "second.json"
    second = invoke_scan(
        assets,
        config,
        second_output,
        cache=cache,
        workers="4",
    )

    assert first.exit_code == 0
    assert second.exit_code == 1
    assert "Cache hits: 1" in second.stdout
    report = json.loads(second_output.read_text(encoding="utf-8"))
    assert [issue["code"] for issue in report["issues"]] == ["NAMING_INVALID_PREFIX"]


def test_parallel_cache_and_output_self_exclusion_are_stable(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    create_png(assets / "T_valid.png")
    config = write_rules(tmp_path / "rules.yaml")
    cache = assets / "metrics.sqlite3"
    output = assets / "report.json"

    first = invoke_scan(assets, config, output, cache=cache, workers="4")
    first_report = json.loads(output.read_text(encoding="utf-8"))
    second = invoke_scan(assets, config, output, cache=cache, workers="4")
    second_report = json.loads(output.read_text(encoding="utf-8"))

    assert first.exit_code == second.exit_code == 0
    assert first_report["scan"]["files_scanned"] == 1
    assert second_report["scan"]["files_scanned"] == 1

    for sidecar in cache_related_paths(cache)[1:]:
        sidecar.write_bytes(b"excluded sidecar")
    report = scan_directory(
        assets,
        rules(meshes=False),
        excluded_files=(output, *cache_related_paths(cache)),
        workers=4,
    )
    assert report.scan.files_scanned == 1


def test_empty_directory_and_fewer_items_than_workers_succeed(tmp_path: Path) -> None:
    empty_report = scan_directory(
        tmp_path,
        rules(textures=False, meshes=False),
        workers=4,
    )
    create_png(tmp_path / "T_only.png")
    one_report = scan_directory(tmp_path, rules(meshes=False), workers=4)

    assert empty_report.scan.files_scanned == 0
    assert one_report.scan.files_scanned == 1
    assert one_report.summary.passed is True


def test_cache_statistics_match_between_worker_counts(tmp_path: Path) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    create_png(assets / "T_valid.png")
    (assets / "SM_valid.obj").write_text(VALID_OBJ, encoding="utf-8")
    config = write_rules(tmp_path / "rules.yaml")

    one = invoke_scan(
        assets,
        config,
        tmp_path / "one-first.json",
        cache=tmp_path / "one.sqlite3",
        workers="1",
    )
    four = invoke_scan(
        assets,
        config,
        tmp_path / "four-first.json",
        cache=tmp_path / "four.sqlite3",
        workers="4",
    )
    one_hit = invoke_scan(
        assets,
        config,
        tmp_path / "one-second.json",
        cache=tmp_path / "one.sqlite3",
        workers="1",
    )
    four_hit = invoke_scan(
        assets,
        config,
        tmp_path / "four-second.json",
        cache=tmp_path / "four.sqlite3",
        workers="4",
    )

    assert "Cache misses: 2" in one.stdout
    assert "Cache misses: 2" in four.stdout
    assert "Cache hits: 2" in one_hit.stdout
    assert "Cache hits: 2" in four_hit.stdout
    assert (tmp_path / "one-first.json").read_bytes() == (
        tmp_path / "four-first.json"
    ).read_bytes()


def test_direct_invalid_worker_count_is_operational_error(tmp_path: Path) -> None:
    with pytest.raises(ScanError, match="workers must be between 1 and 32"):
        scan_directory(tmp_path, rules(), workers=0)


def test_direct_non_directory_input_is_operational_error(tmp_path: Path) -> None:
    file_path = tmp_path / "not-a-directory"
    file_path.write_bytes(b"content")

    with pytest.raises(ScanError, match="input path is not a directory"):
        scan_directory(file_path, rules(), workers=4)


def test_parallel_and_sequential_public_report_serialization_match(tmp_path: Path) -> None:
    create_png(tmp_path / "T_valid.png")
    (tmp_path / "SM_valid.obj").write_text(VALID_OBJ, encoding="utf-8")
    config = rules(duplicates=True)

    sequential = serialize_report(scan_directory(tmp_path, config, workers=1))
    parallel = serialize_report(scan_directory(tmp_path, config, workers=4))

    assert sequential == parallel
    assert list(json.loads(parallel)) == ["schema_version", "tool", "scan", "summary", "issues"]
