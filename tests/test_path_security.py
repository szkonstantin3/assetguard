import os
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from assetguard.cli import app
from assetguard.config import load_config
from assetguard.path_security import (
    FILE_ATTRIBUTE_REPARSE_POINT,
    PathSecurityError,
    lexical_absolute_path,
    prepare_secure_destination,
    validate_secure_path,
)
from assetguard.scanner import ScanError, scan_directory

runner = CliRunner()


def _write_rules(path: Path) -> Path:
    path.write_text(
        """version: 1
scan:
  exclude_directories: []
naming:
  enabled: false
  severity: error
  allowed_prefixes: []
textures:
  enabled: false
  severity: error
  extensions: [.png, .tga]
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
  enabled: true
  severity: warning
""",
        encoding="utf-8",
    )
    return path


def _create_windows_junction(link: Path, target: Path) -> None:
    result = subprocess.run(
        ["cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(target)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert link.is_junction()
    assert link.lstat().st_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT


def test_normal_nested_missing_destination_is_created_lexically(tmp_path: Path) -> None:
    destination = tmp_path / "one" / "two" / "report.json"

    result = prepare_secure_destination(destination, description="test output")

    assert result == lexical_absolute_path(destination)
    assert result.parent.is_dir()
    assert not result.exists()


def test_reparse_destination_and_ancestor_are_rejected_by_nonfollowing_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ancestor = lexical_absolute_path(tmp_path / "safe" / "redirect")
    destination = ancestor / "nested" / "report.json"
    ancestor.parent.mkdir()
    original_lstat = Path.lstat

    def fake_lstat(path: Path) -> os.stat_result | SimpleNamespace:
        if path == ancestor:
            return SimpleNamespace(
                st_mode=stat.S_IFDIR,
                st_file_attributes=FILE_ATTRIBUTE_REPARSE_POINT,
            )
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", fake_lstat)

    with pytest.raises(PathSecurityError, match="reparse point"):
        validate_secure_path(destination, description="test output")


def test_revalidation_detects_reparse_substitution_before_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = lexical_absolute_path(tmp_path / "nested" / "report.json")
    parent = destination.parent
    original_lstat = Path.lstat
    parent_checks = 0

    def changing_lstat(path: Path) -> os.stat_result | SimpleNamespace:
        nonlocal parent_checks
        metadata = original_lstat(path)
        if path == parent:
            parent_checks += 1
            if parent_checks >= 1:
                return SimpleNamespace(
                    st_mode=metadata.st_mode,
                    st_file_attributes=FILE_ATTRIBUTE_REPARSE_POINT,
                )
        return metadata

    monkeypatch.setattr(Path, "lstat", changing_lstat)

    with pytest.raises(PathSecurityError, match="reparse point"):
        prepare_secure_destination(destination, description="test output")
    assert not destination.exists()


def test_scanned_file_reparse_metadata_is_rejected_before_hashing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assets = tmp_path / "assets"
    assets.mkdir()
    linked_file = lexical_absolute_path(assets / "linked.bin")
    linked_file.write_bytes(b"must-not-be-read")
    config = load_config(_write_rules(tmp_path / "rules.yaml"))
    original_lstat = Path.lstat

    def fake_lstat(path: Path) -> os.stat_result | SimpleNamespace:
        metadata = original_lstat(path)
        if path == linked_file:
            return SimpleNamespace(
                st_mode=stat.S_IFREG,
                st_file_attributes=FILE_ATTRIBUTE_REPARSE_POINT,
            )
        return metadata

    monkeypatch.setattr(Path, "lstat", fake_lstat)
    monkeypatch.setattr(
        "assetguard.scanner._sha256",
        lambda _path: pytest.fail("reparse file was hashed"),
    )

    with pytest.raises(ScanError, match="reparse point"):
        scan_directory(assets, config)


@pytest.mark.skipif(os.name != "nt", reason="real Windows junction proof")
@pytest.mark.parametrize("sink", ["json", "html", "cache"])
def test_source_cli_rejects_real_junction_for_each_output_sink(
    tmp_path: Path, sink: str
) -> None:
    assets = tmp_path / "assets"
    outside = tmp_path / "outside"
    link = assets / "redirect"
    assets.mkdir()
    outside.mkdir()
    (assets / "T_asset.bin").write_bytes(b"unchanged")
    config = _write_rules(tmp_path / "rules.yaml")
    before = (assets / "T_asset.bin").read_bytes()
    _create_windows_junction(link, outside)
    arguments = [
        "scan",
        str(assets),
        "--config",
        str(config),
        "--output",
        str(link / "report.json") if sink == "json" else str(tmp_path / "safe.json"),
    ]
    if sink == "html":
        arguments.extend(["--html-output", str(link / "report.html")])
    if sink == "cache":
        arguments.extend(["--cache", str(link / "cache.sqlite3")])
    try:
        result = runner.invoke(app, arguments)
    finally:
        link.rmdir()

    assert result.exit_code == 2
    assert result.stderr.startswith("Error:")
    assert "reparse" in result.stderr.lower()
    assert "Traceback" not in result.stderr
    assert list(outside.iterdir()) == []
    assert (assets / "T_asset.bin").read_bytes() == before
    assert not (tmp_path / "safe.json").exists()


@pytest.mark.skipif(os.name != "nt", reason="real Windows junction proof")
def test_scan_root_and_nested_junctions_are_rejected_without_reading_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    external = target / "external.bin"
    external.write_bytes(b"must-not-be-read")
    config = load_config(_write_rules(tmp_path / "rules.yaml"))

    root_link = tmp_path / "root-link"
    _create_windows_junction(root_link, target)
    try:
        with pytest.raises(ScanError, match="reparse point"):
            scan_directory(root_link, config)
    finally:
        root_link.rmdir()

    assets = tmp_path / "assets"
    assets.mkdir()
    nested_link = assets / "nested"
    _create_windows_junction(nested_link, target)
    monkeypatch.setattr(
        "assetguard.scanner._sha256",
        lambda _path: pytest.fail("linked target was read"),
    )
    try:
        with pytest.raises(ScanError, match="reparse point"):
            scan_directory(assets, config)
    finally:
        nested_link.rmdir()
    assert external.read_bytes() == b"must-not-be-read"


@pytest.mark.skipif(os.name == "nt", reason="POSIX file-symlink proof")
def test_file_symlink_is_rejected_before_hashing(tmp_path: Path) -> None:
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"must-not-be-read")
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "linked.bin").symlink_to(outside)
    config = load_config(_write_rules(tmp_path / "rules.yaml"))

    with pytest.raises(ScanError, match="symbolic link"):
        scan_directory(assets, config)

    assert outside.read_bytes() == b"must-not-be-read"
