from pathlib import Path

from assetguard.config import (
    AssetGuardConfig,
    DuplicateConfig,
    NamingConfig,
    ScanConfig,
    TextureConfig,
)
from assetguard.scanner import scan_directory


def rules(*, naming: bool = False, duplicates: bool = True) -> AssetGuardConfig:
    return AssetGuardConfig(
        version=1,
        scan=ScanConfig(),
        naming=NamingConfig(enabled=naming, allowed_prefixes=["T_"] if naming else []),
        textures=TextureConfig(enabled=False),
        duplicates=DuplicateConfig(enabled=duplicates),
    )


def test_identical_files_produce_one_duplicate_group(tmp_path: Path) -> None:
    (tmp_path / "T_a.bin").write_bytes(b"same")
    (tmp_path / "T_b.bin").write_bytes(b"same")

    report = scan_directory(tmp_path, rules())

    assert report.scan.duplicate_groups == 1
    assert [issue.code for issue in report.issues] == ["DUPLICATE_CONTENT"]
    assert report.issues[0].details is not None
    assert report.issues[0].details["paths"] == ["T_a.bin", "T_b.bin"]


def test_different_files_do_not_produce_duplicate_issues(tmp_path: Path) -> None:
    (tmp_path / "T_a.bin").write_bytes(b"first")
    (tmp_path / "T_b.bin").write_bytes(b"second")

    assert scan_directory(tmp_path, rules()).issues == []


def test_identical_empty_files_are_duplicate_candidates(tmp_path: Path) -> None:
    (tmp_path / "T_empty_a.bin").write_bytes(b"")
    (tmp_path / "T_empty_b.bin").write_bytes(b"")

    report = scan_directory(tmp_path, rules())

    assert report.scan.duplicate_groups == 1
    assert report.issues[0].code == "DUPLICATE_CONTENT"


def test_invalid_filename_prefix_produces_naming_issue(tmp_path: Path) -> None:
    (tmp_path / "bad.bin").write_bytes(b"content")

    report = scan_directory(tmp_path, rules(naming=True, duplicates=False))

    assert [issue.code for issue in report.issues] == ["NAMING_INVALID_PREFIX"]
