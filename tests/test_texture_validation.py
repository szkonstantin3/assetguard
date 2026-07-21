from pathlib import Path

from PIL import Image

from assetguard.config import (
    AssetGuardConfig,
    DuplicateConfig,
    NamingConfig,
    ScanConfig,
    TextureConfig,
)
from assetguard.scanner import scan_directory


def texture_rules(*, max_width: int = 4096, max_height: int = 4096) -> AssetGuardConfig:
    return AssetGuardConfig(
        version=1,
        scan=ScanConfig(),
        naming=NamingConfig(enabled=False),
        textures=TextureConfig(max_width=max_width, max_height=max_height),
        duplicates=DuplicateConfig(enabled=False),
    )


def issue_codes(root: Path, config: AssetGuardConfig) -> list[str]:
    return [issue.code for issue in scan_directory(root, config).issues]


def test_valid_power_of_two_png_passes(tmp_path: Path) -> None:
    Image.new("RGBA", (64, 128)).save(tmp_path / "T_valid.png")

    report = scan_directory(tmp_path, texture_rules())

    assert report.scan.textures_checked == 1
    assert report.issues == []


def test_non_power_of_two_png_emits_issue(tmp_path: Path) -> None:
    Image.new("RGB", (63, 128)).save(tmp_path / "T_odd.png")

    assert issue_codes(tmp_path, texture_rules()) == ["TEXTURE_NON_POWER_OF_TWO"]


def test_oversized_texture_emits_width_and_height_issues(tmp_path: Path) -> None:
    Image.new("RGB", (128, 256)).save(tmp_path / "T_large.png")

    assert issue_codes(tmp_path, texture_rules(max_width=64, max_height=128)) == [
        "TEXTURE_HEIGHT_EXCEEDED",
        "TEXTURE_WIDTH_EXCEEDED",
    ]


def test_tga_validation_works(tmp_path: Path) -> None:
    Image.new("RGB", (32, 32)).save(tmp_path / "T_valid.tga")

    report = scan_directory(tmp_path, texture_rules())

    assert report.scan.textures_checked == 1
    assert report.summary.passed is True

