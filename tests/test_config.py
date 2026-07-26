from pathlib import Path

import pytest

from assetguard.config import ConfigurationError, load_config


VALID_CONFIG = """\
version: 1
scan:
  exclude_directories: [.git]
naming:
  enabled: true
  severity: error
  allowed_prefixes: [T_]
textures:
  enabled: true
  severity: warning
  extensions: [PNG, .TGA]
  require_power_of_two: true
  max_width: 4096
  max_height: 4096
duplicates:
  enabled: true
  severity: warning
"""

MESH_CONFIG = """\
meshes:
  enabled: true
  severity: error
  extensions: [OBJ]
  require_triangulated: true
  require_uv: true
  max_triangles: 100000
  max_material_slots: 8
"""


def write_config(path: Path, text: str = VALID_CONFIG) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def add_mesh_config(text: str = MESH_CONFIG) -> str:
    return VALID_CONFIG.replace("duplicates:\n", f"{text}duplicates:\n")


def test_valid_configuration_loads_and_normalizes_extensions(tmp_path: Path) -> None:
    config = load_config(write_config(tmp_path / "rules.yaml"))

    assert config.version == 1
    assert config.textures.extensions == [".png", ".tga"]
    assert config.meshes.enabled is False


def test_valid_mesh_configuration_loads_and_normalizes_extension(tmp_path: Path) -> None:
    config = load_config(write_config(tmp_path / "rules.yaml", add_mesh_config()))

    assert config.meshes.enabled is True
    assert config.meshes.extensions == [".obj"]


def test_unsupported_mesh_extension_is_rejected(tmp_path: Path) -> None:
    config_text = add_mesh_config(MESH_CONFIG.replace("[OBJ]", "[.fbx]"))

    with pytest.raises(ConfigurationError, match="supports only .obj"):
        load_config(write_config(tmp_path / "rules.yaml", config_text))


def test_empty_mesh_extensions_are_rejected_when_enabled(tmp_path: Path) -> None:
    config_text = add_mesh_config(MESH_CONFIG.replace("[OBJ]", "[]"))

    with pytest.raises(ConfigurationError, match="extensions must not be empty"):
        load_config(write_config(tmp_path / "rules.yaml", config_text))


def test_non_positive_mesh_triangle_limit_is_rejected(tmp_path: Path) -> None:
    config_text = add_mesh_config(MESH_CONFIG.replace("max_triangles: 100000", "max_triangles: 0"))

    with pytest.raises(ConfigurationError, match="max_triangles"):
        load_config(write_config(tmp_path / "rules.yaml", config_text))


def test_non_positive_material_slot_limit_is_rejected(tmp_path: Path) -> None:
    config_text = add_mesh_config(
        MESH_CONFIG.replace("max_material_slots: 8", "max_material_slots: -1")
    )

    with pytest.raises(ConfigurationError, match="max_material_slots"):
        load_config(write_config(tmp_path / "rules.yaml", config_text))


def test_invalid_configuration_version_is_rejected(tmp_path: Path) -> None:
    path = write_config(tmp_path / "rules.yaml", VALID_CONFIG.replace("version: 1", "version: 2"))

    with pytest.raises(ConfigurationError, match="invalid configuration"):
        load_config(path)


def test_unknown_top_level_field_is_rejected(tmp_path: Path) -> None:
    path = write_config(tmp_path / "rules.yaml", VALID_CONFIG + "unexpected: true\n")

    with pytest.raises(ConfigurationError, match="unexpected"):
        load_config(path)


def test_invalid_utf8_configuration_is_a_typed_concise_error(tmp_path: Path) -> None:
    path = tmp_path / "rules.yaml"
    path.write_bytes(b"version: \xff\xfe\n")
    before = path.read_bytes()

    with pytest.raises(ConfigurationError, match="not valid UTF-8") as raised:
        load_config(path)

    assert "codec" not in str(raised.value)
    assert path.read_bytes() == before
