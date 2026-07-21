"""YAML configuration loading and validation."""

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

Severity = Literal["error", "warning"]


class ConfigurationError(Exception):
    """Raised when configuration cannot be read or validated."""


class StrictConfigModel(BaseModel):
    """Base model that rejects unsupported configuration keys."""

    model_config = ConfigDict(extra="forbid")


class ScanConfig(StrictConfigModel):
    exclude_directories: list[str] = Field(default_factory=list)

    @field_validator("exclude_directories")
    @classmethod
    def validate_excluded_directories(cls, values: list[str]) -> list[str]:
        if any(not value or not value.strip() for value in values):
            raise ValueError("excluded directory names must not be empty")
        return values


class NamingConfig(StrictConfigModel):
    enabled: bool = True
    severity: Severity = "error"
    allowed_prefixes: list[str] = Field(default_factory=list)

    @field_validator("allowed_prefixes")
    @classmethod
    def validate_prefix_values(cls, values: list[str]) -> list[str]:
        if any(not value for value in values):
            raise ValueError("allowed prefixes must not be empty strings")
        return values

    @model_validator(mode="after")
    def validate_enabled_prefixes(self) -> "NamingConfig":
        if self.enabled and not self.allowed_prefixes:
            raise ValueError("allowed_prefixes must not be empty when naming validation is enabled")
        return self


class TextureConfig(StrictConfigModel):
    enabled: bool = True
    severity: Severity = "error"
    extensions: list[str] = Field(default_factory=lambda: [".png", ".tga"])
    require_power_of_two: bool = True
    max_width: int = Field(default=4096, gt=0)
    max_height: int = Field(default=4096, gt=0)

    @field_validator("extensions")
    @classmethod
    def normalize_extensions(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            extension = value.strip().lower()
            if not extension or extension == ".":
                raise ValueError("texture extensions must not be empty")
            if not extension.startswith("."):
                extension = f".{extension}"
            if extension not in normalized:
                normalized.append(extension)
        return normalized


class MeshConfig(StrictConfigModel):
    enabled: bool = False
    severity: Severity = "error"
    extensions: list[str] = Field(default_factory=lambda: [".obj"])
    require_triangulated: bool = True
    require_uv: bool = True
    max_triangles: int = Field(default=100000, gt=0)
    max_material_slots: int = Field(default=8, gt=0)

    @field_validator("extensions")
    @classmethod
    def normalize_extensions(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            extension = value.strip().lower()
            if not extension or extension == ".":
                raise ValueError("mesh extensions must not be empty")
            if not extension.startswith("."):
                extension = f".{extension}"
            if extension != ".obj":
                raise ValueError(
                    f"unsupported mesh extension '{extension}'; Phase 02 supports only .obj"
                )
            if extension not in normalized:
                normalized.append(extension)
        return normalized

    @model_validator(mode="after")
    def validate_enabled_extensions(self) -> "MeshConfig":
        if self.enabled and not self.extensions:
            raise ValueError("extensions must not be empty when mesh validation is enabled")
        return self


class DuplicateConfig(StrictConfigModel):
    enabled: bool = True
    severity: Severity = "warning"


class AssetGuardConfig(StrictConfigModel):
    version: Literal[1]
    scan: ScanConfig
    naming: NamingConfig
    textures: TextureConfig
    meshes: MeshConfig = Field(default_factory=MeshConfig)
    duplicates: DuplicateConfig


def load_config(path: Path) -> AssetGuardConfig:
    """Read and validate an AssetGuard YAML configuration file."""

    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigurationError(f"cannot read configuration '{path}': {exc}") from exc

    try:
        data = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"invalid YAML in configuration '{path}': {exc}") from exc

    if not isinstance(data, dict):
        raise ConfigurationError(f"configuration '{path}' must contain a YAML mapping")

    try:
        return AssetGuardConfig.model_validate(data)
    except ValidationError as exc:
        raise ConfigurationError(f"invalid configuration '{path}': {exc}") from exc
