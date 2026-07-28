"""YAML configuration loading and validation."""

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator
from yaml.events import (
    AliasEvent,
    MappingEndEvent,
    MappingStartEvent,
    ScalarEvent,
    SequenceEndEvent,
    SequenceStartEvent,
)

from assetguard.path_security import PathSecurityError, validate_secure_path
from assetguard.resource_limits import (
    PRODUCTION_LIMITS,
    ResourceBudget,
    ResourceLimits,
    active_resource_budget,
)

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


def _validate_yaml_structure(raw_text: str, budget: ResourceBudget) -> None:
    """Count composed YAML nodes and depth from parser events before construction."""

    node_count = 0
    container_depth = 0
    try:
        for event in yaml.parse(raw_text, Loader=yaml.SafeLoader):
            budget.check_deadline()
            if isinstance(event, (MappingStartEvent, SequenceStartEvent)):
                node_count += 1
                container_depth += 1
                budget.check_value(
                    "YAML composed nodes",
                    node_count,
                    budget.limits.yaml_nodes,
                    "nodes",
                )
                budget.check_value(
                    "YAML nesting depth",
                    container_depth,
                    budget.limits.yaml_depth,
                    "levels",
                )
            elif isinstance(event, ScalarEvent):
                node_count += 1
                budget.check_value(
                    "YAML composed nodes",
                    node_count,
                    budget.limits.yaml_nodes,
                    "nodes",
                )
                budget.check_value(
                    "YAML nesting depth",
                    container_depth + 1,
                    budget.limits.yaml_depth,
                    "levels",
                )
            elif isinstance(event, (MappingEndEvent, SequenceEndEvent)):
                container_depth -= 1
            elif isinstance(event, AliasEvent):
                # PyYAML composition reuses the anchored node; aliases do not
                # create another composed node and retain their prior semantics.
                continue
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"invalid YAML in configuration: {exc}") from exc


def load_config(
    path: Path,
    *,
    _budget: ResourceBudget | None = None,
    _limits: ResourceLimits = PRODUCTION_LIMITS,
) -> AssetGuardConfig:
    """Read and validate an AssetGuard YAML configuration file."""

    budget = _budget or active_resource_budget(_limits)
    budget.check_deadline()
    try:
        secure_path = validate_secure_path(path, description="configuration")
        with secure_path.open("rb") as source:
            raw_bytes = source.read(budget.limits.rules_bytes + 1)
        budget.check_deadline()
    except PathSecurityError as exc:
        raise ConfigurationError(str(exc)) from exc
    except OSError as exc:
        raise ConfigurationError(f"cannot read configuration '{path}': {exc}") from exc

    budget.check_value(
        "rules YAML raw bytes",
        len(raw_bytes),
        budget.limits.rules_bytes,
        "bytes",
    )
    try:
        raw_text = raw_bytes.decode("utf-8")
    except UnicodeError as exc:
        raise ConfigurationError(f"configuration '{path}' is not valid UTF-8") from exc

    _validate_yaml_structure(raw_text, budget)
    budget.check_deadline()
    try:
        data = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"invalid YAML in configuration '{path}': {exc}") from exc
    budget.check_deadline()

    if not isinstance(data, dict):
        raise ConfigurationError(f"configuration '{path}' must contain a YAML mapping")

    try:
        return AssetGuardConfig.model_validate(data)
    except ValidationError as exc:
        raise ConfigurationError(f"invalid configuration '{path}': {exc}") from exc
