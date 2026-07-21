"""Typed public JSON report models."""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict


class ReportModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Issue(ReportModel):
    code: str
    severity: Literal["error", "warning"]
    path: str
    message: str
    details: dict[str, Any] | None = None


class ToolInfo(ReportModel):
    name: Literal["AssetGuard"] = "AssetGuard"
    version: str


class ScanInfo(ReportModel):
    root: Literal["."] = "."
    files_scanned: int
    textures_checked: int
    meshes_checked: int
    duplicate_groups: int


class Summary(ReportModel):
    errors: int
    warnings: int
    passed: bool


class Report(ReportModel):
    schema_version: Literal[1] = 1
    tool: ToolInfo
    scan: ScanInfo
    summary: Summary
    issues: list[Issue]
