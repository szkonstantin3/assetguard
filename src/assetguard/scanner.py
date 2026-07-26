"""Deterministic directory scanning and asset validation."""

import hashlib
import os
import stat
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from PIL import Image, UnidentifiedImageError

from assetguard import __version__
from assetguard.cache import (
    OBJ_VALIDATOR_KIND,
    TEXTURE_VALIDATOR_KIND,
    AssetMetricsCache,
    TextureMetrics,
)
from assetguard.config import AssetGuardConfig
from assetguard.models import Issue, Report, ScanInfo, Summary, ToolInfo
from assetguard.obj_mesh import ObjMeshMetrics, ObjParseError, parse_obj
from assetguard.parallel import MAX_WORKERS, MIN_WORKERS, ordered_bounded_map
from assetguard.path_security import (
    PathSecurityError,
    lexical_absolute_path,
    validate_existing_entry,
    validate_secure_path,
)

HASH_CHUNK_SIZE = 1024 * 1024


class ScanError(Exception):
    """Raised for an operational failure while scanning assets."""


@dataclass(frozen=True, slots=True)
class CachedScanResult:
    report: Report
    cache_hits: int
    cache_misses: int


@dataclass(frozen=True, slots=True)
class _ScannedFile:
    relative_path: str
    path: Path
    is_texture: bool
    is_mesh: bool


@dataclass(frozen=True, slots=True)
class _ParseWork:
    relative_path: str
    path: Path
    validator_kind: str
    content_digest: str | None


def _resolved_path(path: Path) -> Path:
    try:
        return validate_secure_path(path, description="scan path")
    except (OSError, PathSecurityError) as exc:
        raise ScanError(f"cannot resolve path '{path}': {exc}") from exc


def _safe_scan_entry(path: Path, *, description: str) -> os.stat_result:
    try:
        return validate_existing_entry(path, description=description)
    except PathSecurityError as exc:
        raise ScanError(str(exc)) from exc


def _collect_files(
    root: Path,
    excluded_directories: set[str],
    excluded_files: set[Path],
) -> list[tuple[str, Path]]:
    collected: list[tuple[str, Path]] = []

    def raise_walk_error(error: OSError) -> None:
        raise ScanError(f"cannot access scanned directory: {error}") from error

    for current_root, directory_names, file_names in os.walk(
        root, topdown=True, onerror=raise_walk_error, followlinks=False
    ):
        current_path = Path(current_root)
        _safe_scan_entry(current_path, description="scanned directory")
        safe_directories: list[str] = []
        for directory_name in sorted(directory_names):
            directory_path = current_path / directory_name
            metadata = _safe_scan_entry(
                directory_path, description="scanned directory entry"
            )
            if not stat.S_ISDIR(metadata.st_mode):
                raise ScanError(f"scanned directory entry is not a directory: '{directory_path}'")
            if directory_name not in excluded_directories:
                safe_directories.append(directory_name)
        directory_names[:] = safe_directories
        for file_name in sorted(file_names):
            file_path = Path(current_root) / file_name
            resolved_file = _resolved_path(file_path)
            if resolved_file in excluded_files:
                continue
            metadata = _safe_scan_entry(file_path, description="scanned file entry")
            if not stat.S_ISREG(metadata.st_mode):
                continue
            relative_path = file_path.relative_to(root).as_posix()
            collected.append((relative_path, file_path))

    collected.sort(key=lambda item: item[0])
    return collected


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        _safe_scan_entry(path, description="scanned file entry")
    except ScanError as exc:
        try:
            path.lstat()
        except OSError:
            raise ScanError("file could not be read") from exc
        raise
    try:
        with path.open("rb") as source:
            while chunk := source.read(HASH_CHUNK_SIZE):
                digest.update(chunk)
    except OSError as exc:
        raise ScanError("file could not be read") from exc
    return digest.hexdigest()


def _hash_scanned_file(asset: _ScannedFile) -> str:
    try:
        return _sha256(asset.path)
    except ScanError as exc:
        raise ScanError(f"cannot hash asset '{asset.relative_path}': {exc}") from exc
    except Exception as exc:
        raise ScanError(
            f"cannot hash asset '{asset.relative_path}': unexpected hashing failure"
        ) from exc


def _is_power_of_two(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0


def _read_texture_metrics(relative_path: str, path: Path) -> TextureMetrics:
    try:
        _safe_scan_entry(path, description="scanned texture entry")
        with Image.open(path) as image:
            width, height = image.size
            image.verify()
    except (OSError, ValueError, UnidentifiedImageError) as exc:
        raise ScanError(f"cannot read texture '{relative_path}': {exc}") from exc
    return TextureMetrics(width=width, height=height)


def _texture_issues(
    relative_path: str,
    metrics: TextureMetrics,
    config: AssetGuardConfig,
) -> list[Issue]:
    issues: list[Issue] = []
    texture_config = config.textures
    if texture_config.require_power_of_two and (
        not _is_power_of_two(metrics.width) or not _is_power_of_two(metrics.height)
    ):
        issues.append(
            Issue(
                code="TEXTURE_NON_POWER_OF_TWO",
                severity=texture_config.severity,
                path=relative_path,
                message=(
                    f"Texture dimensions {metrics.width}x{metrics.height} are not both "
                    "powers of two."
                ),
                details={"height": metrics.height, "width": metrics.width},
            )
        )
    if metrics.width > texture_config.max_width:
        issues.append(
            Issue(
                code="TEXTURE_WIDTH_EXCEEDED",
                severity=texture_config.severity,
                path=relative_path,
                message=(
                    f"Texture width {metrics.width} exceeds the maximum of "
                    f"{texture_config.max_width}."
                ),
                details={"actual": metrics.width, "maximum": texture_config.max_width},
            )
        )
    if metrics.height > texture_config.max_height:
        issues.append(
            Issue(
                code="TEXTURE_HEIGHT_EXCEEDED",
                severity=texture_config.severity,
                path=relative_path,
                message=(
                    f"Texture height {metrics.height} exceeds the maximum of "
                    f"{texture_config.max_height}."
                ),
                details={"actual": metrics.height, "maximum": texture_config.max_height},
            )
        )
    return issues


def _read_mesh_metrics(relative_path: str, path: Path) -> ObjMeshMetrics:
    try:
        _safe_scan_entry(path, description="scanned mesh entry")
        return parse_obj(path)
    except ObjParseError as exc:
        raise ScanError(f"cannot parse mesh '{relative_path}': {exc}") from exc


def _parse_asset_metrics(work: _ParseWork) -> TextureMetrics | ObjMeshMetrics:
    try:
        if work.validator_kind == TEXTURE_VALIDATOR_KIND:
            return _read_texture_metrics(work.relative_path, work.path)
        if work.validator_kind == OBJ_VALIDATOR_KIND:
            return _read_mesh_metrics(work.relative_path, work.path)
        raise ScanError(
            f"internal error: unsupported validator kind '{work.validator_kind}'"
        )
    except ScanError:
        raise
    except Exception as exc:
        raise ScanError(
            f"cannot parse asset '{work.relative_path}': unexpected parser failure"
        ) from exc


def _mesh_issues(
    relative_path: str,
    metrics: ObjMeshMetrics,
    config: AssetGuardConfig,
) -> list[Issue]:
    issues: list[Issue] = []
    mesh_config = config.meshes
    if mesh_config.require_triangulated and metrics.non_triangulated_face_count > 0:
        issues.append(
            Issue(
                code="MESH_NON_TRIANGULATED_FACE",
                severity=mesh_config.severity,
                path=relative_path,
                message=(
                    f"Mesh contains {metrics.non_triangulated_face_count} "
                    "non-triangulated face(s)."
                ),
                details={
                    "non_triangulated_faces": metrics.non_triangulated_face_count,
                },
            )
        )
    if metrics.triangle_count > mesh_config.max_triangles:
        issues.append(
            Issue(
                code="MESH_TRIANGLE_COUNT_EXCEEDED",
                severity=mesh_config.severity,
                path=relative_path,
                message=(
                    f"Mesh triangle count {metrics.triangle_count} exceeds the maximum "
                    f"of {mesh_config.max_triangles}."
                ),
                details={
                    "triangle_count": metrics.triangle_count,
                    "max_triangles": mesh_config.max_triangles,
                },
            )
        )
    if (
        mesh_config.require_uv
        and metrics.face_count > 0
        and metrics.face_corners_with_uv < metrics.face_corner_count
    ):
        missing_uv_corners = metrics.face_corner_count - metrics.face_corners_with_uv
        issues.append(
            Issue(
                code="MESH_MISSING_UV",
                severity=mesh_config.severity,
                path=relative_path,
                message=f"Mesh is missing UV indexes on {missing_uv_corners} face corner(s).",
                details={
                    "face_corners": metrics.face_corner_count,
                    "face_corners_with_uv": metrics.face_corners_with_uv,
                    "missing_uv_corners": missing_uv_corners,
                },
            )
        )
    if metrics.material_slot_count > mesh_config.max_material_slots:
        issues.append(
            Issue(
                code="MESH_MATERIAL_SLOTS_EXCEEDED",
                severity=mesh_config.severity,
                path=relative_path,
                message=(
                    f"Mesh material slot count {metrics.material_slot_count} exceeds the "
                    f"maximum of {mesh_config.max_material_slots}."
                ),
                details={
                    "material_slots": metrics.material_slot_count,
                    "max_material_slots": mesh_config.max_material_slots,
                },
            )
        )
    return issues


def _scan_directory(
    root: Path,
    config: AssetGuardConfig,
    *,
    metrics_cache: AssetMetricsCache | None,
    excluded_files: Iterable[Path] = (),
    workers: int = 1,
) -> CachedScanResult:

    if not MIN_WORKERS <= workers <= MAX_WORKERS:
        raise ScanError(f"workers must be between {MIN_WORKERS} and {MAX_WORKERS}")
    lexical_root = lexical_absolute_path(root)
    if not os.path.lexists(lexical_root):
        raise ScanError(f"input directory does not exist: '{root}'")
    try:
        root_metadata = validate_existing_entry(
            lexical_root, description="scanned root"
        )
    except PathSecurityError as exc:
        raise ScanError(str(exc)) from exc
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise ScanError(f"input path is not a directory: '{root}'")

    resolved_root = _resolved_path(lexical_root)
    resolved_exclusions = {_resolved_path(path) for path in excluded_files}
    collected_files = _collect_files(
        resolved_root,
        set(config.scan.exclude_directories),
        resolved_exclusions,
    )

    files = [
        _ScannedFile(
            relative_path=relative_path,
            path=file_path,
            is_texture=(
                config.textures.enabled
                and file_path.suffix.lower() in config.textures.extensions
            ),
            is_mesh=(
                config.meshes.enabled
                and file_path.suffix.lower() in config.meshes.extensions
            ),
        )
        for relative_path, file_path in collected_files
    ]

    if config.duplicates.enabled:
        hash_work = files
    elif metrics_cache is not None:
        hash_work = [asset for asset in files if asset.is_texture or asset.is_mesh]
    else:
        hash_work = []

    try:
        digest_results = ordered_bounded_map(_hash_scanned_file, hash_work, workers)
    except ScanError:
        raise
    except Exception as exc:
        raise ScanError("parallel hashing failed") from exc
    digests = {
        asset.relative_path: digest
        for asset, digest in zip(hash_work, digest_results, strict=True)
    }

    metric_by_candidate: dict[
        tuple[str, str], TextureMetrics | ObjMeshMetrics
    ] = {}
    pending_by_identity: dict[tuple[str, str], _ParseWork] = {}
    candidate_identity: dict[tuple[str, str], tuple[str, str]] = {}
    parse_work: list[_ParseWork] = []
    cache_hits = 0
    cache_misses = 0

    for asset in files:
        validator_kinds: list[str] = []
        if asset.is_texture:
            validator_kinds.append(TEXTURE_VALIDATOR_KIND)
        if asset.is_mesh:
            validator_kinds.append(OBJ_VALIDATOR_KIND)

        for validator_kind in validator_kinds:
            candidate_key = (asset.relative_path, validator_kind)
            if metrics_cache is None:
                work = _ParseWork(
                    relative_path=asset.relative_path,
                    path=asset.path,
                    validator_kind=validator_kind,
                    content_digest=None,
                )
                parse_work.append(work)
                candidate_identity[candidate_key] = (validator_kind, asset.relative_path)
                continue

            content_digest = digests.get(asset.relative_path)
            if content_digest is None:
                raise ScanError("internal error: cache candidate has no content digest")
            identity = (validator_kind, content_digest)
            candidate_identity[candidate_key] = identity

            if identity in pending_by_identity:
                cache_hits += 1
                continue

            if validator_kind == TEXTURE_VALIDATOR_KIND:
                cached_metrics = metrics_cache.get_texture(content_digest)
            else:
                cached_metrics = metrics_cache.get_obj(content_digest)

            if cached_metrics is not None:
                cache_hits += 1
                metric_by_candidate[identity] = cached_metrics
                continue

            cache_misses += 1
            work = _ParseWork(
                relative_path=asset.relative_path,
                path=asset.path,
                validator_kind=validator_kind,
                content_digest=content_digest,
            )
            pending_by_identity[identity] = work
            parse_work.append(work)

    try:
        parsed_results = ordered_bounded_map(_parse_asset_metrics, parse_work, workers)
    except ScanError:
        raise
    except Exception as exc:
        raise ScanError("parallel parser execution failed") from exc

    for work, metrics in zip(parse_work, parsed_results, strict=True):
        identity = (
            work.validator_kind,
            work.content_digest or work.relative_path,
        )
        metric_by_candidate[identity] = metrics

    issues: list[Issue] = []
    hashes: dict[str, list[str]] = defaultdict(list)

    for asset in files:
        relative_path = asset.relative_path
        if config.naming.enabled and not asset.path.name.startswith(
            tuple(config.naming.allowed_prefixes)
        ):
            issues.append(
                Issue(
                    code="NAMING_INVALID_PREFIX",
                    severity=config.naming.severity,
                    path=relative_path,
                    message="Filename does not start with an allowed prefix.",
                    details={"allowed_prefixes": config.naming.allowed_prefixes},
                )
            )

        if asset.is_texture:
            texture_metrics = metric_by_candidate[
                candidate_identity[(relative_path, TEXTURE_VALIDATOR_KIND)]
            ]
            if not isinstance(texture_metrics, TextureMetrics):
                raise ScanError("internal error: texture parser returned invalid metrics")
            issues.extend(_texture_issues(relative_path, texture_metrics, config))

        if asset.is_mesh:
            mesh_metrics = metric_by_candidate[
                candidate_identity[(relative_path, OBJ_VALIDATOR_KIND)]
            ]
            if not isinstance(mesh_metrics, ObjMeshMetrics):
                raise ScanError("internal error: OBJ parser returned invalid metrics")
            issues.extend(_mesh_issues(relative_path, mesh_metrics, config))

        if config.duplicates.enabled:
            content_digest = digests.get(relative_path)
            if content_digest is None:
                raise ScanError("internal error: duplicate candidate has no content digest")
            hashes[content_digest].append(relative_path)

    if metrics_cache is not None:
        cache_writes = sorted(
            (
                work
                for work in parse_work
                if work.content_digest is not None
            ),
            key=lambda work: (
                work.content_digest or "",
                work.validator_kind,
                work.relative_path,
            ),
        )
        for work in cache_writes:
            content_digest = work.content_digest
            if content_digest is None:
                raise ScanError("internal error: cache write has no content digest")
            metrics = metric_by_candidate[(work.validator_kind, content_digest)]
            if work.validator_kind == TEXTURE_VALIDATOR_KIND:
                if not isinstance(metrics, TextureMetrics):
                    raise ScanError("internal error: invalid cached texture metrics")
                metrics_cache.store_texture(content_digest, metrics)
            else:
                if not isinstance(metrics, ObjMeshMetrics):
                    raise ScanError("internal error: invalid cached OBJ metrics")
                metrics_cache.store_obj(content_digest, metrics)

    duplicate_groups = 0
    if config.duplicates.enabled:
        for digest, members in sorted(hashes.items()):
            if len(members) < 2:
                continue
            sorted_members = sorted(members)
            duplicate_groups += 1
            issues.append(
                Issue(
                    code="DUPLICATE_CONTENT",
                    severity=config.duplicates.severity,
                    path=sorted_members[0],
                    message=f"{len(sorted_members)} files have identical content.",
                    details={"paths": sorted_members, "sha256": digest},
                )
            )

    issues.sort(key=lambda issue: (issue.code, issue.path, issue.message))
    error_count = sum(issue.severity == "error" for issue in issues)
    warning_count = sum(issue.severity == "warning" for issue in issues)

    return CachedScanResult(
        report=Report(
            tool=ToolInfo(version=__version__),
            scan=ScanInfo(
                files_scanned=len(files),
                textures_checked=sum(asset.is_texture for asset in files),
                meshes_checked=sum(asset.is_mesh for asset in files),
                duplicate_groups=duplicate_groups,
            ),
            summary=Summary(
                errors=error_count,
                warnings=warning_count,
                passed=error_count == 0,
            ),
            issues=issues,
        ),
        cache_hits=cache_hits,
        cache_misses=cache_misses,
    )


def scan_directory(
    root: Path,
    config: AssetGuardConfig,
    *,
    excluded_files: Iterable[Path] = (),
    workers: int = 1,
) -> Report:
    """Scan without caching and return the deterministic public report."""

    return _scan_directory(
        root,
        config,
        metrics_cache=None,
        excluded_files=excluded_files,
        workers=workers,
    ).report


def scan_directory_with_cache(
    root: Path,
    config: AssetGuardConfig,
    metrics_cache: AssetMetricsCache,
    *,
    excluded_files: Iterable[Path] = (),
    workers: int = 1,
) -> CachedScanResult:
    """Scan with content-addressed metric reuse and return internal cache statistics."""

    return _scan_directory(
        root,
        config,
        metrics_cache=metrics_cache,
        excluded_files=excluded_files,
        workers=workers,
    )
