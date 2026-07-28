"""Deterministic directory scanning and asset validation."""

import hashlib
import json
import os
import re
import stat
import threading
import warnings
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

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
from assetguard.obj_mesh import (
    ObjMeshMetrics,
    ObjParseError,
    parse_obj,
    validate_obj_resources,
)
from assetguard.parallel import (
    MAX_WORKERS,
    MIN_WORKERS,
    ordered_bounded_map,
    resource_budget_context,
)
from assetguard.path_security import (
    PathSecurityError,
    lexical_absolute_path,
    validate_existing_entry,
    validate_secure_path,
)
from assetguard.resource_limits import (
    PRODUCTION_LIMITS,
    ResourceBudget,
    ResourceLimitError,
    ResourceLimits,
    active_resource_budget,
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
class _FileIdentity:
    device: int
    inode: int
    size: int
    modified_ns: int


@dataclass(frozen=True, slots=True)
class _ScannedFile:
    relative_path: str
    path: Path
    is_texture: bool
    is_mesh: bool
    identity: _FileIdentity | None = None
    budget: ResourceBudget | None = None


@dataclass(frozen=True, slots=True)
class _ParseWork:
    relative_path: str
    path: Path
    validator_kind: str
    content_digest: str | None
    identity: _FileIdentity | None = None
    budget: ResourceBudget | None = None


_WORK_CONTEXT = threading.local()


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


def _file_identity(metadata: os.stat_result) -> _FileIdentity:
    return _FileIdentity(
        device=int(metadata.st_dev),
        inode=int(metadata.st_ino),
        size=int(metadata.st_size),
        modified_ns=int(metadata.st_mtime_ns),
    )


def _identity_matches(metadata: os.stat_result, identity: _FileIdentity) -> bool:
    return stat.S_ISREG(metadata.st_mode) and _file_identity(metadata) == identity


def _verify_file_identity(
    path: Path,
    relative_path: str,
    identity: _FileIdentity,
) -> None:
    metadata = _safe_scan_entry(path, description="scanned file entry")
    if not _identity_matches(metadata, identity):
        raise ScanError(f"scanned file '{relative_path}' changed after resource preflight")


def _collect_files(
    root: Path,
    excluded_directories: set[str],
    excluded_files: set[Path],
) -> list[tuple[str, Path, _FileIdentity]]:
    budget = getattr(_WORK_CONTEXT, "collection_budget", None)
    if not isinstance(budget, ResourceBudget):
        budget = active_resource_budget()
    collected: list[tuple[str, Path, _FileIdentity]] = []

    def visit(current_path: Path, relative_parts: tuple[str, ...]) -> None:
        budget.check_deadline()
        directory_metadata = _safe_scan_entry(
            current_path, description="scanned directory"
        )
        if not stat.S_ISDIR(directory_metadata.st_mode):
            raise ScanError(f"scanned directory entry is not a directory: '{current_path}'")

        names: list[str] = []
        try:
            with os.scandir(current_path) as entries:
                for entry in entries:
                    budget.check_deadline()
                    observed = len(names) + 1
                    budget.check_value(
                        "entries within one directory",
                        observed,
                        budget.limits.directory_entries,
                        "entries",
                        path="/".join(relative_parts) or None,
                    )
                    names.append(entry.name)
        except ResourceLimitError:
            raise
        except OSError as exc:
            raise ScanError(f"cannot access scanned directory: {exc}") from exc

        for name in sorted(names):
            budget.check_deadline()
            entry_parts = (*relative_parts, name)
            relative_path = "/".join(entry_parts)
            budget.check_value(
                "relative directory depth",
                len(entry_parts),
                budget.limits.relative_depth,
                "levels",
                path=relative_path,
            )
            try:
                path_bytes = len(relative_path.encode("utf-8"))
            except UnicodeEncodeError as exc:
                raise ScanError(
                    f"scanned path is not valid UTF-8: '{relative_path}'"
                ) from exc
            budget.check_value(
                "relative path UTF-8 bytes",
                path_bytes,
                budget.limits.relative_path_bytes,
                "bytes",
                path=relative_path,
            )
            budget.add_tree_entry(path=relative_path)

            entry_path = current_path / name
            metadata = _safe_scan_entry(entry_path, description="scanned tree entry")
            if stat.S_ISDIR(metadata.st_mode):
                if name not in excluded_directories:
                    visit(entry_path, entry_parts)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                continue
            if lexical_absolute_path(entry_path) in excluded_files:
                continue
            budget.add_regular_file(metadata.st_size, path=relative_path)
            collected.append((relative_path, entry_path, _file_identity(metadata)))

    visit(root, ())
    collected.sort(key=lambda item: item[0])
    return collected


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    budget = getattr(_WORK_CONTEXT, "budget", None)
    identity = getattr(_WORK_CONTEXT, "identity", None)
    relative_path = getattr(_WORK_CONTEXT, "relative_path", path.name)
    if isinstance(budget, ResourceBudget):
        budget.check_deadline()
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
            if isinstance(identity, _FileIdentity):
                opened_metadata = os.fstat(source.fileno())
                if not _identity_matches(opened_metadata, identity):
                    raise ScanError(
                        f"scanned file '{relative_path}' changed after resource preflight"
                    )
            bytes_read = 0
            while True:
                if isinstance(budget, ResourceBudget):
                    budget.check_deadline()
                chunk = source.read(HASH_CHUNK_SIZE)
                if not chunk:
                    break
                bytes_read += len(chunk)
                if isinstance(identity, _FileIdentity) and bytes_read > identity.size:
                    raise ScanError(
                        f"scanned file '{relative_path}' grew after resource preflight"
                    )
                digest.update(chunk)
                if isinstance(budget, ResourceBudget):
                    budget.check_deadline()
            if isinstance(identity, _FileIdentity):
                final_metadata = os.fstat(source.fileno())
                if bytes_read != identity.size or not _identity_matches(
                    final_metadata, identity
                ):
                    raise ScanError(
                        f"scanned file '{relative_path}' changed after resource preflight"
                    )
    except OSError as exc:
        raise ScanError("file could not be read") from exc
    if isinstance(identity, _FileIdentity):
        _verify_file_identity(path, relative_path, identity)
    return digest.hexdigest()


def _hash_scanned_file(asset: _ScannedFile) -> str:
    previous_budget = getattr(_WORK_CONTEXT, "budget", None)
    previous_identity = getattr(_WORK_CONTEXT, "identity", None)
    previous_path = getattr(_WORK_CONTEXT, "relative_path", None)
    _WORK_CONTEXT.budget = asset.budget
    _WORK_CONTEXT.identity = asset.identity
    _WORK_CONTEXT.relative_path = asset.relative_path
    try:
        return _sha256(asset.path)
    except ResourceLimitError:
        raise
    except ScanError as exc:
        raise ScanError(f"cannot hash asset '{asset.relative_path}': {exc}") from exc
    except Exception as exc:
        raise ScanError(
            f"cannot hash asset '{asset.relative_path}': unexpected hashing failure"
        ) from exc
    finally:
        _WORK_CONTEXT.budget = previous_budget
        _WORK_CONTEXT.identity = previous_identity
        _WORK_CONTEXT.relative_path = previous_path


def _is_power_of_two(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0


def _decompression_bomb_pixels(error: BaseException, limit: int) -> int:
    match = re.search(r"(\d+) pixels", str(error))
    return int(match.group(1)) if match else limit + 1


def _inspect_texture(
    relative_path: str,
    path: Path,
    budget: ResourceBudget,
    identity: _FileIdentity | None,
) -> TextureMetrics:
    budget.check_deadline()
    try:
        _safe_scan_entry(path, description="scanned texture entry")
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(path) as image:
                budget.check_deadline()
                width, height = image.size
                if width <= 0 or height <= 0:
                    raise ValueError("texture dimensions must be positive")
                pixel_count = width * height
                if height > budget.limits.texture_pixels // width:
                    raise ResourceLimitError(
                        "texture pixels",
                        pixel_count,
                        budget.limits.texture_pixels,
                        "pixels",
                        path=relative_path,
                    )
                image.verify()
                budget.check_deadline()
    except ResourceLimitError:
        raise
    except (Image.DecompressionBombWarning, Image.DecompressionBombError) as exc:
        raise ResourceLimitError(
            "texture pixels",
            _decompression_bomb_pixels(exc, budget.limits.texture_pixels),
            budget.limits.texture_pixels,
            "pixels",
            path=relative_path,
        ) from exc
    except (OSError, ValueError, UnidentifiedImageError) as exc:
        raise ScanError(f"cannot read texture '{relative_path}': {exc}") from exc
    if identity is not None:
        _verify_file_identity(path, relative_path, identity)
    return TextureMetrics(width=width, height=height)


def _read_texture_metrics(relative_path: str, path: Path) -> TextureMetrics:
    budget = getattr(_WORK_CONTEXT, "budget", None)
    if not isinstance(budget, ResourceBudget):
        budget = active_resource_budget()
    identity = getattr(_WORK_CONTEXT, "identity", None)
    return _inspect_texture(
        relative_path,
        path,
        budget,
        identity if isinstance(identity, _FileIdentity) else None,
    )


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
    budget = getattr(_WORK_CONTEXT, "budget", None)
    if not isinstance(budget, ResourceBudget):
        budget = active_resource_budget()
    identity = getattr(_WORK_CONTEXT, "identity", None)
    try:
        _safe_scan_entry(path, description="scanned mesh entry")
        metrics = parse_obj(
            path,
            _budget=budget,
            _relative_path=relative_path,
            _expected_size=(identity.size if isinstance(identity, _FileIdentity) else None),
        )
        if isinstance(identity, _FileIdentity):
            _verify_file_identity(path, relative_path, identity)
        return metrics
    except ObjParseError as exc:
        raise ScanError(f"cannot parse mesh '{relative_path}': {exc}") from exc


def _parse_asset_metrics(work: _ParseWork) -> TextureMetrics | ObjMeshMetrics:
    previous_budget = getattr(_WORK_CONTEXT, "budget", None)
    previous_identity = getattr(_WORK_CONTEXT, "identity", None)
    previous_path = getattr(_WORK_CONTEXT, "relative_path", None)
    _WORK_CONTEXT.budget = work.budget
    _WORK_CONTEXT.identity = work.identity
    _WORK_CONTEXT.relative_path = work.relative_path
    try:
        if work.validator_kind == TEXTURE_VALIDATOR_KIND:
            return _read_texture_metrics(work.relative_path, work.path)
        if work.validator_kind == OBJ_VALIDATOR_KIND:
            return _read_mesh_metrics(work.relative_path, work.path)
        raise ScanError(
            f"internal error: unsupported validator kind '{work.validator_kind}'"
        )
    except (ResourceLimitError, ScanError):
        raise
    except Exception as exc:
        raise ScanError(
            f"cannot parse asset '{work.relative_path}': unexpected parser failure"
        ) from exc
    finally:
        _WORK_CONTEXT.budget = previous_budget
        _WORK_CONTEXT.identity = previous_identity
        _WORK_CONTEXT.relative_path = previous_path


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


def _append_issue(issues: list[Issue], issue: Issue, budget: ResourceBudget) -> None:
    payload = json.dumps(
        issue.model_dump(mode="json", exclude_none=True),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    budget.reserve_issue(len(payload), path=issue.path)
    issues.append(issue)


def _prepare_scan_files(
    root: Path,
    config: AssetGuardConfig,
    *,
    excluded_files: Iterable[Path] = (),
    _budget: ResourceBudget | None = None,
    _limits: ResourceLimits = PRODUCTION_LIMITS,
) -> tuple[_ScannedFile, ...]:
    """Complete deterministic structural preflight without opening a cache."""

    budget = _budget or active_resource_budget(_limits)
    budget.check_deadline()
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

    budget.check_deadline()
    resolved_root = _resolved_path(lexical_root)
    resolved_exclusions = {_resolved_path(path) for path in excluded_files}
    previous_collection_budget = getattr(_WORK_CONTEXT, "collection_budget", None)
    _WORK_CONTEXT.collection_budget = budget
    try:
        collected_files = _collect_files(
            resolved_root,
            set(config.scan.exclude_directories),
            resolved_exclusions,
        )
    finally:
        _WORK_CONTEXT.collection_budget = previous_collection_budget

    files = tuple(
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
            identity=identity,
            budget=budget,
        )
        for relative_path, file_path, identity in collected_files
    )
    for asset in files:
        if asset.is_mesh and asset.identity is not None:
            budget.check_value(
                "one OBJ file",
                asset.identity.size,
                budget.limits.obj_file_bytes,
                "bytes",
                path=asset.relative_path,
            )
    return files


def _scan_directory(
    root: Path,
    config: AssetGuardConfig,
    *,
    metrics_cache: AssetMetricsCache | None,
    excluded_files: Iterable[Path] = (),
    workers: int = 1,
    _budget: ResourceBudget | None = None,
    _limits: ResourceLimits = PRODUCTION_LIMITS,
    _clock: Callable[[], float] | None = None,
    _prepared_files: tuple[_ScannedFile, ...] | None = None,
) -> CachedScanResult:

    budget = _budget or (
        active_resource_budget(_limits)
        if _clock is None
        else ResourceBudget(_limits, clock=_clock)
    )
    maximum_workers = min(MAX_WORKERS, budget.limits.max_workers)
    if not MIN_WORKERS <= workers <= maximum_workers:
        raise ScanError(f"workers must be between {MIN_WORKERS} and {maximum_workers}")
    files = list(
        _prepared_files
        if _prepared_files is not None
        else _prepare_scan_files(
            root,
            config,
            excluded_files=excluded_files,
            _budget=budget,
        )
    )

    if config.duplicates.enabled:
        hash_work = files
    elif metrics_cache is not None:
        hash_work = [asset for asset in files if asset.is_texture or asset.is_mesh]
    else:
        hash_work = []

    try:
        with resource_budget_context(budget):
            digest_results = ordered_bounded_map(_hash_scanned_file, hash_work, workers)
    except (ResourceLimitError, ScanError):
        raise
    except Exception as exc:
        raise ScanError("parallel hashing failed") from exc
    digests = {
        asset.relative_path: digest
        for asset, digest in zip(hash_work, digest_results, strict=True)
    }

    resource_metrics: dict[
        tuple[str, str], TextureMetrics | ObjMeshMetrics
    ] = {}
    for asset in files:
        budget.check_deadline()
        if asset.is_texture:
            resource_metrics[(asset.relative_path, TEXTURE_VALIDATOR_KIND)] = (
                _inspect_texture(
                    asset.relative_path,
                    asset.path,
                    budget,
                    asset.identity,
                )
            )
        if asset.is_mesh:
            if asset.identity is None:
                raise ScanError("internal error: OBJ candidate has no file identity")
            try:
                resource_metrics[(asset.relative_path, OBJ_VALIDATOR_KIND)] = (
                    validate_obj_resources(
                        asset.path,
                        budget=budget,
                        relative_path=asset.relative_path,
                        expected_size=asset.identity.size,
                    )
                )
            except ObjParseError as exc:
                raise ScanError(
                    f"cannot parse mesh '{asset.relative_path}': {exc}"
                ) from exc
            _verify_file_identity(asset.path, asset.relative_path, asset.identity)

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
                    identity=asset.identity,
                    budget=budget,
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
                budget.check_deadline()
                cached_metrics = metrics_cache.get_texture(content_digest)
            else:
                budget.check_deadline()
                cached_metrics = metrics_cache.get_obj(content_digest)

            if cached_metrics is not None:
                if cached_metrics != resource_metrics[candidate_key]:
                    raise ScanError(
                        f"cached {validator_kind} metrics do not match asset "
                        f"'{asset.relative_path}'"
                    )
                cache_hits += 1
                metric_by_candidate[identity] = cached_metrics
                continue

            cache_misses += 1
            work = _ParseWork(
                relative_path=asset.relative_path,
                path=asset.path,
                validator_kind=validator_kind,
                content_digest=content_digest,
                identity=asset.identity,
                budget=budget,
            )
            pending_by_identity[identity] = work
            parse_work.append(work)

    try:
        with resource_budget_context(budget):
            parsed_results = ordered_bounded_map(_parse_asset_metrics, parse_work, workers)
    except (ResourceLimitError, ScanError):
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
        budget.check_deadline()
        relative_path = asset.relative_path
        if config.naming.enabled and not asset.path.name.startswith(
            tuple(config.naming.allowed_prefixes)
        ):
            _append_issue(
                issues,
                Issue(
                    code="NAMING_INVALID_PREFIX",
                    severity=config.naming.severity,
                    path=relative_path,
                    message="Filename does not start with an allowed prefix.",
                    details={"allowed_prefixes": config.naming.allowed_prefixes},
                ),
                budget,
            )

        if asset.is_texture:
            texture_metrics = metric_by_candidate[
                candidate_identity[(relative_path, TEXTURE_VALIDATOR_KIND)]
            ]
            if not isinstance(texture_metrics, TextureMetrics):
                raise ScanError("internal error: texture parser returned invalid metrics")
            for issue in _texture_issues(relative_path, texture_metrics, config):
                _append_issue(issues, issue, budget)

        if asset.is_mesh:
            mesh_metrics = metric_by_candidate[
                candidate_identity[(relative_path, OBJ_VALIDATOR_KIND)]
            ]
            if not isinstance(mesh_metrics, ObjMeshMetrics):
                raise ScanError("internal error: OBJ parser returned invalid metrics")
            for issue in _mesh_issues(relative_path, mesh_metrics, config):
                _append_issue(issues, issue, budget)

        if config.duplicates.enabled:
            content_digest = digests.get(relative_path)
            if content_digest is None:
                raise ScanError("internal error: duplicate candidate has no content digest")
            members = hashes[content_digest]
            budget.check_value(
                "members in one duplicate group",
                len(members) + 1,
                budget.limits.duplicate_members,
                "members",
                path=relative_path,
            )
            members.append(relative_path)

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
            budget.check_deadline()
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
            budget.check_deadline()

    duplicate_groups = 0
    if config.duplicates.enabled:
        for digest, members in sorted(hashes.items()):
            budget.check_deadline()
            if len(members) < 2:
                continue
            sorted_members = sorted(members)
            duplicate_groups += 1
            _append_issue(
                issues,
                Issue(
                    code="DUPLICATE_CONTENT",
                    severity=config.duplicates.severity,
                    path=sorted_members[0],
                    message=f"{len(sorted_members)} files have identical content.",
                    details={"paths": sorted_members, "sha256": digest},
                ),
                budget,
            )

    for asset in files:
        budget.check_deadline()
        if asset.identity is None:
            raise ScanError("internal error: scanned file has no identity")
        _verify_file_identity(asset.path, asset.relative_path, asset.identity)

    issues.sort(key=lambda issue: (issue.code, issue.path, issue.message))
    error_count = sum(issue.severity == "error" for issue in issues)
    warning_count = sum(issue.severity == "warning" for issue in issues)

    budget.check_deadline()
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
    _budget: ResourceBudget | None = None,
    _limits: ResourceLimits = PRODUCTION_LIMITS,
    _clock: Callable[[], float] | None = None,
) -> Report:
    """Scan without caching and return the deterministic public report."""

    return _scan_directory(
        root,
        config,
        metrics_cache=None,
        excluded_files=excluded_files,
        workers=workers,
        _budget=_budget,
        _limits=_limits,
        _clock=_clock,
    ).report


def scan_directory_with_cache(
    root: Path,
    config: AssetGuardConfig,
    metrics_cache: AssetMetricsCache,
    *,
    excluded_files: Iterable[Path] = (),
    workers: int = 1,
    _budget: ResourceBudget | None = None,
    _limits: ResourceLimits = PRODUCTION_LIMITS,
    _clock: Callable[[], float] | None = None,
    _prepared_files: tuple[_ScannedFile, ...] | None = None,
) -> CachedScanResult:
    """Scan with content-addressed metric reuse and return internal cache statistics."""

    return _scan_directory(
        root,
        config,
        metrics_cache=metrics_cache,
        excluded_files=excluded_files,
        workers=workers,
        _budget=_budget,
        _limits=_limits,
        _clock=_clock,
        _prepared_files=_prepared_files,
    )
