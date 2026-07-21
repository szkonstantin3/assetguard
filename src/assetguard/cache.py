"""Content-addressed SQLite cache for successful validator metrics."""

import hashlib
import hmac
import json
import sqlite3
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Self

from assetguard.obj_mesh import ObjMeshMetrics

CACHE_SCHEMA_VERSION = 1
TEXTURE_METRICS_VERSION = 1
OBJ_METRICS_VERSION = 1

TEXTURE_VALIDATOR_KIND = "texture"
OBJ_VALIDATOR_KIND = "obj"

_OWNER_KEY = "owner"
_OWNER_VALUE = "AssetGuard"
_SCHEMA_VERSION_KEY = "schema_version"
_METADATA_TABLE = "assetguard_metadata"
_METRICS_TABLE = "metric_entries"
_METADATA_SCHEMA = [
    ("key", "TEXT", 1, 1),
    ("value", "TEXT", 1, 0),
]
_METRICS_SCHEMA = [
    ("content_sha256", "TEXT", 1, 1),
    ("validator_kind", "TEXT", 1, 2),
    ("validator_version", "INTEGER", 1, 3),
    ("payload", "TEXT", 1, 0),
    ("payload_sha256", "TEXT", 1, 0),
]


class CacheError(Exception):
    """Raised when a cache cannot be safely opened, read, written, or validated."""


@dataclass(frozen=True, slots=True)
class TextureMetrics:
    width: int
    height: int

    def __post_init__(self) -> None:
        if type(self.width) is not int or type(self.height) is not int:
            raise ValueError("texture dimensions must be integers")
        if self.width <= 0 or self.height <= 0:
            raise ValueError("texture dimensions must be positive")


def _canonical_payload(values: dict[str, int]) -> str:
    return json.dumps(values, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _payload_checksum(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _validate_content_digest(content_sha256: str) -> None:
    if len(content_sha256) != 64 or any(
        character not in "0123456789abcdef" for character in content_sha256
    ):
        raise CacheError("internal cache key is not a lowercase SHA-256 digest")


def _strict_json_object(payload: str, validator_kind: str) -> dict[str, Any]:
    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    try:
        decoded = json.loads(payload, object_pairs_hook=reject_duplicate_keys)
    except (json.JSONDecodeError, UnicodeError, ValueError) as exc:
        raise CacheError(f"cached {validator_kind} metrics payload is invalid JSON") from exc
    if not isinstance(decoded, dict):
        raise CacheError(f"cached {validator_kind} metrics payload must be an object")
    return decoded


def _require_exact_integer_fields(
    payload: dict[str, Any],
    expected_fields: set[str],
    validator_kind: str,
) -> dict[str, int]:
    if set(payload) != expected_fields:
        raise CacheError(f"cached {validator_kind} metrics payload has invalid fields")
    if any(type(payload[field]) is not int for field in expected_fields):
        raise CacheError(f"cached {validator_kind} metrics payload has invalid value types")
    return {field: payload[field] for field in expected_fields}


def _decode_texture_metrics(payload: str) -> TextureMetrics:
    values = _require_exact_integer_fields(
        _strict_json_object(payload, TEXTURE_VALIDATOR_KIND),
        {"width", "height"},
        TEXTURE_VALIDATOR_KIND,
    )
    try:
        return TextureMetrics(width=values["width"], height=values["height"])
    except ValueError as exc:
        raise CacheError("cached texture metrics payload has invalid values") from exc


def _decode_obj_metrics(payload: str) -> ObjMeshMetrics:
    expected_fields = {
        "face_count",
        "triangle_count",
        "non_triangulated_face_count",
        "face_corner_count",
        "face_corners_with_uv",
        "material_slot_count",
    }
    values = _require_exact_integer_fields(
        _strict_json_object(payload, OBJ_VALIDATOR_KIND),
        expected_fields,
        OBJ_VALIDATOR_KIND,
    )
    if any(value < 0 for value in values.values()):
        raise CacheError("cached obj metrics payload has invalid values")

    face_count = values["face_count"]
    triangle_count = values["triangle_count"]
    non_triangulated = values["non_triangulated_face_count"]
    corner_count = values["face_corner_count"]
    corners_with_uv = values["face_corners_with_uv"]
    material_slots = values["material_slot_count"]
    invalid = (
        non_triangulated > face_count
        or corners_with_uv > corner_count
        or material_slots > face_count
        or corner_count != triangle_count + (2 * face_count)
        or (face_count == 0 and material_slots != 0)
        or (face_count > 0 and material_slots == 0)
        or (non_triangulated == 0 and triangle_count != face_count)
        or (non_triangulated > 0 and triangle_count - face_count < non_triangulated)
    )
    if invalid:
        raise CacheError("cached obj metrics payload has invalid values")

    return ObjMeshMetrics(
        face_count=face_count,
        triangle_count=triangle_count,
        non_triangulated_face_count=non_triangulated,
        face_corner_count=corner_count,
        face_corners_with_uv=corners_with_uv,
        material_slot_count=material_slots,
    )


def validate_cache_path(cache_path: Path, config_path: Path, output_path: Path) -> Path:
    """Resolve and validate a cache path before any cache file is opened."""

    try:
        resolved_cache = cache_path.resolve(strict=False)
        resolved_config = config_path.resolve(strict=False)
        resolved_output = output_path.resolve(strict=False)
    except OSError as exc:
        raise CacheError("cannot resolve cache, configuration, or report path") from exc

    if resolved_cache == resolved_output:
        raise CacheError("cache path must not be the same as the report output path")
    if resolved_cache == resolved_config:
        raise CacheError("cache path must not be the same as the configuration path")
    if resolved_cache.exists() and resolved_cache.is_dir():
        raise CacheError("cache path is a directory")
    return resolved_cache


def cache_related_paths(cache_path: Path) -> tuple[Path, Path, Path, Path]:
    """Return the cache database and SQLite sidecar paths that scanning must exclude."""

    cache_text = str(cache_path)
    return (
        cache_path,
        Path(f"{cache_text}-journal"),
        Path(f"{cache_text}-wal"),
        Path(f"{cache_text}-shm"),
    )


class AssetMetricsCache:
    """Transaction-scoped AssetGuard metric cache."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._connection: sqlite3.Connection | None = None

        existed = path.exists()
        if existed and path.is_dir():
            raise CacheError("cache path is a directory")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise CacheError("cache parent directory could not be created") from exc

        try:
            connection = sqlite3.connect(str(path), timeout=1.0)
        except sqlite3.Error as exc:
            raise CacheError("cache could not be opened") from exc

        self._connection = connection
        try:
            if existed:
                self._validate_existing_schema()
            else:
                self._initialize_schema()
            connection.execute("BEGIN")
        except CacheError:
            connection.close()
            self._connection = None
            raise
        except sqlite3.Error as exc:
            connection.close()
            self._connection = None
            raise CacheError("cache transaction could not be started") from exc

    @property
    def _db(self) -> sqlite3.Connection:
        if self._connection is None:
            raise CacheError("cache connection is closed")
        return self._connection

    def _initialize_schema(self) -> None:
        connection = self._db
        try:
            connection.execute("BEGIN")
            connection.execute(
                f"""
                CREATE TABLE {_METADATA_TABLE} (
                    key TEXT NOT NULL PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            connection.execute(
                f"""
                CREATE TABLE {_METRICS_TABLE} (
                    content_sha256 TEXT NOT NULL,
                    validator_kind TEXT NOT NULL,
                    validator_version INTEGER NOT NULL,
                    payload TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    PRIMARY KEY (content_sha256, validator_kind, validator_version)
                )
                """
            )
            connection.executemany(
                f"INSERT INTO {_METADATA_TABLE} (key, value) VALUES (?, ?)",
                [
                    (_OWNER_KEY, _OWNER_VALUE),
                    (_SCHEMA_VERSION_KEY, str(CACHE_SCHEMA_VERSION)),
                ],
            )
            connection.execute(f"PRAGMA user_version = {CACHE_SCHEMA_VERSION}")
            connection.commit()
        except sqlite3.Error as exc:
            try:
                connection.rollback()
            except sqlite3.Error as rollback_exc:
                raise CacheError("cache schema initialization and rollback failed") from rollback_exc
            raise CacheError("cache schema could not be initialized") from exc

    def _validate_existing_schema(self) -> None:
        connection = self._db
        try:
            integrity_rows = connection.execute("PRAGMA quick_check").fetchall()
            if integrity_rows != [("ok",)]:
                raise CacheError("cache database integrity check failed")

            table_rows = connection.execute(
                "SELECT name FROM sqlite_master WHERE type = ?",
                ("table",),
            ).fetchall()
            tables = {row[0] for row in table_rows}
            if _METADATA_TABLE not in tables:
                raise CacheError("existing SQLite database is not owned by AssetGuard")

            metadata_rows = connection.execute(
                f"SELECT key, value FROM {_METADATA_TABLE}"
            ).fetchall()
            metadata = {key: value for key, value in metadata_rows}
            if metadata.get(_OWNER_KEY) != _OWNER_VALUE:
                raise CacheError("existing SQLite database is not owned by AssetGuard")

            raw_schema_version = metadata.get(_SCHEMA_VERSION_KEY)
            try:
                schema_version = int(raw_schema_version)
            except (TypeError, ValueError) as exc:
                raise CacheError("AssetGuard cache schema metadata is invalid") from exc
            if schema_version != CACHE_SCHEMA_VERSION:
                raise CacheError(
                    f"unsupported AssetGuard cache schema version {schema_version}"
                )

            user_version = connection.execute("PRAGMA user_version").fetchone()[0]
            if user_version != CACHE_SCHEMA_VERSION:
                raise CacheError(
                    f"unsupported AssetGuard cache schema version {user_version}"
                )
            if _METRICS_TABLE not in tables:
                raise CacheError("AssetGuard cache schema is incomplete")

            metadata_column_rows = connection.execute(
                f"PRAGMA table_info({_METADATA_TABLE})"
            ).fetchall()
            metadata_schema = [
                (row[1], str(row[2]).upper(), row[3], row[5])
                for row in metadata_column_rows
            ]
            metric_column_rows = connection.execute(
                f"PRAGMA table_info({_METRICS_TABLE})"
            ).fetchall()
            metrics_schema = [
                (row[1], str(row[2]).upper(), row[3], row[5])
                for row in metric_column_rows
            ]
            if metadata_schema != _METADATA_SCHEMA or metrics_schema != _METRICS_SCHEMA:
                raise CacheError("AssetGuard cache schema is incompatible")
        except CacheError:
            raise
        except sqlite3.Error as exc:
            raise CacheError("cache database could not be validated") from exc

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: object | None,
    ) -> None:
        try:
            if self._connection is not None and self._connection.in_transaction:
                self._connection.rollback()
        except sqlite3.Error as exc:
            raise CacheError("cache transaction rollback failed") from exc
        finally:
            if self._connection is not None:
                self._connection.close()
                self._connection = None

    def _fetch_payload(
        self,
        content_sha256: str,
        validator_kind: str,
        validator_version: int,
    ) -> str | None:
        _validate_content_digest(content_sha256)
        try:
            row = self._db.execute(
                f"""
                SELECT payload, payload_sha256
                FROM {_METRICS_TABLE}
                WHERE content_sha256 = ?
                  AND validator_kind = ?
                  AND validator_version = ?
                """,
                (content_sha256, validator_kind, validator_version),
            ).fetchone()
        except sqlite3.Error as exc:
            raise CacheError("cache metric lookup failed") from exc
        if row is None:
            return None

        payload, stored_checksum = row
        if not isinstance(payload, str) or not isinstance(stored_checksum, str):
            raise CacheError(f"cached {validator_kind} metrics payload is invalid")
        actual_checksum = _payload_checksum(payload)
        if not hmac.compare_digest(actual_checksum, stored_checksum):
            raise CacheError(f"cached {validator_kind} metrics payload checksum mismatch")
        return payload

    def _store_payload(
        self,
        content_sha256: str,
        validator_kind: str,
        validator_version: int,
        payload: str,
    ) -> None:
        _validate_content_digest(content_sha256)
        try:
            self._db.execute(
                f"""
                INSERT INTO {_METRICS_TABLE} (
                    content_sha256,
                    validator_kind,
                    validator_version,
                    payload,
                    payload_sha256
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    content_sha256,
                    validator_kind,
                    validator_version,
                    payload,
                    _payload_checksum(payload),
                ),
            )
        except sqlite3.Error as exc:
            raise CacheError("cache metric write failed") from exc

    def get_texture(self, content_sha256: str) -> TextureMetrics | None:
        payload = self._fetch_payload(
            content_sha256,
            TEXTURE_VALIDATOR_KIND,
            TEXTURE_METRICS_VERSION,
        )
        return None if payload is None else _decode_texture_metrics(payload)

    def store_texture(self, content_sha256: str, metrics: TextureMetrics) -> None:
        payload = _canonical_payload({"width": metrics.width, "height": metrics.height})
        self._store_payload(
            content_sha256,
            TEXTURE_VALIDATOR_KIND,
            TEXTURE_METRICS_VERSION,
            payload,
        )

    def get_obj(self, content_sha256: str) -> ObjMeshMetrics | None:
        payload = self._fetch_payload(
            content_sha256,
            OBJ_VALIDATOR_KIND,
            OBJ_METRICS_VERSION,
        )
        return None if payload is None else _decode_obj_metrics(payload)

    def store_obj(self, content_sha256: str, metrics: ObjMeshMetrics) -> None:
        payload = _canonical_payload(asdict(metrics))
        self._store_payload(
            content_sha256,
            OBJ_VALIDATOR_KIND,
            OBJ_METRICS_VERSION,
            payload,
        )

    def commit(self) -> None:
        try:
            self._db.commit()
        except sqlite3.Error as exc:
            try:
                self._db.rollback()
            except sqlite3.Error as rollback_exc:
                raise CacheError("cache commit and rollback failed") from rollback_exc
            raise CacheError("cache commit failed") from exc
