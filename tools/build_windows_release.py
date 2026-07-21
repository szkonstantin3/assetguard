"""Build deterministic local Windows release artifacts for AssetGuard."""

from __future__ import annotations

import argparse
import ast
import getpass
import hashlib
import importlib.metadata
import json
import os
import platform
import shutil
import struct
import subprocess
import sys
import time
import tomllib
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable, Mapping, Sequence


SOURCE_DATE_EPOCH = 1767225600
REQUIRED_PYTHON = "3.13.9"
REQUIRED_PYINSTALLER = "6.21.0"
REQUIRED_HOOKS = "2026.6"
PE_MACHINE_AMD64 = 0x8664
PRODUCT_NAME = "AssetGuard"
ARTIFACT_PLATFORM = "windows"
ARTIFACT_ARCHITECTURE = "x86_64"
PROJECT_ROOT = Path(__file__).resolve().parents[1]


class BuildError(Exception):
    """Raised for an expected release-build failure."""


@dataclass(frozen=True)
class ReleaseArtifactSet:
    """Paths to one complete staged release artifact set."""

    executable: Path
    archive: Path
    manifest: Path
    checksums: Path

    def ordered_paths(self) -> tuple[Path, ...]:
        return tuple(sorted(self.__dict__.values(), key=lambda path: path.name))


@dataclass(frozen=True)
class PackagedProof:
    """Deterministic packaged-runtime proof summary."""

    valid_exit: int
    warning_exit: int
    error_exit: int
    operational_exit: int
    cache_hits: int
    json_equal: bool
    html_equal: bool
    assets_unchanged: bool


def sha256_bytes(data: bytes) -> str:
    """Return a lowercase SHA-256 digest."""

    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    """Hash a file without loading it fully into memory."""

    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_project_version(project_root: Path) -> str:
    """Read the authoritative package version from pyproject.toml."""

    try:
        with (project_root / "pyproject.toml").open("rb") as source:
            version = tomllib.load(source)["project"]["version"]
    except (OSError, KeyError, tomllib.TOMLDecodeError) as exc:
        raise BuildError(f"cannot read project version: {exc}") from exc
    if not isinstance(version, str) or not version:
        raise BuildError("project version must be a non-empty string")
    return version


def read_runtime_version(project_root: Path) -> str:
    """Read the report/runtime version without importing application code."""

    version_path = project_root / "src" / "assetguard" / "__init__.py"
    try:
        tree = ast.parse(version_path.read_text(encoding="utf-8"), filename=str(version_path))
    except (OSError, SyntaxError, UnicodeError) as exc:
        raise BuildError(f"cannot read runtime version: {exc}") from exc
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            return node.value.value
    raise BuildError("runtime __version__ is missing")


def windows_version_tuple(version: str) -> tuple[int, int, int, int]:
    """Convert a three-part semantic version into a Windows numeric tuple."""

    parts = version.split(".")
    if len(parts) != 3 or any(not part.isdigit() for part in parts):
        raise BuildError(f"project version '{version}' is not a three-part numeric version")
    values = tuple(int(part) for part in parts)
    if any(value > 65535 for value in values):
        raise BuildError("Windows version components must not exceed 65535")
    return values[0], values[1], values[2], 0


def verify_platform(
    *,
    system: str | None = None,
    implementation: str | None = None,
    python_version: tuple[int, int, int] | None = None,
    machine: str | None = None,
    is_64_bit: bool | None = None,
) -> None:
    """Reject any build host outside the exact Phase 07 release profile."""

    actual_system = system if system is not None else platform.system()
    actual_implementation = (
        implementation if implementation is not None else platform.python_implementation()
    )
    actual_python = python_version if python_version is not None else sys.version_info[:3]
    actual_machine = machine if machine is not None else platform.machine()
    actual_64_bit = is_64_bit if is_64_bit is not None else sys.maxsize > 2**32
    if actual_system != "Windows":
        raise BuildError(f"Windows is required; found {actual_system}")
    if actual_implementation != "CPython":
        raise BuildError(f"CPython is required; found {actual_implementation}")
    rendered_python = ".".join(str(part) for part in actual_python)
    if rendered_python != REQUIRED_PYTHON:
        raise BuildError(
            f"CPython {REQUIRED_PYTHON} is required; found {rendered_python}"
        )
    if actual_machine.upper() not in {"AMD64", "X86_64"} or not actual_64_bit:
        raise BuildError(f"Windows x86_64/AMD64 is required; found {actual_machine}")


def verify_tool_versions(
    version_reader: Callable[[str], str] = importlib.metadata.version,
) -> None:
    """Require the exact pinned PyInstaller toolchain."""

    required = {
        "pyinstaller": REQUIRED_PYINSTALLER,
        "pyinstaller-hooks-contrib": REQUIRED_HOOKS,
    }
    for distribution, expected in required.items():
        try:
            actual = version_reader(distribution)
        except importlib.metadata.PackageNotFoundError as exc:
            raise BuildError(f"required build package is not installed: {distribution}") from exc
        if actual != expected:
            raise BuildError(
                f"{distribution} {expected} is required; found {actual}"
            )


def verify_build_environment(project_root: Path) -> str:
    """Verify versions, platform, architecture, and toolchain before mutation."""

    project_version = read_project_version(project_root)
    runtime_version = read_runtime_version(project_root)
    if runtime_version != project_version:
        raise BuildError(
            f"project version {project_version} does not match runtime version {runtime_version}"
        )
    windows_version_tuple(project_version)
    verify_platform()
    verify_tool_versions()
    return project_version


def generate_version_resource(destination: Path, version: str) -> None:
    """Write a deterministic PyInstaller Windows version resource."""

    numeric = windows_version_tuple(version)
    text = f"""# UTF-8
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers={numeric},
    prodvers={numeric},
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo([
      StringTable(
        '040904B0',
        [StringStruct('CompanyName', 'AssetGuard Project'),
         StringStruct('FileDescription', 'AssetGuard Game Asset Validator'),
         StringStruct('FileVersion', '{version}'),
         StringStruct('InternalName', 'AssetGuard'),
         StringStruct('OriginalFilename', 'AssetGuard.exe'),
         StringStruct('ProductName', 'AssetGuard'),
         StringStruct('ProductVersion', '{version}')]
      )
    ]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
"""
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(text, encoding="utf-8", newline="\n")


def controlled_build_environment(config_dir: Path, temporary_dir: Path) -> dict[str, str]:
    """Create the controlled environment used only by the PyInstaller subprocess."""

    config_dir.mkdir(parents=True, exist_ok=True)
    temporary_dir.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment.update(
        {
            "SOURCE_DATE_EPOCH": str(SOURCE_DATE_EPOCH),
            "PYTHONHASHSEED": "0",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYINSTALLER_CONFIG_DIR": str(config_dir.resolve()),
            "TEMP": str(temporary_dir.resolve()),
            "TMP": str(temporary_dir.resolve()),
        }
    )
    return environment


def _safe_recreate(path: Path, allowed_parent: Path) -> None:
    resolved = path.resolve()
    resolved_parent = allowed_parent.resolve()
    if resolved.parent != resolved_parent:
        raise BuildError(f"refusing to recreate unexpected path: {path}")
    if resolved.exists():
        shutil.rmtree(resolved)
    resolved.mkdir(parents=True)


def invoke_pyinstaller(project_root: Path, build_root: Path, version: str) -> Path:
    """Run PyInstaller for one clean build root."""

    work_dir = build_root / "work"
    dist_dir = build_root / "dist"
    config_dir = build_root / "pyinstaller-config"
    temporary_dir = build_root / "temp"
    for directory in (work_dir, dist_dir, config_dir, temporary_dir):
        directory.mkdir(parents=True, exist_ok=True)
    version_file = build_root / "version-info.txt"
    generate_version_resource(version_file, version)
    environment = controlled_build_environment(config_dir, temporary_dir)
    environment["ASSETGUARD_VERSION_FILE"] = str(version_file.resolve())
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--clean",
        "--noconfirm",
        "--log-level",
        "WARN",
        "--distpath",
        str(dist_dir),
        "--workpath",
        str(work_dir),
        str(project_root / "packaging" / "windows" / "assetguard.spec"),
    ]
    result = subprocess.run(
        command,
        cwd=project_root,
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if result.returncode != 0:
        diagnostic = (result.stderr or result.stdout).strip().splitlines()[-12:]
        raise BuildError(
            "PyInstaller failed with exit code "
            f"{result.returncode}: {' | '.join(diagnostic)}"
        )
    executable = dist_dir / "AssetGuard.exe"
    if not executable.is_file():
        raise BuildError("PyInstaller did not create AssetGuard.exe")
    validate_amd64_pe(executable)
    return executable


def validate_amd64_pe(path: Path) -> None:
    """Require valid DOS/PE signatures and the AMD64 machine type."""

    try:
        with path.open("rb") as executable:
            header = executable.read(64)
            if len(header) < 64 or header[:2] != b"MZ":
                raise BuildError(f"'{path.name}' is not a Windows PE executable")
            pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
            executable.seek(pe_offset)
            pe_header = executable.read(6)
    except OSError as exc:
        raise BuildError(f"cannot read executable '{path}': {exc}") from exc
    if len(pe_header) != 6 or pe_header[:4] != b"PE\0\0":
        raise BuildError(f"'{path.name}' has an invalid PE signature")
    machine = struct.unpack_from("<H", pe_header, 4)[0]
    if machine != PE_MACHINE_AMD64:
        raise BuildError(
            f"'{path.name}' is not AMD64 PE (machine 0x{machine:04x})"
        )


def _png_chunk(kind: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
    )


def deterministic_png(width: int = 64, height: int = 64) -> bytes:
    """Create a small deterministic RGB PNG without build-time fixture files."""

    rows = b"".join(b"\0" + (b"\x18\x7f\xc0" * width) for _ in range(height))
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + _png_chunk(b"IDAT", zlib.compress(rows, level=9))
        + _png_chunk(b"IEND", b"")
    )


def _write_lf(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def _valid_rules(path: Path) -> Path:
    _write_lf(
        path,
        """version: 1
scan:
  exclude_directories: []
naming:
  enabled: true
  severity: error
  allowed_prefixes: [T_, SM_]
textures:
  enabled: true
  severity: error
  extensions: [.png, .tga]
  require_power_of_two: true
  max_width: 4096
  max_height: 4096
meshes:
  enabled: true
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
    )
    return path


def _naming_rules(path: Path, *, duplicates: bool) -> Path:
    _write_lf(
        path,
        f"""version: 1
scan:
  exclude_directories: []
naming:
  enabled: true
  severity: error
  allowed_prefixes: [T_]
textures:
  enabled: false
  severity: error
  extensions: [.png, .tga]
  require_power_of_two: true
  max_width: 4096
  max_height: 4096
duplicates:
  enabled: {str(duplicates).lower()}
  severity: warning
""",
    )
    return path


def _texture_rules(path: Path) -> Path:
    _write_lf(
        path,
        """version: 1
scan:
  exclude_directories: []
naming:
  enabled: true
  severity: error
  allowed_prefixes: [T_]
textures:
  enabled: true
  severity: error
  extensions: [.png, .tga]
  require_power_of_two: true
  max_width: 4096
  max_height: 4096
duplicates:
  enabled: false
  severity: warning
""",
    )
    return path


def sanitized_runtime_environment(temporary_dir: Path) -> dict[str, str]:
    """Return a minimal Windows environment without Python/venv influence."""

    temporary_dir.mkdir(parents=True, exist_ok=True)
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    system_paths = [
        str(Path(system_root) / "System32"),
        system_root,
        str(Path(system_root) / "System32" / "Wbem"),
    ]
    environment = {
        "SystemRoot": system_root,
        "WINDIR": os.environ.get("WINDIR", system_root),
        "COMSPEC": os.environ.get("COMSPEC", str(Path(system_root) / "System32" / "cmd.exe")),
        "PATH": os.pathsep.join(system_paths),
        "PATHEXT": os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD"),
        "PROCESSOR_ARCHITECTURE": "AMD64",
        "TEMP": str(temporary_dir.resolve()),
        "TMP": str(temporary_dir.resolve()),
        "PYTHONUTF8": "1",
    }
    return environment


def _run_command(
    command: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    expected_exit: int,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        list(command),
        cwd=cwd,
        env=dict(environment),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if result.returncode != expected_exit:
        raise BuildError(
            f"command returned {result.returncode}, expected {expected_exit}: "
            f"{' '.join(command)}; stderr={result.stderr.strip()}"
        )
    return result


def _scan_command(
    executable: Path,
    assets: Path,
    config: Path,
    output: Path,
    *,
    html_output: Path | None = None,
    cache: Path | None = None,
    workers: int = 4,
) -> list[str]:
    command = [
        str(executable.resolve()),
        "scan",
        str(assets.resolve()),
        "--config",
        str(config.resolve()),
        "--output",
        str(output.resolve()),
        "--workers",
        str(workers),
    ]
    if html_output is not None:
        command.extend(["--html-output", str(html_output.resolve())])
    if cache is not None:
        command.extend(["--cache", str(cache.resolve())])
    return command


def _asset_state(paths: Sequence[Path]) -> dict[str, tuple[str, int, int]]:
    return {
        path.name: (sha256_file(path), path.stat().st_size, path.stat().st_mtime_ns)
        for path in paths
    }


def run_packaged_proofs(executable: Path, build_root: Path) -> PackagedProof:
    """Exercise the frozen CLI and compare it with the installed module CLI."""

    validate_amd64_pe(executable)
    proof_root = build_root / "proof-данные"
    if proof_root.exists():
        shutil.rmtree(proof_root)
    proof_root.mkdir(parents=True)
    runtime_temp = proof_root / "runtime-temp"
    executable_environment = sanitized_runtime_environment(runtime_temp)
    _run_command(
        [str(executable.resolve()), "--help"],
        cwd=proof_root,
        environment=executable_environment,
        expected_exit=0,
    )
    _run_command(
        [str(executable.resolve()), "scan", "--help"],
        cwd=proof_root,
        environment=executable_environment,
        expected_exit=0,
    )

    valid_assets = proof_root / "активы"
    valid_assets.mkdir()
    texture = valid_assets / "T_текстура.png"
    mesh = valid_assets / "SM_модель.obj"
    texture.write_bytes(deterministic_png())
    _write_lf(
        mesh,
        """v 0 0 0
v 1 0 0
v 0 1 0
vt 0 0
vt 1 0
vt 0 1
f 1/1 2/2 3/3
""",
    )
    valid_config = _valid_rules(proof_root / "правила.yaml")
    asset_paths = [texture, mesh]
    before = _asset_state(asset_paths)

    executable_report = proof_root / "отчёты" / "executable.json"
    executable_html = proof_root / "отчёты" / "executable.html"
    executable_cache = proof_root / "кэш" / "executable.sqlite3"
    valid_result = _run_command(
        _scan_command(
            executable,
            valid_assets,
            valid_config,
            executable_report,
            html_output=executable_html,
            cache=executable_cache,
        ),
        cwd=proof_root,
        environment=executable_environment,
        expected_exit=0,
    )
    repeated_result = _run_command(
        _scan_command(
            executable,
            valid_assets,
            valid_config,
            proof_root / "отчёты" / "executable-repeat.json",
            html_output=proof_root / "отчёты" / "executable-repeat.html",
            cache=executable_cache,
        ),
        cwd=proof_root,
        environment=executable_environment,
        expected_exit=0,
    )
    if "Cache hits: 2" not in repeated_result.stdout:
        raise BuildError("packaged cache repeat did not report two cache hits")

    python_environment = os.environ.copy()
    python_environment.pop("PYTHONHOME", None)
    python_environment.pop("PYTHONPATH", None)
    python_report = proof_root / "отчёты" / "python.json"
    python_html = proof_root / "отчёты" / "python.html"
    python_cache = proof_root / "кэш" / "python.sqlite3"
    python_command = _scan_command(
        Path(sys.executable),
        valid_assets,
        valid_config,
        python_report,
        html_output=python_html,
        cache=python_cache,
    )
    python_command[1:1] = ["-m", "assetguard"]
    python_result = _run_command(
        python_command,
        cwd=proof_root,
        environment=python_environment,
        expected_exit=0,
    )
    json_equal = executable_report.read_bytes() == python_report.read_bytes()
    html_equal = executable_html.read_bytes() == python_html.read_bytes()
    if not json_equal or not html_equal or valid_result.returncode != python_result.returncode:
        raise BuildError("packaged reports do not match python -m assetguard")

    warning_assets = proof_root / "warning-assets"
    warning_assets.mkdir()
    (warning_assets / "T_first.bin").write_bytes(b"duplicate")
    (warning_assets / "T_second.bin").write_bytes(b"duplicate")
    warning_result = _run_command(
        _scan_command(
            executable,
            warning_assets,
            _naming_rules(proof_root / "warning.yaml", duplicates=True),
            proof_root / "warning.json",
        ),
        cwd=proof_root,
        environment=executable_environment,
        expected_exit=0,
    )

    error_assets = proof_root / "error-assets"
    error_assets.mkdir()
    (error_assets / "invalid.bin").write_bytes(b"invalid")
    error_result = _run_command(
        _scan_command(
            executable,
            error_assets,
            _naming_rules(proof_root / "error.yaml", duplicates=False),
            proof_root / "error.json",
        ),
        cwd=proof_root,
        environment=executable_environment,
        expected_exit=1,
    )

    malformed_assets = proof_root / "malformed-assets"
    malformed_assets.mkdir()
    (malformed_assets / "T_bad.png").write_bytes(b"not an image")
    malformed_output = proof_root / "malformed.json"
    malformed_result = _run_command(
        _scan_command(
            executable,
            malformed_assets,
            _texture_rules(proof_root / "malformed.yaml"),
            malformed_output,
        ),
        cwd=proof_root,
        environment=executable_environment,
        expected_exit=2,
    )
    if "Traceback" in malformed_result.stderr or malformed_output.exists():
        raise BuildError("packaged operational failure exposed a traceback or report")

    after = _asset_state(asset_paths)
    assets_unchanged = before == after
    if not assets_unchanged:
        raise BuildError("packaged scan modified a source asset")
    return PackagedProof(
        valid_exit=valid_result.returncode,
        warning_exit=warning_result.returncode,
        error_exit=error_result.returncode,
        operational_exit=malformed_result.returncode,
        cache_hits=2,
        json_equal=json_equal,
        html_equal=html_equal,
        assets_unchanged=assets_unchanged,
    )


def source_input_paths(project_root: Path) -> list[Path]:
    """Return the deterministic relative build-input set."""

    paths = [
        Path("pyproject.toml"),
        Path("README.md"),
        Path("examples/rules.yaml"),
        Path("packaging/windows/assetguard_entry.py"),
        Path("packaging/windows/assetguard.spec"),
        Path("tools/build_windows_release.py"),
    ]
    source_root = project_root / "src" / "assetguard"
    paths.extend(path.relative_to(project_root) for path in source_root.rglob("*.py"))
    return sorted(set(paths), key=lambda path: path.as_posix())


def calculate_source_digest(
    project_root: Path,
    relative_paths: Sequence[Path] | None = None,
) -> str:
    """Hash normalized relative paths and raw bytes for exact build inputs."""

    paths = list(relative_paths) if relative_paths is not None else source_input_paths(project_root)
    digest = hashlib.sha256()
    for relative_path in sorted(paths, key=lambda path: path.as_posix()):
        normalized = relative_path.as_posix()
        if PurePosixPath(normalized).is_absolute() or ".." in PurePosixPath(normalized).parts:
            raise BuildError(f"invalid source input path: {normalized}")
        try:
            data = (project_root / relative_path).read_bytes()
        except OSError as exc:
            raise BuildError(f"cannot read source input '{normalized}': {exc}") from exc
        digest.update(normalized.encode("utf-8"))
        digest.update(b"\0")
        digest.update(data)
        digest.update(b"\0")
    return digest.hexdigest()


def normalized_text_bytes(path: Path) -> bytes:
    """Read UTF-8 text and normalize line endings without modifying the source."""

    text = path.read_text(encoding="utf-8")
    return text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")


def validate_archive_path(path: str) -> None:
    """Reject unsafe ZIP member paths."""

    pure_path = PurePosixPath(path)
    if (
        pure_path.is_absolute()
        or ".." in pure_path.parts
        or not pure_path.parts
        or ":" in pure_path.parts[0]
        or "\\" in path
    ):
        raise BuildError(f"unsafe ZIP path: {path}")


def fixed_zip_datetime() -> tuple[int, int, int, int, int, int]:
    fixed = time.gmtime(SOURCE_DATE_EPOCH)
    return fixed.tm_year, fixed.tm_mon, fixed.tm_mday, fixed.tm_hour, fixed.tm_min, fixed.tm_sec


def create_deterministic_zip(
    destination: Path,
    root_name: str,
    payload: Mapping[str, bytes],
) -> None:
    """Write a stored ZIP with fixed ordering, metadata, and timestamps."""

    validate_archive_path(root_name)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_STORED) as archive:
        for relative_path in sorted(payload):
            validate_archive_path(relative_path)
            member_name = f"{root_name}/{relative_path}"
            validate_archive_path(member_name)
            info = zipfile.ZipInfo(member_name, date_time=fixed_zip_datetime())
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.flag_bits |= 0x800
            archive.writestr(info, payload[relative_path])


def serialize_manifest(
    version: str,
    source_digest: str,
    payload: Mapping[str, bytes],
) -> bytes:
    """Serialize the canonical deterministic release manifest."""

    payload_entries = [
        {
            "path": path,
            "size": len(payload[path]),
            "sha256": sha256_bytes(payload[path]),
        }
        for path in sorted(payload)
    ]
    manifest = {
        "schema_version": 1,
        "product": {
            "name": PRODUCT_NAME,
            "version": version,
            "platform": ARTIFACT_PLATFORM,
            "architecture": ARTIFACT_ARCHITECTURE,
            "format": "pyinstaller-onefile",
        },
        "toolchain": {
            "python": REQUIRED_PYTHON,
            "pyinstaller": REQUIRED_PYINSTALLER,
            "pyinstaller_hooks_contrib": REQUIRED_HOOKS,
            "source_date_epoch": SOURCE_DATE_EPOCH,
        },
        "source": {"sha256": source_digest},
        "payload": payload_entries,
    }
    return (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def serialize_checksums(files: Mapping[str, bytes]) -> bytes:
    """Serialize lowercase SHA-256 lines in filename order."""

    return "".join(
        f"{sha256_bytes(files[name])}  {name}\n" for name in sorted(files)
    ).encode("utf-8")


def create_release_artifact_set(
    project_root: Path,
    executable: Path,
    destination: Path,
    version: str,
) -> ReleaseArtifactSet:
    """Create one complete staged executable/ZIP/manifest/checksum set."""

    destination.mkdir(parents=True, exist_ok=True)
    artifact_stem = f"AssetGuard-{version}-windows-x86_64"
    executable_name = f"{artifact_stem}.exe"
    archive_name = f"{artifact_stem}.zip"
    manifest_name = f"{artifact_stem}.manifest.json"
    checksum_name = f"{artifact_stem}.sha256"
    executable_bytes = executable.read_bytes()
    payload = {
        "AssetGuard.exe": executable_bytes,
        "README.md": normalized_text_bytes(project_root / "README.md"),
        "examples/rules.yaml": normalized_text_bytes(project_root / "examples" / "rules.yaml"),
    }
    published_executable = destination / executable_name
    published_executable.write_bytes(executable_bytes)
    archive = destination / archive_name
    create_deterministic_zip(archive, artifact_stem, payload)
    manifest = destination / manifest_name
    manifest.write_bytes(
        serialize_manifest(version, calculate_source_digest(project_root), payload)
    )
    checksums = destination / checksum_name
    checksums.write_bytes(
        serialize_checksums(
            {
                executable_name: published_executable.read_bytes(),
                archive_name: archive.read_bytes(),
                manifest_name: manifest.read_bytes(),
            }
        )
    )
    artifact_set = ReleaseArtifactSet(
        executable=published_executable,
        archive=archive,
        manifest=manifest,
        checksums=checksums,
    )
    verify_checksum_file(artifact_set)
    return artifact_set


def verify_checksum_file(artifacts: ReleaseArtifactSet) -> None:
    """Verify every declared checksum against its staged file."""

    expected = {
        path.name: sha256_file(path)
        for path in (artifacts.executable, artifacts.archive, artifacts.manifest)
    }
    try:
        lines = artifacts.checksums.read_text(encoding="utf-8").splitlines()
        actual = {
            filename: digest
            for digest, filename in (line.split("  ", 1) for line in lines)
        }
    except (OSError, ValueError) as exc:
        raise BuildError(f"invalid checksum file: {exc}") from exc
    if actual != expected:
        raise BuildError("release checksum verification failed")


def artifact_hashes(artifacts: ReleaseArtifactSet) -> dict[str, str]:
    """Return deterministic hashes keyed by artifact filename."""

    return {path.name: sha256_file(path) for path in artifacts.ordered_paths()}


def compare_artifact_sets(
    first: ReleaseArtifactSet,
    second: ReleaseArtifactSet,
) -> dict[str, str]:
    """Require byte equality for all four staged artifact classes."""

    first_hashes = artifact_hashes(first)
    second_hashes = artifact_hashes(second)
    if first_hashes.keys() != second_hashes.keys():
        raise BuildError("reproducibility artifact sets contain different filenames")
    differences = [
        f"{name}: {first_hashes[name]} != {second_hashes[name]}"
        for name in sorted(first_hashes)
        if first_hashes[name] != second_hashes[name]
    ]
    if differences:
        raise BuildError("same-toolchain reproducibility mismatch: " + "; ".join(differences))
    return first_hashes


def assert_no_artifact_leakage(
    artifacts: ReleaseArtifactSet,
    project_root: Path,
) -> None:
    """Reject meaningful project-root or username byte leakage."""

    sensitive_values = {str(project_root.resolve()), getpass.getuser()}
    patterns: list[tuple[str, bytes]] = []
    for value in sorted(sensitive_values):
        if value:
            patterns.extend(
                [
                    (value, value.encode("utf-8")),
                    (value, value.encode("utf-16le")),
                ]
            )
    binary_targets = [artifacts.executable, artifacts.manifest, artifacts.checksums]
    for target in binary_targets:
        data = target.read_bytes()
        for label, pattern in patterns:
            if pattern in data:
                raise BuildError(f"release artifact '{target.name}' contains sensitive value '{label}'")
    with zipfile.ZipFile(artifacts.archive) as archive:
        for info in archive.infolist():
            name_bytes = info.filename.encode("utf-8")
            payload = archive.read(info)
            for label, pattern in patterns:
                if pattern in name_bytes or pattern in payload:
                    raise BuildError(
                        f"ZIP member '{info.filename}' contains sensitive value '{label}'"
                    )


def _atomic_publish(source: Path, destination: Path) -> None:
    temporary = destination.with_name(f".{destination.name}.tmp")
    try:
        with source.open("rb") as input_file, temporary.open("wb") as output_file:
            shutil.copyfileobj(input_file, output_file, length=1024 * 1024)
            output_file.flush()
            os.fsync(output_file.fileno())
        os.replace(temporary, destination)
    except OSError as exc:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise BuildError(f"cannot publish '{destination.name}': {exc}") from exc


def publish_artifacts(
    artifacts: ReleaseArtifactSet,
    release_dir: Path,
    dist_root: Path,
) -> ReleaseArtifactSet:
    """Publish validated files through temporary siblings and atomic replacements."""

    _safe_recreate(release_dir, dist_root)
    published: dict[str, Path] = {}
    for source in artifacts.ordered_paths():
        destination = release_dir / source.name
        _atomic_publish(source, destination)
        published[source.name] = destination
    result = ReleaseArtifactSet(
        executable=published[artifacts.executable.name],
        archive=published[artifacts.archive.name],
        manifest=published[artifacts.manifest.name],
        checksums=published[artifacts.checksums.name],
    )
    verify_checksum_file(result)
    return result


def build_release(
    project_root: Path = PROJECT_ROOT,
    *,
    verify_reproducible: bool = False,
) -> tuple[ReleaseArtifactSet, list[PackagedProof], list[dict[str, str]]]:
    """Build, prove, optionally compare, and finally publish a release."""

    version = verify_build_environment(project_root)
    build_parent = project_root / "build"
    build_root = build_parent / "windows-release"
    _safe_recreate(build_root, build_parent)
    build_count = 2 if verify_reproducible else 1
    staged_sets: list[ReleaseArtifactSet] = []
    proofs: list[PackagedProof] = []
    build_hashes: list[dict[str, str]] = []
    for build_number in range(1, build_count + 1):
        current_root = build_root / f"build-{build_number}"
        current_root.mkdir()
        print(f"Building clean copy {build_number}/{build_count}...")
        executable = invoke_pyinstaller(project_root, current_root, version)
        proof = run_packaged_proofs(executable, current_root)
        staged = create_release_artifact_set(
            project_root,
            executable,
            current_root / "release-set",
            version,
        )
        assert_no_artifact_leakage(staged, project_root)
        staged_sets.append(staged)
        proofs.append(proof)
        build_hashes.append(artifact_hashes(staged))
    if verify_reproducible:
        compare_artifact_sets(staged_sets[0], staged_sets[1])
    release_dir = project_root / "dist" / "release"
    published = publish_artifacts(staged_sets[0], release_dir, project_root / "dist")
    assert_no_artifact_leakage(published, project_root)
    return published, proofs, build_hashes


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build deterministic local Windows AssetGuard release artifacts."
    )
    parser.add_argument(
        "--verify-reproducible",
        action="store_true",
        help="build two clean copies and require byte-identical artifact sets",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        artifacts, proofs, builds = build_release(
            verify_reproducible=arguments.verify_reproducible
        )
    except (BuildError, OSError, ValueError, zipfile.BadZipFile) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    for index, hashes in enumerate(builds, start=1):
        print(f"Build {index} SHA-256:")
        for filename in sorted(hashes):
            print(f"  {hashes[filename]}  {filename}")
    if arguments.verify_reproducible:
        print("Same-toolchain byte-repeatability: PASSED")
    last_proof = proofs[-1]
    print(
        "Packaged proof: "
        f"exits {last_proof.valid_exit}/{last_proof.warning_exit}/"
        f"{last_proof.error_exit}/{last_proof.operational_exit}, "
        f"cache hits {last_proof.cache_hits}, JSON/HTML equal"
    )
    print(f"Published release: {artifacts.executable.parent}")
    for path in artifacts.ordered_paths():
        print(f"  {path.name} ({path.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
